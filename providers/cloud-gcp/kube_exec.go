package cloudgcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/console7/console7/sandbox/policyhelper"
	"github.com/console7/console7/sdk/interfaces"
)

// This file is the REAL adapter: it satisfies the SandboxRuntime and EgressController ports by
// shelling out to the adopter's pinned `kubectl` + `gcloud` (Option A — zero new dependency for
// this Tier-1 public module; the conformance suite never reaches this code, it runs the fakes).
// It is production code in the default build, but it is exercised only by the opt-in
// integration test (integration_test.go, build tag `cloud_gcp_integration`) against a real
// cluster — unit tests and CI use NewWithPorts with the in-memory fakes.
//
// Manifests are rendered to YAML and applied via `kubectl apply -f -` over stdin. Every dynamic
// string embedded in a manifest is encoded with encoding/json (a JSON string is a valid
// double-quoted YAML scalar), so an untrusted value (e.g. a subject containing a colon or
// newline) cannot break out of its field — there is no YAML-injection path even though we hold
// no YAML library.

// kubeRunner centralises every subprocess launch through one helper so the unavoidable G204
// (subprocess with non-constant args) has a SINGLE audited site. The binaries are literals
// ("gcloud"/"kubectl"); the only variable inputs are validated Config fields and the provider's
// own crypto-random handle IDs — never an external string. KUBECONFIG is pinned to the
// provider's private kubeconfig so calls never touch the operator's ambient config.
type kubeRunner struct {
	kubeconfig string
	project    string
}

// run executes name with args, feeding stdin (may be nil) and returning combined output on
// error for diagnosis. This is the SINGLE audited subprocess site (see the gosec note below).
func (r *kubeRunner) run(ctx context.Context, name string, stdin []byte, args ...string) ([]byte, error) {
	// G204: the command name is a literal ("gcloud"/"kubectl") and args are validated Config
	// fields + the provider's own crypto-random handle IDs, never external input; shelling out is
	// the deliberate zero-dependency adapter (Option A). Tracked: docs/RISKS.md R-3.
	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // G204 — see note above; RISKS R-3
	cmd.Env = r.env()
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("cloudgcp: %s %s: %w: %s", name, strings.Join(args, " "), err, bytes.TrimSpace(out))
	}
	return out, nil
}

// env inherits the process environment (so kubectl/gcloud find their binaries and ambient
// Workload-Identity config) but pins KUBECONFIG to the provider's private kubeconfig, dropping
// any inherited KUBECONFIG so a call can never fall back to the operator's ambient config.
func (r *kubeRunner) env() []string {
	base := os.Environ()
	out := make([]string, 0, len(base)+1)
	for _, kv := range base {
		if strings.HasPrefix(kv, "KUBECONFIG=") {
			continue
		}
		out = append(out, kv)
	}
	return append(out, "KUBECONFIG="+r.kubeconfig)
}

// getCredentials populates the private kubeconfig for cluster@location (gcloud Workload Identity;
// no key file).
func (r *kubeRunner) getCredentials(ctx context.Context, cluster, location string) error {
	_, err := r.run(ctx, "gcloud", nil,
		"container", "clusters", "get-credentials", cluster,
		"--location", location, "--project", r.project)
	return err
}

func (r *kubeRunner) kubectlApply(ctx context.Context, manifest []byte) error {
	_, err := r.run(ctx, "kubectl", manifest, "apply", "-f", "-")
	return err
}

func (r *kubeRunner) kubectlDeleteNamespace(ctx context.Context, ns string) error {
	_, err := r.run(ctx, "kubectl", nil,
		"delete", "namespace", ns, "--ignore-not-found", "--wait=false")
	return err
}

func (r *kubeRunner) kubectlAnnotate(ctx context.Context, kind, name, kv string) error {
	_, err := r.run(ctx, "kubectl", nil, "annotate", "--overwrite", kind, name, kv)
	return err
}

// preflightNetworkPolicyEnforced refuses to build the provider against a cluster where a
// NetworkPolicy would be INERT. On GKE Standard without GKE Dataplane V2 (ADVANCED_DATAPATH) or
// the legacy network-policy addon, `kubectl apply` of a NetworkPolicy succeeds but enforces
// nothing (Kubernetes: a NetworkPolicy with no implementing controller "will have no effect"), so
// ProvisionSandbox would start a pod believing default-deny/isolation is active when it is not —
// the perimeter must fail CLOSED at construction instead.
func (r *kubeRunner) preflightNetworkPolicyEnforced(ctx context.Context, cluster, location string) error {
	out, err := r.run(ctx, "gcloud", nil,
		"container", "clusters", "describe", cluster,
		"--location", location, "--project", r.project,
		"--format=value(networkPolicy.enabled,networkConfig.datapathProvider)")
	if err != nil {
		return err
	}
	if !networkPolicyEnforced(string(out)) {
		return fmt.Errorf("cloudgcp: cluster %q has no NetworkPolicy enforcement (need GKE Dataplane V2 or the network-policy addon) — refusing to provision sandboxes whose egress perimeter would be inert; got %q", cluster, strings.TrimSpace(string(out)))
	}
	return nil
}

// networkPolicyEnforced reports whether a `gcloud container clusters describe` value(...) output
// indicates a cluster that ENFORCES NetworkPolicy: GKE Dataplane V2 (datapathProvider
// ADVANCED_DATAPATH) enforces inherently; otherwise the legacy network-policy addon must be on
// (networkPolicy.enabled = True). Fail-closed: any other/unrecognised output is "not enforced".
func networkPolicyEnforced(describeOutput string) bool {
	s := strings.ToUpper(strings.TrimSpace(describeOutput))
	return strings.Contains(s, "ADVANCED_DATAPATH") || strings.Contains(s, "TRUE")
}

// preflightNodePoolMetadataConcealed refuses to build the provider against a sandbox node pool
// that would EXPOSE the node's GCE service-account token to the pod. The GKE metadata server
// (workloadMetadataConfig.mode = GKE_METADATA) intercepts the node-local metadata endpoint and
// conceals the node SA, serving only Workload-Identity tokens for a pod's bound KSA (and the
// sandbox pods are bound to none, with automountServiceAccountToken=false). The legacy
// GCE_METADATA mode (or an unset mode) leaves the node SA reachable at 169.254.169.254/.252 — a
// standing credential a prompt-injected sandbox could mint, violating cloud.go's "MUST NOT grant
// the sandbox any standing credential of its own". A VPC firewall cannot block that node-local
// path (PR-1), so this construction-time gate is the enforcement point. Fail closed.
func (r *kubeRunner) preflightNodePoolMetadataConcealed(ctx context.Context, cluster, location, nodePool string) error {
	out, err := r.run(ctx, "gcloud", nil,
		"container", "node-pools", "describe", nodePool,
		"--cluster", cluster, "--location", location, "--project", r.project,
		"--format=value(config.workloadMetadataConfig.mode)")
	if err != nil {
		return err
	}
	if !nodePoolMetadataConcealed(string(out)) {
		return fmt.Errorf("cloudgcp: sandbox node pool %q does not conceal the node service account (workloadMetadataConfig.mode must be GKE_METADATA; got %q) — refusing to provision untrusted pods that could mint the node credential", nodePool, strings.TrimSpace(string(out)))
	}
	return nil
}

// nodePoolMetadataConcealed reports whether the node pool's workloadMetadataConfig.mode conceals
// the node SA. Only GKE_METADATA does; GCE_METADATA / EXPOSE / unset all expose it. Fail-closed.
func nodePoolMetadataConcealed(mode string) bool {
	return strings.EqualFold(strings.TrimSpace(mode), "GKE_METADATA")
}

func (r *kubeRunner) kubectlDeletePod(ctx context.Context, ns, pod string) error {
	// WAIT for the pod to actually be gone (kubectl --wait defaults true), with a short SIGTERM
	// grace then SIGKILL, bounded by --timeout. DestroySandbox must not return — letting the
	// orchestrator record session-end — while the workload (and any injected credential material)
	// is still running through a long termination grace. A sandbox that ignores SIGTERM is killed
	// after grace-period; the bound stops a wedged node from hanging teardown forever.
	_, err := r.run(ctx, "kubectl", nil,
		"delete", "pod", pod, "-n", ns, "--ignore-not-found", "--grace-period=5", "--timeout=30s")
	return err
}

// kubeRuntime realises SandboxRuntime: the gVisor pod for one sandbox. The pod's NAMESPACE (and
// its egress NetworkPolicy) are created FIRST by the EgressController — that is how the provider's
// perimeter-before-workload ordering is realised on GKE: the deny-egress policy exists in the
// namespace before this pod is ever created into it.
type kubeRuntime struct {
	run *kubeRunner
	cfg Config
}

// Provision creates the gVisor pod (in the namespace the EgressController already created), pinned
// to the sandbox node pool, with no automounted service-account token and a hard
// activeDeadlineSeconds from spec.MaxTTL. It then stamps the ABSOLUTE session deadline onto the
// namespace so the modules/gke reaper (PR-2b) can hard-delete the sandbox no later than that
// deadline: activeDeadlineSeconds is RELATIVE to the pod's StartTime (scheduling/image-pull latency
// pushes it out past the absolute deadline) and only a backstop, so the annotation is the
// authoritative absolute-deadline signal.
func (k *kubeRuntime) Provision(ctx context.Context, h interfaces.SandboxHandle, spec interfaces.SandboxSpec) error {
	if err := k.run.kubectlApply(ctx, renderSandboxPod(h.ID, k.cfg, spec)); err != nil {
		return err
	}
	expiresAt := nowUTC().Add(spec.MaxTTL).Format(time.RFC3339)
	return k.run.kubectlAnnotate(ctx, "namespace", h.ID, "console7.dev/expires-at="+expiresAt)
}

// Destroy deletes the sandbox pod (the workload). The namespace and its NetworkPolicy are reaped
// by the EgressController's Clear; tearing the pod down first stops the thing that can act before
// the perimeter is removed.
func (k *kubeRuntime) Destroy(ctx context.Context, h interfaces.SandboxHandle) error {
	return k.run.kubectlDeletePod(ctx, h.ID, h.ID)
}

// netpolEgressController realises EgressController: it owns the sandbox NAMESPACE and its
// default-deny NetworkPolicy (the perimeter), plus a ConfigMap carrying the FQDN allowlist the
// out-of-band forward proxy consumes. The NetworkPolicy is an allow-list whose ONLY permitted
// egress is to the proxy namespace (on the proxy port) — so every other destination, INCLUDING
// DNS and the metadata server, is denied by omission at this layer. The sandbox is granted NO
// in-cluster DNS deliberately (docs/THREAT-MODEL.md "no in-sandbox DNS for arbitrary names"): even
// kube-dns resolves arbitrary names and forwards them upstream, which is a DNS-tunnelling exfil
// path that bypasses the FQDN allowlist; name resolution is the forward proxy's job, and the proxy
// is reached by IP (the orchestrator injects its address, no lookup needed — PR-3). It also sets a
// default-deny INGRESS so another pod that discovers the sandbox IP cannot reach the engine. This
// in-cluster policy is defence-in-depth, NOT the authoritative metadata block: a VPC firewall
// cannot see the node-local metadata path, so the authoritative control is the GKE metadata server
// (GKE_METADATA mode) on the sandbox node pool, which conceals the node service account
// (deploy/gcp/modules/networking + modules/gke, PR-2b; New preflights it).
type netpolEgressController struct {
	run *kubeRunner
	cfg Config
}

// Set creates/updates the sandbox namespace, its default-deny NetworkPolicy, and the allowlist
// ConfigMap for handle. It is applied (idempotent upsert) so a later narrow can update the
// allowlist in place. An empty allowlist is deny-all (egress is pinned to the proxy namespace; the
// proxy then admits nothing).
func (e *netpolEgressController) Set(ctx context.Context, h interfaces.SandboxHandle, allowlist []string) error {
	return e.run.kubectlApply(ctx, renderNamespaceAndEgress(h.ID, allowlist))
}

// Clear deletes the sandbox namespace, which reaps its NetworkPolicy, ConfigMap, and any pod still
// in it. It is the teardown counterpart to Set (Set creates the namespace; Clear deletes it) and
// is idempotent (--ignore-not-found), so the provider's failed-provision rollback can call it to
// remove a perimeter whose workload never started, without leaking the namespace.
func (e *netpolEgressController) Clear(ctx context.Context, h interfaces.SandboxHandle) error {
	return e.run.kubectlDeleteNamespace(ctx, h.ID)
}

// kubeEngineRunner realises EngineRunner: it runs the genuine Claude Code engine inside an
// already-provisioned sandbox pod via `kubectl exec` and captures the commit it produces. The
// provider has already gated this on the sandbox being live and perimeter-intact, and egress is
// already narrowed to the inference endpoint, so the engine runs under the default-deny perimeter.
//
// Like the rest of this file it is PRODUCTION code in the default build but exercised only by the
// opt-in integration test against a real cluster (CI runs the InMemoryEngineRunner fake). It is the
// CI blind spot, so it is kept deliberately small and every dynamic value funnels through the single
// audited kubeRunner.run site, with the untrusted prompt + the managed-settings passed over STDIN
// (never an argv string a shell could re-split).
//
// The locked managed-settings are rendered from the resolved profile and mounted READ-ONLY at
// PROVISION time (the agent never writes its own policy — DESIGN.md §5.1, tenet 3); this runner only
// VERIFIES they are present and fails closed if not, mirroring the base image's own entrypoint guard.
// It deliberately does NOT write the policy itself: the locked path is root-owned (sandbox/base-image:
// /etc/claude-code is root:sandbox 2750) and the pod runs runAsNonRoot, so a writable render path would
// be one the agent (same uid) could overwrite — the opposite of a locked policy.
//
// RESIDUALS (Tier-2 / sandbox-image, tracked — this adapter is not yet proven end to end):
//   - The locked managed-settings ARE now rendered at provision time: an init container runs
//     console7-policyhelper (non-root) and writes the 0444 policy into a memory emptyDir that the
//     engine container mounts READ-ONLY at /etc/claude-code (B4). This Run still only VERIFIES the
//     file is present and fails closed if not — it never writes the policy itself.
//   - renderSandboxPod pins the digest-pinned signed engine image (Config.SandboxImage, B3) and
//     renders the non-secret ANTHROPIC_MODEL env, so `claude -p` exists in the pod. Still missing for
//     an end-to-end run: the credential injection (below) and the workspace repo-seed (B6).
//   - The Anthropic credential reaches the engine via the SecretsProvider injection path, not this
//     seam (EngineTask carries no secret); the integration wiring of that injection is Tier-2 (B5/B9).
type kubeEngineRunner struct {
	run *kubeRunner
	cfg Config
}

// execIn runs `kubectl exec -n <ns> <pod> [-i] -- args...`, feeding stdin (nil ⇒ no -i). The pod
// name equals the namespace name (the crypto-random handle ID), as the renderers establish.
func (k *kubeEngineRunner) execIn(ctx context.Context, h interfaces.SandboxHandle, stdin []byte, args ...string) ([]byte, error) {
	base := []string{"exec", "-n", h.ID, h.ID}
	if stdin != nil {
		base = append(base, "-i")
	}
	base = append(base, "--")
	return k.run.run(ctx, "kubectl", stdin, append(base, args...)...)
}

// Run verifies the locked managed-settings are present (fail closed otherwise), runs `claude -p`
// headless under them, and captures the commit the engine produced on the working branch. It NEVER
// pushes, merges, or widens egress; it returns only the digest/head/summary (cloud.go EngineResult
// SECURITY).
func (k *kubeEngineRunner) Run(ctx context.Context, h interfaces.SandboxHandle, task interfaces.EngineTask) (interfaces.EngineResult, error) {
	// Ephemeral by default (tenet 5): a non-positive timeout means the session budget is already
	// spent — refuse rather than run the engine unbounded. The orchestrator passes the time REMAINING
	// to the session deadline, so this is the adapter's fail-closed half of "MUST honour task.Timeout".
	if task.Timeout <= 0 {
		return interfaces.EngineResult{}, errors.New("cloudgcp: non-positive task timeout (session budget exhausted) — refusing to run the engine (ephemeral by default)")
	}
	ctx, cancel := context.WithTimeout(ctx, task.Timeout)
	defer cancel()

	// 1. Fail closed unless the LOCKED managed-settings are already present in the pod. They are
	// rendered from the resolved profile and mounted READ-ONLY at PROVISION time (the agent never
	// writes its own policy — DESIGN.md §5.1, tenet 3); this run only VERIFIES them, mirroring the
	// base image entrypoint's own guard. `test -s` is true only for a present, non-empty file. (The
	// provision-time render + volume mount is the tracked Tier-2 residual — see the type comment.)
	if _, err := k.execIn(ctx, h, nil, "test", "-s", policyhelper.ManagedSettingsPath); err != nil {
		return interfaces.EngineResult{}, fmt.Errorf("cloudgcp: locked managed-settings absent/empty at %s — refusing to run the engine without its policy (fail closed): %w", policyhelper.ManagedSettingsPath, err)
	}

	// 2. Run the genuine engine headless. The untrusted prompt is passed over STDIN, so a shell can
	// never re-split it into extra argv. The engine reads the locked managed-settings itself (the
	// verified file is the authority; the conservative default permission mode is belt-and-suspenders).
	if _, err := k.execIn(ctx, h, []byte(task.Prompt),
		"claude", "-p", "--permission-mode", "default"); err != nil {
		return interfaces.EngineResult{}, fmt.Errorf("cloudgcp: run engine: %w", err)
	}

	// 3. Capture the proposal: stage and commit whatever the engine changed, then read the head. A
	// clean tree (the engine proposed nothing) is a no-op, not an error. NOTE (Tier-2 residual): the
	// resulting commit is the one sanctioned outward channel (the deferred control-plane-side push →
	// PR, under human review); `git add -A` stages broadly, so that push path MUST DLP-scan the diff
	// pre-egress (DESIGN.md §10; the planned pre-egress DLP control) — it is not this seam's job.
	if _, err := k.gitExec(ctx, h, "add", "-A"); err != nil {
		return interfaces.EngineResult{}, fmt.Errorf("cloudgcp: stage engine changes: %w", err)
	}
	status, err := k.gitExec(ctx, h, "status", "--porcelain")
	if err != nil {
		return interfaces.EngineResult{}, fmt.Errorf("cloudgcp: read worktree status: %w", err)
	}
	if len(bytes.TrimSpace(status)) == 0 {
		return interfaces.EngineResult{Changed: false}, nil
	}
	if _, err := k.gitExec(ctx, h, "commit", "-m", "Console7 session "+string(task.SessionID)); err != nil {
		return interfaces.EngineResult{}, fmt.Errorf("cloudgcp: commit engine changes: %w", err)
	}
	head, err := k.gitExec(ctx, h, "rev-parse", "HEAD")
	if err != nil {
		return interfaces.EngineResult{}, fmt.Errorf("cloudgcp: read commit head: %w", err)
	}
	headSHA := strings.TrimSpace(string(head))
	files, _ := k.gitExec(ctx, h, "show", "--stat", "--name-only", "--format=", "HEAD")
	return interfaces.EngineResult{
		// The commit SHA uniquely identifies the engine's real output; the orchestrator domain-tags
		// it (commitTBS) before the NHI signs it, so the raw identity is all this seam returns.
		CommitDigest: []byte(headSHA),
		HeadSHA:      headSHA,
		FilesChanged: nonEmptyLines(string(files)),
		Changed:      true,
	}, nil
}

// gitExec runs a git subcommand in the in-pod working directory via `kubectl exec`. safe.directory
// is set because the checkout may be owned by a uid other than the engine's (e.g. a mounted or
// pre-populated workspace), which modern git otherwise refuses with "dubious ownership".
func (k *kubeEngineRunner) gitExec(ctx context.Context, h interfaces.SandboxHandle, args ...string) ([]byte, error) {
	return k.execIn(ctx, h, nil, append([]string{"git", "-c", "safe.directory=" + k.cfg.Workdir, "-C", k.cfg.Workdir}, args...)...)
}

// nonEmptyLines splits s into its non-blank, trimmed lines — the file paths from `git show
// --name-only` — for the auditable FilesChanged summary (paths only, never file contents).
func nonEmptyLines(s string) []string {
	var out []string
	for _, ln := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(ln); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// credentialPath is the in-pod file the CredentialDeliverer writes short-lived credential material
// to. It lives under /run/console7 — a `medium: Memory` emptyDir mounted into the sandbox container
// (renderSandboxPod) — so the secret is tmpfs-only (never on disk) and dies with the pod. The value
// is a filesystem PATH, not a credential, so gosec G101 is a false positive here (RISKS R-5).
const credentialPath = "/run/console7/credential" //nolint:gosec // G101 false positive: a tmpfs path, not a secret value; RISKS R-5

// kubeCredentialDeliverer realises CredentialDeliverer: it writes credential material into a live
// sandbox pod's memory volume via `kubectl exec`, feeding the material over STDIN (never argv) so it
// cannot leak into a process table, shell history, or this adapter's logs. The provider only calls
// Deliver after re-verifying ownership under its lock (DeliverIfOwned). Like the rest of this file it
// is exercised live only by the integration test; CI drives the provider over the in-memory fake.
type kubeCredentialDeliverer struct {
	run *kubeRunner
}

// Deliver writes material to credentialPath in the sandbox container. `umask 077` makes the file
// 0600 (owner-only); the engine runs as that same non-root uid and reads its own credential. The
// material is the exec's STDIN, so it is never an argument. cat truncates+rewrites, so a re-deliver
// (a refreshed token) replaces the prior bytes.
func (d *kubeCredentialDeliverer) Deliver(ctx context.Context, h interfaces.SandboxHandle, material []byte) error {
	_, err := d.run.run(ctx, "kubectl", material,
		"exec", "-n", h.ID, h.ID, "-c", "sandbox", "-i", "--",
		"/bin/sh", "-c", "umask 077; cat > "+credentialPath)
	return err
}

// Wipe best-effort shreds the credential file. The authoritative wipe is the pod's deletion (the
// volume is medium: Memory), so an exec failure here (e.g. the pod is already gone) is tolerated by
// the caller; `rm -f` is idempotent.
func (d *kubeCredentialDeliverer) Wipe(ctx context.Context, h interfaces.SandboxHandle) error {
	_, err := d.run.run(ctx, "kubectl", nil,
		"exec", "-n", h.ID, h.ID, "-c", "sandbox", "--",
		"/bin/sh", "-c", "rm -f "+credentialPath)
	return err
}

// jsonScalar encodes s as a double-quoted YAML scalar via encoding/json (a JSON string is a valid
// YAML double-quoted scalar, with the YAML-structural characters — quote, backslash, newline,
// colon, etc. — escaped). For the validated values this adapter renders (the persona enum,
// RuntimeClass/NodePool config, policy-sourced FQDNs) this removes any field-breakout path.
// CAVEAT: encoding/json does not escape U+2028/U+2029/U+0085, which YAML 1.1 can read as line
// breaks; do not feed jsonScalar a value that could carry those without escaping them first.
func jsonScalar(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		return `""`
	}
	return string(b)
}

// sandboxPodManifestTemplate is the ConfigMap(session-profile)+Pod manifest rendered per sandbox.
// Kept as a package const so the renderer stays small; the %[n]s args are filled by renderSandboxPod.
const sandboxPodManifestTemplate = `apiVersion: v1
kind: ConfigMap
metadata:
  name: %[1]s-session-profile
  namespace: %[1]s
data:
  profile.json: %[7]s
---
apiVersion: v1
kind: Pod
metadata:
  name: %[1]s
  namespace: %[1]s
spec:
  runtimeClassName: %[2]s
  automountServiceAccountToken: false
  nodeSelector:
    cloud.google.com/gke-nodepool: %[3]s
  activeDeadlineSeconds: %[4]d
  restartPolicy: Never
  securityContext:
    runAsNonRoot: true
    runAsUser: 65532
    runAsGroup: 65532
    fsGroup: 65532
    seccompProfile:
      type: RuntimeDefault
  volumes:
    - name: managed-settings
      emptyDir:
        medium: Memory
        sizeLimit: 1Mi
    - name: credentials
      emptyDir:
        medium: Memory
        sizeLimit: 1Mi
    - name: session-profile
      configMap:
        name: %[1]s-session-profile
        items:
          - key: profile.json
            path: profile.json
  initContainers:
    - name: render-policy
      image: %[5]s
      command: ["/bin/sh", "-c", "exec console7-policyhelper < /etc/console7/session-profile/profile.json"]
      securityContext:
        allowPrivilegeEscalation: false
        capabilities:
          drop: [ALL]
      volumeMounts:
        - name: managed-settings
          mountPath: /etc/claude-code
        - name: session-profile
          mountPath: /etc/console7/session-profile
          readOnly: true
      resources:
        requests:
          cpu: 50m
          memory: 64Mi
        limits:
          cpu: 250m
          memory: 128Mi
  containers:
    - name: sandbox
      image: %[5]s
%[6]s      securityContext:
        allowPrivilegeEscalation: false
        capabilities:
          drop: [ALL]
      volumeMounts:
        - name: managed-settings
          mountPath: /etc/claude-code
          readOnly: true
        - name: credentials
          mountPath: /run/console7
      resources:
        requests:
          cpu: 250m
          memory: 256Mi
          ephemeral-storage: 1Gi
        limits:
          cpu: "2"
          memory: 2Gi
          ephemeral-storage: 4Gi
`

// renderSandboxPod renders the gVisor Pod for one sandbox into the namespace the EgressController
// already created. nsID is the crypto-random handle ID (a valid DNS-1123 label, safe unquoted as
// the resource/namespace name); every other dynamic value is json-encoded.
func renderSandboxPod(nsID string, cfg Config, spec interfaces.SandboxSpec) []byte {
	ttlSeconds := int64(spec.MaxTTL.Seconds())
	if ttlSeconds < 1 {
		ttlSeconds = 1
	}
	// Render only the NON-SECRET inference env at provision time: ANTHROPIC_MODEL (the org-API model
	// pin; the engine's default 404s, so a real run needs it). The Anthropic API KEY is deliberately
	// NOT in the pod spec — a secret in the manifest would persist in etcd; it is injected into the
	// running pod at run time by the SecretsProvider injection path (B5/B9). When AnthropicModel is
	// empty (e.g. a lifecycle-only provision) no env block is rendered.
	envBlock := ""
	if cfg.AnthropicModel != "" {
		envBlock = fmt.Sprintf("      env:\n        - name: ANTHROPIC_MODEL\n          value: %s\n", jsonScalar(cfg.AnthropicModel))
	}

	// The session's resolved profile (persona) the init container renders the LOCKED managed-settings
	// from. Only Persona drives the render (policyhelper.Render switches on it); marshaling the typed
	// struct keeps it forward-compatible. A marshal failure (cannot happen for this struct) yields
	// empty JSON → the init's policyhelper fails to parse → fail closed (the engine never starts).
	profileJSON, _ := json.Marshal(interfaces.SessionProfile{Persona: spec.Persona})

	// The managed-settings LOCK (DESIGN.md §5.1, tenet 3): an init container runs console7-policyhelper
	// AS A NON-ROOT user (PSA `restricted` forbids root, see renderNamespaceAndEgress), reading the
	// SessionProfile over stdin from a read-only ConfigMap mount and writing the 0444 managed-settings
	// into a memory emptyDir at /etc/claude-code. The MAIN container mounts that SAME volume at
	// /etc/claude-code READ-ONLY — and the readOnly MOUNT, not the file's uid/mode, is the authoritative
	// lock: the kernel denies writes to a readOnly mount regardless of ownership, so the non-root engine
	// (same uid) cannot overwrite its own policy. The emptyDir is `medium: Memory` (never on disk) and
	// deliberately SHADOWS the image's baked /etc/claude-code. The init container completes before the
	// engine starts, so at run time the only mount of the volume is the engine's readOnly one.
	return fmt.Appendf(nil, sandboxPodManifestTemplate,
		nsID,
		jsonScalar(cfg.RuntimeClass),
		jsonScalar(cfg.NodePool),
		ttlSeconds,
		jsonScalar(cfg.SandboxImage),
		envBlock,
		jsonScalar(string(profileJSON)),
	)
}

// nowUTC is the wall clock the adapter stamps absolute-deadline annotations from. A package var so
// it is unambiguous (and stubbable) though the adapter is exercised only by the integration test.
var nowUTC = func() time.Time { return time.Now().UTC() }

// proxyPort is the forward-proxy listener the sandbox is allowed to reach. It is the conventional
// Squid/forward-proxy port; sandbox/egress-proxy (PR-3) sets the authoritative value when it ships
// the proxy workload, at which point this rule is reconciled to match.
const proxyPort = 3128

// renderNamespaceAndEgress renders the sandbox Namespace + the default-deny NetworkPolicy + the
// allowlist ConfigMap. The NetworkPolicy denies ALL ingress (no ingress rules), and its ONLY
// permitted egress is to the proxy namespace on the proxy port — every other destination,
// including DNS and the metadata server, is denied by omission. The sandbox does NO DNS of its own
// (the proxy resolves names and enforces the FQDN allowlist, which is carried to it in the
// ConfigMap; a NetworkPolicy is IP-based and cannot match FQDNs anyway).
func renderNamespaceAndEgress(nsID string, allowlist []string) []byte {
	// Canonicalise the deny-all wire format: json.Marshal of a nil []string is "null", not "[]",
	// and every deny-all path (widen-refused, narrow-fallback, an empty spec allowlist) passes nil.
	// The NetworkPolicy is the authoritative perimeter regardless, but this ConfigMap is the
	// contract PR-3's forward proxy will parse — emit exactly "[]" so a "null = no policy = allow"
	// reading can never invert deny-all into allow-all (ports.go: empty allowlist means deny-all).
	encoded := []byte("[]")
	if len(allowlist) > 0 {
		if m, err := json.Marshal(allowlist); err == nil {
			encoded = m
		}
	}
	return fmt.Appendf(nil, `apiVersion: v1
kind: Namespace
metadata:
  name: %[1]s
  labels:
    app.kubernetes.io/managed-by: console7
    # Pod Security Admission "restricted": forbids hostNetwork/privileged/root and requires
    # seccomp + dropped capabilities, so a renderer that (incorrectly) set hostNetwork could not
    # bypass GKE_METADATA node-SA concealment at the host netns. This is the admission-layer
    # enforcement of the no-standing-credential property the sandbox pod manifest already honours
    # (gke/README.md residual); enforce-version pinned so the policy can't silently relax.
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: latest
    pod-security.kubernetes.io/warn: restricted
    pod-security.kubernetes.io/audit: restricted
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: console7-egress-allowlist
  namespace: %[1]s
data:
  allowlist.json: %[2]s
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: console7-default-deny
  namespace: %[1]s
spec:
  podSelector: {}
  policyTypes: [Egress, Ingress]
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              console7.dev/egress-proxy: "true"
      ports:
        - protocol: TCP
          port: %[3]d
`,
		nsID,
		jsonScalar(string(encoded)),
		proxyPort,
	)
}
