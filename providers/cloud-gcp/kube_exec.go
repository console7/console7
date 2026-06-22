package cloudgcp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"regexp"
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
	// The EgressController.Set already created this sandbox's PER-SESSION forward proxy (its own
	// <id>-proxy namespace + Squid Deployment/Service), so its Service ClusterIP is allocated and
	// resolvable now. Resolve it and inject it as the sandbox's HTTPS_PROXY — the sandbox has NO DNS,
	// so it must reach the proxy by IP. Fail closed: if the proxy has no usable ClusterIP we do NOT
	// start a workload that has no egress path (or, worse, one that silently bypasses the proxy).
	endpoint, err := k.run.proxyEndpoint(ctx, proxyNS(h.ID))
	if err != nil {
		return fmt.Errorf("cloudgcp: resolve per-session egress proxy endpoint before provision: %w", err)
	}
	if err := k.run.kubectlApply(ctx, renderSandboxPod(h.ID, k.cfg, spec, endpoint)); err != nil {
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

// netpolEgressController realises EgressController. It owns BOTH halves of one session's perimeter:
//
//  1. the sandbox NAMESPACE + its default-deny NetworkPolicy (the in-cluster wall) + an audit
//     ConfigMap recording the resolved FQDN allowlist; and
//  2. a PER-SESSION forward proxy — its OWN namespace (<id>-proxy) holding a Squid Deployment +
//     Service + ConfigMap whose squid.conf is the session's allowlist as Squid ACLs over a deny-all
//     floor (renderPerSessionProxy / renderSquidConf).
//
// PER-SESSION (not one shared proxy) is deliberate (the B7→B8 decision): a single shared Squid with
// `dstdomain`-only allows would admit each session's hosts to EVERY client on the listener — a
// cluster-wide UNION of allowlists (a tenet-4 / scope-follows-artefact violation). A proxy that
// lives and dies with its one session makes the source discriminator STRUCTURAL (the proxy serves
// exactly one sandbox), needs no in-place config reload (a re-Set rolls the pod via a config-hash
// annotation), and scopes a proxy failure to its own session instead of the whole data plane.
//
// The NetworkPolicy is an allow-list whose ONLY permitted egress is to THIS session's proxy
// namespace (selected by the per-session `console7.dev/proxy-for: <id>` label, never a shared label)
// on the proxy port — so every other destination, INCLUDING DNS and the metadata server, is denied
// by omission at this layer. The sandbox is granted NO in-cluster DNS deliberately
// (docs/THREAT-MODEL.md "no in-sandbox DNS for arbitrary names"): even kube-dns resolves arbitrary
// names and forwards them upstream, a DNS-tunnelling exfil path that bypasses the FQDN allowlist;
// name resolution is the proxy's job, and the proxy is reached by IP (Provision injects its
// ClusterIP as HTTPS_PROXY, no lookup needed). It also sets a default-deny INGRESS so another pod
// that discovers the sandbox IP cannot reach the engine; symmetrically the proxy namespace admits
// ingress ONLY from its own sandbox namespace (console7.dev/session: <id>). This in-cluster policy
// is defence-in-depth, NOT the authoritative metadata block: a VPC firewall cannot see the
// node-local metadata path, so the authoritative control is the GKE metadata server (GKE_METADATA
// mode) on the sandbox node pool, which conceals the node service account (deploy/gcp/modules/
// networking + modules/gke; New preflights it).
type netpolEgressController struct {
	run *kubeRunner
	cfg Config
}

// Set creates/updates, for handle, BOTH the per-session forward proxy (its namespace + Squid
// Deployment/Service rendering this allowlist as ACLs) AND the sandbox namespace + default-deny
// NetworkPolicy (pinned to that proxy) + the audit allowlist ConfigMap. It is applied (idempotent
// upsert) so a later narrow re-renders the proxy's ACLs in place: the squid.conf changes, its
// config-hash annotation on the Deployment pod template changes, and the Deployment rolls a fresh
// Squid pod with the narrowed config (a subPath ConfigMap mount does NOT hot-reload, so the
// annotation-driven roll is how the new ACLs take effect). The proxy is rendered FIRST so its
// Service ClusterIP exists before Provision resolves it. An empty allowlist is deny-all: the proxy's
// squid.conf has no allow line above its `http_access deny all` floor, and egress is pinned to that
// proxy. FAIL-CLOSED: a malformed allowlist entry aborts the whole Set (renderSquidConf errors)
// rather than rendering a proxy that silently drops the bad entry.
func (e *netpolEgressController) Set(ctx context.Context, h interfaces.SandboxHandle, allowlist []string) error {
	conf, err := renderSquidConf(allowlist)
	if err != nil {
		// A malformed entry must never collapse into an over-broad or vacuously-empty perimeter.
		return fmt.Errorf("cloudgcp: render per-session proxy config (fail closed): %w", err)
	}
	if err := e.run.kubectlApply(ctx, renderPerSessionProxy(h.ID, conf, squidConfigHash(conf))); err != nil {
		return fmt.Errorf("cloudgcp: set per-session egress proxy: %w", err)
	}
	return e.run.kubectlApply(ctx, renderNamespaceAndEgress(h.ID, allowlist))
}

// Clear deletes BOTH the sandbox namespace and its per-session proxy namespace, each of which reaps
// its own NetworkPolicy/ConfigMap/Service/workload. It is the teardown counterpart to Set and is
// idempotent (--ignore-not-found), so the provider's failed-provision rollback can call it to remove
// a perimeter whose workload never started without leaking either namespace. Both deletes are
// attempted (errors joined) so a failure tearing one down never orphans the other.
func (e *netpolEgressController) Clear(ctx context.Context, h interfaces.SandboxHandle) error {
	perr := e.run.kubectlDeleteNamespace(ctx, proxyNS(h.ID))
	serr := e.run.kubectlDeleteNamespace(ctx, h.ID)
	return errors.Join(perr, serr)
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
//     renders the non-secret ANTHROPIC_MODEL env, so `claude -p` exists in the pod. Run now SEEDS the
//     working repo (workspaceSeedScript: git init on a fresh branch, origin remote, .git/info/exclude
//     — B6); fetching origin's CONTENT (an SCM token via the Injector + egress to the SCM host) is the
//     live wiring B11 adds.
//   - Credential delivery into the pod EXISTS (the Provider's Owns/DeliverIfOwned over a memory
//     volume, B5) and Run now CONSUMES it: engineRunScript reads credentialPath and exports it as the
//     engine's ANTHROPIC_API_KEY for the `claude -p` process only (the B9 file→env bridge), failing
//     closed if absent. STILL the orchestrator wiring: resolving the minted org-API CredentialRef and
//     DeliverIfOwned'ing it to credentialPath before RunTask (the next rung), and the seed's SCM token.
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

	// 2. Seed the working repo at Workdir from task.Repo/task.Branch BEFORE the engine runs: establish
	// a git repo on a FRESH working branch (never a protected ref — tenet 6), record the origin remote,
	// and write .git/info/exclude so the proposed commit is the task diff only (not the engine's own
	// dotfiles — the local-dogfood lesson). Without this, `git rev-parse HEAD` below errors on an empty
	// tree. Fetching origin's CONTENT (a short-lived SCM token via the Injector + egress to the SCM
	// host) is the live step the integration wiring adds (B11); this scaffolding is what makes the
	// commit/HEAD read succeed and keeps the engine's scaffolding out of the proposal.
	seed, err := workspaceSeedScript(k.cfg.Workdir, task)
	if err != nil {
		return interfaces.EngineResult{}, fmt.Errorf("cloudgcp: build workspace seed: %w", err)
	}
	if _, err := k.execIn(ctx, h, nil, "/bin/sh", "-c", seed); err != nil {
		return interfaces.EngineResult{}, fmt.Errorf("cloudgcp: seed workspace: %w", err)
	}

	// 3. Run the genuine engine headless UNDER THE DELIVERED CREDENTIAL (the B9 file→env bridge). The
	// CredentialDeliverer (B5) wrote the short-lived org-API key to credentialPath; engineRunScript
	// reads it FROM THAT IN-POD FILE and exports it as ANTHROPIC_API_KEY for the claude process only —
	// so the secret value is never in the kubectl argv (control side), the pod spec (etcd), claude's
	// own argv, or this adapter's logs. It fails CLOSED if the credential is absent/empty (the engine
	// must not run unauthenticated). The untrusted prompt is still passed over STDIN (claude inherits
	// fd 0), so a shell can never re-split it into extra argv; the engine reads the locked
	// managed-settings itself (the verified file is the authority; default permission mode belt-and-braces).
	if _, err := k.execIn(ctx, h, []byte(task.Prompt),
		"/bin/sh", "-c", engineRunScript(credentialPath)); err != nil {
		return interfaces.EngineResult{}, fmt.Errorf("cloudgcp: run engine: %w", err)
	}

	// 4. Capture the proposal: stage and commit whatever the engine changed, then read the head. A
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

// engineDotfileExcludes are the engine's OWN working-dir dropfiles (per-project settings, todos,
// transcripts, caches) that must NOT appear in the proposed commit — the commit is the task diff
// only, not the agent's scaffolding (the local-dogfood lesson). They go in .git/info/exclude, an
// in-repo ignore that is itself never committed and that a target repo's own .gitignore cannot undo.
var engineDotfileExcludes = []string{".claude/", ".config/", ".cache/"}

// protectedBranches is a DEFENCE-IN-DEPTH seed-time pre-check, NOT the control of record: the
// authoritative tenet-6 (observe/propose, never actuate) enforcement is the SCMProvider seam, which
// refuses a push to the ADOPTER-configured protected set (scm-github). This is a deliberately small,
// non-configurable denylist of common defaults — it can DIVERGE from the adopter's real set both
// ways, so it never stands alone; the seed also does no push (content fetch/push is B11), and
// task.Branch is orchestrator-set, not agent-set. Case-insensitive exact match.
var protectedBranches = map[string]bool{
	"main": true, "master": true, "trunk": true, "develop": true, "production": true, "release": true,
}

func isProtectedBranch(b string) bool {
	return protectedBranches[strings.ToLower(strings.TrimSpace(b))]
}

// shquote wraps s as a single-quoted POSIX shell word (escaping embedded single quotes), so a
// task-supplied value composed into the seed script cannot break out of its argument — defence in
// depth even though Repo/Branch are validated SCM identifiers.
func shquote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// workspaceSeedScript builds the /bin/sh script that seeds the engine's working repo at workdir from
// task.Repo/task.Branch before the engine runs. It is a PURE function (the unit-testable core of the
// seed; the exec is integration-only): it validates the coordinates, refuses a protected branch, and
// emits an idempotent script that git-inits the repo on the fresh branch, records the origin remote
// (no network — the content fetch is the live B11 step), and writes .git/info/exclude. Every embedded
// value is shell-quoted.
func workspaceSeedScript(workdir string, task interfaces.EngineTask) (string, error) {
	if task.Repo.Host == "" || task.Repo.Owner == "" || task.Repo.Name == "" {
		return "", errors.New("cloudgcp: EngineTask.Repo requires Host, Owner, and Name to seed the workspace")
	}
	branch := strings.TrimSpace(task.Branch)
	if branch == "" {
		return "", errors.New("cloudgcp: EngineTask.Branch is required (the session's fresh working branch)")
	}
	if isProtectedBranch(branch) {
		return "", fmt.Errorf("cloudgcp: refusing to seed onto protected branch %q — a session works a fresh branch (defence-in-depth; the SCM seam enforces the adopter's protected set authoritatively, tenet 6)", branch)
	}
	remote := fmt.Sprintf("https://%s/%s/%s.git", task.Repo.Host, task.Repo.Owner, task.Repo.Name)

	var b strings.Builder
	b.WriteString("set -eu\n")
	b.WriteString("cd " + shquote(workdir) + "\n")
	b.WriteString("if [ ! -d .git ]; then git init -q; fi\n")
	// Set the unborn HEAD to the fresh branch (idempotent; works before any commit exists).
	b.WriteString("git symbolic-ref HEAD " + shquote("refs/heads/"+branch) + "\n")
	b.WriteString(`git config user.email "console7-agent@console7.dev"` + "\n")
	b.WriteString(`git config user.name "Console7 Agent"` + "\n")
	// Record origin without fetching (the content fetch with a short-lived SCM token + egress is B11).
	b.WriteString("git remote add origin " + shquote(remote) + " 2>/dev/null || git remote set-url origin " + shquote(remote) + "\n")
	// (Re)write .git/info/exclude so the engine's own dropfiles stay out of `git add -A`.
	b.WriteString(": > .git/info/exclude\n")
	for _, e := range engineDotfileExcludes {
		b.WriteString("echo " + shquote(e) + " >> .git/info/exclude\n")
	}
	return b.String(), nil
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
//
// FILE→ENV BRIDGE (B9): B5 DELIVERS the material to this file; the runner (engineRunScript, below)
// reads it FROM THE IN-POD FILE and exports it as the engine's ANTHROPIC_API_KEY on the Run-controlled
// `claude -p` invocation — set at exec time on that one process, never baked into the pod spec (no
// secret in etcd) and never in argv. The two seams agree on this path as the contract. (The ORCHESTRATOR
// side — resolving the minted org-API CredentialRef and DeliverIfOwned'ing it to this file before
// RunTask — is the next rung; until it lands, a live Run fails closed here, by design.)
const credentialPath = "/run/console7/credential" //nolint:gosec // G101 false positive: a tmpfs path, not a secret value; RISKS R-5

// engineRunScript builds the in-pod `/bin/sh -c` program kubeEngineRunner.Run executes to run the
// genuine engine under the delivered credential (the B9 file→env bridge). It:
//  1. fails CLOSED unless the credential the CredentialDeliverer wrote (credPath) is present AND
//     non-empty — the engine must never run unauthenticated; and
//  2. runs `claude -p` with the credential exported as ANTHROPIC_API_KEY for THAT PROCESS ONLY, read
//     from the in-pod file by the in-pod shell. A prefix assignment (VAR="$ref" cmd) puts the value in
//     claude's ENVIRONMENT, not its argv, so the secret is never in /proc/<pid>/cmdline, the kubectl
//     argv (control side), the pod spec, or this adapter's logs — only the prompt (STDIN) and this fixed
//     command shape cross the wire.
//
// The credential is read ONCE into a shell variable as a STANDALONE assignment (not a prefix
// command-substitution): under `set -e` a standalone failed `$(cat …)` aborts the script, whereas a
// FAILED substitution in a prefix assignment (`VAR="$(cat …)" cmd`) does NOT abort on dash — it would
// run the engine with an empty key. The explicit `[ -n ]` then closes the TOCTOU window between the
// `test -s` check and the read (a racing Wipe/refresh/eviction). Both together make fail-closed real,
// not just asserted (the unit test exercises it under the actual shell).
//
// A function (not a const) so the fail-closed behaviour is testable against a temp path without a
// cluster (the runner is integration-only). The prompt arrives on STDIN, which claude inherits (the
// cat/test read the file, not STDIN). credPath is a trusted no-space constant (credentialPath).
func engineRunScript(credPath string) string {
	return `set -eu
test -s ` + credPath + ` || { echo "cloudgcp: engine credential absent/empty at ` + credPath + ` (fail closed)" >&2; exit 1; }
_c7cred="$(cat ` + credPath + `)"
[ -n "$_c7cred" ] || { echo "cloudgcp: engine credential empty at ` + credPath + ` (fail closed)" >&2; exit 1; }
ANTHROPIC_API_KEY="$_c7cred" claude -p --permission-mode default`
}

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

// hostRe bounds an egress-allowlist host to a DNS hostname (labels of alphanumerics/hyphens, dot-
// separated) so a crafted allowlist entry cannot inject a Squid directive (newline/space/control) or
// a wildcard. It is an EXACT host — never a leading-dot subdomain wildcard — so the perimeter admits
// only the named host (tenet 3: the boundary is the host:port allowlist, not a pattern).
var hostRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

// egressAllowlistToSquidACL transforms the session's default-deny URL allowlist into the Squid
// http_access ACL fragment the per-session proxy enforces (B8). Each URL becomes an EXACT-host +
// EXACT-port allow. It FAILS CLOSED on ANY malformed/unsupported entry (a non-http(s) scheme, a
// missing/invalid host, an unparseable port) — returning an error rather than silently dropping the
// entry, so a bad allowlist can never collapse into an empty (deny-all-but-then-mis-handled) or
// over-broad config that would make the egress proof vacuous (DESIGN.md §5.2; the review's
// fail-closed-on-malformed requirement). An EMPTY allowlist yields an empty fragment — the proxy's
// trailing `http_access deny all` then denies everything (deny-all, the correct default).
//
// The host is lower-cased and validated against hostRe; the port defaults to 443 (https) / 80 (http).
// Values are interpolated into squid.conf, so the strict host charset + numeric port are the
// injection guard (a Squid config has no string-quoting we could rely on instead).
func egressAllowlistToSquidACL(allowlist []string) (string, error) {
	var b strings.Builder
	for i, raw := range allowlist {
		raw = strings.TrimSpace(raw)
		u, err := url.Parse(raw)
		if err != nil {
			return "", fmt.Errorf("cloudgcp: malformed egress allowlist URL %q: %w", raw, err)
		}
		switch u.Scheme {
		case "http", "https":
		default:
			return "", fmt.Errorf("cloudgcp: egress allowlist URL %q has unsupported scheme %q (want http/https)", raw, u.Scheme)
		}
		host := strings.ToLower(u.Hostname())
		if host == "" || !hostRe.MatchString(host) {
			return "", fmt.Errorf("cloudgcp: egress allowlist URL %q has missing/invalid host %q", raw, host)
		}
		// Reject an IP-literal host: Squid's dstdomain matches by name, and a CONNECT to a bare IP is
		// matched by `dst` (not dstdomain), so an IP entry would NOT reliably permit the intended
		// traffic — it would silently fail toward the deny floor. The allowlist is FQDN-based by design
		// (DESIGN.md §5.2: the proxy resolves names; the sandbox has no DNS), so fail CLOSED and loud
		// here rather than render a dstdomain ACL that does not do what it says. (IPv4 literals pass
		// hostRe — digits and dots are valid labels — so this check, not the regex, is the gate.)
		if net.ParseIP(host) != nil {
			return "", fmt.Errorf("cloudgcp: egress allowlist URL %q uses an IP-literal host %q — the allowlist is FQDN-based (Squid dstdomain); use a hostname", raw, host)
		}
		port := u.Port()
		if port == "" {
			if u.Scheme == "https" {
				port = "443"
			} else {
				port = "80"
			}
		}
		if !isNumericPort(port) {
			return "", fmt.Errorf("cloudgcp: egress allowlist URL %q has invalid port %q", raw, port)
		}
		// Per-entry ACLs so host A:443 and host B:8443 are paired exactly (never cross-allowed).
		fmt.Fprintf(&b, "acl c7_dst_%d dstdomain %s\n", i, host)
		fmt.Fprintf(&b, "acl c7_port_%d port %s\n", i, port)
		fmt.Fprintf(&b, "http_access allow c7_dst_%d c7_port_%d\n", i, i)
	}
	return b.String(), nil
}

// isNumericPort reports whether p is a 1-5 digit port in 1..65535.
func isNumericPort(p string) bool {
	if len(p) < 1 || len(p) > 5 {
		return false
	}
	n := 0
	for _, c := range p {
		if c < '0' || c > '9' {
			return false
		}
		n = n*10 + int(c-'0')
	}
	return n >= 1 && n <= 65535
}

// jsonScalar encodes s as a double-quoted YAML scalar via encoding/json (a JSON string is a valid
// YAML double-quoted scalar, with the YAML-structural characters — quote, backslash, newline,
// colon, etc. — escaped), then escapes U+2028/U+2029/U+0085 itself (encoding/json does NOT, yet
// YAML 1.1 can read them as line breaks). The result is UNCONDITIONALLY field-breakout-safe for any
// input — so a future caller feeding policy- or agent-influenced text (e.g. the B8 host:port ACLs)
// cannot inject a YAML structure, with no per-caller reasoning required.
func jsonScalar(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		return `""`
	}
	out := string(b)
	// json.Marshal emits these code points literally; replace each with its 6-char \u escape (valid
	// inside the already double-quoted JSON/YAML scalar) so YAML 1.1 cannot read them as line breaks
	// that escape the field.
	out = strings.ReplaceAll(out, "\u2028", `\u2028`)
	out = strings.ReplaceAll(out, "\u2029", `\u2029`)
	out = strings.ReplaceAll(out, "\u0085", `\u0085`)
	return out
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
func renderSandboxPod(nsID string, cfg Config, spec interfaces.SandboxSpec, proxyEndpoint string) []byte {
	ttlSeconds := int64(spec.MaxTTL.Seconds())
	if ttlSeconds < 1 {
		ttlSeconds = 1
	}
	// Render only NON-SECRET env at provision time. The Anthropic API KEY is deliberately NOT in the
	// pod spec — a secret in the manifest would persist in etcd; it is injected into the running pod at
	// run time by the SecretsProvider injection path (B5/B9).
	//   - HTTPS_PROXY/HTTP_PROXY (both cases) point the engine + git/curl at THIS session's forward
	//     proxy by IP (the sandbox has no DNS). This is CONVENIENCE for well-behaved clients only — the
	//     NetworkPolicy that pins egress to the proxy is the AUTHORITATIVE perimeter; a hostile client
	//     that ignores the env var still has nowhere else to go (DESIGN.md §5.2).
	//   - ANTHROPIC_MODEL is the org-API model pin (the engine's default 404s, so a real run needs it);
	//     empty when not configured (e.g. a lifecycle-only provision).
	var env strings.Builder
	if proxyEndpoint != "" {
		for _, name := range []string{"HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"} {
			fmt.Fprintf(&env, "        - name: %s\n          value: %s\n", name, jsonScalar(proxyEndpoint))
		}
	}
	if cfg.AnthropicModel != "" {
		fmt.Fprintf(&env, "        - name: ANTHROPIC_MODEL\n          value: %s\n", jsonScalar(cfg.AnthropicModel))
	}
	envBlock := ""
	if env.Len() > 0 {
		envBlock = "      env:\n" + env.String()
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
// Squid/forward-proxy port; it MUST stay in sync with deploy/gcp/modules/networking's
// var.egress_proxy_port (the VPC sandbox→pod-range ALLOW rule) and the readiness/Service port below.
const proxyPort = 3128

// proxyNamespaceSuffix derives a sandbox's per-session proxy namespace from its handle id. The id is
// a DNS-1123 label ("<prefix>-sb-<32 hex>"); appending "-proxy" stays a valid label and is unique
// per session, so the proxy namespace is never shared and Set/Provision/Clear all derive it
// identically from h.ID.
const proxyNamespaceSuffix = "-proxy"

func proxyNS(id string) string { return id + proxyNamespaceSuffix }

// proxyServiceName is the per-session Squid Service/Deployment name (within its own namespace, so a
// constant name is unambiguous). Provision resolves <proxyServiceName>.<id>-proxy's ClusterIP to
// inject HTTPS_PROXY.
const proxyServiceName = "egress-proxy"

// squidImage is the digest-pinned forward-proxy image (Squid 6.x on Ubuntu 24.04, Canonical-
// maintained, content-addressed — the bytes can't change under us). It is the same hardened image
// the sandbox runs behind; an adopter MAY mirror it into their in-tenancy Artifact Registry (the
// sandbox-image model). Pinned here in code (the per-session proxy is rendered by this provider, not
// a static manifest), so a registry-trust scanner heuristic does not apply.
const squidImage = "ubuntu/squid@sha256:6a097f68bae708cedbabd6188d68c7e2e7a38cedd05a176e1cc0ba29e3bbe029"

// proxyEndpoint resolves the per-session proxy Service's ClusterIP and returns the HTTPS_PROXY URL
// (http://<ip>:<port>) the sandbox reaches it by. The Service exists as soon as Set applied it (the
// API server allocates the ClusterIP synchronously), so this read succeeds before the Squid pod is
// even Ready. FAIL-CLOSED: a missing/headless/unparseable ClusterIP errors rather than yielding a
// broken proxy URL — the sandbox has no DNS, so a bad address means no egress, and provisioning must
// not proceed believing a proxy is reachable when it is not.
func (r *kubeRunner) proxyEndpoint(ctx context.Context, proxyNamespace string) (string, error) {
	out, err := r.run(ctx, "kubectl", nil,
		"get", "svc", proxyServiceName, "-n", proxyNamespace, "-o", "jsonpath={.spec.clusterIP}")
	if err != nil {
		return "", err
	}
	ip := strings.TrimSpace(string(out))
	if net.ParseIP(ip) == nil {
		return "", fmt.Errorf("cloudgcp: per-session proxy Service %s/%s has no usable ClusterIP (got %q) — refusing to provision a sandbox with no resolvable egress proxy (fail closed)", proxyNamespace, proxyServiceName, ip)
	}
	return fmt.Sprintf("http://%s:%d", ip, proxyPort), nil
}

// renderSquidConf builds the full per-session squid.conf: the stateless policy-gateway preamble, the
// session's allowlist as exact host:port ACLs (egressAllowlistToSquidACL — fail-closed on any
// malformed entry), then the `http_access deny all` floor. An EMPTY allowlist yields a config with
// no allow line above the floor = deny-all (the correct default). The preamble mirrors the reviewed
// reference Squid shape (no cache, no identity/forwarded-for leakage).
func renderSquidConf(allowlist []string) (string, error) {
	acls, err := egressAllowlistToSquidACL(allowlist)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("http_port 3128\n")
	// No caching: this is a policy gateway, not a cache — keep it stateless and memory-light.
	b.WriteString("cache deny all\n")
	// Do not leak the proxy's identity or the client's address downstream.
	b.WriteString("via off\n")
	b.WriteString("forwarded_for delete\n")
	// The per-session allowlist (empty ⇒ no allow line ⇒ everything hits the deny floor below).
	b.WriteString(acls)
	b.WriteString("http_access deny all\n")
	b.WriteString("coredump_dir /var/spool/squid\n")
	return b.String(), nil
}

// squidConfigHash is the content hash of a rendered squid.conf, stamped as a pod-template annotation
// so a re-Set with a NARROWED allowlist changes the Deployment's pod template and rolls a fresh Squid
// pod that reads the new ConfigMap (a subPath ConfigMap mount is frozen at pod creation and does not
// hot-reload, so the roll — not an in-place edit — is how new ACLs take effect).
func squidConfigHash(conf string) string {
	sum := sha256.Sum256([]byte(conf))
	return hex.EncodeToString(sum[:])
}

// indentLines prefixes every non-empty line of s with indent (empty lines stay truly empty so a YAML
// block scalar reads them as blank, not as indent-only whitespace). Used to embed squid.conf as a
// `|` block scalar in the ConfigMap.
func indentLines(s, indent string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, ln := range lines {
		if ln != "" {
			lines[i] = indent + ln
		}
	}
	return strings.Join(lines, "\n")
}

// perSessionProxyTemplate is the per-session forward-proxy manifest: its own PSA-restricted
// Namespace, the squid.conf ConfigMap, the hardened Squid Deployment (non-root uid 65532, read-only
// root FS, dropped caps, RuntimeDefault seccomp, readiness-gated, config-hash annotation), the
// Service, and an ingress NetworkPolicy admitting ONLY this session's sandbox namespace. Args:
// 1=proxy namespace, 2=session id (the proxy-for + ingress session-selector value), 3=indented
// squid.conf, 4=config hash, 5=image, 6=proxy port.
const perSessionProxyTemplate = `apiVersion: v1
kind: Namespace
metadata:
  name: %[1]s
  labels:
    app.kubernetes.io/managed-by: console7
    # The PER-SESSION label the sandbox NetworkPolicy's egress namespaceSelector pins to — so a
    # sandbox can reach ONLY its own session's proxy, never another session's (no allowlist union).
    console7.dev/proxy-for: %[2]s
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: latest
    pod-security.kubernetes.io/warn: restricted
    pod-security.kubernetes.io/audit: restricted
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: squid-config
  namespace: %[1]s
data:
  squid.conf: |
%[3]s
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: egress-proxy
  namespace: %[1]s
  labels:
    app: egress-proxy
spec:
  replicas: 1
  # Recreate (not the default RollingUpdate): on a NARROW the config-hash annotation rolls the pod,
  # and Recreate tears the OLD (broader) Squid down BEFORE the new one serves — so narrowing fails
  # CLOSED (a brief no-egress gap) instead of load-balancing across an old pod that still admits a
  # just-removed destination. A momentary egress gap is the correct trade for never serving stale reach.
  strategy:
    type: Recreate
  selector:
    matchLabels:
      app: egress-proxy
  template:
    metadata:
      labels:
        app: egress-proxy
      annotations:
        # Rolls the pod when the allowlist narrows (subPath ConfigMap mounts don't hot-reload).
        console7.dev/squid-config-hash: "%[4]s"
    spec:
      # No nodeSelector: the gVisor sandbox pool's structural taint keeps this untolerating
      # Deployment off it, so it schedules on the control pool (which has the sanctioned NAT egress).
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        runAsGroup: 65532
        fsGroup: 65532
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: squid
          image: %[5]s
          ports:
            - name: proxy
              containerPort: %[6]d
          # Gate Service Endpoints on Squid actually listening (no connect-before-listen race).
          readinessProbe:
            tcpSocket:
              port: %[6]d
            initialDelaySeconds: 2
            periodSeconds: 5
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
          volumeMounts:
            - name: squid-config
              mountPath: /etc/squid/squid.conf
              subPath: squid.conf
              readOnly: true
            - name: spool
              mountPath: /var/spool/squid
            - name: logs
              mountPath: /var/log/squid
            - name: run
              mountPath: /var/run
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
            limits:
              cpu: "1"
              memory: 512Mi
      volumes:
        - name: squid-config
          configMap:
            name: squid-config
        - name: spool
          emptyDir: {}
        - name: logs
          emptyDir: {}
        - name: run
          emptyDir: {}
---
apiVersion: v1
kind: Service
metadata:
  name: egress-proxy
  namespace: %[1]s
spec:
  selector:
    app: egress-proxy
  ports:
    - name: proxy
      port: %[6]d
      targetPort: %[6]d
      protocol: TCP
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: console7-proxy-ingress
  namespace: %[1]s
spec:
  podSelector: {}
  policyTypes: [Ingress]
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              console7.dev/session: %[2]s
      ports:
        - protocol: TCP
          port: %[6]d
`

// renderPerSessionProxy renders the per-session forward proxy for one sandbox. nsID is the sandbox's
// crypto-random handle id (a valid DNS-1123 label, safe unquoted as a name/label value); the proxy
// lives in nsID+"-proxy". squidConf is the rendered config (embedded as an indented block scalar);
// configHash rolls the pod on a narrow.
func renderPerSessionProxy(nsID string, squidConf, configHash string) []byte {
	return fmt.Appendf(nil, perSessionProxyTemplate,
		proxyNS(nsID),
		nsID,
		indentLines(squidConf, "    "),
		configHash,
		squidImage,
		proxyPort,
	)
}

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
    # The PER-SESSION identity this sandbox namespace carries — the per-session proxy's ingress
    # NetworkPolicy admits ONLY a source namespace bearing this exact label, so a sandbox can talk to
    # its own proxy and nothing else can.
    console7.dev/session: %[1]s
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
              # THIS session's proxy namespace only (per-session, never a shared label) — so the
              # sandbox's one egress path is its own forward proxy, which enforces the FQDN allowlist.
              console7.dev/proxy-for: %[1]s
      ports:
        - protocol: TCP
          port: %[3]d
`,
		nsID,
		jsonScalar(string(encoded)),
		proxyPort,
	)
}
