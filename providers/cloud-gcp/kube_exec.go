package cloudgcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

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

// renderSandboxPod renders the gVisor Pod for one sandbox into the namespace the EgressController
// already created. nsID is the crypto-random handle ID (a valid DNS-1123 label, safe unquoted as
// the resource/namespace name); every other dynamic value is json-encoded.
func renderSandboxPod(nsID string, cfg Config, spec interfaces.SandboxSpec) []byte {
	ttlSeconds := int64(spec.MaxTTL.Seconds())
	if ttlSeconds < 1 {
		ttlSeconds = 1
	}
	return fmt.Appendf(nil, `apiVersion: v1
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
  containers:
    - name: sandbox
      image: %[5]s
      securityContext:
        allowPrivilegeEscalation: false
        runAsNonRoot: true
      resources:
        requests:
          cpu: 250m
          memory: 256Mi
          ephemeral-storage: 1Gi
        limits:
          cpu: "2"
          memory: 2Gi
          ephemeral-storage: 4Gi
`,
		nsID,
		jsonScalar(cfg.RuntimeClass),
		jsonScalar(cfg.NodePool),
		ttlSeconds,
		jsonScalar(sandboxImagePlaceholder),
	)
}

// nowUTC is the wall clock the adapter stamps absolute-deadline annotations from. A package var so
// it is unambiguous (and stubbable) though the adapter is exercised only by the integration test.
var nowUTC = func() time.Time { return time.Now().UTC() }

// sandboxImagePlaceholder is a stand-in until sandbox/base-image (PR-3) publishes the signed
// engine image; the integration test asserts lifecycle, not engine behaviour, so the pod runs the
// placeholder only to exercise provision/destroy.
const sandboxImagePlaceholder = "gcr.io/google-containers/pause:3.9"

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
	encoded, err := json.Marshal(allowlist)
	if err != nil {
		encoded = []byte("[]")
	}
	return fmt.Appendf(nil, `apiVersion: v1
kind: Namespace
metadata:
  name: %[1]s
  labels:
    app.kubernetes.io/managed-by: console7
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
