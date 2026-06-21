package cloudgcp

import (
	"context"

	"github.com/console7/console7/sdk/interfaces"
)

// The provider logic depends only on these two ports; the kubectl/gcloud shell-out is
// confined to the adapter that satisfies them (kube_exec.go, build tag
// `cloud_gcp_integration`) and to the in-memory fakes (fakes.go). They are exported so the
// conformance harness — and out-of-tree providers — can assemble a fully-faked provider via
// NewWithPorts without any GCP project or credentials.
//
// The split is deliberate: SandboxRuntime owns the isolated COMPUTE (the gVisor pod in its
// own namespace), EgressController owns the out-of-band PERIMETER (the per-session egress
// policy). Keeping them separate is what lets the provider enforce the seam's ordering
// guarantee — the perimeter is set BEFORE the workload can run — by calling EgressController
// before SandboxRuntime, rather than trusting one combined adapter to get the order right.

// SandboxRuntime provisions and destroys the per-session, gVisor-isolated workload. The real
// adapter creates an isolated Kubernetes namespace + a pod with the gVisor RuntimeClass,
// pinned to the sandbox node pool, with no service-account token and an activeDeadlineSeconds
// derived from spec.MaxTTL; Destroy deletes the namespace.
type SandboxRuntime interface {
	// Provision creates the isolated workload identified by handle for spec. The provider
	// guarantees EgressController.Set has already succeeded for handle when this is called, so
	// the implementation MUST NOT assume it is responsible for the perimeter — its job is the
	// kernel/syscall-isolated compute only (gVisor RuntimeClass), never an in-process egress
	// guard. It MUST stamp a hard lifetime from spec.MaxTTL onto the workload so an un-destroyed
	// sandbox still dies (ephemeral by default), and MUST NOT grant the workload any standing
	// credential of its own (no automounted service-account token; the node pool runs without
	// Workload Identity — modules/gke).
	Provision(ctx context.Context, handle interfaces.SandboxHandle, spec interfaces.SandboxSpec) error
	// Destroy irreversibly tears the workload down and reclaims its namespace, wiping the
	// ephemeral workspace and any injected credential material. It MUST NOT snapshot or persist
	// sandbox contents anywhere another session or the maintainer could read (GOAL.md tenet 1,
	// tenet 5). Destroying a workload the cloud no longer has is acceptable success — the
	// provider is the source of truth for liveness and fails closed on a double destroy itself.
	Destroy(ctx context.Context, handle interfaces.SandboxHandle) error
}

// EgressController programs the OUT-OF-BAND egress perimeter for one sandbox: it sets the
// allowlist the cloud enforces around handle (the real adapter owns the sandbox namespace and a
// per-session allow-list NetworkPolicy pinning the pod's egress to the approved forward proxy
// ONLY, so every other destination — including DNS and the metadata server — is denied by omission
// at this layer; the authoritative metadata block is node-level, modules/gke). The zero/empty
// allowlist is deny-all.
type EgressController interface {
	// Set makes the perimeter for handle enforce EXACTLY allowlist (default-deny everything
	// else). It MUST take effect at the cloud perimeter, never inside the sandbox, and MUST
	// fail closed: if it cannot apply the policy it MUST leave handle denying all egress and
	// return an error, never leave the prior (now-stale) allowlist in force. An empty allowlist
	// is a valid request meaning deny-all.
	Set(ctx context.Context, handle interfaces.SandboxHandle, allowlist []string) error
	// Clear removes handle's perimeter configuration at teardown. Like Destroy it tolerates an
	// already-absent perimeter as success.
	Clear(ctx context.Context, handle interfaces.SandboxHandle) error
}
