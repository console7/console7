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

// SandboxRuntime provisions and destroys the per-session, gVisor-isolated workload — the POD
// only. The namespace it runs in (and that namespace's egress NetworkPolicy) is owned by the
// EgressController, created by Set BEFORE Provision (perimeter-before-workload) and deleted by
// Clear. The real adapter creates a pod with the gVisor RuntimeClass, pinned to the sandbox node
// pool, with no service-account token and an activeDeadlineSeconds derived from spec.MaxTTL;
// Destroy deletes that pod.
type SandboxRuntime interface {
	// Provision creates the isolated workload identified by handle for spec. The provider
	// guarantees EgressController.Set has already succeeded for handle when this is called, so
	// the implementation MUST NOT assume it is responsible for the perimeter — its job is the
	// kernel/syscall-isolated compute only (gVisor RuntimeClass), never an in-process egress
	// guard. It MUST stamp a hard lifetime from spec.MaxTTL onto the workload so an un-destroyed
	// sandbox still dies (ephemeral by default), and MUST NOT grant the workload any standing
	// credential of its own (no automounted service-account token; the node pool runs the GKE
	// metadata server — GKE_METADATA mode — which conceals the node service account, and the
	// sandbox pods are bound to no KSA — modules/gke; New preflights this).
	Provision(ctx context.Context, handle interfaces.SandboxHandle, spec interfaces.SandboxSpec) error
	// Destroy irreversibly tears the workload (the pod) down, wiping the ephemeral workspace and
	// any injected credential material; the namespace + NetworkPolicy + ConfigMap are reaped by
	// EgressController.Clear, which the provider calls after Destroy. It MUST NOT snapshot or
	// persist sandbox contents anywhere another session or the maintainer could read (GOAL.md
	// tenet 1, tenet 5). Destroying a workload the cloud no longer has is acceptable success — the
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

// EngineRunner runs the genuine Claude Code engine inside an already-provisioned sandbox pod and
// captures the commit it produces. It is a SEPARATE port from SandboxRuntime because running the
// engine is an EXEC INTO a live pod, not a lifecycle op on the pod — keeping it distinct lets the
// provider gate the run on the sandbox's liveness/taint under the lock before any exec happens, and
// lets a deployment swap the engine-exec mechanism (kubectl exec vs a typed client) without
// touching provisioning. The real adapter (kube_exec.go) shells `kubectl exec` (no new dependency);
// the in-memory fake (fakes.go) records the task so conformance runs credential-free.
type EngineRunner interface {
	// Run renders task.Profile into the engine's LOCKED managed-settings inside the pod, runs
	// `claude -p`, and returns the engine's produced commit. The provider GUARANTEES handle is live
	// and perimeter-intact when Run is called (it holds that gate under the lock); the adapter MUST
	// NOT widen egress, MUST NOT push/merge/actuate, and MUST return only the digest/head/summary —
	// never transcripts or secret material (cloud.go EngineResult SECURITY; GOAL.md tenets 1/3/6).
	Run(ctx context.Context, handle interfaces.SandboxHandle, task interfaces.EngineTask) (interfaces.EngineResult, error)
}

// CredentialDeliverer writes short-lived credential material into a live sandbox pod's MEMORY
// volume and shreds it. It is a SEPARATE port (like EngineRunner) because delivery is an EXEC INTO a
// live pod, not a lifecycle op: it lets the provider gate delivery on the ownership check under the
// lock before any exec, and lets a deployment swap the mechanism (kubectl exec vs a typed client).
// The real adapter (kube_exec.go) shells `kubectl exec` and feeds material over STDIN (never argv, so
// it cannot leak into a process table or shell history); the in-memory fake records it.
//
// SECURITY: the material is a secret. The adapter MUST write it only to a memory-backed
// (medium: Memory) volume so it never reaches disk, MUST pass it over stdin (not as an argument),
// and MUST NOT log it. The provider only ever calls Deliver after DeliverIfOwned has re-verified,
// under the lock, that the handle is owned by exactly the target subject+session.
type CredentialDeliverer interface {
	// Deliver writes material into handle's in-pod credential file (memory-backed). It returns an
	// error if the write could not be confirmed; the provider then reports non-delivery (fail closed).
	Deliver(ctx context.Context, handle interfaces.SandboxHandle, material []byte) error
	// DeliverInference writes the minted short-lived INFERENCE credential (the Vertex bearer) into the
	// session's per-session AUTH-PROXY pod's memory-backed bearer file — NOT into the sandbox. The
	// auth-proxy is the credential-attaching gateway the engine reaches Vertex through, so the sandbox
	// stays credential-free (it never holds the cloud bearer). Same SECURITY obligations as Deliver:
	// material is a secret, written only to a memory-backed file, passed over stdin (never argv), never
	// logged. The provider only calls it after DeliverInferenceIfOwned re-verifies ownership under the
	// lock. It returns an error if the write could not be confirmed (the provider then fails closed).
	DeliverInference(ctx context.Context, handle interfaces.SandboxHandle, material []byte) error
	// Wipe best-effort shreds the in-pod credential file at teardown. The authoritative wipe is the
	// pod's deletion (the volume is medium: Memory, so it dies with the pod); Wipe is defence in
	// depth, so it tolerates an already-absent file/pod as success.
	Wipe(ctx context.Context, handle interfaces.SandboxHandle) error
}
