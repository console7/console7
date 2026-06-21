// Package cloudgcp is the Console7 reference CloudProvider on GCP — gVisor-isolated
// sandboxes as GKE pods, with the default-deny egress perimeter enforced out-of-band
// (ARCHITECTURE.md §4/§5; DESIGN.md §5.1/§5.2; sdk/interfaces/cloud.go). It is an
// in-tree reference implementation of the sdk/interfaces.CloudProvider seam; community
// providers live out-of-tree against the published SDK.
//
// # What the provider owns vs what the cloud enforces
//
// The provider is the control-side lifecycle: it assigns a fresh handle per session,
// enforces the seam's SECURITY invariants in Go (perimeter-before-workload, narrow-only
// egress, irreversible destroy, fail-closed on an unknown/expired handle, never reuse a
// handle across session/user/persona), and threads each effect to a port. The AUTHORITATIVE
// controls are the cloud's: gVisor at the syscall boundary and the VPC/out-of-band egress
// perimeter (deploy/gcp/modules/networking + modules/gke). The provider configures; the
// cloud enforces (DESIGN.md §11) — so a bug here cannot widen what the boundary already denies.
//
// # The GCP/Kubernetes surface is confined behind two ports
//
// The provider logic (provider.go) depends only on SandboxRuntime and EgressController
// (ports.go); nothing in it imports a cloud or Kubernetes SDK. The real adapter
// (kube_exec.go, build tag `cloud_gcp_integration`) realises those ports by shelling out
// to the adopter's pinned `kubectl` + `gcloud` — a deliberate dependency choice (Option A,
// PR-2a): it adds ZERO dependency to this Tier-1 public module's graph, so `go build ./...`,
// the linters, and govulncheck see no new surface, and the conformance harness wires the
// exported in-memory fakes (fakes.go) to run the whole CloudProvider contract with no GCP
// project and no credentials. Because the ports are the seam, a production deployment that
// wants a typed Kubernetes client can swap the adapter (e.g. a nested module embedding
// client-go) via NewWithPorts WITHOUT changing the CloudProvider interface or this logic.
//
// # Real vs deferred in this PR (PR-2a)
//
//   - REAL: the full CloudProvider lifecycle logic + its SECURITY invariants, proven by the
//     conformance suite and white-box tests against the fakes; the build-tagged kubectl/gcloud
//     adapter for the per-session namespace + gVisor pod lifecycle and the per-session egress
//     NetworkPolicy.
//   - DEFERRED to modules/gke (PR-2b): the gVisor sandbox node pool (carrying the
//     networking module's sandbox tag), Workload Identity, Cloud Router + NAT for the
//     sanctioned egress path, and the NODE-layer metadata block (no Workload Identity on the
//     sandbox node pool + GKE metadata concealment) — the authoritative metadata control a VPC
//     firewall cannot provide (see deploy/gcp/modules/networking).
//   - DEFERRED to the egress-proxy + base-image (PR-3): the out-of-band forward proxy that does
//     FQDN allowlisting is what the EgressController's allowlist ultimately feeds; the NetworkPolicy
//     this adapter applies pins sandbox egress to that proxy ONLY (denying everything else —
//     including DNS and the metadata server — by omission; name resolution is the proxy's job, so
//     the sandbox does no DNS of its own per THREAT-MODEL.md). The genuine Claude Code engine +
//     policyHelper-rendered managed settings ride the base image; this provider does not wrap the
//     agent — Console7 orchestrates the genuine engine, it does not reimplement it (GOAL.md
//     "what Console7 is not"; the wrap-not-reimplement principle).
package cloudgcp
