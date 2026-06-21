# `providers/cloud-gcp/` — reference `CloudProvider`

**Trust tier:** reference provider implementation.

Reference implementation of [`CloudProvider`](../../sdk/interfaces/cloud.go) on **GCP**:
gVisor-isolated sandboxes as GKE pods, with the default-deny egress perimeter enforced
**out-of-band** (`ARCHITECTURE.md` §4/§5; `DESIGN.md` §5.1/§5.2). The provider is the
control-side lifecycle and enforces the seam's SECURITY invariants in Go; the
**authoritative** controls are the cloud's (gVisor at the syscall boundary, the VPC/egress
perimeter from `deploy/gcp/modules/networking` + `modules/gke`). The provider configures; the
cloud enforces — so a bug here cannot widen what the boundary already denies.

## Shape — hexagonal, zero new dependency (Option A)

The GCP/Kubernetes surface is confined behind two ports (`ports.go`):

- **`SandboxRuntime`** — the per-session, gVisor-isolated workload (a pod in its own
  namespace), and
- **`EgressController`** — the out-of-band per-session egress perimeter.

`provider.go` depends only on those ports and holds the lifecycle logic + SECURITY invariants:
**perimeter-before-workload**, **narrow-only (never widen) egress that fails closed**,
**irreversible destroy**, **fail-closed on an unknown/expired handle**, and **a fresh handle
per call** (so a sandbox is never reused across session/user/persona). It mirrors
`sdk/devkit.MemCloud`'s contract, delegating the cloud effects to the ports.

The real adapter (`kube_exec.go`) realises the ports by **shelling out to the adopter's pinned
`kubectl` + `gcloud`** — the deliberate zero-dependency choice: this Tier-1 **public** module
gains **no** new dependency (no `k8s.io/client-go`), so `go build ./...`, the linters, and
govulncheck see no new surface. The conformance harness and unit tests wire the exported
in-memory fakes (`fakes.go`) via `NewWithPorts`, so the **whole CloudProvider contract runs
with no GCP project and no credentials** (`conformance/cloud_gcp_test.go`). Because the ports
are the seam, a deployment wanting a typed Kubernetes client swaps the adapter (e.g. a nested
module embedding `client-go`) **without changing the interface or this logic**.

The single `exec` site carries a scoped `//nolint:gosec` for G204 (subprocess with non-constant
args) — justified and tracked as **`docs/RISKS.md` R-3**: the command name is always a literal
and the only variable inputs are validated `Config` fields + the provider's own crypto-random
handle IDs.

## Real vs deferred

- **REAL (this PR, PR-2a):** the full CloudProvider lifecycle logic + invariants (CI-tested via
  conformance + white-box tests); the kubectl/gcloud adapter for the per-session namespace +
  gVisor pod (RuntimeClass `gvisor`, `automountServiceAccountToken: false`, node-pool-pinned,
  hard `activeDeadlineSeconds` from `MaxTTL`) and the per-session egress NetworkPolicy +
  allowlist ConfigMap.
- **DEFERRED to `deploy/gcp/modules/gke` (PR-2b):** the gVisor sandbox node pool (carrying the
  networking module's sandbox tag), Workload Identity, Cloud Router + NAT for the sanctioned
  egress path, and the **NODE-layer metadata block** (no Workload Identity on the sandbox node
  pool + GKE metadata concealment) — the authoritative metadata control a VPC firewall cannot
  provide (see `deploy/gcp/modules/networking`).
- **DEFERRED to the egress proxy + base image (PR-3):** the out-of-band forward proxy that does
  the FQDN allowlisting the `EgressController`'s allowlist feeds (a NetworkPolicy is IP-based and
  cannot match FQDNs); and the signed engine image the sandbox pod runs (this provider does not
  wrap the agent — Console7 orchestrates the genuine engine, it does not reimplement it).

> **Deployment precondition (gating, not future work).** Until `modules/gke` (PR-2b) lands, this
> provider MUST NOT be pointed at a cluster whose sandbox node pool still has **Workload Identity
> enabled**: `automountServiceAccountToken: false` stops the pod's *projected* SA token, but a pod
> that schedules onto a WI-enabled pool can still reach the node-local GKE metadata server and mint
> the node SA token. The authoritative metadata block is *no Workload Identity on the sandbox node
> pool* — a `modules/gke` responsibility — so a WI-disabled sandbox pool is a precondition for any
> real deployment of this provider.

## Live integration test

`integration_test.go` (build tag `cloud_gcp_integration`) provisions → narrows → destroys against
a real cluster; it is never part of CI. Run:

```
C7_GKE_PROJECT=console7-dev C7_GKE_LOCATION=us-east4 C7_GKE_CLUSTER=console7-sandbox \
  go test -tags cloud_gcp_integration -run TestIntegration ./providers/cloud-gcp/...
```
