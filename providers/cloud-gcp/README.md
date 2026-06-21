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
  networking module's sandbox tag), Cloud Router + NAT for the sanctioned egress path, the
  **NODE-layer metadata block** (the GKE metadata server in **`GKE_METADATA` mode** on the sandbox
  node pool, which conceals the node service account; sandbox pods are bound to no KSA) — the
  authoritative metadata control a VPC firewall cannot provide — **GKE Dataplane V2** (so the
  egress NetworkPolicy actually enforces), and the **absolute-deadline reaper** (a namespace-TTL
  CronJob keyed on the `console7.dev/expires-at` annotation this provider stamps).
  `activeDeadlineSeconds` is a pod-relative backstop; the annotation + reaper enforce the absolute
  session deadline regardless of scheduling/image-pull latency. **`New` preflights both the
  Dataplane-V2 NetworkPolicy enforcement and the `GKE_METADATA` node-pool concealment, failing
  closed** — so a misconfigured cluster cannot construct a usable provider.
- **DEFERRED to the egress proxy + base image (PR-3):** the out-of-band forward proxy that does
  the FQDN allowlisting the `EgressController`'s allowlist feeds (a NetworkPolicy is IP-based and
  cannot match FQDNs); and the signed engine image the sandbox pod runs (this provider does not
  wrap the agent — Console7 orchestrates the genuine engine, it does not reimplement it).

> **Metadata posture (corrects an earlier inversion).** The node SA is concealed by running the
> GKE metadata server (**`GKE_METADATA` mode = Workload Identity**) on the sandbox node pool, with
> sandbox pods bound to **no** KSA and `automountServiceAccountToken: false`. (Earlier wording in
> this package said "*no* Workload Identity on the sandbox node pool" — that was backwards:
> disabling WI leaves `GCE_METADATA`, which *exposes* the node SA token at the node-local metadata
> server. The networking/gke module comments are reconciled to this in PR-2b.) `New` refuses to
> construct against a node pool whose `workloadMetadataConfig.mode` is not `GKE_METADATA`, so this
> is an enforced gate, not just a documented precondition.

## Live integration test

`integration_test.go` (build tag `cloud_gcp_integration`) provisions → narrows → destroys against
a real cluster; it is never part of CI. Run:

```
C7_GKE_PROJECT=console7-dev C7_GKE_LOCATION=us-east4 C7_GKE_CLUSTER=console7-sandbox \
  go test -tags cloud_gcp_integration -run TestIntegration ./providers/cloud-gcp/...
```
