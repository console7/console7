# 4. The `InferenceBackend` seam is pure routing; the inference cloud is orthogonal to the control-plane cloud

- **Status:** Accepted
- **Date:** 2026-06-21
- **Deciders:** Console7 maintainers
- **Supersedes / Superseded by:** —

ADRs capture a single, significant, hard-to-reverse choice and the reasoning behind it
(see `docs/adr/0001-language.md`). They are immutable once accepted: to change a decision,
add a new ADR that supersedes this one rather than editing it.

## Context

`providers/inference-vertex` is the in-tenancy inference component required for the Phase-1
exit (`docs/ROADMAP.md`): the **in-tenancy** `InferenceBackend`, serving Claude through the
adopter's own Google Vertex AI (the exit gate itself is the full end-to-end governed task, of
which this backend is one part). Before building
it, an earlier planning note assumed Vertex would mirror `providers/secrets-gcp` — a hexagonal
shape with the real GCP SDK (`cloud.google.com/go/aiplatform`) confined behind a port and faked
for tests, on the reasoning "a GCP provider needs the GCP SDK."

Building `providers/inference-anthropic` (PR #32) disproved that assumption for this seam. The
`InferenceBackend.Resolve` contract's entire output is a `BackendEndpoint{Mode, URL}`; the
interface docstring states it "makes no network call and holds no key"
(`sdk/interfaces/inference.go`). The Anthropic backend is consequently dependency-free: it
decides *which credential class* and *which endpoint URL* a session gets, nothing more. Vertex's
endpoint (`https://{region}-aiplatform.googleapis.com`, or the global host) is **fully derivable
from configuration** — project and region — so resolving it needs no API call either.

A second question surfaced while planning: many adopters are **multicloud**, with cloud-linked
internal network zones (Cloud Interconnect / Direct Connect / ExpressRoute, private VPC/VNet
peering). They may legitimately run the control plane in one cloud and reach an inference backend
in another (e.g. a GCP-hosted control plane calling Bedrock, or an Azure-hosted control plane
calling Vertex) over a private path. The seam design must not foreclose that.

Constraints that bound the choice:

- **Boundary controls are authoritative (`GOAL.md` tenet 3).** Least-privilege identity and
  the default-deny egress perimeter are the controls of record; in-band routing is layered under
  them. A router that holds a credential and makes a network call would put authority in the
  wrong layer.
- **`providers/` is the reference set only (`CLAUDE.md`; ARCHITECTURE §6.1).** Per-cloud
  long-tail backends must not be buried in core; community backends live out-of-tree against the
  published SDK.
- **One human, one credential, one beneficiary (`GOAL.md` tenet 2; DESIGN.md §3).** The
  attended/unattended seam is enforced in policy at `Resolve`.

## Decision

**The `InferenceBackend` seam is a pure routing decision, and the inference-backend cloud is an
axis orthogonal to the control-plane cloud.** Concretely:

1. **Pure routing, no SDK dependency.** A reference `InferenceBackend` resolves a session to a
   `BackendEndpoint{Mode, URL}` from configuration only — no network call, no held credential, no
   provider SDK. `providers/inference-vertex` is therefore dependency-free Go (adds nothing to
   `go.mod`), with no `ports.go`, no SDK `fakes.go`, and no live `integration_test.go` — their
   absence is intentional. The hexagonal SDK-port shape (`providers/secrets-gcp`) is the right
   tool for a seam that genuinely performs cryptographic I/O (KMS wrap/unwrap) and the **wrong**
   tool here. This confirms, not overturns, the pattern `providers/inference-anthropic` set.

2. **Orthogonal axes.** Where the control plane and sandbox *run* (`CloudProvider`) and where
   inference *goes* (`InferenceBackend`) are independent decisions. Any cell of the
   cross-product — GCP control plane → Vertex, GCP control plane → Bedrock, Azure → Vertex, … —
   is a supported **topology**, not a new seam. The reference set ships GCP+Vertex first (the
   lowest-friction same-cloud path); Bedrock is a reference candidate, other clouds live
   out-of-tree.

3. **"In-tenancy" is a boundary property, not a provider-identity property.** Whether a
   cross-cloud inference path counts as staying inside the adopter's tenancy is decided by the
   **egress allowlist and the network zone** the adopter defines (e.g. a Bedrock call over a
   private interconnect into the adopter's AWS VPC endpoint), not by the backend's cloud. Console7
   neither blesses nor forbids cross-cloud inference: it names the endpoint at this seam and
   enforces reachability at the default-deny boundary. The adopter puts the endpoint on the
   allowlist or does not.

4. **Cross-cloud identity is a key-broker concern — which is *why* this seam stays pure.** A
   GCP workload calling Bedrock needs AWS SigV4 credentials (e.g. GCP workload identity → AWS STS
   `AssumeRoleWithWebIdentity` via OIDC federation, minted short-lived at session start). That
   belongs to `keybroker` / `IdentityProvider` / `SecretsProvider`, and the actual signed call is
   made by the wrapped engine inside the sandbox. Keeping the inference seam free of credentials
   and SDKs is what lets a future per-cloud backend stay a thin peer.

5. **Vertex refuses `ModeSubscription` unconditionally.** A personal Claude subscription seat is
   an Anthropic OAuth credential with no meaning on Vertex (disjoint auth and billing), so Vertex
   refuses every subscription selection — including the attended, single-beneficiary case the
   Anthropic backend serves — rather than fabricating a route. This is stricter than the contract
   floor (which refuses only unattended/multi-beneficiary subscription) and is fail-closed;
   composing "subscription → direct-Anthropic, org-API → Vertex" is the control plane's job, and
   each backend stays self-contained.

## Decision drivers

- **Match the contract.** The seam's whole output is a URL; modelling it as routing rather than
  I/O is the honest shape and keeps authority at the boundary, not in a router.
- **Uniformity enables the ecosystem.** Thin, uniform backends (Anthropic, Vertex, future
  Bedrock) make multicloud a drop-in topology and keep `providers/` the reference set.
- **Smallest Tier-1 dependency surface.** A public, security-sensitive codebase avoids a heavy
  cloud SDK on a path that does not need one.

## Consequences

**Positive**
- `providers/inference-vertex` lands dependency-free; the cross-product of control-plane and
  inference clouds is expressible without new seams; a future `inference-bedrock` is a thin peer,
  anticipated not retrofitted.
- The authoritative control (egress allowlist) and the in-band routing decision stay cleanly
  separated.

**Negative / costs**
- The seam does **not** validate at resolve-time that a model/region exists or that the endpoint
  is reachable — that is deferred to deploy-time IAM and the egress allowlist. A misconfigured
  project/region surfaces as a failed call later, not a routing error (mitigated by config
  validation at `New` — required fields, region host-injection guard, https-only PSC override).
- Cross-cloud identity (OIDC federation, STS) is real work owned by the broker; this ADR scopes
  only the inference seam's shape, not that mint path.

**Neutral**
- Bedrock and non-GCP inference backends remain future/out-of-tree; this ADR records the shape
  they will take, not their delivery.

## Amendment — 2026-06-23 (PR-C1, Phase-1 EXIT Vertex lane)

The decision (pure routing; inference cloud orthogonal to the control-plane cloud) stands
unchanged. One factual detail above is now narrower than the shipped type: the contract output
is no longer literally `BackendEndpoint{Mode, URL}`. To let a consumer (the CloudProvider
rendering engine env + selecting the credential type) tell the **Vertex** lane from the
**direct-Anthropic** lane — which `Mode` alone cannot, since both the in-tenancy Vertex route and
the direct-Anthropic org route are `ModeOrgAPI` — `BackendEndpoint` gained:

- `Kind BackendKind` — the concrete lane (`BackendAnthropicAPI` / `BackendVertex`); and
- `VertexProjectID` / `VertexRegion` — the Vertex routing **facts** the wrapped engine needs
  (`ANTHROPIC_VERTEX_PROJECT_ID` / `CLOUD_ML_REGION`), `"global"` for the location-independent
  endpoint.

This does **not** weaken "pure routing": the new fields are configuration-derived routing facts,
not credentials, no client, no network call. They are the orthogonal *lane* axis the
"orthogonal axes" framing already anticipated, sitting beside the *credential-class* axis
(`Mode`). The Vertex credential (a short-lived GCP bearer token) still travels the separate
`SecretsProvider` injection seam, never this struct. Read every "the seam's whole output is a
URL" phrasing above as "the seam's whole output is a set of non-secret routing facts (endpoint
URL + lane + the engine env facts for that lane)."

## Links

- `docs/adr/0001-language.md` — the ADR that established this record format.
- `sdk/interfaces/inference.go` — the `InferenceBackend` SECURITY contract (pure `Resolve`,
  attended/unattended seam, fail-closed).
- `providers/inference-anthropic/` — the boundary-crossing reference backend that set the
  pure-routing pattern (PR #32).
- `providers/inference-vertex/`, `deploy/gcp/modules/inference-vertex/` — the in-tenancy backend
  and its least-privilege predict IAM, decided here.
- `docs/ARCHITECTURE.md` §3 (the single model-inference boundary crossing), §5 (provider seams).
- `docs/DESIGN.md` §3 (inference routing; the attended/unattended seam in policy).
- `GOAL.md` — tenet 1 (adopter tenancy), tenet 2 (one human, one credential, one beneficiary),
  tenet 3 (boundary controls authoritative), tenet 9 (pluggable everything).
