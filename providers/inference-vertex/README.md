# `providers/inference-vertex/` — reference `InferenceBackend`

**Trust tier:** reference provider implementation (runs as part of the control plane; holds
no key).

Reference implementation of [`InferenceBackend`](../../sdk/interfaces/inference.go) on
**Google Vertex AI** (`ARCHITECTURE.md` §5). It is the **in-tenancy** counterpart to
[`inference-anthropic`](../inference-anthropic/): Vertex keeps inference inside the adopter's
own GCP **account and region** (`ARCHITECTURE.md` §3), where `inference-anthropic` crosses the
boundary to first-party Anthropic. It is the in-tenancy inference **component required for
the Phase-1 exit** (`docs/ROADMAP.md`) — the exit gate is the full end-to-end governed task
(policy-bound sandbox, default-deny egress, attested output, lineage, WORM), "deployable by an
adopter in their own GCP project with their own Vertex backend, maintainer-uninvolved," of
which this backend is one part.

## What it does — routing, not a credential

`Resolve` is a **pure policy decision**: given an `InferenceSelection` it returns a
`BackendEndpoint{Mode, URL}`. It makes **no network call** and holds **no key**. It is
dependency-free Go (adds nothing to `go.mod`) — the Vertex endpoint is fully derivable from
config, so there is no GCP SDK to confine and hence (deliberately) no `ports.go`, no
`fakes.go`, and no `integration_test.go`. See [ADR-0004](../../docs/adr/0004-inference-backend-is-pure-routing.md)
for why the inference seam is pure routing and why the inference-backend cloud is an axis
orthogonal to the control-plane cloud.

The GCP credential a Vertex call needs (a short-lived ADC / workload-SA token) is acquired by
the `SecretsProvider` / key broker and injected into the sandbox — not held here.

## SECURITY — the seam it enforces

- **Vertex refuses `ModeSubscription` unconditionally.** A personal Claude subscription seat is
  an Anthropic OAuth credential with no meaning on Vertex (disjoint auth + billing), so there is
  no route to fabricate — even the attended, single-beneficiary case is refused (an attended
  subscription session belongs on the direct-Anthropic backend). This is *stricter* than the
  contract floor and fails closed.
- **`ModeOrgAPI`** — every unattended or multi-beneficiary session — resolves to the configured
  in-tenancy Vertex endpoint.
- **`ModeUnspecified` / any unrecognised mode** is refused, never defaulted.
- The resolved URL is an **in-band routing decision only**: it MUST already be on the session's
  default-deny egress allowlist, which the boundary authoritatively enforces (GOAL.md tenet 3).

## Config

| Field | Meaning |
| --- | --- |
| `ProjectID` | Adopter GCP project (required; billed for inference; carried to the engine env later). |
| `Region` | Vertex location, e.g. `us-east5` (required unless `Global`; validated as a host-injection guard). |
| `Global` | Use the location-independent `https://aiplatform.googleapis.com` instead of the regional host. |
| `EndpointBaseURL` | Optional Private Service Connect / VPC-SC override (absolute https, no userinfo/query/fragment); takes precedence. |

Endpoint precedence: `EndpointBaseURL` → `Global` → `https://{region}-aiplatform.googleapis.com`.

## Deploying it

[`deploy/gcp/modules/inference-vertex`](../../deploy/gcp/modules/inference-vertex/) enables the
Vertex API and grants the workload SA a least-privilege **predict-only** custom role (not
`roles/aiplatform.user`). The module also outputs the regional endpoint host so the deploy root
can add it to the session egress allowlist — the authoritative control.

> Reference set only. Community/other-cloud backends (Bedrock, gateways) live out-of-tree
> against the published SDK.
