# `providers/inference-anthropic/` — reference `InferenceBackend`

**Trust tier:** reference provider implementation (runs as part of the control plane;
holds no key).

Reference implementation of [`InferenceBackend`](../../sdk/interfaces/inference.go) for the
**Anthropic API** (`ARCHITECTURE.md` §5; `DESIGN.md` §3). It is the first of the two
reference inference backends; the in-tenancy **Vertex** backend
([`providers/inference-vertex`](../inference-vertex)) is the Phase-1 exit and lands next
(`docs/ROADMAP.md`). Anthropic comes first because it is the simpler backend, proves the
attended/unattended routing seam, and lets Console7 dogfood its own inference.

## What this is — routing, not a credential

`Resolve` is a **pure policy decision**: given an `InferenceSelection` it returns a
`BackendEndpoint{Mode, URL}`. It makes **no network call** and holds **no key**. It decides
*which credential class* backs a session and *which Anthropic endpoint* that class may
reach. The credential material itself lives elsewhere:

- the **subscription OAuth** token is sealed/injected by the `SecretsProvider`
  ([`providers/secrets-gcp`](../secrets-gcp) `StoreSubscriptionToken`/`InjectSubscriptionToken`,
  `DESIGN.md` §2.2);
- the **org API key** is a `SecretsProvider` secret fetched for `ModeOrgAPI` sessions
  (a follow-up; see *Real vs deferred*).

## What it upholds

- **First-party pin (subscription).** `ModeSubscription` **always** resolves to
  `https://api.anthropic.com`. There is deliberately no subscription-endpoint config field —
  a personal seat token is structurally un-routable through a third-party gateway, which
  would be a terms-of-service and credential-misuse boundary (`GOAL.md` tenet 7).
- **Org gateway override (org-API only).** `ModeOrgAPI` **may** resolve to an
  adopter-configured `OrgAPIBaseURL` (a self-hosted gateway/proxy fronting the org key),
  because that is org-owned material under the adopter's own egress control. It is validated
  as an absolute **https** URL — `http://` and malformed values **fail closed**.
- **Fail-closed routing.** `ModeUnspecified` and any unrecognised mode are refused rather
  than defaulting to a credential class. A `ModeSubscription` selection that is not attended,
  serves more than one beneficiary, or is disabled by policy is an **error**, never a silent
  downgrade to org-API.
- **The discriminator is `(Attended, Beneficiaries)`, not invocation mode.** A
  forked/headless `claude -p` inside an attended single-user session carries
  `Attended=true, Beneficiaries=1` and stays on `ModeSubscription`.

This seam is **not** the authoritative network control (`GOAL.md` tenet 2). `Resolve`
returning a URL does not make it reachable: the resolved endpoint MUST already be on the
session's **default-deny egress allowlist**, which the orchestrator validates
([`control-plane/orchestrator`](../../control-plane/orchestrator)) and the sandbox boundary
enforces. This is the in-band routing decision layered under that boundary.

## Architecture — deliberately thin, no SDK to confine

Because `Resolve` is pure (no Anthropic API call, no token mint), there is **no real-SDK
port to wall off** — hence no `ports.go`, no SDK `fakes.go`, and no live
`integration_test.go`. Their absence is intentional. The package is **dependency-free Go**;
the Anthropic SDK lands later, in the sandbox PR that drives the engine against the resolved
endpoint (CLI + OAuth for subscription, Agent SDK + API key for org-API, `DESIGN.md` §1.4).
The routing logic shape mirrors [`sdk/devkit.PolicyInference`](../../sdk/devkit/inference_policy.go),
adding the Anthropic-specific endpoint policy.

## Wiring

```go
// Subscription routing is OFF by default (fail-closed); set SubscriptionEnabled to opt in
// (the DESIGN.md §3 policy flip). Omit the field to keep it disabled.
backend, err := inferenceanthropic.New(inferenceanthropic.Config{
    SubscriptionEnabled: true,
    // Optional: front the ORG-API route with a self-hosted gateway. Never affects the
    // subscription route, which is pinned to first-party Anthropic.
    // OrgAPIBaseURL: "https://anthropic-gw.corp.example.com",
})
```

## Real vs deferred

- **Real:** the attended/unattended routing decision, fail-closed mode handling, the
  first-party subscription pin, and the optional org-API gateway override.
- **Deferred:** the org-API-key fetch/injection path (a `SecretsProvider` follow-up); the
  engine-invocation config emitted to the sandbox; and all **live inference traffic** —
  gated behind the not-yet-built sandbox/egress boundary.

## Tests

```bash
go test ./providers/inference-anthropic/...   # routing + pin invariants (no credentials)
go test ./conformance/...                      # InferenceBackend.Resolve contract on this provider
```
