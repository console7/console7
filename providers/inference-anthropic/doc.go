// Package inferenceanthropic is the Console7 reference InferenceBackend for the
// Anthropic API (ARCHITECTURE.md §5; DESIGN.md §3). It is an in-tree reference
// implementation of the sdk/interfaces.InferenceBackend seam; community backends
// (Bedrock, gateways) live out-of-tree against the published SDK, and the in-tenancy
// Vertex reference lands alongside it (docs/ROADMAP.md Phase 1).
//
// # What this seam is — routing, not a credential
//
// InferenceBackend.Resolve is a PURE policy decision: given an InferenceSelection it
// returns a BackendEndpoint{Mode, URL}. It makes no network call and holds no key. It
// decides, per the attended/unattended seam (DESIGN.md §3; GOAL.md tenet 7), WHICH
// credential class backs a session and WHICH Anthropic endpoint that class is allowed to
// reach. The credential material itself lives elsewhere and is out of scope here:
//
//   - the subscription OAuth token is sealed/injected by the SecretsProvider
//     (providers/secrets-gcp StoreSubscriptionToken/InjectSubscriptionToken, DESIGN.md §2.2);
//   - the org API key is a SecretsProvider secret fetched for ModeOrgAPI sessions.
//
// The shape mirrors sdk/devkit.PolicyInference, adding Anthropic-specific endpoint policy.
//
// # SECURITY: the first-party pin (the reason this provider is not generic)
//
// A personal subscription seat token MUST only ever be pointed at first-party Anthropic.
// Routing a seat token through a third-party gateway/proxy is a terms-of-service and
// credential-misuse boundary (GOAL.md tenet 7 — one human, one credential, one
// beneficiary). So ModeSubscription ALWAYS resolves to FirstPartyBaseURL and there is
// deliberately no subscription-endpoint config field to override it — the pin is
// structural, not a runtime check. ModeOrgAPI, by contrast, MAY resolve to an
// adopter-configured base URL (a self-hosted gateway/proxy fronting the org key), because
// that is org-owned material under the adopter's own egress control.
//
// SECURITY: Resolve fails closed. ModeUnspecified and any unrecognised mode are refused
// rather than defaulting to a credential class; a ModeSubscription selection that is not
// attended, serves more than one beneficiary, or is disabled by enterprise policy is an
// ERROR, never a silent downgrade to org-API. The (Attended, Beneficiaries) facts are the
// discriminator, NOT the invocation mode: a forked/headless `claude -p` inside an attended
// single-user session carries Attended=true, Beneficiaries=1 and stays on ModeSubscription.
//
// This provider is NOT the authoritative network control. Resolve returning a URL does not
// make it reachable: the resolved endpoint MUST already be on the session's default-deny
// egress allowlist, which the orchestrator validates and the sandbox boundary enforces
// (GOAL.md tenet 2). This seam is the in-band routing decision layered under that boundary.
//
// # No SDK to confine — deliberately thin
//
// Because Resolve is pure (no Anthropic API call, no token mint), there is NO real-SDK
// port to wall off and hence no ports.go, no SDK fakes.go, and no live integration_test.go
// — their absence is intentional, not an omission. The package is dependency-free Go; the
// Anthropic SDK lands later, in the sandbox PR that actually drives the engine against the
// resolved endpoint (CLI + OAuth for subscription, Agent SDK + API key for org-API,
// DESIGN.md §1.4).
//
// # Real vs deferred in this PR
//
//   - REAL: the attended/unattended routing decision, fail-closed mode handling, the
//     first-party subscription pin, and the optional org-API gateway override.
//   - REAL (as of B9b): the org-API-key fetch/injection path — the SecretsProvider now seals an
//     adopter org credential (SetOrgCredential) and injects it into a session's sandbox by reference
//     (InjectOrgCredential), and the orchestrator's org-API lane delivers it; the runner exports it
//     as the engine's ANTHROPIC_API_KEY (providers/cloud-gcp, B9).
//   - DEFERRED: the engine-invocation config (CLI+OAuth vs Agent SDK+API key) emitted to the
//     sandbox; and live inference traffic over the egress boundary (proven by the B11 integration test).
package inferenceanthropic
