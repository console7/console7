// Package inferencevertex is the Console7 reference InferenceBackend for Google
// Vertex AI (ARCHITECTURE.md §5; DESIGN.md §3). It is the IN-TENANCY counterpart to
// providers/inference-anthropic: where the Anthropic backend leaves the adopter's
// tenancy for first-party Anthropic under commercial terms, Vertex keeps inference
// inside the adopter's own GCP account and region (ARCHITECTURE.md §3). Community
// backends (Bedrock, gateways, other clouds) live out-of-tree against the published
// SDK; only the GCP Vertex reference lands in-tree (docs/ROADMAP.md Phase 1, exit gate).
//
// # What this seam is — routing, not a credential
//
// InferenceBackend.Resolve is a PURE policy decision: given an InferenceSelection it
// returns a BackendEndpoint{Mode, URL}. It makes no network call and holds no key — it
// decides WHICH credential class backs a session and WHICH Vertex endpoint that class
// is allowed to reach. The credential material itself is out of scope here: a Vertex
// call authenticates with a short-lived GCP identity (Application Default Credentials /
// a workload SA token) acquired by the SecretsProvider / key broker and injected into
// the sandbox, not held by this router.
//
// # No SDK to confine — deliberately thin (docs/adr/0004)
//
// Because Resolve is pure (no Vertex API call, no token mint), there is NO real-SDK port
// to wall off, and hence NO ports.go, NO SDK fakes.go, and NO live integration_test.go —
// their absence is intentional, not an omission. The package is dependency-free Go and
// adds nothing to go.mod. The Vertex endpoint (https://{region}-aiplatform.googleapis.com,
// or the global host) is fully derivable from config, so a GCP-SDK dependency would buy
// nothing the interface asks for and would push a credentialled network call into a seam
// the contract says holds no key. The shape mirrors providers/inference-anthropic and a
// future providers/inference-bedrock; the inference-backend cloud and the control-plane
// cloud are orthogonal axes (docs/adr/0004), so "in-tenancy" is a property of the egress
// allowlist and network zone, NOT of this provider's cloud identity.
//
// # SECURITY: Vertex refuses ModeSubscription, unconditionally
//
// A personal Claude subscription seat is an Anthropic OAuth credential that authenticates
// against first-party Anthropic; it has no meaning on Vertex, which is reached with a GCP
// IAM identity and billed to the adopter's GCP project. The two auth systems are disjoint,
// so routing a subscription session "to Vertex" is incoherent. This provider therefore
// refuses EVERY ModeSubscription selection — including the attended, single-beneficiary
// case the Anthropic backend would serve — rather than fabricating a route. That is a
// STRICTER posture than the contract floor (which refuses only unattended/multi-beneficiary
// subscription), and it fails closed: an attended subscription session belongs on the
// direct-Anthropic backend, not here.
//
// SECURITY: Resolve fails closed elsewhere too. ModeUnspecified and any unrecognised mode
// are refused rather than defaulting to a credential class. ModeOrgAPI — every session
// without a present human or with more than one beneficiary (orchestrated, scheduled,
// triggered, headless, or cross-repo fan-out) — resolves to the configured Vertex endpoint.
//
// This provider is NOT the authoritative network control. Resolve returning a URL does not
// make it reachable: the resolved endpoint MUST already be on the session's default-deny
// egress allowlist, which the orchestrator validates and the sandbox boundary enforces
// (GOAL.md tenet 3). This seam is the in-band routing decision layered under that boundary.
//
// # Real vs deferred in this PR
//
//   - REAL: org-API endpoint resolution (regional / global / a Private-Service-Connect or
//     VPC-SC base-URL override) and the fail-closed seam, including the subscription refusal.
//   - DEFERRED: GCP credential acquisition (ADC / workload-SA token mint, a SecretsProvider
//     and key-broker concern); the engine-invocation env emitted to the sandbox
//     (ANTHROPIC_VERTEX_PROJECT_ID / CLOUD_ML_REGION for the wrapped Claude Code engine); and
//     all live inference traffic — gated behind the not-yet-built sandbox/egress boundary.
package inferencevertex
