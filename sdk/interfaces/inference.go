package interfaces

import "context"

// InferenceMode is the credential class backing a session's model inference. The
// attended/unattended seam between the two is enforced in policy, not guidance
// (DESIGN.md §3; GOAL.md tenet 2).
type InferenceMode int

const (
	// ModeUnspecified is the zero value and is INVALID. It exists so that a selection
	// constructed or decoded without an explicit Mode does NOT silently default to a
	// credential class — least of all the user's subscription. Resolve MUST reject it
	// (fail closed).
	ModeUnspecified InferenceMode = iota
	// ModeSubscription backs ONLY attended, single-user, first-party interactive
	// sessions (one human, one credential, one beneficiary).
	ModeSubscription
	// ModeOrgAPI backs any session without a present human or with more than one
	// beneficiary — orchestrated, scheduled, webhook-triggered, headless/unattended,
	// or cross-repo fan-out — via an org API key (Vertex / Bedrock / direct
	// Anthropic). The discriminator is human presence and single beneficiary, NOT
	// invocation mode (DESIGN.md §3).
	ModeOrgAPI
)

// InferenceSelection describes the session asking to reach a model backend.
type InferenceSelection struct {
	SessionID SessionID
	Subject   Subject
	Mode      InferenceMode
	// Attended is true only when a human is present for this session. It is half the
	// discriminator for the seam, not the invocation mode: a forked/headless
	// `claude -p` inside an attended single-user session is still attended (DESIGN.md
	// §3).
	Attended bool
	// Beneficiaries is the number of distinct beneficiaries the session serves — the
	// other half of the discriminator, supplied as an explicit fact rather than
	// folded into Attended so the backend can detect a human-present fan-out
	// (Attended && Beneficiaries > 1). ModeSubscription requires exactly 1.
	Beneficiaries int
}

// BackendEndpoint is the resolved destination for model inference — the one and
// only boundary crossing out of the adopter's tenancy (ARCHITECTURE.md §3).
type BackendEndpoint struct {
	Mode InferenceMode
	// URL is the resolved inference endpoint; it MUST already be present on the
	// session's egress allowlist (the boundary is authoritative).
	URL string
	// Kind names the concrete backend lane (Anthropic API vs Vertex). Mode is the
	// credential CLASS (subscription vs org-API); Kind is the provider LANE, which a
	// consumer needs to render the right engine env and credential type. Resolve MUST
	// set it explicitly on a returned endpoint.
	Kind BackendKind
	// VertexProjectID and VertexRegion carry the Vertex routing facts when Kind is
	// BackendVertex (VertexRegion is "global" for the location-independent endpoint);
	// both are empty otherwise. They are emitted to the wrapped engine as
	// ANTHROPIC_VERTEX_PROJECT_ID / CLOUD_ML_REGION and are NOT secrets.
	VertexProjectID string
	VertexRegion    string
}

// BackendKind names the concrete inference LANE a BackendEndpoint resolves to, so a
// consumer (the CloudProvider rendering the engine-invocation env and selecting the
// credential type) can tell an Anthropic-API org key from a Vertex GCP-bearer-token
// lane. Mode alone cannot: both the in-tenancy Vertex route and the direct-Anthropic
// org route are ModeOrgAPI. It is a routing FACT, never a credential.
type BackendKind int

const (
	// BackendUnspecified is the zero value and is INVALID for a resolved endpoint: a
	// consumer MUST NOT infer a lane from it. A Resolve implementation that returns an
	// endpoint MUST set an explicit kind.
	BackendUnspecified BackendKind = iota
	// BackendAnthropicAPI is the direct-Anthropic lane — a subscription seat or an org
	// API key spoken over the Anthropic API; authenticated with an ANTHROPIC_API_KEY.
	BackendAnthropicAPI
	// BackendVertex is the in-tenancy Vertex AI lane (org-API only), reached at a
	// *-aiplatform.googleapis.com endpoint and authenticated with a short-lived GCP
	// bearer token (NOT an ANTHROPIC_API_KEY, NOT the node metadata server).
	BackendVertex
)

// InferenceBackend abstracts backend selection and the attended/unattended seam
// (ARCHITECTURE.md §5; default ref: Vertex). It is the only seam whose traffic
// leaves the adopter's tenancy, and the destination is an adopter choice.
type InferenceBackend interface {
	// Resolve selects the backend endpoint for a session, enforcing the
	// attended/unattended seam in policy.
	//
	// SECURITY: the implementation MUST reject ModeUnspecified (and any unrecognised
	// mode) rather than defaulting — fail closed. It MUST refuse a ModeSubscription
	// selection unless it is both Attended and sel.Beneficiaries == 1, and MUST route
	// to ModeOrgAPI any
	// session without a present human or with more than one beneficiary (orchestrated,
	// scheduled, triggered,
	// headless/unattended, or cross-repo fan-out) — a subscription credential MUST
	// NEVER back an unattended or multi-beneficiary session (DESIGN.md §3; GOAL.md
	// tenet 2). The discriminator is human presence and single beneficiary, NOT
	// invocation mode: a forked/headless `claude -p` INSIDE an attended single-user
	// session stays on ModeSubscription and MUST NOT be rerouted. The seam trigger
	// MUST be a configurable enterprise policy (flip policy, not architecture), and
	// the implementation MUST NOT pool one user's subscription across beneficiaries.
	Resolve(ctx context.Context, sel InferenceSelection) (BackendEndpoint, error)
}
