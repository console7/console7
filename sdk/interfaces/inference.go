package interfaces

import "context"

// InferenceMode is the credential class backing a session's model inference. The
// attended/unattended seam between the two is enforced in policy, not guidance
// (DESIGN.md §3; GOAL.md tenet 7).
type InferenceMode int

const (
	// ModeSubscription backs ONLY attended, single-user, first-party interactive
	// sessions (one human, one credential, one beneficiary).
	ModeSubscription InferenceMode = iota
	// ModeOrgAPI backs anything orchestrated, scheduled, triggered, headless, or
	// multi-beneficiary, via an org API key (Vertex / Bedrock / direct Anthropic).
	ModeOrgAPI
)

// InferenceSelection describes the session asking to reach a model backend.
type InferenceSelection struct {
	SessionID SessionID
	Subject   Subject
	Mode      InferenceMode
	// Attended is true only when a human is present for, and the sole beneficiary
	// of, this session. It is the discriminator for the seam, not the invocation
	// mode: a forked/headless `claude -p` inside an attended single-user session is
	// still attended (DESIGN.md §3).
	Attended bool
}

// BackendEndpoint is the resolved destination for model inference — the one and
// only boundary crossing out of the adopter's tenancy (ARCHITECTURE.md §3).
type BackendEndpoint struct {
	Mode InferenceMode
	// URL is the resolved inference endpoint; it MUST already be present on the
	// session's egress allowlist (the boundary is authoritative).
	URL string
}

// InferenceBackend abstracts backend selection and the attended/unattended seam
// (ARCHITECTURE.md §5; default ref: Vertex). It is the only seam whose traffic
// leaves the adopter's tenancy, and the destination is an adopter choice.
type InferenceBackend interface {
	// Resolve selects the backend endpoint for a session, enforcing the
	// attended/unattended seam in policy.
	//
	// SECURITY: the implementation MUST refuse a ModeSubscription selection that is
	// not Attended, and MUST route anything orchestrated/scheduled/triggered/headless
	// or multi-beneficiary to ModeOrgAPI — a subscription credential MUST NEVER back
	// an unattended or multi-beneficiary session (DESIGN.md §3; GOAL.md tenet 7). The
	// seam trigger MUST be a configurable enterprise policy (flip policy, not
	// architecture). The implementation MUST NOT pool one user's subscription across
	// beneficiaries.
	Resolve(ctx context.Context, sel InferenceSelection) (BackendEndpoint, error)
}
