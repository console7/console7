package interfaces

import "context"

// PolicyQuery is a single authorization question put to the policy engine at an
// action boundary.
type PolicyQuery struct {
	// Input is the fact set the decision is computed from (subject, persona, target
	// tier × stratum, action, resources in scope). It is data, not code.
	Input map[string]any
}

// Decision is the policy engine's verdict. It defaults to deny: the zero value
// (Allow false) is a denial, so a dropped or malformed decision fails closed.
type Decision struct {
	Allow bool
	// Reason is a human-readable justification, recorded as evidence.
	Reason string
	// Obligations are additional controls the caller MUST apply when Allow is true
	// (e.g. "human-gate", "dlp-block", "step-up-auth").
	Obligations []string
}

// PolicyEngine abstracts rule evaluation (ARCHITECTURE.md §5; default ref: OPA, or
// Cedar). It evaluates rules over supplied facts; it is NOT the system of record for
// what those facts are (that is PolicySoR).
type PolicyEngine interface {
	// Evaluate decides a single PolicyQuery.
	//
	// SECURITY: the implementation MUST be deterministic and MUST fail closed —
	// any error, timeout, or ambiguity MUST yield a deny, never a default-allow
	// (DESIGN.md §4; GOAL.md tenet 3). It MUST decide only from query.Input and MUST
	// NOT widen scope beyond those facts or reach back to mutable in-band state the
	// governed agent could edit.
	Evaluate(ctx context.Context, q PolicyQuery) (Decision, error)
}

// PolicySoR abstracts the authoritative tier × stratum lookup — the adopter's GRC /
// central policy registry, keyed by target (ARCHITECTURE.md §5; default ref:
// pluggable adapter). It is the authority for "what tier is this artefact"; Console7
// integrates it and MUST NOT own it (DESIGN.md §4.1).
type PolicySoR interface {
	// ResolveRepo returns the authoritative TierStratum for a repository.
	//
	// SECURITY: the result MUST come from the central system of record, NEVER from
	// an in-repo file — an in-repo control is editable by the very agent it governs
	// (the self-relaxation / "prompt-edited-in-prod" threat, DESIGN.md §4.1). The
	// implementation MUST fail closed: an unknown or unresolvable target MUST be
	// treated as the most restrictive tier × stratum, never the most permissive.
	ResolveRepo(ctx context.Context, repo RepoRef) (TierStratum, error)

	// ResolveResource returns the authoritative TierStratum for a non-repo resource
	// (e.g. a production service the operate lane reads), for cross-tier reach.
	//
	// SECURITY: same authority and fail-closed contract as ResolveRepo. A permissive
	// origin MUST NOT confer a stricter target's reach — take-the-max applies
	// (DESIGN.md §4.2).
	ResolveResource(ctx context.Context, res ResourceRef) (TierStratum, error)
}
