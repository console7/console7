package interfaces

import "context"

// AuthnToken is an inbound, untrusted SSO/OIDC assertion presented by a user's
// browser. It is untrusted until the IdentityProvider verifies it.
type AuthnToken string

// Group is an adopter-IdP group/role used to map a Subject onto policy.
type Group string

// IdentityProvider abstracts user SSO/OIDC authentication and group/role mapping
// against the adopter's IdP (ARCHITECTURE.md §5; default ref: OIDC — Okta / Entra).
// It establishes the human Subject that anchors all lineage (DESIGN.md §2.3).
type IdentityProvider interface {
	// Authenticate verifies an inbound SSO/OIDC assertion and returns the
	// authenticated Subject.
	//
	// SECURITY: the implementation MUST cryptographically verify the token against
	// the adopter IdP (signature, issuer, audience, expiry) and MUST NEVER trust
	// client-asserted identity claims without verification. It MUST NOT mint or
	// persist a long-lived session secret of its own — the verified Subject is an
	// assertion of identity, not a stored credential (GOAL.md tenet 4).
	Authenticate(ctx context.Context, token AuthnToken) (Subject, error)

	// ResolveGroups returns the adopter-IdP groups/roles a Subject belongs to, for
	// policy composition (enterprise > team > user).
	//
	// SECURITY: the implementation MUST read group membership from the authoritative
	// IdP at evaluation time and MUST NOT let a Subject self-assert or widen its own
	// group membership — scope must never be grantable by the principal it governs
	// (DESIGN.md §4.1).
	ResolveGroups(ctx context.Context, subject Subject) ([]Group, error)
}
