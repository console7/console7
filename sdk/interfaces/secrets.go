package interfaces

import (
	"context"
	"time"
)

// EphemeralRequest asks the secrets provider to mint short-lived, session-scoped
// credential material from the adopter's secrets manager / identity platform.
type EphemeralRequest struct {
	SessionID SessionID
	Subject   Subject
	// Scopes are the least-privilege permissions the credential should carry. The
	// provider MUST NOT grant more than these.
	Scopes []string
	// TTL is the requested lifetime.
	TTL time.Duration
	// SessionDeadline is the authoritative ABSOLUTE time the session ends, supplied so
	// the provider has a hard deadline to cap against (it does not otherwise know the
	// session profile). The provider MUST cap the credential's expiry to no later than
	// min(now+TTL, SessionDeadline) and MUST NOT issue material that outlives the
	// session. A duration ceiling alone is insufficient — a credential minted
	// mid-session with a fresh TTL would otherwise outlive the session end.
	SessionDeadline time.Time
}

// SubscriptionToken is a user's freshly-captured subscription OAuth token, handed to
// the KMS-owning provider (the key broker) to be sealed and stored — the one
// unavoidable stored credential (DESIGN.md §2.2). Sealing happens INSIDE the
// provider so the per-user envelope-encryption invariant is enforced at the KMS
// seam, not trusted from a caller-supplied blob; the plaintext exists only
// transiently inside the broker and MUST NEVER reach the control plane (DESIGN.md
// §8; GOAL.md tenet 4).
type SubscriptionToken struct {
	// Subject is the token's owner; storage is keyed per-user (no pooling).
	Subject Subject
	// Token is the OAuth token material to seal. The provider MUST envelope-encrypt it
	// under the owner's per-user customer-managed KMS key before persisting, and MUST
	// NEVER persist, log, or return it unsealed.
	Token []byte
}

// SubscriptionInjection identifies a per-user subscription-token injection into one
// attended session's sandbox. It carries exactly the facts a provider needs to
// uphold the injection invariant: the token's owner (the only permitted
// beneficiary), the session and sandbox it is bound to, and that a human is present.
type SubscriptionInjection struct {
	// Subject is the token's owner — the ONLY permitted beneficiary (no pooling).
	Subject Subject
	// SessionID is the session the sandbox belongs to; lets the provider bind the
	// injection to a single session and refuse a mismatched/stale handle.
	SessionID SessionID
	// Sandbox is the owning subject's sandbox to inject into.
	Sandbox SandboxHandle
	// Attended MUST be true: a subscription token backs only attended sessions. The
	// provider MUST refuse injection when it is false (DESIGN.md §3).
	Attended bool
	// Beneficiaries is the number of distinct beneficiaries the session serves. A
	// subscription token backs a single beneficiary only, so the provider MUST refuse
	// injection unless this is exactly 1 — carried here (not folded into Attended) so
	// an attended fan-out (Attended && Beneficiaries > 1) is refused at this seam too.
	Beneficiaries int
}

// OrgCredentialInjection identifies an injection of the adopter's shared ORG API credential
// (the engine's ANTHROPIC_API_KEY for the org-API lane) into one session's sandbox. Unlike a
// subscription token it is NOT beneficiary-bound: the org credential backs EVERY session the
// orchestrator routes to the org-API lane — anything orchestrated/scheduled/headless, OR an
// attended session whose user did not opt into their subscription (GOAL.md tenet 2 — subscription
// is permitted, never mandatory). So it carries only the binding facts needed to deliver into the
// right sandbox, no attended/beneficiary flags.
type OrgCredentialInjection struct {
	// Subject is the session's human subject — used (with SessionID) to verify the target sandbox
	// is the one provisioned for this session before the org credential is delivered into it.
	Subject Subject
	// SessionID is the session the sandbox belongs to; binds the injection to one session.
	SessionID SessionID
	// Sandbox is the session's sandbox to inject the org credential into.
	Sandbox SandboxHandle
}

// InferenceCredentialInjection identifies an injection of a freshly-MINTED short-lived cloud
// inference credential (a GCP bearer token for the in-tenancy Vertex lane) into one session's
// sandbox. Unlike OrgCredentialInjection (which delivers a STORED org API key) the provider MINTS
// the credential on demand from the adopter's identity platform (workload-identity token mint) — so
// no long-lived inference credential is ever stored, and the sandbox can authenticate to the backend
// from this delivered token INSTEAD of the node metadata server. (Whether the sandbox can reach the
// metadata server at all is the egress boundary / GKE metadata config's job — the authoritative
// control, GOAL.md tenet 3 — not this seam's; this seam's job is to make a delivered token the
// credential source.) It is not beneficiary-bound: the inference credential backs any session the
// orchestrator routes to the in-tenancy backend, so it carries only the binding facts plus the
// deadline to cap the minted token's lifetime against.
type InferenceCredentialInjection struct {
	// Subject is the session's human subject — used (with SessionID) to verify the target sandbox
	// is the one provisioned for this session before the credential is delivered into it.
	Subject Subject
	// SessionID is the session the sandbox belongs to; binds the injection to one session.
	SessionID SessionID
	// Sandbox is the session's sandbox to inject the minted inference credential into.
	Sandbox SandboxHandle
	// SessionDeadline is the authoritative ABSOLUTE time the session ends. The provider MUST cap the
	// minted credential's expiry to no later than min(now+providerMax, SessionDeadline) and MUST NOT
	// mint material that outlives the session (ephemeral by default; GOAL.md tenet 5).
	SessionDeadline time.Time
}

// SecretsProvider abstracts secret storage, envelope encryption, and KMS
// (ARCHITECTURE.md §5; default ref: GCP Secret Manager + Cloud KMS). It is a broker,
// not a vault the control plane reads: it mints and injects, it does not hand keys
// back (DESIGN.md §2.1).
type SecretsProvider interface {
	// MintEphemeral issues short-lived, session-scoped credential material and
	// returns only an opaque, expiring reference to it.
	//
	// SECURITY: the implementation MUST NEVER return long-lived material, and MUST
	// NEVER return plaintext credential material to the control plane at all — only
	// a CredentialRef (DESIGN.md §2.1, §8). The minted credential MUST carry an
	// expiry no later than min(now+req.TTL, req.SessionDeadline), MUST be scoped to
	// req.Scopes and no wider, and MUST become unusable when the session ends.
	// Workload-identity federation / OIDC SHOULD be preferred over any stored secret.
	MintEphemeral(ctx context.Context, req EphemeralRequest) (CredentialRef, error)

	// StoreSubscriptionToken seals a user's subscription OAuth token and persists it.
	// The provider performs the envelope encryption itself (it owns the KMS); it does
	// NOT accept caller-sealed ciphertext, so the per-user-key invariant is enforced
	// at the seam rather than trusted.
	//
	// SECURITY: the implementation MUST envelope-encrypt tok.Token under tok.Subject's
	// own per-user customer-managed KMS key before persisting, MUST store it ONLY
	// under that per-user key, and MUST NOT make it readable by platform operators
	// (no standing operator read path). It MUST NEVER persist or log the token
	// unsealed, and MUST NEVER pool it or store it under a shared/multi-user key
	// (DESIGN.md §2.2, §8; GOAL.md tenet 2 — one human, one credential, one beneficiary).
	StoreSubscriptionToken(ctx context.Context, tok SubscriptionToken) error

	// InjectSubscriptionToken decrypts a user's subscription token and injects it
	// directly into THAT user's sandbox at session start.
	//
	// SECURITY: the implementation MUST verify in.Sandbox belongs to in.Subject's
	// session and MUST refuse injection unless in.Attended is true AND
	// in.Beneficiaries == 1; it MUST inject the token only into that owning sandbox,
	// MUST NOT return the plaintext token to the caller (the control plane never sees
	// it), and MUST NEVER use it for any beneficiary but its owner or for any
	// unattended/orchestrated/multi-beneficiary session (DESIGN.md §2.2, §3).
	InjectSubscriptionToken(ctx context.Context, in SubscriptionInjection) error

	// InjectOrgCredential injects the adopter's ORG API credential — configured out-of-band on the
	// provider, NEVER supplied by the control plane — into a session's sandbox for the org-API lane.
	//
	// SECURITY: the implementation MUST verify in.Sandbox belongs to in.Subject's in.SessionID and
	// MUST inject the credential ONLY into that owning sandbox; it MUST NOT return the plaintext
	// credential to the caller (the control plane never sees it); and it MUST fail closed if no org
	// credential is configured (refuse, rather than let the engine run unauthenticated). The org
	// credential is org-wide, not per-user, so — unlike InjectSubscriptionToken — there is no
	// attended/single-beneficiary gate: it backs ANY session routed to the org-API lane, which is
	// exactly the orchestrated/scheduled/headless/multi-beneficiary work GOAL.md tenet 2 assigns to
	// org API keys (DESIGN.md §2.1, §3).
	InjectOrgCredential(ctx context.Context, in OrgCredentialInjection) error

	// InjectInferenceCredential MINTS a short-lived cloud inference credential (e.g. a GCP bearer
	// token for the in-tenancy Vertex backend) and injects it ONLY for the session's own sandbox —
	// delivered to that session's AUTH-PROXY gateway (the credential-attaching reverse proxy the engine
	// reaches the backend through), NOT into the sandbox itself, so the sandbox stays credential-free
	// (it never holds the cloud bearer). Unlike InjectOrgCredential it does NOT deliver a stored secret —
	// it mints on demand from the adopter's identity platform (workload-identity token mint), so no
	// long-lived inference credential is ever stored and a delivered token — not the node metadata
	// server — is the inference credential source. (Denying the sandbox the metadata server is the egress
	// boundary / GKE metadata config's job, not this seam's.)
	//
	// SECURITY: the implementation MUST verify in.Sandbox belongs to in.Subject's in.SessionID and
	// inject the minted credential ONLY for that owning session (delivered to its auth-proxy gateway,
	// keeping the sandbox credential-free); it MUST cap the credential's expiry
	// to no later than min(now+providerMax, in.SessionDeadline) and MUST NOT mint material that
	// outlives the session; it MUST scope the credential to the least privilege the backend needs;
	// it MUST NOT return the plaintext credential to the caller (the mint AND the delivery both happen
	// INSIDE the provider — the control plane never sees it); and it MUST fail closed on any mint or
	// delivery error, never letting the engine run unauthenticated (DESIGN.md §2.1, §3; GOAL.md
	// tenet 5 — least privilege, ephemeral by default).
	InjectInferenceCredential(ctx context.Context, in InferenceCredentialInjection) error

	// RevokeSubject deletes a user's stored material on revocation/offboarding
	// (e.g. SCIM deprovision).
	//
	// SECURITY: the implementation MUST make the material unrecoverable after this
	// call and MUST NOT retain a readable copy for "audit" — evidence lives in the
	// EvidenceSink, not in recoverable secrets (DESIGN.md §2.2).
	RevokeSubject(ctx context.Context, subject Subject) error
}
