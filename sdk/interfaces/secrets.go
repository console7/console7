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
	// TTL is the requested lifetime. The provider MUST cap it to the session's
	// MaxTTL and MUST NOT issue non-expiring material.
	TTL time.Duration
}

// SealedToken is per-user, envelope-encrypted credential material at rest — the one
// unavoidable stored credential, the user's subscription OAuth token (DESIGN.md
// §2.2). It carries only ciphertext and the KMS key reference, never plaintext.
type SealedToken struct {
	Subject Subject
	// Ciphertext is envelope-encrypted under the adopter's customer-managed KMS key.
	Ciphertext []byte
	// KMSKeyRef identifies the per-user customer-managed key; it is a reference, not
	// key material.
	KMSKeyRef string
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
	// Attended MUST be true: a subscription token backs only attended, single-user
	// sessions. The provider MUST refuse injection when it is false (DESIGN.md §3).
	Attended bool
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
	// expiry no later than req.TTL (and the session MaxTTL), MUST be scoped to
	// req.Scopes and no wider, and MUST become unusable when the session ends.
	// Workload-identity federation / OIDC SHOULD be preferred over any stored secret.
	MintEphemeral(ctx context.Context, req EphemeralRequest) (CredentialRef, error)

	// StoreSubscriptionToken persists a user's subscription OAuth token, envelope-
	// encrypted under that user's KMS key.
	//
	// SECURITY: the implementation MUST store the token ONLY under a per-user key,
	// MUST envelope-encrypt it under the adopter's customer-managed KMS, and MUST
	// NOT make it readable by platform operators (no standing operator read path).
	// It MUST NEVER pool the token or store it under a shared/multi-user key
	// (DESIGN.md §2.2; GOAL.md tenet 7 — one human, one credential, one beneficiary).
	StoreSubscriptionToken(ctx context.Context, tok SealedToken) error

	// InjectSubscriptionToken decrypts a user's subscription token and injects it
	// directly into THAT user's sandbox at session start.
	//
	// SECURITY: the implementation MUST verify in.Sandbox belongs to in.Subject's
	// session and MUST refuse injection when in.Attended is false; it MUST inject the
	// token only into that owning sandbox, MUST NOT return the plaintext token to the
	// caller (the control plane never sees it), and MUST NEVER use it for any
	// beneficiary but its owner or for any unattended/orchestrated session (DESIGN.md
	// §2.2, §3).
	InjectSubscriptionToken(ctx context.Context, in SubscriptionInjection) error

	// RevokeSubject deletes a user's stored material on revocation/offboarding
	// (e.g. SCIM deprovision).
	//
	// SECURITY: the implementation MUST make the material unrecoverable after this
	// call and MUST NOT retain a readable copy for "audit" — evidence lives in the
	// EvidenceSink, not in recoverable secrets (DESIGN.md §2.2).
	RevokeSubject(ctx context.Context, subject Subject) error
}
