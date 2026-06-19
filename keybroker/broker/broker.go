package broker

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/console7/console7/keybroker/signing"
	"github.com/console7/console7/sdk/interfaces"
)

// Broker mints per-session identities and credentials by driving the provider seams. The
// seam fields are interface-typed so the same broker runs against the in-memory devkit
// seams (Phase 0) or real cloud providers (later phases) unchanged.
//
// The broker also CUSTODIES each session's NHI signing key: the ephemeral
// *signing.SessionSigner stays inside the broker (the dedicated, separately-hardened
// signing artifact) and callers sign via SignSession, so the control plane never holds the
// key and a compromised orchestrator cannot mint signatures past a session's life
// (ARCHITECTURE.md §2; GOAL.md tenet 6 — distinct signing identity, control-plane holds no
// keys).
type Broker struct {
	Identity  interfaces.IdentityProvider
	Secrets   interfaces.SecretsProvider
	SCM       interfaces.SCMProvider
	Inference interfaces.InferenceBackend
	Binder    *signing.NHIBinder

	mu      sync.Mutex
	signers map[interfaces.SessionID]*signing.SessionSigner
}

// New returns a Broker wired to the given seams and NHI binder. Each is required by the
// method that uses it: MintSessionIdentity needs Identity, Secrets, SCM, and Binder;
// the vault helpers need Secrets and Inference. A nil dependency is a programming error
// surfaced when its method is first called, not silently tolerated.
func New(id interfaces.IdentityProvider, secrets interfaces.SecretsProvider, scm interfaces.SCMProvider, inference interfaces.InferenceBackend, binder *signing.NHIBinder) *Broker {
	return &Broker{
		Identity:  id,
		Secrets:   secrets,
		SCM:       scm,
		Inference: inference,
		Binder:    binder,
		signers:   make(map[interfaces.SessionID]*signing.SessionSigner),
	}
}

// Authenticate verifies an inbound SSO assertion and returns the human Subject, without
// minting any credential. It lets a caller establish identity BEFORE taking any
// identity-dependent action (e.g. resolving a policy target), so an unauthenticated caller
// cannot probe downstream systems. The Subject is verified by the IdentityProvider; a
// caller-asserted subject is never trusted.
func (b *Broker) Authenticate(ctx context.Context, authn interfaces.AuthnToken) (interfaces.Subject, error) {
	if b.Identity == nil {
		return "", errors.New("broker: missing identity seam")
	}
	return b.Identity.Authenticate(ctx, authn)
}

// SessionRequest describes a session asking to be credentialed: the inbound (untrusted)
// SSO assertion, the session and persona it runs as, the repo/branch it will work on, and
// the least-privilege scope, lifetime, and hard deadline its cloud credential must carry.
type SessionRequest struct {
	Authn           interfaces.AuthnToken
	SessionID       interfaces.SessionID
	Persona         interfaces.Persona
	Repo            interfaces.RepoRef
	Branch          string
	Scopes          []string
	TTL             time.Duration
	SessionDeadline time.Time
}

// MintedSession is the result of MintSessionIdentity: the per-session identity (carrying
// its ephemeral cloud credential reference), the short-lived SCM working-credential
// reference, and the NHI the session signs as. The signing KEY is deliberately NOT here —
// it stays inside the broker; the caller stamps lineage by calling SignSession, so no
// key-bearing object crosses into the control plane.
type MintedSession struct {
	Identity interfaces.SessionIdentity
	SCM      interfaces.CredentialRef
	NHI      string
}

// MintSessionIdentity runs the core credential flow:
//  1. authenticate the human SSO subject (the lineage anchor),
//  2. bind a per-session non-human identity the subject acts through,
//  3. mint a short-lived, scoped cloud credential that dies with the session,
//  4. mint a short-lived, branch-scoped SCM working credential.
//
// It returns the assembled identity, the SCM reference, and the session signer. Every
// returned credential is an opaque, expiring reference — the broker never returns or
// holds plaintext material, and never stores a long-lived secret.
func (b *Broker) MintSessionIdentity(ctx context.Context, req SessionRequest) (MintedSession, error) {
	if b.Identity == nil || b.Secrets == nil || b.SCM == nil || b.Binder == nil {
		return MintedSession{}, errors.New("broker: missing a required seam (identity/secrets/scm/binder)")
	}

	// 1. Authenticate. The Subject is verified by the IdentityProvider; the broker never
	// trusts a caller-asserted subject.
	subject, err := b.Identity.Authenticate(ctx, req.Authn)
	if err != nil {
		return MintedSession{}, err
	}

	// Reject a duplicate live session up front: replacing an in-flight session's signer
	// would let its next SignSession use the wrong subject's key and let either session's
	// ReleaseSession drop the other's. (Re-checked atomically at registration below.)
	b.mu.Lock()
	_, dup := b.signers[req.SessionID]
	b.mu.Unlock()
	if dup {
		return MintedSession{}, fmt.Errorf("broker: session %q already has a live signer", req.SessionID)
	}

	// 2. Bind a per-session NHI to the verified subject. This is the root of lineage. The
	// signer (which owns the ephemeral private key) is retained inside the broker, never
	// returned, so the control plane signs through SignSession and holds no key. It is
	// registered only AFTER all minting succeeds (below), so a failed mint never leaves a
	// usable signer for a session that did not launch.
	signer, err := b.Binder.Bind(subject, req.SessionID, req.Persona)
	if err != nil {
		return MintedSession{}, err
	}

	// 3. Mint the ephemeral cloud credential, capped to the session deadline by the seam.
	cloudRef, err := b.Secrets.MintEphemeral(ctx, interfaces.EphemeralRequest{
		SessionID:       req.SessionID,
		Subject:         subject,
		Scopes:          req.Scopes,
		TTL:             req.TTL,
		SessionDeadline: req.SessionDeadline,
	})
	if err != nil {
		return MintedSession{}, err
	}

	// 4. Mint the branch-scoped SCM working credential.
	scmRef, err := b.SCM.MintWorkingCredential(ctx, interfaces.WorkingCredentialRequest{
		Subject:         subject,
		SessionID:       req.SessionID,
		Repo:            req.Repo,
		Branch:          req.Branch,
		SessionDeadline: req.SessionDeadline,
	})
	if err != nil {
		return MintedSession{}, err
	}

	// Register the signer only now that authentication, binding, and BOTH credential mints
	// have succeeded — atomically re-checking for a duplicate so a racing mint cannot clobber
	// an active session's key.
	b.mu.Lock()
	if _, dup := b.signers[req.SessionID]; dup {
		b.mu.Unlock()
		return MintedSession{}, fmt.Errorf("broker: session %q already has a live signer", req.SessionID)
	}
	b.signers[req.SessionID] = signer
	b.mu.Unlock()

	return MintedSession{
		Identity: interfaces.SessionIdentity{
			Subject:    subject,
			SessionID:  req.SessionID,
			Persona:    req.Persona,
			Credential: cloudRef,
		},
		SCM: scmRef,
		NHI: signer.NHI,
	}, nil
}

// SignSession signs payload with the session's NHI key and returns the lineage-stamped
// signature. The key stays inside the broker; the caller only ever sees the Signature. It
// fails if the session has no live signer (never minted, or already released) — a released
// key cannot sign, so signatures cannot outlive the session.
func (b *Broker) SignSession(ctx context.Context, session interfaces.SessionID, payload []byte) (signing.Signature, error) {
	b.mu.Lock()
	signer, ok := b.signers[session]
	b.mu.Unlock()
	if !ok {
		return signing.Signature{}, fmt.Errorf("broker: no live signer for session %q", session)
	}
	return signer.Sign(payload), nil
}

// ReleaseSession discards the session's NHI signer, ending its ability to sign. The
// orchestrator calls this at teardown so the ephemeral key does not outlive the session
// (GOAL.md tenet 4). Releasing an unknown session is a no-op.
func (b *Broker) ReleaseSession(session interfaces.SessionID) {
	b.mu.Lock()
	delete(b.signers, session)
	b.mu.Unlock()
}
