package broker

import (
	"context"
	"errors"
	"time"

	"github.com/console7/console7/keybroker/signing"
	"github.com/console7/console7/sdk/interfaces"
)

// Broker mints per-session identities and credentials by driving the provider seams. The
// seam fields are interface-typed so the same broker runs against the in-memory devkit
// seams (Phase 0) or real cloud providers (later phases) unchanged.
type Broker struct {
	Identity  interfaces.IdentityProvider
	Secrets   interfaces.SecretsProvider
	SCM       interfaces.SCMProvider
	Inference interfaces.InferenceBackend
	Binder    *signing.NHIBinder
}

// New returns a Broker wired to the given seams and NHI binder. Each is required by the
// method that uses it: MintSessionIdentity needs Identity, Secrets, SCM, and Binder;
// the vault helpers need Secrets and Inference. A nil dependency is a programming error
// surfaced when its method is first called, not silently tolerated.
func New(id interfaces.IdentityProvider, secrets interfaces.SecretsProvider, scm interfaces.SCMProvider, inference interfaces.InferenceBackend, binder *signing.NHIBinder) *Broker {
	return &Broker{Identity: id, Secrets: secrets, SCM: scm, Inference: inference, Binder: binder}
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
// reference, and the signer that stamps the lineage onto commits/artefacts.
type MintedSession struct {
	Identity interfaces.SessionIdentity
	SCM      interfaces.CredentialRef
	Signer   *signing.SessionSigner
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

	// 2. Bind a per-session NHI to the verified subject. This is the root of lineage.
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

	return MintedSession{
		Identity: interfaces.SessionIdentity{
			Subject:    subject,
			SessionID:  req.SessionID,
			Persona:    req.Persona,
			Credential: cloudRef,
		},
		SCM:    scmRef,
		Signer: signer,
	}, nil
}
