package secretsgcp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/console7/console7/sdk/interfaces"
)

// Provider is the GCP reference SecretsProvider. Its logic depends only on the KEKWrapper,
// SecretStore, and Injector ports; New wires the real Cloud KMS + Secret Manager adapters,
// while NewWithPorts wires fakes for tests/conformance.
//
// It holds no token and no key at rest: the sealed payloads live in the SecretStore (Secret
// Manager) and the KEK lives in KMS. The only process-local state is the ephemeral lease
// book (MintEphemeral) and a revocation tombstone — see RevokeSubject for the tombstone's
// single-replica scope.
type Provider struct {
	kek    KEKWrapper
	store  SecretStore
	inject Injector
	prefix string
	now    func() time.Time

	// closers are the underlying GCP clients New opened; NewWithPorts leaves this nil.
	closers []io.Closer

	mu      sync.Mutex
	revoked map[interfaces.Subject]bool
	leases  map[string]leaseRec
}

// Close releases any GCP clients opened by New. It is a no-op for a Provider built with
// NewWithPorts (fakes). Safe to call once at control-plane shutdown.
func (p *Provider) Close() error {
	var firstErr error
	for _, c := range p.closers {
		if err := c.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

type leaseRec struct {
	subject interfaces.Subject
	session interfaces.SessionID
	scopes  []string
	expiry  time.Time
}

// Compile-time assertion that Provider satisfies the seam.
var _ interfaces.SecretsProvider = (*Provider)(nil)

// NewWithPorts assembles a Provider from explicit ports. It is the seam tests, the
// conformance harness, and (once the data plane exists) the orchestrator use to wire a real
// Injector. prefix defaults to DefaultSecretPrefix; now defaults to time.Now; a nil Injector
// defaults to the fail-closed denyInjector so a missing wiring refuses injection rather than
// nil-panicking (defence-in-depth, GOAL.md tenet 2).
func NewWithPorts(kek KEKWrapper, store SecretStore, inject Injector, prefix string, now func() time.Time) *Provider {
	if prefix == "" {
		prefix = DefaultSecretPrefix
	}
	if now == nil {
		now = time.Now
	}
	if inject == nil {
		inject = denyInjector{}
	}
	return &Provider{
		kek:     kek,
		store:   store,
		inject:  inject,
		prefix:  prefix,
		now:     now,
		revoked: make(map[interfaces.Subject]bool),
		leases:  make(map[string]leaseRec),
	}
}

// secretID derives the per-subject Secret Manager secret ID. It is "<prefix>-sub-<hex
// SHA-256(subject)>": a fixed-length, name-prefixed, charset-safe id that keeps the SSO
// subject (often an email) out of resource names and audit logs. The same value is the AAD
// bound into the KMS wrap, so it also pins a wrapped DEK to its owner. See the package doc on
// the unsalted-hash trade-off.
func (p *Provider) secretID(subject interfaces.Subject) string {
	sum := sha256.Sum256([]byte(subject))
	return p.prefix + "-sub-" + hex.EncodeToString(sum[:])
}

// MintEphemeral issues a short-lived, session-scoped credential lease and returns an opaque,
// expiring reference — never the material. The GCP-native backing (IAM Credentials
// GenerateAccessToken) is deferred (see doc.go); the expiry-capping and opaque-ref contract
// is fully real here.
func (p *Provider) MintEphemeral(ctx context.Context, req interfaces.EphemeralRequest) (interfaces.CredentialRef, error) {
	if err := ctx.Err(); err != nil {
		return interfaces.CredentialRef{}, err
	}
	// The credential is keyed per-subject (so RevokeSubject can reach it) and anchors lineage
	// to the session; refuse to mint an unattributable one.
	if req.Subject == "" || req.SessionID == "" {
		return interfaces.CredentialRef{}, errors.New("secretsgcp: MintEphemeral requires a subject and session for lineage")
	}
	if req.TTL <= 0 {
		return interfaces.CredentialRef{}, errors.New("secretsgcp: MintEphemeral requires a positive TTL")
	}
	now := p.now()
	// A zero or already-past SessionDeadline gives no hard cap; refuse rather than mint
	// material that could outlive the session.
	if req.SessionDeadline.IsZero() || !req.SessionDeadline.After(now) {
		return interfaces.CredentialRef{}, errors.New("secretsgcp: MintEphemeral requires a SessionDeadline in the future")
	}
	// Cap expiry to the earlier of now+TTL and the absolute session deadline.
	expiry := now.Add(req.TTL)
	if req.SessionDeadline.Before(expiry) {
		expiry = req.SessionDeadline
	}
	// Scope is captured exactly as requested and never widened; a defensive copy stops a
	// caller mutating the slice it shares with us after the fact.
	scopes := append([]string(nil), req.Scopes...)

	p.mu.Lock()
	defer p.mu.Unlock()
	// Refuse to mint for a revoked subject: RevokeSubject is offboarding, after which no new
	// identity should be issued. The in-memory reference does not check this; this provider
	// strengthens it because the tombstone is the local offboarding signal (and matters once
	// the real IAM-Credentials backing lands — an offboarded user must not get fresh creds).
	// The check is under the SAME lock as the insert (and as RevokeSubject's tombstone write),
	// so a RevokeSubject racing this mint cannot interleave to record a lease post-revoke.
	if p.revoked[req.Subject] {
		return interfaces.CredentialRef{}, errors.New("secretsgcp: refusing to mint an ephemeral credential for a revoked subject")
	}
	ref := "lease-" + randHex(12) // opaque; carries no material and no scope.
	p.leases[ref] = leaseRec{subject: req.Subject, session: req.SessionID, scopes: scopes, expiry: expiry}
	return interfaces.CredentialRef{Ref: ref, Expiry: expiry}, nil
}

// StoreSubscriptionToken seals a user's token under a fresh per-user DEK, wraps that DEK under
// the KMS KEK (bound to the owner via AAD), and persists only the ciphertext envelope. The
// plaintext exists transiently inside this call and is zeroed before return.
func (p *Provider) StoreSubscriptionToken(ctx context.Context, tok interfaces.SubscriptionToken) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if tok.Subject == "" {
		return errors.New("secretsgcp: StoreSubscriptionToken requires a Subject")
	}
	if len(tok.Token) == 0 {
		return errors.New("secretsgcp: StoreSubscriptionToken requires non-empty token material")
	}
	if p.isRevoked(tok.Subject) {
		return errors.New("secretsgcp: refusing to store a token for a revoked subject")
	}

	sid := p.secretID(tok.Subject)
	aad := []byte(sid)

	dek, err := mintDEK()
	if err != nil {
		return err
	}
	defer zero(dek)

	sealedTok, err := seal(dek, tok.Token, aad)
	if err != nil {
		return err
	}
	wrapped, kekVersion, err := p.kek.WrapDEK(ctx, dek, aad)
	if err != nil {
		return err
	}

	// Re-check the tombstone immediately before the (remote) commit so a RevokeSubject that
	// committed while we were sealing/wrapping is not raced past.
	if p.isRevoked(tok.Subject) {
		return errors.New("secretsgcp: refusing to store a token for a revoked subject")
	}
	if _, err := p.store.Put(ctx, sid, payload{kekVersion: kekVersion, wrappedDEK: wrapped, sealedToken: sealedTok}.marshal()); err != nil {
		return err
	}
	// Compensating shred: unlike the in-memory reference, the remote Put cannot be held under
	// the same lock as the tombstone check, so a RevokeSubject could commit between the
	// re-check above and the Put. If the tombstone flipped while we were committing, delete
	// what we just wrote so revocation wins the race. (InjectSubscriptionToken also refuses a
	// revoked subject, so this material cannot be injected on this replica even if the delete
	// fails.) Durable cross-replica offboarding remains the upstream identity control.
	if p.isRevoked(tok.Subject) {
		if derr := p.store.Destroy(ctx, sid); derr != nil {
			// Surface the failure rather than reporting a clean shred — the just-written material
			// may still be at rest (and recoverable after a restart or by another replica that
			// lacks this process-local tombstone), so the caller/ops must be able to act on it.
			return fmt.Errorf("secretsgcp: subject revoked during store and the compensating delete FAILED; stored material may remain and must be purged: %w", derr)
		}
		return errors.New("secretsgcp: subject revoked during store; stored material shredded")
	}
	return nil
}

// InjectSubscriptionToken decrypts a user's token and delivers it ONLY into that user's own
// attended sandbox. It returns nil on success and never the plaintext. It fails closed on any
// error — a decrypt or store failure never results in delivery.
func (p *Provider) InjectSubscriptionToken(ctx context.Context, in interfaces.SubscriptionInjection) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// Policy gate first (the load-bearing attended/single-beneficiary invariant): a
	// subscription token backs only an attended, single-beneficiary session.
	if !in.Attended {
		return errors.New("secretsgcp: refusing subscription injection into an unattended session")
	}
	if in.Beneficiaries != 1 {
		return errors.New("secretsgcp: refusing subscription injection for a multi-beneficiary session")
	}
	// Revocation backstop (fast-fail before the KMS round-trip): refuse injection for a subject
	// already revoked. This is re-checked ATOMICALLY with delivery below — the authoritative
	// guarantee — so a RevokeSubject racing this injection cannot deliver a token post-revoke.
	if p.isRevoked(in.Subject) {
		return errors.New("secretsgcp: refusing subscription injection for a revoked subject")
	}
	// Ownership gate (cheap fail-fast before the decrypt): the sandbox must belong to this
	// subject's session. The authoritative check is re-done atomically with delivery below.
	if !p.inject.Owns(in.Sandbox, in.Subject, in.SessionID) {
		return errors.New("secretsgcp: sandbox does not belong to the subject's session")
	}

	sid := p.secretID(in.Subject)
	aad := []byte(sid)

	blob, found, err := p.store.Get(ctx, sid)
	if err != nil {
		return err
	}
	if !found {
		return errors.New("secretsgcp: no stored subscription token for subject (revoked or never stored)")
	}
	pl, err := unmarshalPayload(blob)
	if err != nil {
		return err
	}

	dek, err := p.kek.UnwrapDEK(ctx, pl.wrappedDEK, pl.kekVersion, aad)
	if err != nil {
		return err
	}
	defer zero(dek)
	token, err := open(dek, pl.sealedToken, aad)
	if err != nil {
		return err
	}
	defer zero(token)

	// Deliver only into the verified owning sandbox, re-checking BOTH the revocation tombstone
	// and ownership ATOMICALLY with the delivery — the revocation check and DeliverIfOwned run
	// under p.mu, the same lock RevokeSubject sets the tombstone under. So a RevokeSubject that
	// races this injection either (a) commits its tombstone before this block and the token is
	// refused, or (b) loses the race, in which case delivery happened before revocation
	// committed (a legitimate just-before-revoke injection). The ownership re-check inside
	// DeliverIfOwned likewise closes the teardown race. The plaintext never leaves this call by
	// any other path.
	p.mu.Lock()
	revoked := p.revoked[in.Subject]
	delivered := false
	if !revoked {
		delivered = p.inject.DeliverIfOwned(in.Sandbox, in.Subject, in.SessionID, token)
	}
	p.mu.Unlock()
	if revoked {
		return errors.New("secretsgcp: subject revoked during injection")
	}
	if !delivered {
		return errors.New("secretsgcp: sandbox no longer belongs to the subject's session")
	}
	return nil
}

// RevokeSubject deletes a user's at-rest material, making it unrecoverable. Destroying the
// secret destroys the only copy of the per-user wrapped DEK, so the sealed token is
// crypto-shredded; the KEK is left untouched (it wraps every other user's DEK).
//
// SCOPE: this reaches the at-rest copy only. A token already injected into a live sandbox is
// reaped by tearing the sandbox down (the CloudProvider's job), not here. The tombstone is
// process-local — a single-replica simplification; durable cross-replica offboarding is the
// upstream SCIM/identity control (docs/THREAT-MODEL.md §4).
func (p *Provider) RevokeSubject(ctx context.Context, subject interfaces.Subject) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// Tombstone before the destroy so a concurrent store checking the tombstone refuses rather
	// than racing the delete to resurrect material.
	p.mu.Lock()
	p.revoked[subject] = true
	for ref, l := range p.leases {
		if l.subject == subject {
			delete(p.leases, ref)
		}
	}
	p.mu.Unlock()

	return p.store.Destroy(ctx, p.secretID(subject))
}

func (p *Provider) isRevoked(subject interfaces.Subject) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.revoked[subject]
}
