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
	minter AccessTokenMinter
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
		kek:    kek,
		store:  store,
		inject: inject,
		// Fail-closed default: no access-token minter until one is wired (SetAccessTokenMinter or New),
		// so InjectInferenceCredential refuses rather than running the engine with no inference credential.
		minter:  denyMinter{},
		prefix:  prefix,
		now:     now,
		revoked: make(map[interfaces.Subject]bool),
		leases:  make(map[string]leaseRec),
	}
}

// SetInjector wires the data-plane Injector that the ownership check (Owns) and the atomic
// check-and-deliver (DeliverIfOwned) use to deliver credential material into a session's sandbox.
// It is the production wiring seam alongside NewWithPorts: New defaults to the fail-closed
// denyInjector, and the orchestrator — which holds BOTH this provider and the providers/cloud-gcp
// Provider (which satisfies Injector via Owns/DeliverIfOwned) — calls this to wire the real
// data-plane path without having to reconstruct via NewWithPorts. The write and every read of the
// inject port are guarded by p.mu (each Inject* method snapshots it via injector()), so calling
// this concurrently with an in-flight injection is data-race-safe; it is still intended for
// wiring time. A nil argument is ignored — the fail-closed default is kept — so a missing or
// fat-fingered wiring refuses injection rather than nil-panicking; it does NOT reset an
// already-wired injector to deny (GOAL.md tenet 2: the boundary wins, fail closed).
func (p *Provider) SetInjector(inject Injector) {
	if inject == nil {
		return
	}
	p.mu.Lock()
	p.inject = inject
	p.mu.Unlock()
}

// injector returns the currently wired Injector under p.mu, so a read never races a SetInjector
// write. Each Inject* method snapshots it ONCE and uses the snapshot for both the cheap fail-fast
// Owns and the authoritative DeliverIfOwned, so a wiring swap mid-method cannot make those two
// observe different injectors. Callers must not already hold p.mu (the lock is not reentrant).
func (p *Provider) injector() Injector {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.inject
}

// SetAccessTokenMinter wires the workload-identity token minter InjectInferenceCredential uses to
// mint a short-lived GCP bearer for the in-tenancy inference lane (Vertex). It mirrors SetInjector:
// New defaults to the fail-closed denyMinter, and the production constructor (or the orchestrator)
// wires the real IAM-Credentials adapter here. Guarded by p.mu and read via minter(); a nil argument
// is ignored (the fail-closed default / already-wired minter is kept). Intended for wiring time.
func (p *Provider) SetAccessTokenMinter(m AccessTokenMinter) {
	if m == nil {
		return
	}
	p.mu.Lock()
	p.minter = m
	p.mu.Unlock()
}

// accessTokenMinter returns the wired AccessTokenMinter under p.mu, so a read never races a
// SetAccessTokenMinter write (the same discipline as injector()).
func (p *Provider) accessTokenMinter() AccessTokenMinter {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.minter
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
	// Snapshot the wired Injector once under the lock so the fail-fast Owns and the authoritative
	// DeliverIfOwned below observe the SAME injector and neither read races a SetInjector wiring.
	inj := p.injector()
	// Ownership gate (cheap fail-fast before the decrypt): the sandbox must belong to this
	// subject's session. The authoritative check is re-done atomically with delivery below.
	if !inj.Owns(in.Sandbox, in.Subject, in.SessionID) {
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
		delivered = inj.DeliverIfOwned(in.Sandbox, in.Subject, in.SessionID, token)
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

// orgSecretID is the fixed Secret Manager id the adopter's shared ORG API credential is sealed
// under — org-wide, not per-subject. The same value is the AAD bound into the KMS wrap.
func (p *Provider) orgSecretID() string { return p.prefix + "-org" }

// SetOrgCredential seals the adopter's shared ORG API credential under a fresh DEK, wraps that DEK
// under the KMS KEK (AAD-bound to the org secret id), and persists only the ciphertext envelope. It
// is provider CONFIGURATION supplied out-of-band at wiring time (modelling the adopter loading their
// org key into the secrets manager) — NOT on the SecretsProvider seam, so the control plane never
// carries the plaintext through the seam. An empty key destroys it (injection then fails closed).
//
// ROTATION/REVOCATION is ORG-WIDE and out-of-band (this is one shared key, not per-subject — there
// is no per-subject tombstone like RevokeSubject): SetOrgCredential replaces it for every future
// session, and an empty key clears the lane for all. A copy already injected into a live sandbox is
// reaped only by tearing that sandbox down (the CloudProvider's job), exactly as for a subscription
// token. There is one org credential per provider instance (the fixed orgSecretID).
func (p *Provider) SetOrgCredential(ctx context.Context, key []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	sid := p.orgSecretID()
	if len(key) == 0 {
		return p.store.Destroy(ctx, sid)
	}
	aad := []byte(sid)
	dek, err := mintDEK()
	if err != nil {
		return err
	}
	defer zero(dek)
	sealedKey, err := seal(dek, key, aad)
	if err != nil {
		return err
	}
	wrapped, kekVersion, err := p.kek.WrapDEK(ctx, dek, aad)
	if err != nil {
		return err
	}
	_, err = p.store.Put(ctx, sid, payload{kekVersion: kekVersion, wrappedDEK: wrapped, sealedToken: sealedKey}.marshal())
	return err
}

// InjectOrgCredential decrypts the adopter's shared ORG API credential and delivers it ONLY into the
// session's own sandbox. It returns nil on success and never the plaintext; it fails CLOSED if no org
// credential is configured or on any decrypt/store error. There is no attended/beneficiary gate — the
// org credential backs any org-API-lane session (GOAL.md tenet 2).
func (p *Provider) InjectOrgCredential(ctx context.Context, in interfaces.OrgCredentialInjection) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// Snapshot the wired Injector once under the lock so the fail-fast Owns and the authoritative
	// DeliverIfOwned below observe the SAME injector and neither read races a SetInjector wiring.
	inj := p.injector()
	// Ownership gate (cheap fail-fast before the KMS round-trip): the sandbox must belong to this
	// subject's session. The authoritative check is re-done atomically with delivery below.
	if !inj.Owns(in.Sandbox, in.Subject, in.SessionID) {
		return errors.New("secretsgcp: sandbox does not belong to the subject's session")
	}
	sid := p.orgSecretID()
	aad := []byte(sid)
	blob, found, err := p.store.Get(ctx, sid)
	if err != nil {
		return err
	}
	if !found {
		return errors.New("secretsgcp: no org credential configured (the org-API lane requires SetOrgCredential)")
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
	key, err := open(dek, pl.sealedToken, aad)
	if err != nil {
		return err
	}
	defer zero(key)
	// Deliver only into the verified owning sandbox, re-checking ownership ATOMICALLY with delivery
	// (DeliverIfOwned closes the teardown race). The plaintext never leaves this call by any other path.
	if !inj.DeliverIfOwned(in.Sandbox, in.Subject, in.SessionID, key) {
		return errors.New("secretsgcp: sandbox no longer belongs to the subject's session")
	}
	return nil
}

// inferenceTokenMaxTTL caps a minted inference token's lifetime. IAM access tokens default to a 1h
// maximum; the provider additionally caps to the session deadline (whichever is sooner).
const inferenceTokenMaxTTL = time.Hour

// inferenceScopes is the least-privilege OAuth scope the minted GCP token carries for the in-tenancy
// inference lane. cloud-platform is the scope Vertex AI requires; the underlying IAM permission is
// constrained to aiplatform.endpoints.predict on the workload SA by deploy/gcp/modules/inference-vertex,
// so the scope grants no more than the SA's own bindings allow.
var inferenceScopes = []string{"https://www.googleapis.com/auth/cloud-platform"}

// InjectInferenceCredential mints a short-lived GCP access token (via the workload-identity minter)
// and delivers it ONLY into the session's own sandbox, for the in-tenancy inference lane (Vertex).
// It never stores the token and never returns it to the caller; both the mint and the delivery happen
// inside the provider. It fails CLOSED on a missing/zero/past deadline, a revoked subject, a mint
// error, an empty minted token, or a non-owning sandbox (the engine must not run unauthenticated).
func (p *Provider) InjectInferenceCredential(ctx context.Context, in interfaces.InferenceCredentialInjection) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	now := p.now()
	// Refuse to mint material that could outlive the session (ephemeral by default; tenet 5).
	if in.SessionDeadline.IsZero() || !in.SessionDeadline.After(now) {
		return errors.New("secretsgcp: InjectInferenceCredential requires a SessionDeadline in the future")
	}
	// Cap the requested lifetime to the earlier of the provider max and the absolute session deadline.
	lifetime := inferenceTokenMaxTTL
	if d := in.SessionDeadline.Sub(now); d < lifetime {
		lifetime = d
	}
	// Revocation backstop: refuse to mint for an offboarded subject. NOTE the deliberate divergence
	// from InjectOrgCredential (which has NO revocation gate): the org credential is a SHARED,
	// org-wide secret with no per-subject meaning (rotated out-of-band), whereas this token is minted
	// fresh and anchored to THIS subject's session — so gating it on the subject's tombstone is the
	// right offboarding backstop (consistent with MintEphemeral).
	if p.isRevoked(in.Subject) {
		return errors.New("secretsgcp: refusing inference-credential injection for a revoked subject")
	}
	// Snapshot the injector + minter once under the lock so neither read races a wiring swap and the
	// fail-fast Owns and the authoritative DeliverIfOwned observe the same injector.
	inj := p.injector()
	mint := p.accessTokenMinter()
	// Ownership fail-fast before the (remote) mint; the authoritative check is DeliverIfOwned below.
	if !inj.Owns(in.Sandbox, in.Subject, in.SessionID) {
		return errors.New("secretsgcp: sandbox does not belong to the subject's session")
	}
	token, expiry, err := mint.MintAccessToken(ctx, inferenceScopes, lifetime)
	if err != nil {
		return fmt.Errorf("secretsgcp: mint inference token: %w", err)
	}
	defer zero(token)
	if len(token) == 0 {
		return errors.New("secretsgcp: minter returned an empty inference token (fail closed)")
	}
	// Defence in depth: enforce the "MUST cap expiry" obligation PROVIDER-side rather than trusting
	// the adapter. A real mint ALWAYS reports a truthful, future expiry — so reject a token whose
	// reported expiry is missing/in the past (note: a nil protobuf ExpireTime decodes to the Unix
	// EPOCH, not Go's zero time, so check against `now`, not IsZero) OR that outlives the requested
	// lifetime (a bug or a compromised adapter). A small skew tolerates clock drift.
	if !expiry.After(now) || expiry.After(now.Add(lifetime+time.Minute)) {
		return errors.New("secretsgcp: minted inference token has an implausible expiry — missing, past, or longer-lived than requested (fail closed)")
	}
	// Deliver only into the verified owning session's AUTH-PROXY (NOT the sandbox), re-checking ownership
	// ATOMICALLY with delivery. The inference credential goes to the auth-proxy gateway the engine reaches
	// Vertex through, so the sandbox stays credential-free.
	if !inj.DeliverInferenceIfOwned(in.Sandbox, in.Subject, in.SessionID, token) {
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
