package devkit

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"sync"
	"time"

	"github.com/console7/console7/sdk/interfaces"
)

// MemSecrets is an in-memory, NON-PRODUCTION SecretsProvider. It realises the per-user
// envelope-encryption, no-operator-read, and no-pooling invariants with stdlib crypto
// so a bench exercises the real contract shape rather than a stub.
//
// Key hierarchy (modelling Cloud KMS + per-user CMK):
//
//	rootKey (KEK)  — one random 32-byte key, the "KMS root". Never leaves this struct.
//	per-user DEK   — a fresh random 32-byte data-encryption key minted PER SUBJECT,
//	                 stored only in KEK-wrapped form (no shared/multi-user key exists,
//	                 so pooling is impossible by construction, not by a runtime check).
//	sealed token   — the subscription token, AES-256-GCM-sealed under that user's DEK.
//
// SECURITY: there is deliberately NO exported method that returns plaintext credential
// material. MintEphemeral returns an opaque CredentialRef; InjectSubscriptionToken
// delivers plaintext only into the owning sandbox and returns nil. That absence IS the
// "no standing operator read path" invariant (DESIGN.md §2.2). This is not a real KMS
// boundary — see package doc; the cryptographic boundary is Phase-1+.
type MemSecrets struct {
	mu         sync.Mutex
	rootKey    []byte                            // KEK; random per process.
	wrappedDEK map[interfaces.Subject][]byte     // per-user DEK, sealed under rootKey.
	sealed     map[interfaces.Subject]sealedBlob // subscription token, sealed under the user's DEK.
	revoked    map[interfaces.Subject]bool       // tombstones: a store after revoke must refuse.
	leases     map[string]lease                  // ephemeral credential leases by Ref.
	orgSealed  sealedBlob                        // adopter ORG API credential, sealed under rootKey (org-wide; nil = unconfigured ⇒ inject fails closed).
	sandboxes  *SandboxRegistry                  // ownership oracle for injection.
	now        func() time.Time                  // injectable clock; defaults to time.Now.
}

// sealedBlob is nonce||ciphertext from an AES-GCM seal. It carries no key.
type sealedBlob []byte

type lease struct {
	subject interfaces.Subject
	session interfaces.SessionID
	scopes  []string
	expiry  time.Time
}

// Compile-time assertion that MemSecrets satisfies the seam.
var _ interfaces.SecretsProvider = (*MemSecrets)(nil)

// NewMemSecrets returns a MemSecrets with a freshly-generated random root key. The
// sandboxes registry is the ownership oracle InjectSubscriptionToken checks; it must be
// the same registry used to Provision the sandboxes tokens are injected into.
func NewMemSecrets(sandboxes *SandboxRegistry) *MemSecrets {
	kek := make([]byte, 32)
	if _, err := rand.Read(kek); err != nil {
		panic("devkit: crypto/rand failed generating root key: " + err.Error())
	}
	return &MemSecrets{
		rootKey:    kek,
		wrappedDEK: make(map[interfaces.Subject][]byte),
		sealed:     make(map[interfaces.Subject]sealedBlob),
		revoked:    make(map[interfaces.Subject]bool),
		leases:     make(map[string]lease),
		sandboxes:  sandboxes,
		now:        time.Now,
	}
}

// MintEphemeral issues a short-lived, session-scoped credential lease and returns an
// opaque, expiring reference — never the material.
func (m *MemSecrets) MintEphemeral(ctx context.Context, req interfaces.EphemeralRequest) (interfaces.CredentialRef, error) {
	if err := ctx.Err(); err != nil {
		return interfaces.CredentialRef{}, err
	}
	// The credential is keyed per-subject (so RevokeSubject can reach it) and anchors
	// lineage to the session; refuse to mint an unattributable one.
	if req.Subject == "" || req.SessionID == "" {
		return interfaces.CredentialRef{}, errors.New("devkit: MintEphemeral requires a subject and session for lineage")
	}
	if req.TTL <= 0 {
		return interfaces.CredentialRef{}, errors.New("devkit: MintEphemeral requires a positive TTL")
	}
	now := m.now()
	// A zero or already-past SessionDeadline gives no hard cap; refuse rather than mint
	// material that could outlive the session (the credential MUST die with the session).
	if req.SessionDeadline.IsZero() || !req.SessionDeadline.After(now) {
		return interfaces.CredentialRef{}, errors.New("devkit: MintEphemeral requires a SessionDeadline in the future")
	}
	// Cap expiry to the earlier of now+TTL and the absolute session deadline.
	expiry := now.Add(req.TTL)
	if req.SessionDeadline.Before(expiry) {
		expiry = req.SessionDeadline
	}

	// Scope is captured exactly as requested and never widened. A defensive copy stops a
	// caller mutating the slice it shares with us after the fact.
	scopes := append([]string(nil), req.Scopes...)

	m.mu.Lock()
	defer m.mu.Unlock()
	ref := "lease-" + randHex(12) // opaque; carries no material and no scope.
	m.leases[ref] = lease{subject: req.Subject, session: req.SessionID, scopes: scopes, expiry: expiry}
	return interfaces.CredentialRef{Ref: ref, Expiry: expiry}, nil
}

// SetOrgCredential configures the adopter's shared ORG API credential (the org-API-lane
// ANTHROPIC_API_KEY), sealing it under the root key. It is provider CONFIGURATION supplied
// out-of-band at wiring time (modelling the real provider reading it from the secrets manager) — it
// is deliberately NOT on the SecretsProvider seam, so the control plane never carries the plaintext
// through the seam. An empty key clears it (injection then fails closed).
func (m *MemSecrets) SetOrgCredential(key []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(key) == 0 {
		m.orgSealed = nil
		return nil
	}
	sealed, err := seal(m.rootKey, key)
	if err != nil {
		return err
	}
	m.orgSealed = sealed
	return nil
}

// InjectOrgCredential delivers the configured org API credential ONLY into the session's own
// sandbox. It returns nil on success and never the plaintext; it fails CLOSED if no org credential
// is configured (rather than run the engine unauthenticated). There is no attended/beneficiary gate
// — the org credential backs any org-API-lane session (GOAL.md tenet 2).
func (m *MemSecrets) InjectOrgCredential(ctx context.Context, in interfaces.OrgCredentialInjection) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// Ownership gate (cheap fail-fast before the decrypt): the sandbox must belong to this subject's
	// session. The authoritative check is re-done atomically with delivery below.
	if !m.sandboxes.Owns(in.Sandbox, in.Subject, in.SessionID) {
		return errors.New("devkit: sandbox does not belong to the subject's session")
	}
	m.mu.Lock()
	sealed := m.orgSealed
	m.mu.Unlock()
	// NOTE (dev-double only): the snapshot is read under the lock then released, so a concurrent
	// SetOrgCredential(nil) racing this deliver could still deliver a just-cleared credential. This is
	// a benign CONFIG race for a non-production double — NOT the load-bearing per-subject revocation
	// guarantee (org-credential rotation is org-wide and out-of-band; see SetOrgCredential).
	if sealed == nil {
		return errors.New("devkit: no org credential configured (the org-API lane requires SetOrgCredential)")
	}
	key, err := open(m.rootKey, sealed)
	if err != nil {
		return err
	}
	defer zero(key)
	// Deliver only into the verified owning sandbox, re-checking ownership ATOMICALLY with delivery
	// so a concurrent Destroy cannot let the credential land in a torn-down sandbox.
	if !m.sandboxes.DeliverIfOwned(in.Sandbox, in.Subject, in.SessionID, key) {
		return errors.New("devkit: sandbox no longer belongs to the subject's session")
	}
	return nil
}

// InjectInferenceCredential MINTS a short-lived (fake) inference credential and delivers it ONLY
// into the session's own sandbox, modelling the production workload-identity token mint for the
// in-tenancy backend (Vertex). It mints nothing the control plane sees, caps to the session
// deadline, and fails closed on a missing/past deadline, a revoked subject, or a non-owning sandbox.
func (m *MemSecrets) InjectInferenceCredential(ctx context.Context, in interfaces.InferenceCredentialInjection) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if in.SessionDeadline.IsZero() || !in.SessionDeadline.After(m.now()) {
		return errors.New("devkit: InjectInferenceCredential requires a SessionDeadline in the future")
	}
	m.mu.Lock()
	revoked := m.revoked[in.Subject]
	m.mu.Unlock()
	if revoked {
		return errors.New("devkit: refusing inference-credential injection for a revoked subject")
	}
	// Ownership gate (cheap fail-fast); the authoritative re-check is DeliverIfOwned below.
	if !m.sandboxes.Owns(in.Sandbox, in.Subject, in.SessionID) {
		return errors.New("devkit: sandbox does not belong to the subject's session")
	}
	// The "mint": a deterministic non-empty fake bearer. A real provider mints this from the
	// adopter's identity platform; the control plane never sees it either way.
	token := []byte("devkit-fake-inference-token")
	defer zero(token)
	// Deliver to the session's AUTH-PROXY gateway, NOT the sandbox: the inference credential reaches the
	// auth-proxy the engine talks to Vertex through, so the sandbox stays credential-free.
	if !m.sandboxes.DeliverInferenceIfOwned(in.Sandbox, in.Subject, in.SessionID, token) {
		return errors.New("devkit: sandbox no longer belongs to the subject's session")
	}
	return nil
}

// StoreSubscriptionToken seals a user's subscription token under that user's own DEK and
// persists only the ciphertext. The plaintext exists transiently inside this call and is
// zeroed before return; it never reaches the control plane.
func (m *MemSecrets) StoreSubscriptionToken(ctx context.Context, tok interfaces.SubscriptionToken) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if tok.Subject == "" {
		return errors.New("devkit: StoreSubscriptionToken requires a Subject")
	}
	if len(tok.Token) == 0 {
		return errors.New("devkit: StoreSubscriptionToken requires non-empty token material")
	}

	// Fresh per-user DEK on every store: a re-login replaces the prior token, and there
	// is never a key shared across subjects.
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return errors.New("devkit: crypto/rand failed minting DEK")
	}
	defer zero(dek)

	sealedTok, err := seal(dek, tok.Token)
	if err != nil {
		return err
	}
	wrapped, err := seal(m.rootKey, dek) // DEK wrapped under the KEK.
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	// Refuse a store for a revoked subject. The check and the write happen under the same
	// lock the revoke uses, so a concurrent RevokeSubject cannot interleave to leave fresh
	// recoverable material behind after revocation (the post-revoke unrecoverability
	// contract holds under an offboarding/login race).
	if m.revoked[tok.Subject] {
		return errors.New("devkit: refusing to store a token for a revoked subject")
	}
	m.wrappedDEK[tok.Subject] = wrapped
	m.sealed[tok.Subject] = sealedTok
	return nil
}

// InjectSubscriptionToken decrypts a user's token and delivers it ONLY into that user's
// own attended sandbox. It returns nil on success and never the plaintext.
func (m *MemSecrets) InjectSubscriptionToken(ctx context.Context, in interfaces.SubscriptionInjection) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// Policy gate first (cheapest, and the load-bearing attended/single-beneficiary
	// invariant): a subscription token backs only an attended, single-beneficiary session.
	if !in.Attended {
		return errors.New("devkit: refusing subscription injection into an unattended session")
	}
	if in.Beneficiaries != 1 {
		return errors.New("devkit: refusing subscription injection for a multi-beneficiary session")
	}
	// Ownership gate (cheap fail-fast before the decrypt): the sandbox must belong to this
	// subject's session. An unknown, mismatched, or expired handle fails closed. The
	// authoritative check is re-done atomically with delivery below.
	if !m.sandboxes.Owns(in.Sandbox, in.Subject, in.SessionID) {
		return errors.New("devkit: sandbox does not belong to the subject's session")
	}

	m.mu.Lock()
	wrapped, okDEK := m.wrappedDEK[in.Subject]
	sealedTok, okTok := m.sealed[in.Subject]
	m.mu.Unlock()
	if !okDEK || !okTok {
		return errors.New("devkit: no stored subscription token for subject (revoked or never stored)")
	}

	dek, err := open(m.rootKey, wrapped)
	if err != nil {
		return err
	}
	defer zero(dek)
	token, err := open(dek, sealedTok)
	if err != nil {
		return err
	}
	defer zero(token)

	// Deliver only into the verified owning sandbox, re-checking ownership ATOMICALLY with
	// the delivery so a concurrent Destroy cannot let the token land in a sandbox that was
	// torn down after the gate above. The plaintext never leaves this call by any other path.
	if !m.sandboxes.DeliverIfOwned(in.Sandbox, in.Subject, in.SessionID, token) {
		return errors.New("devkit: sandbox no longer belongs to the subject's session")
	}
	return nil
}

// RevokeSubject deletes a user's stored AT-REST material, making it unrecoverable. With
// the DEK gone the sealed token is crypto-shredded; no readable copy is retained for
// "audit".
//
// SCOPE: this reaches the at-rest copy only. A token already injected into a live sandbox
// resides in that sandbox's address space (modelled here by SandboxRegistry.injected) and
// is NOT reached by revocation — killing a live token requires tearing the sandbox down,
// which is the CloudProvider's job (Phase 1). See docs/THREAT-MODEL.md §4 residual risk.
func (m *MemSecrets) RevokeSubject(ctx context.Context, subject interfaces.Subject) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.wrappedDEK, subject)
	delete(m.sealed, subject)
	// Tombstone the subject so an in-flight StoreSubscriptionToken that seals outside the
	// lock cannot resurrect material after this revocation commits.
	m.revoked[subject] = true
	for ref, l := range m.leases {
		if l.subject == subject {
			delete(m.leases, ref)
		}
	}
	return nil
}

// --- stdlib AES-256-GCM envelope helpers ---

// seal returns nonce||ciphertext for plaintext under key using AES-256-GCM. The nonce is
// random per call (GCM is catastrophic under nonce reuse).
func seal(key, plaintext []byte) (sealedBlob, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, errors.New("devkit: crypto/rand failed generating nonce")
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// open reverses seal: it splits nonce||ciphertext and authenticates+decrypts.
func open(key []byte, blob sealedBlob) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(blob) < ns {
		return nil, errors.New("devkit: sealed blob too short")
	}
	nonce, ct := blob[:ns], blob[ns:]
	return gcm.Open(nil, nonce, ct, nil)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key) // 32-byte key => AES-256.
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// zero overwrites a byte slice in place — best-effort hygiene for transient plaintext.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
