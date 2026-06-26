package secretsgcp

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/console7/console7/sdk/devkit"
	"github.com/console7/console7/sdk/interfaces"
)

// hookStore wraps InMemoryStore to inject deterministic races: onPut/onGet fire INSIDE the
// provider's Put/Get (before the delegate runs), and failDestroy forces Destroy to error.
// This lets a single-threaded test land a RevokeSubject at the exact interleave the Codex
// findings describe.
type hookStore struct {
	*InMemoryStore
	onPut       func()
	onGet       func()
	failDestroy bool
}

func (h *hookStore) Put(ctx context.Context, secretID string, payload []byte) (string, error) {
	if h.onPut != nil {
		h.onPut()
	}
	return h.InMemoryStore.Put(ctx, secretID, payload)
}

func (h *hookStore) Get(ctx context.Context, secretID string) ([]byte, bool, error) {
	if h.onGet != nil {
		h.onGet()
	}
	return h.InMemoryStore.Get(ctx, secretID)
}

func (h *hookStore) Destroy(ctx context.Context, secretID string) error {
	if h.failDestroy {
		return errors.New("induced Destroy failure")
	}
	return h.InMemoryStore.Destroy(ctx, secretID)
}

// White-box tests (package secretsgcp) so they can inspect the fake store's sealed payloads
// and prove the at-rest invariants — there is deliberately no exported read path on the
// provider. They mirror sdk/devkit/secrets_mem_test.go (the contract is identical) plus the
// GCP-specific concerns: KEK-version recording, fail-closed on a KMS error, AAD owner-binding,
// and re-login versioning. The fakes stand in for Cloud KMS + Secret Manager (no credentials).

var fixedNow = time.Date(2026, 6, 19, 12, 0, 0, 0, time.UTC)

func newTestProvider() (*Provider, *InMemoryKEK, *InMemoryStore, *devkit.SandboxRegistry) {
	reg := devkit.NewSandboxRegistry()
	kek := NewInMemoryKEK()
	store := NewInMemoryStore()
	p := NewWithPorts(kek, store, reg, "console7", func() time.Time { return fixedNow })
	return p, kek, store, reg
}

func TestMintEphemeral_CapsExpiryToDeadline(t *testing.T) {
	p, _, _, _ := newTestProvider()
	deadline := fixedNow.Add(2 * time.Minute)
	ref, err := p.MintEphemeral(context.Background(), interfaces.EphemeralRequest{
		SessionID:       "s1",
		Subject:         "alice",
		Scopes:          []string{"repo:read"},
		TTL:             1 * time.Hour, // longer than the deadline.
		SessionDeadline: deadline,
	})
	if err != nil {
		t.Fatalf("MintEphemeral: %v", err)
	}
	if !ref.Expiry.Equal(deadline) {
		t.Errorf("expiry should be capped to the deadline, got %v want %v", ref.Expiry, deadline)
	}
	if ref.Ref == "" {
		t.Error("CredentialRef.Ref must be set")
	}
}

func TestMintEphemeral_CapsExpiryToTTL(t *testing.T) {
	p, _, _, _ := newTestProvider()
	ttl := 5 * time.Minute
	ref, err := p.MintEphemeral(context.Background(), interfaces.EphemeralRequest{
		SessionID:       "s1",
		Subject:         "alice",
		TTL:             ttl,
		SessionDeadline: fixedNow.Add(1 * time.Hour), // further out than TTL.
	})
	if err != nil {
		t.Fatalf("MintEphemeral: %v", err)
	}
	if want := fixedNow.Add(ttl); !ref.Expiry.Equal(want) {
		t.Errorf("expiry should be capped to now+TTL, got %v want %v", ref.Expiry, want)
	}
}

func TestMintEphemeral_RejectsZeroOrPastDeadline(t *testing.T) {
	p, _, _, _ := newTestProvider()
	cases := []struct {
		name     string
		deadline time.Time
	}{
		{"zero deadline", time.Time{}},
		{"past deadline", fixedNow.Add(-time.Second)},
		{"deadline == now", fixedNow},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := p.MintEphemeral(context.Background(), interfaces.EphemeralRequest{
				Subject:         "alice",
				SessionID:       "s1",
				TTL:             time.Minute,
				SessionDeadline: tc.deadline,
			}); err == nil {
				t.Error("expected error, got nil — must not mint material that can outlive the session")
			}
		})
	}
}

func TestStoreSubscriptionToken_SealsAndNeverStoresPlaintext(t *testing.T) {
	p, _, store, _ := newTestProvider()
	plaintext := []byte("sk-subscription-oauth-token-DO-NOT-LEAK")

	if err := p.StoreSubscriptionToken(context.Background(), interfaces.SubscriptionToken{
		Subject: "alice",
		Token:   plaintext,
	}); err != nil {
		t.Fatalf("StoreSubscriptionToken: %v", err)
	}

	raw, ok := store.Stored(p.secretID("alice"))
	if !ok {
		t.Fatal("token not stored")
	}
	if bytes.Contains(raw, plaintext) {
		t.Error("stored payload contains the plaintext token — envelope encryption failed")
	}
	pl, err := unmarshalPayload(raw)
	if err != nil {
		t.Fatalf("stored payload does not parse: %v", err)
	}
	if len(pl.wrappedDEK) == 0 {
		t.Error("per-user wrapped DEK not stored")
	}
	if len(pl.sealedToken) == 0 {
		t.Error("sealed token not stored")
	}
}

func TestNoPooling_PerUserKeysDiffer(t *testing.T) {
	p, _, store, _ := newTestProvider()
	ctx := context.Background()
	token := []byte("same-bytes-different-users")

	if err := p.StoreSubscriptionToken(ctx, interfaces.SubscriptionToken{Subject: "alice", Token: token}); err != nil {
		t.Fatal(err)
	}
	if err := p.StoreSubscriptionToken(ctx, interfaces.SubscriptionToken{Subject: "bob", Token: token}); err != nil {
		t.Fatal(err)
	}
	aliceRaw, _ := store.Stored(p.secretID("alice"))
	bobRaw, _ := store.Stored(p.secretID("bob"))
	alice, err := unmarshalPayload(aliceRaw)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := unmarshalPayload(bobRaw)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(alice.wrappedDEK, bob.wrappedDEK) {
		t.Error("two subjects share a wrapped DEK — keys are pooled")
	}
	if bytes.Equal(alice.sealedToken, bob.sealedToken) {
		t.Error("identical tokens sealed to identical ciphertext — keying is not per-user")
	}
}

func TestInject_Roundtrip_DeliversOnlyToOwner(t *testing.T) {
	p, _, _, reg := newTestProvider()
	ctx := context.Background()
	plaintext := []byte("alice-subscription-token")

	if err := p.StoreSubscriptionToken(ctx, interfaces.SubscriptionToken{Subject: "alice", Token: plaintext}); err != nil {
		t.Fatal(err)
	}
	aliceBox := reg.Provision("alice", "s1")
	bobBox := reg.Provision("bob", "s2")

	if err := p.InjectSubscriptionToken(ctx, interfaces.SubscriptionInjection{
		Subject:       "alice",
		SessionID:     "s1",
		Sandbox:       aliceBox,
		Attended:      true,
		Beneficiaries: 1,
	}); err != nil {
		t.Fatalf("InjectSubscriptionToken: %v", err)
	}

	got, ok := reg.Injected(aliceBox)
	if !ok || !bytes.Equal(got, plaintext) {
		t.Errorf("token not delivered to owner's sandbox: ok=%v got=%q", ok, got)
	}
	if _, ok := reg.Injected(bobBox); ok {
		t.Error("token leaked into a non-owner sandbox")
	}
}

func TestInjectOrgCredential(t *testing.T) {
	p, _, store, reg := newTestProvider()
	ctx := context.Background()
	owned := reg.Provision("alice", "s1")
	other := reg.Provision("bob", "s2")

	// Unconfigured ⇒ fail CLOSED, nothing delivered.
	if err := p.InjectOrgCredential(ctx, interfaces.OrgCredentialInjection{Subject: "alice", SessionID: "s1", Sandbox: owned}); err == nil {
		t.Error("InjectOrgCredential should fail closed when no org credential is configured")
	}
	if _, ok := reg.Injected(owned); ok {
		t.Error("delivered an org credential despite none being configured")
	}

	orgKey := []byte("org-api-key")
	if err := p.SetOrgCredential(ctx, orgKey); err != nil {
		t.Fatalf("SetOrgCredential: %v", err)
	}
	// The org key is sealed at rest, never stored plaintext (same envelope as subscription tokens).
	if blob, found, _ := store.Get(ctx, p.orgSecretID()); !found || bytes.Contains(blob, orgKey) {
		t.Errorf("org credential not sealed at rest: found=%v plaintext-present=%v", found, bytes.Contains(blob, orgKey))
	}

	// A non-owned sandbox is refused even once configured (no cross-session delivery).
	if err := p.InjectOrgCredential(ctx, interfaces.OrgCredentialInjection{Subject: "alice", SessionID: "s1", Sandbox: other}); err == nil {
		t.Error("InjectOrgCredential delivered into a non-owned sandbox")
	}
	// The owning sandbox receives EXACTLY the configured org key.
	if err := p.InjectOrgCredential(ctx, interfaces.OrgCredentialInjection{Subject: "alice", SessionID: "s1", Sandbox: owned}); err != nil {
		t.Fatalf("InjectOrgCredential into owner: %v", err)
	}
	got, ok := reg.Injected(owned)
	if !ok || !bytes.Equal(got, orgKey) {
		t.Errorf("org credential not delivered to owner: ok=%v got=%q", ok, got)
	}

	// Clearing it (empty key ⇒ store.Destroy) restores fail-closed.
	if err := p.SetOrgCredential(ctx, nil); err != nil {
		t.Fatalf("SetOrgCredential(nil): %v", err)
	}
	fresh := reg.Provision("carol", "s3")
	if err := p.InjectOrgCredential(ctx, interfaces.OrgCredentialInjection{Subject: "carol", SessionID: "s3", Sandbox: fresh}); err == nil {
		t.Error("InjectOrgCredential should fail closed after the org credential is cleared")
	}
}

func TestInjectInferenceCredential(t *testing.T) {
	p, _, _, reg := newTestProvider()
	ctx := context.Background()
	owned := reg.Provision("alice", "s1")
	other := reg.Provision("bob", "s2")
	deadline := fixedNow.Add(30 * time.Minute)

	// Fail closed before a minter is wired (denyMinter): a valid owned+future request still refuses.
	if err := p.InjectInferenceCredential(ctx, interfaces.InferenceCredentialInjection{Subject: "alice", SessionID: "s1", Sandbox: owned, SessionDeadline: deadline}); err == nil {
		t.Error("expected fail-closed refusal with no minter wired")
	}
	if _, ok := reg.Injected(owned); ok {
		t.Error("delivered an inference credential with no minter wired")
	}

	minter := NewInMemoryAccessTokenMinter()
	minter.now = func() time.Time { return fixedNow } // share the provider's clock so the expiry-cap check compares like-for-like.
	p.SetAccessTokenMinter(minter)

	// Past / zero deadline is refused (never mint material that outlives the session).
	for _, dl := range []time.Time{{}, fixedNow.Add(-time.Second), fixedNow} {
		if err := p.InjectInferenceCredential(ctx, interfaces.InferenceCredentialInjection{Subject: "alice", SessionID: "s1", Sandbox: owned, SessionDeadline: dl}); err == nil {
			t.Errorf("expected refusal for non-future deadline %v", dl)
		}
	}
	// A non-owned sandbox is refused even with a valid deadline.
	if err := p.InjectInferenceCredential(ctx, interfaces.InferenceCredentialInjection{Subject: "alice", SessionID: "s1", Sandbox: other, SessionDeadline: deadline}); err == nil {
		t.Error("injected into a non-owned sandbox")
	}
	// The owning sandbox receives the minted token, and the requested lifetime is capped to the
	// deadline (30m < the 1h provider max).
	if err := p.InjectInferenceCredential(ctx, interfaces.InferenceCredentialInjection{Subject: "alice", SessionID: "s1", Sandbox: owned, SessionDeadline: deadline}); err != nil {
		t.Fatalf("InjectInferenceCredential into owner: %v", err)
	}
	// The inference credential is delivered to the session's AUTH-PROXY gateway, NOT the sandbox.
	got, ok := reg.InferenceInjected(owned)
	if !ok || !bytes.Equal(got, []byte("fake-gcp-access-token")) {
		t.Errorf("minted token not delivered to the owner's auth-proxy: ok=%v got=%q", ok, got)
	}
	// And it must NOT land in the sandbox's own credential slot (sandbox stays credential-free).
	if got, ok := reg.Injected(owned); ok {
		t.Errorf("inference credential wrongly delivered into the sandbox: got=%q", got)
	}
	if want := 30 * time.Minute; minter.LastLifetime() != want {
		t.Errorf("lifetime not capped to the deadline: got %v want %v", minter.LastLifetime(), want)
	}

	// A mint error fails closed (engine never runs unauthenticated).
	minter.SetFail(true)
	if err := p.InjectInferenceCredential(ctx, interfaces.InferenceCredentialInjection{Subject: "alice", SessionID: "s1", Sandbox: owned, SessionDeadline: deadline}); err == nil {
		t.Error("expected fail-closed on a mint error")
	}
	minter.SetFail(false)

	// An implausible reported expiry fails closed: the Unix epoch (what a nil protobuf ExpireTime
	// decodes to — NOT Go's zero time), and a far-future value that outlives the requested lifetime.
	for _, badExpiry := range []time.Time{time.Unix(0, 0), fixedNow.Add(2 * time.Hour)} {
		minter.SetExpiry(badExpiry)
		if err := p.InjectInferenceCredential(ctx, interfaces.InferenceCredentialInjection{Subject: "alice", SessionID: "s1", Sandbox: owned, SessionDeadline: deadline}); err == nil {
			t.Errorf("expected fail-closed on an implausible expiry %v", badExpiry)
		}
	}
	minter.useForceExpiry = false // back to the truthful now+lifetime expiry.

	// A revoked subject is refused (offboarding backstop), even with a wired minter + owned sandbox.
	if err := p.RevokeSubject(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	if err := p.InjectInferenceCredential(ctx, interfaces.InferenceCredentialInjection{Subject: "alice", SessionID: "s1", Sandbox: owned, SessionDeadline: deadline}); err == nil {
		t.Error("minted an inference credential for a revoked subject")
	}
}

func TestInject_RefusesUnattendedOrFanoutOrNonOwner(t *testing.T) {
	p, _, _, reg := newTestProvider()
	ctx := context.Background()
	if err := p.StoreSubscriptionToken(ctx, interfaces.SubscriptionToken{Subject: "alice", Token: []byte("tok")}); err != nil {
		t.Fatal(err)
	}
	aliceBox := reg.Provision("alice", "s1")
	malloryBox := reg.Provision("mallory", "s9")

	cases := []struct {
		name string
		in   interfaces.SubscriptionInjection
	}{
		{"unattended", interfaces.SubscriptionInjection{Subject: "alice", SessionID: "s1", Sandbox: aliceBox, Attended: false, Beneficiaries: 1}},
		{"fan-out", interfaces.SubscriptionInjection{Subject: "alice", SessionID: "s1", Sandbox: aliceBox, Attended: true, Beneficiaries: 3}},
		{"zero beneficiaries", interfaces.SubscriptionInjection{Subject: "alice", SessionID: "s1", Sandbox: aliceBox, Attended: true, Beneficiaries: 0}},
		{"non-owner sandbox", interfaces.SubscriptionInjection{Subject: "alice", SessionID: "s1", Sandbox: malloryBox, Attended: true, Beneficiaries: 1}},
		{"mismatched session", interfaces.SubscriptionInjection{Subject: "alice", SessionID: "wrong", Sandbox: aliceBox, Attended: true, Beneficiaries: 1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := p.InjectSubscriptionToken(ctx, tc.in); err == nil {
				t.Error("expected refusal, got nil")
			}
			if _, ok := reg.Injected(tc.in.Sandbox); ok {
				t.Error("material was delivered despite refusal")
			}
		})
	}
}

func TestRevoke_MakesMaterialUnrecoverable(t *testing.T) {
	p, _, store, reg := newTestProvider()
	ctx := context.Background()
	if err := p.StoreSubscriptionToken(ctx, interfaces.SubscriptionToken{Subject: "alice", Token: []byte("tok")}); err != nil {
		t.Fatal(err)
	}
	if err := p.RevokeSubject(ctx, "alice"); err != nil {
		t.Fatalf("RevokeSubject: %v", err)
	}
	if _, ok := store.Stored(p.secretID("alice")); ok {
		t.Error("stored material retained after revocation")
	}
	box := reg.Provision("alice", "s1")
	if err := p.InjectSubscriptionToken(ctx, interfaces.SubscriptionInjection{
		Subject: "alice", SessionID: "s1", Sandbox: box, Attended: true, Beneficiaries: 1,
	}); err == nil {
		t.Error("injection succeeded after revocation — material was recoverable")
	}
}

func TestRevoke_TombstonesFutureStores(t *testing.T) {
	p, _, store, _ := newTestProvider()
	ctx := context.Background()
	if err := p.RevokeSubject(ctx, "alice"); err != nil {
		t.Fatalf("RevokeSubject: %v", err)
	}
	// A store after revocation must be refused, so an in-flight store racing a revoke cannot
	// resurrect recoverable material once revocation has committed.
	if err := p.StoreSubscriptionToken(ctx, interfaces.SubscriptionToken{Subject: "alice", Token: []byte("tok")}); err == nil {
		t.Error("stored a token for a revoked subject — post-revoke unrecoverability violated")
	}
	if _, ok := store.Stored(p.secretID("alice")); ok {
		t.Error("material present for a revoked subject after a store attempt")
	}
}

func TestMintEphemeral_RefusesRevokedSubject(t *testing.T) {
	p, _, _, _ := newTestProvider()
	ctx := context.Background()
	if err := p.RevokeSubject(ctx, "alice"); err != nil {
		t.Fatalf("RevokeSubject: %v", err)
	}
	// Offboarding (RevokeSubject) must stop new identity minting for that subject.
	if _, err := p.MintEphemeral(ctx, interfaces.EphemeralRequest{
		Subject:         "alice",
		SessionID:       "s1",
		TTL:             time.Minute,
		SessionDeadline: fixedNow.Add(time.Hour),
	}); err == nil {
		t.Error("MintEphemeral succeeded for a revoked subject — offboarding bypassed")
	}
}

func TestInject_RefusesRevokedSubjectEvenIfMaterialPresent(t *testing.T) {
	p, _, store, reg := newTestProvider()
	ctx := context.Background()
	if err := p.StoreSubscriptionToken(ctx, interfaces.SubscriptionToken{Subject: "alice", Token: []byte("tok")}); err != nil {
		t.Fatal(err)
	}
	// Revoke, then simulate a store/revoke race that left at-rest material behind by planting
	// the (pre-revoke) sealed payload back into the store. The injection backstop must still
	// refuse on the tombstone alone, regardless of the store's state.
	raw, _ := store.Stored(p.secretID("alice"))
	if err := p.RevokeSubject(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put(ctx, p.secretID("alice"), raw); err != nil {
		t.Fatal(err)
	}
	box := reg.Provision("alice", "s1")
	if err := p.InjectSubscriptionToken(ctx, interfaces.SubscriptionInjection{
		Subject: "alice", SessionID: "s1", Sandbox: box, Attended: true, Beneficiaries: 1,
	}); err == nil {
		t.Error("injection succeeded for a revoked subject despite the tombstone backstop")
	}
	if _, ok := reg.Injected(box); ok {
		t.Error("material delivered for a revoked subject")
	}
}

func TestInject_AtomicRevocationDuringInject(t *testing.T) {
	// A RevokeSubject that lands AFTER the early backstop check but while the token is being
	// fetched/decrypted must still block delivery — the final revocation check is atomic with
	// DeliverIfOwned under p.mu. We set the tombstone (without deleting the at-rest material)
	// from inside Get, so the payload is still readable yet the subject is revoked by the time
	// delivery is attempted.
	reg := devkit.NewSandboxRegistry()
	store := &hookStore{InMemoryStore: NewInMemoryStore()}
	p := NewWithPorts(NewInMemoryKEK(), store, reg, "console7", func() time.Time { return fixedNow })
	ctx := context.Background()
	if err := p.StoreSubscriptionToken(ctx, interfaces.SubscriptionToken{Subject: "alice", Token: []byte("tok")}); err != nil {
		t.Fatal(err)
	}
	box := reg.Provision("alice", "s1")
	store.onGet = func() { // mid-injection revoke: tombstone only, material left in place
		p.mu.Lock()
		p.revoked["alice"] = true
		p.mu.Unlock()
	}

	if err := p.InjectSubscriptionToken(ctx, interfaces.SubscriptionInjection{
		Subject: "alice", SessionID: "s1", Sandbox: box, Attended: true, Beneficiaries: 1,
	}); err == nil {
		t.Error("expected refusal when revocation races injection, got nil")
	}
	if _, ok := reg.Injected(box); ok {
		t.Error("token delivered despite a revocation that landed before delivery")
	}
}

func TestStore_CompensatingShredOnRevokeDuringStore(t *testing.T) {
	// A RevokeSubject that lands during the remote Put must not leave recoverable material:
	// the compensating shred deletes it and the store reports failure.
	reg := devkit.NewSandboxRegistry()
	store := &hookStore{InMemoryStore: NewInMemoryStore()}
	p := NewWithPorts(NewInMemoryKEK(), store, reg, "console7", func() time.Time { return fixedNow })
	ctx := context.Background()
	store.onPut = func() { _ = p.RevokeSubject(ctx, "alice") } // revoke commits during the Put

	err := p.StoreSubscriptionToken(ctx, interfaces.SubscriptionToken{Subject: "alice", Token: []byte("tok")})
	if err == nil {
		t.Error("expected an error when revocation races the store, got nil")
	}
	if _, ok := store.Stored(p.secretID("alice")); ok {
		t.Error("material remained after a revoke-during-store — compensating shred did not run")
	}
}

func TestStore_CompensatingShredFailureSurfaced(t *testing.T) {
	// If the compensating shred itself fails, the store MUST NOT report a clean shred — the
	// material may remain, and the caller has to know.
	reg := devkit.NewSandboxRegistry()
	store := &hookStore{InMemoryStore: NewInMemoryStore(), failDestroy: true}
	p := NewWithPorts(NewInMemoryKEK(), store, reg, "console7", func() time.Time { return fixedNow })
	ctx := context.Background()
	store.onPut = func() {
		// Set the tombstone directly (RevokeSubject would also hit the failing Destroy); this
		// isolates the store's own compensating-delete failure path.
		p.mu.Lock()
		p.revoked["alice"] = true
		p.mu.Unlock()
	}

	err := p.StoreSubscriptionToken(ctx, interfaces.SubscriptionToken{Subject: "alice", Token: []byte("tok")})
	if err == nil {
		t.Fatal("expected an error when the compensating delete fails, got nil")
	}
	if !strings.Contains(err.Error(), "may remain") {
		t.Errorf("error must surface that material may remain, got: %v", err)
	}
}

func TestNewWithPorts_NilInjectorFailsClosed(t *testing.T) {
	kek := NewInMemoryKEK()
	store := NewInMemoryStore()
	p := NewWithPorts(kek, store, nil, "console7", nil) // nil Injector must default fail-closed.
	ctx := context.Background()
	if err := p.StoreSubscriptionToken(ctx, interfaces.SubscriptionToken{Subject: "alice", Token: []byte("tok")}); err != nil {
		t.Fatal(err)
	}
	// A nil Injector must become denyInjector, so injection refuses rather than nil-panicking.
	if err := p.InjectSubscriptionToken(ctx, interfaces.SubscriptionInjection{
		Subject: "alice", SessionID: "s1", Sandbox: interfaces.SandboxHandle{ID: "x"}, Attended: true, Beneficiaries: 1,
	}); err == nil {
		t.Error("expected refusal with a nil (fail-closed) Injector, got nil")
	}
}

// TestSetInjector_WiresRealDeliveryAndStaysFailClosed proves the production wiring seam: a Provider
// built fail-closed (denyInjector) refuses delivery, SetInjector swaps in a real Injector so the
// owning sandbox receives the credential, a non-owned sandbox is still refused, and SetInjector(nil)
// is ignored (the wired injector is kept, never silently reverted to fail-open).
func TestSetInjector_WiresRealDeliveryAndStaysFailClosed(t *testing.T) {
	kek := NewInMemoryKEK()
	store := NewInMemoryStore()
	p := NewWithPorts(kek, store, nil, "console7", func() time.Time { return fixedNow }) // fail-closed default.
	ctx := context.Background()

	orgKey := []byte("org-api-key")
	if err := p.SetOrgCredential(ctx, orgKey); err != nil {
		t.Fatalf("SetOrgCredential: %v", err)
	}

	reg := devkit.NewSandboxRegistry()
	owned := reg.Provision("alice", "s1")
	other := reg.Provision("bob", "s2")

	// Before wiring, delivery into the owning sandbox is refused (denyInjector owns nothing).
	if err := p.InjectOrgCredential(ctx, interfaces.OrgCredentialInjection{Subject: "alice", SessionID: "s1", Sandbox: owned}); err == nil {
		t.Error("expected fail-closed refusal before SetInjector, got nil")
	}
	if _, ok := reg.Injected(owned); ok {
		t.Error("delivered before an Injector was wired")
	}

	// Wire the real Injector.
	p.SetInjector(reg)

	// A non-owned sandbox is still refused (no cross-session delivery).
	if err := p.InjectOrgCredential(ctx, interfaces.OrgCredentialInjection{Subject: "alice", SessionID: "s1", Sandbox: other}); err == nil {
		t.Error("delivered into a non-owned sandbox after SetInjector")
	}
	// The owning sandbox now receives exactly the configured org key.
	if err := p.InjectOrgCredential(ctx, interfaces.OrgCredentialInjection{Subject: "alice", SessionID: "s1", Sandbox: owned}); err != nil {
		t.Fatalf("InjectOrgCredential into owner after SetInjector: %v", err)
	}
	got, ok := reg.Injected(owned)
	if !ok || !bytes.Equal(got, orgKey) {
		t.Errorf("org credential not delivered to owner: ok=%v got=%q", ok, got)
	}

	// SetInjector(nil) is ignored: the wired injector is kept, not reverted to fail-open.
	p.SetInjector(nil)
	fresh := reg.Provision("carol", "s3")
	if err := p.SetOrgCredential(ctx, orgKey); err != nil {
		t.Fatalf("SetOrgCredential(carol): %v", err)
	}
	if err := p.InjectOrgCredential(ctx, interfaces.OrgCredentialInjection{Subject: "carol", SessionID: "s3", Sandbox: fresh}); err != nil {
		t.Errorf("SetInjector(nil) wrongly dropped the wired injector: %v", err)
	}
}

// TestSetInjector_NoRaceWithConcurrentInject exercises SetInjector concurrently with in-flight
// injections so `go test -race` flags any unsynchronized read of p.inject. Each Inject* method
// snapshots the injector under p.mu, so this must be clean. It does not assert delivery outcome
// (the swap is racing on purpose); the race detector is the assertion.
func TestSetInjector_NoRaceWithConcurrentInject(t *testing.T) {
	kek := NewInMemoryKEK()
	store := NewInMemoryStore()
	p := NewWithPorts(kek, store, devkit.NewSandboxRegistry(), "console7", func() time.Time { return fixedNow })
	ctx := context.Background()
	if err := p.SetOrgCredential(ctx, []byte("org-api-key")); err != nil {
		t.Fatalf("SetOrgCredential: %v", err)
	}
	if err := p.StoreSubscriptionToken(ctx, interfaces.SubscriptionToken{Subject: "alice", Token: []byte("tok")}); err != nil {
		t.Fatalf("StoreSubscriptionToken: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(3)
		go func() { defer wg.Done(); p.SetInjector(devkit.NewSandboxRegistry()) }()
		go func() {
			defer wg.Done()
			_ = p.InjectOrgCredential(ctx, interfaces.OrgCredentialInjection{Subject: "alice", SessionID: "s1", Sandbox: interfaces.SandboxHandle{ID: "x"}})
		}()
		go func() {
			defer wg.Done()
			_ = p.InjectSubscriptionToken(ctx, interfaces.SubscriptionInjection{Subject: "alice", SessionID: "s1", Sandbox: interfaces.SandboxHandle{ID: "x"}, Attended: true, Beneficiaries: 1})
		}()
	}
	wg.Wait()
}

func TestStore_RecordsKEKVersion(t *testing.T) {
	p, kek, store, _ := newTestProvider()
	if err := p.StoreSubscriptionToken(context.Background(), interfaces.SubscriptionToken{Subject: "alice", Token: []byte("tok")}); err != nil {
		t.Fatal(err)
	}
	raw, _ := store.Stored(p.secretID("alice"))
	pl, err := unmarshalPayload(raw)
	if err != nil {
		t.Fatal(err)
	}
	if pl.kekVersion != kek.version {
		t.Errorf("payload recorded KEK version %q, want %q", pl.kekVersion, kek.version)
	}
}

func TestStore_ReloginAddsNewVersion(t *testing.T) {
	p, _, store, _ := newTestProvider()
	ctx := context.Background()
	sid := p.secretID("alice")
	if err := p.StoreSubscriptionToken(ctx, interfaces.SubscriptionToken{Subject: "alice", Token: []byte("tok-1")}); err != nil {
		t.Fatal(err)
	}
	if err := p.StoreSubscriptionToken(ctx, interfaces.SubscriptionToken{Subject: "alice", Token: []byte("tok-2")}); err != nil {
		t.Fatal(err)
	}
	if got := store.Versions(sid); got != 2 {
		t.Errorf("re-login should add a new version: got %d versions, want 2", got)
	}
}

func TestInject_FailsClosedOnKMSError(t *testing.T) {
	p, kek, _, reg := newTestProvider()
	ctx := context.Background()
	if err := p.StoreSubscriptionToken(ctx, interfaces.SubscriptionToken{Subject: "alice", Token: []byte("tok")}); err != nil {
		t.Fatal(err)
	}
	box := reg.Provision("alice", "s1")
	kek.SetFailUnwrap(true) // a KMS Decrypt failure must never result in delivery.

	if err := p.InjectSubscriptionToken(ctx, interfaces.SubscriptionInjection{
		Subject: "alice", SessionID: "s1", Sandbox: box, Attended: true, Beneficiaries: 1,
	}); err == nil {
		t.Error("expected error on KMS unwrap failure, got nil")
	}
	if _, ok := reg.Injected(box); ok {
		t.Error("material delivered despite a KMS unwrap failure — not fail-closed")
	}
}

func TestInject_AADBindingRejectsSwappedSecret(t *testing.T) {
	p, _, store, reg := newTestProvider()
	ctx := context.Background()
	// Store a token for alice, then plant alice's exact sealed payload under bob's secret ID.
	// The DEK was KMS-wrapped with AAD = alice's secret ID; unwrapping it under bob's secret ID
	// must fail authentication, so a confused/swapped secret cannot be opened for the wrong user.
	if err := p.StoreSubscriptionToken(ctx, interfaces.SubscriptionToken{Subject: "alice", Token: []byte("alice-tok")}); err != nil {
		t.Fatal(err)
	}
	aliceRaw, _ := store.Stored(p.secretID("alice"))
	if _, err := store.Put(ctx, p.secretID("bob"), aliceRaw); err != nil {
		t.Fatal(err)
	}
	bobBox := reg.Provision("bob", "s1")

	if err := p.InjectSubscriptionToken(ctx, interfaces.SubscriptionInjection{
		Subject: "bob", SessionID: "s1", Sandbox: bobBox, Attended: true, Beneficiaries: 1,
	}); err == nil {
		t.Error("expected AAD-binding failure injecting a swapped secret, got nil")
	}
	if _, ok := reg.Injected(bobBox); ok {
		t.Error("a swapped secret was delivered — AAD owner-binding not enforced")
	}
}

// hookMinter wraps InMemoryAccessTokenMinter to fire onMint INSIDE MintAccessToken (before it
// returns), so a single-threaded test can land a RevokeSubject during the remote-mint window the
// inference-injection TOCTOU lives in — mirroring hookStore for the subscription path.
type hookMinter struct {
	*InMemoryAccessTokenMinter
	onMint func()
}

func (h *hookMinter) MintAccessToken(ctx context.Context, scopes []string, lifetime time.Duration) ([]byte, time.Time, error) {
	if h.onMint != nil {
		h.onMint()
	}
	return h.InMemoryAccessTokenMinter.MintAccessToken(ctx, scopes, lifetime)
}

// TestInjectInferenceCredential_AtomicRevocationDuringMint proves the inference path re-checks the
// revocation tombstone ATOMICALLY with delivery: a RevokeSubject that commits DURING the remote mint
// (after the fast-fail check) must cause the delivery to be refused, so no bearer reaches an
// offboarded subject's session. Without the under-p.mu re-check this leaked a fresh token.
func TestInjectInferenceCredential_AtomicRevocationDuringMint(t *testing.T) {
	p, _, _, reg := newTestProvider()
	ctx := context.Background()
	owned := reg.Provision("alice", "s1")
	deadline := fixedNow.Add(30 * time.Minute)

	base := NewInMemoryAccessTokenMinter()
	base.now = func() time.Time { return fixedNow }
	hm := &hookMinter{InMemoryAccessTokenMinter: base, onMint: func() { _ = p.RevokeSubject(ctx, "alice") }}
	p.SetAccessTokenMinter(hm)

	err := p.InjectInferenceCredential(ctx, interfaces.InferenceCredentialInjection{
		Subject: "alice", SessionID: "s1", Sandbox: owned, SessionDeadline: deadline,
	})
	if err == nil || !strings.Contains(err.Error(), "revoked during injection") {
		t.Fatalf("expected refusal due to revocation during the mint window, got: %v", err)
	}
	if got, ok := reg.InferenceInjected(owned); ok {
		t.Errorf("inference credential delivered to a subject revoked during injection: got=%q", got)
	}
}
