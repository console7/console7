package devkit

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/console7/console7/sdk/interfaces"
)

// These are white-box (package devkit) tests so they can inspect the sealed store and
// prove the at-rest invariants — there is deliberately no exported read path.

func TestMemSecrets_MintEphemeral_CapsExpiryToDeadline(t *testing.T) {
	reg := NewSandboxRegistry()
	m := NewMemSecrets(reg)
	now := time.Date(2026, 6, 19, 12, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return now }

	deadline := now.Add(2 * time.Minute)
	ref, err := m.MintEphemeral(context.Background(), interfaces.EphemeralRequest{
		SessionID:       "s1",
		Subject:         "alice",
		Scopes:          []string{"repo:read"},
		TTL:             1 * time.Hour, // longer than the deadline.
		SessionDeadline: deadline,
	})
	if err != nil {
		t.Fatalf("MintEphemeral: %v", err)
	}
	if ref.Expiry.After(deadline) {
		t.Errorf("expiry %v exceeds session deadline %v", ref.Expiry, deadline)
	}
	if !ref.Expiry.Equal(deadline) {
		t.Errorf("expiry should be capped to the deadline, got %v want %v", ref.Expiry, deadline)
	}
	if ref.Ref == "" {
		t.Error("CredentialRef.Ref must be set")
	}
}

func TestMemSecrets_MintEphemeral_CapsExpiryToTTL(t *testing.T) {
	reg := NewSandboxRegistry()
	m := NewMemSecrets(reg)
	now := time.Date(2026, 6, 19, 12, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return now }

	ttl := 5 * time.Minute
	ref, err := m.MintEphemeral(context.Background(), interfaces.EphemeralRequest{
		SessionID:       "s1",
		Subject:         "alice",
		TTL:             ttl,
		SessionDeadline: now.Add(1 * time.Hour), // further out than TTL.
	})
	if err != nil {
		t.Fatalf("MintEphemeral: %v", err)
	}
	if want := now.Add(ttl); !ref.Expiry.Equal(want) {
		t.Errorf("expiry should be capped to now+TTL, got %v want %v", ref.Expiry, want)
	}
}

func TestMemSecrets_MintEphemeral_RejectsZeroOrPastDeadline(t *testing.T) {
	reg := NewSandboxRegistry()
	m := NewMemSecrets(reg)
	now := time.Date(2026, 6, 19, 12, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return now }

	cases := []struct {
		name     string
		deadline time.Time
	}{
		{"zero deadline", time.Time{}},
		{"past deadline", now.Add(-time.Second)},
		{"deadline == now", now},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := m.MintEphemeral(context.Background(), interfaces.EphemeralRequest{
				Subject:         "alice",
				TTL:             time.Minute,
				SessionDeadline: tc.deadline,
			}); err == nil {
				t.Error("expected error, got nil — must not mint material that can outlive the session")
			}
		})
	}
}

func TestMemSecrets_StoreSubscriptionToken_SealsAndNeverStoresPlaintext(t *testing.T) {
	reg := NewSandboxRegistry()
	m := NewMemSecrets(reg)
	plaintext := []byte("sk-subscription-oauth-token-DO-NOT-LEAK")

	if err := m.StoreSubscriptionToken(context.Background(), interfaces.SubscriptionToken{
		Subject: "alice",
		Token:   plaintext,
	}); err != nil {
		t.Fatalf("StoreSubscriptionToken: %v", err)
	}

	sealed, ok := m.sealed["alice"]
	if !ok {
		t.Fatal("token not stored")
	}
	if bytes.Contains(sealed, plaintext) {
		t.Error("sealed store contains the plaintext token — envelope encryption failed")
	}
	// The DEK must be stored only wrapped, and the wrapped form must not be the raw DEK.
	if _, ok := m.wrappedDEK["alice"]; !ok {
		t.Error("per-user wrapped DEK not stored")
	}
}

func TestMemSecrets_NoPooling_PerUserKeysDiffer(t *testing.T) {
	reg := NewSandboxRegistry()
	m := NewMemSecrets(reg)
	ctx := context.Background()
	token := []byte("same-bytes-different-users")

	if err := m.StoreSubscriptionToken(ctx, interfaces.SubscriptionToken{Subject: "alice", Token: token}); err != nil {
		t.Fatal(err)
	}
	if err := m.StoreSubscriptionToken(ctx, interfaces.SubscriptionToken{Subject: "bob", Token: token}); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(m.wrappedDEK["alice"], m.wrappedDEK["bob"]) {
		t.Error("two subjects share a wrapped DEK — keys are pooled")
	}
	// Identical plaintext under distinct per-user keys (and random nonces) must not
	// produce identical ciphertext.
	if bytes.Equal(m.sealed["alice"], m.sealed["bob"]) {
		t.Error("identical tokens sealed to identical ciphertext — keying is not per-user")
	}
}

func TestMemSecrets_Inject_Roundtrip_DeliversOnlyToOwner(t *testing.T) {
	reg := NewSandboxRegistry()
	m := NewMemSecrets(reg)
	ctx := context.Background()
	plaintext := []byte("alice-subscription-token")

	if err := m.StoreSubscriptionToken(ctx, interfaces.SubscriptionToken{Subject: "alice", Token: plaintext}); err != nil {
		t.Fatal(err)
	}
	aliceBox := reg.Provision("alice", "s1")
	bobBox := reg.Provision("bob", "s2")

	if err := m.InjectSubscriptionToken(ctx, interfaces.SubscriptionInjection{
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

func TestMemSecrets_InjectOrgCredential(t *testing.T) {
	reg := NewSandboxRegistry()
	m := NewMemSecrets(reg)
	ctx := context.Background()
	owned := reg.Provision("alice", "s1")
	other := reg.Provision("bob", "s2")

	// Unconfigured ⇒ fail CLOSED (never run the engine unauthenticated), and nothing is delivered.
	if err := m.InjectOrgCredential(ctx, interfaces.OrgCredentialInjection{Subject: "alice", SessionID: "s1", Sandbox: owned}); err == nil {
		t.Error("InjectOrgCredential should fail closed when no org credential is configured")
	}
	if _, ok := reg.Injected(owned); ok {
		t.Error("delivered an org credential despite none being configured")
	}

	orgKey := []byte("org-api-key")
	if err := m.SetOrgCredential(orgKey); err != nil {
		t.Fatalf("SetOrgCredential: %v", err)
	}

	// A non-owned sandbox is refused even once configured (no cross-session delivery).
	if err := m.InjectOrgCredential(ctx, interfaces.OrgCredentialInjection{Subject: "alice", SessionID: "s1", Sandbox: other}); err == nil {
		t.Error("InjectOrgCredential delivered into a non-owned sandbox")
	}
	if _, ok := reg.Injected(other); ok {
		t.Error("org credential leaked into a non-owner sandbox")
	}

	// The owning sandbox receives EXACTLY the configured org key.
	if err := m.InjectOrgCredential(ctx, interfaces.OrgCredentialInjection{Subject: "alice", SessionID: "s1", Sandbox: owned}); err != nil {
		t.Fatalf("InjectOrgCredential into owner: %v", err)
	}
	got, ok := reg.Injected(owned)
	if !ok || !bytes.Equal(got, orgKey) {
		t.Errorf("org credential not delivered to the owning sandbox: ok=%v got=%q", ok, got)
	}

	// Clearing it (empty key) restores fail-closed.
	if err := m.SetOrgCredential(nil); err != nil {
		t.Fatalf("SetOrgCredential(nil): %v", err)
	}
	fresh := reg.Provision("carol", "s3")
	if err := m.InjectOrgCredential(ctx, interfaces.OrgCredentialInjection{Subject: "carol", SessionID: "s3", Sandbox: fresh}); err == nil {
		t.Error("InjectOrgCredential should fail closed after the org credential is cleared")
	}
}

func TestMemSecrets_Inject_RefusesUnattendedOrFanoutOrNonOwner(t *testing.T) {
	reg := NewSandboxRegistry()
	m := NewMemSecrets(reg)
	ctx := context.Background()
	if err := m.StoreSubscriptionToken(ctx, interfaces.SubscriptionToken{Subject: "alice", Token: []byte("tok")}); err != nil {
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
			if err := m.InjectSubscriptionToken(ctx, tc.in); err == nil {
				t.Error("expected refusal, got nil")
			}
			if _, ok := reg.Injected(tc.in.Sandbox); ok {
				t.Error("material was delivered despite refusal")
			}
		})
	}
}

func TestMemSecrets_Revoke_MakesMaterialUnrecoverable(t *testing.T) {
	reg := NewSandboxRegistry()
	m := NewMemSecrets(reg)
	ctx := context.Background()
	if err := m.StoreSubscriptionToken(ctx, interfaces.SubscriptionToken{Subject: "alice", Token: []byte("tok")}); err != nil {
		t.Fatal(err)
	}
	if err := m.RevokeSubject(ctx, "alice"); err != nil {
		t.Fatalf("RevokeSubject: %v", err)
	}
	if _, ok := m.sealed["alice"]; ok {
		t.Error("sealed token retained after revocation")
	}
	if _, ok := m.wrappedDEK["alice"]; ok {
		t.Error("wrapped DEK retained after revocation")
	}
	box := reg.Provision("alice", "s1")
	if err := m.InjectSubscriptionToken(ctx, interfaces.SubscriptionInjection{
		Subject: "alice", SessionID: "s1", Sandbox: box, Attended: true, Beneficiaries: 1,
	}); err == nil {
		t.Error("injection succeeded after revocation — material was recoverable")
	}
}

func TestMemSecrets_Revoke_TombstonesFutureStores(t *testing.T) {
	reg := NewSandboxRegistry()
	m := NewMemSecrets(reg)
	ctx := context.Background()
	if err := m.RevokeSubject(ctx, "alice"); err != nil {
		t.Fatalf("RevokeSubject: %v", err)
	}
	// A store after revocation must be refused, so an in-flight store racing a revoke
	// cannot resurrect recoverable material once revocation has committed.
	if err := m.StoreSubscriptionToken(ctx, interfaces.SubscriptionToken{Subject: "alice", Token: []byte("tok")}); err == nil {
		t.Error("stored a token for a revoked subject — post-revoke unrecoverability violated")
	}
	if _, ok := m.sealed["alice"]; ok {
		t.Error("material present for a revoked subject after a store attempt")
	}
}
