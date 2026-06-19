package devkit

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/console7/console7/sdk/interfaces"
)

func newDevIdentity(t *testing.T, groups map[interfaces.Subject][]interfaces.Group) (*DevIdentity, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return NewDevIdentity(pub, groups), priv
}

func TestDevIdentity_Authenticate_AcceptsValidAssertion(t *testing.T) {
	id, priv := newDevIdentity(t, nil)
	tok := IssueDevAssertion(priv, "alice", time.Now().Add(time.Hour))
	got, err := id.Authenticate(context.Background(), tok)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if got != "alice" {
		t.Errorf("subject = %q, want alice", got)
	}
}

func TestDevIdentity_Authenticate_RejectsForgedOrTampered(t *testing.T) {
	id, priv := newDevIdentity(t, nil)
	// A token signed by a DIFFERENT key (an attacker's) must not verify.
	_, attacker, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	forged := IssueDevAssertion(attacker, "alice", time.Now().Add(time.Hour))
	if _, err := id.Authenticate(context.Background(), forged); err == nil {
		t.Error("forged assertion accepted — client-asserted identity was trusted without verification")
	}

	// A token whose claimed subject is swapped after signing must not verify.
	valid := string(IssueDevAssertion(priv, "alice", time.Now().Add(time.Hour)))
	tampered := interfaces.AuthnToken("mallory" + valid[len("alice"):])
	if _, err := id.Authenticate(context.Background(), tampered); err == nil {
		t.Error("tampered subject accepted — signature did not bind the subject")
	}
}

func TestDevIdentity_Authenticate_RejectsExpiredAndMalformed(t *testing.T) {
	id, priv := newDevIdentity(t, nil)
	expired := IssueDevAssertion(priv, "alice", time.Now().Add(-time.Minute))
	if _, err := id.Authenticate(context.Background(), expired); err == nil {
		t.Error("expired assertion accepted")
	}
	for _, bad := range []interfaces.AuthnToken{"", "no-delimiters", "a|b", "a|b|c|d"} {
		if _, err := id.Authenticate(context.Background(), bad); err == nil {
			t.Errorf("malformed token %q accepted", bad)
		}
	}
}

func TestDevIdentity_ResolveGroups_FromAuthoritativeStore(t *testing.T) {
	id, _ := newDevIdentity(t, map[interfaces.Subject][]interfaces.Group{
		"alice": {"eng", "release"},
	})
	got, err := id.ResolveGroups(context.Background(), "alice")
	if err != nil {
		t.Fatalf("ResolveGroups: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("groups = %v, want 2", got)
	}
	// A subject with no entry gets no groups — it cannot self-assert membership.
	if g, _ := id.ResolveGroups(context.Background(), "mallory"); len(g) != 0 {
		t.Errorf("unknown subject got groups %v, want none", g)
	}
}
