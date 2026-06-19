package signing

import (
	"crypto/ed25519"
	"testing"

	"github.com/console7/console7/sdk/interfaces"
)

func TestBindAndSign_LineageVerifies(t *testing.T) {
	ca := NewDevCA()
	binder := NewNHIBinder(ca)

	signer, err := binder.Bind("alice", "s1", interfaces.PersonaAuthor)
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if signer.NHI != "nhi/s1/author" {
		t.Errorf("NHI = %q, want nhi/s1/author", signer.NHI)
	}

	payload := []byte("commit-digest-abc123")
	sig := signer.Sign(payload)

	if err := Verify(ca.Root(), payload, sig); err != nil {
		t.Errorf("legitimate lineage failed to verify: %v", err)
	}
	// Lineage carries the human at its root.
	if sig.Subject != "alice" {
		t.Errorf("signature subject = %q, want alice", sig.Subject)
	}
}

func TestVerify_RejectsWrongPayload(t *testing.T) {
	ca := NewDevCA()
	signer, _ := NewNHIBinder(ca).Bind("alice", "s1", interfaces.PersonaAuthor)
	sig := signer.Sign([]byte("original"))
	if err := Verify(ca.Root(), []byte("tampered"), sig); err == nil {
		t.Error("verified a signature against a different payload")
	}
}

func TestVerify_RejectsUntrustedCARoot(t *testing.T) {
	ca := NewDevCA()
	signer, _ := NewNHIBinder(ca).Bind("alice", "s1", interfaces.PersonaAuthor)
	payload := []byte("commit")
	sig := signer.Sign(payload)

	// A verifier pinning a DIFFERENT CA root must reject the chain.
	otherRoot, _, _ := ed25519.GenerateKey(nil)
	if err := Verify(otherRoot, payload, sig); err == nil {
		t.Error("verified a certificate against an untrusted CA root")
	}
}

func TestVerify_RejectsForgedLineageClaim(t *testing.T) {
	ca := NewDevCA()
	signer, _ := NewNHIBinder(ca).Bind("alice", "s1", interfaces.PersonaAuthor)
	payload := []byte("commit")
	sig := signer.Sign(payload)

	// An attacker swaps the claimed Subject but cannot re-mint the CA-signed cert: the
	// lineage-consistency check (sig vs cert) must catch the mismatch.
	forged := sig
	forged.Subject = "mallory"
	if err := Verify(ca.Root(), payload, forged); err == nil {
		t.Error("verified a signature whose claimed subject differs from its certificate")
	}
}

func TestVerify_RejectsForgedSessionID(t *testing.T) {
	ca := NewDevCA()
	signer, _ := NewNHIBinder(ca).Bind("alice", "s1", interfaces.PersonaAuthor)
	payload := []byte("commit")
	sig := signer.Sign(payload)

	// The SessionID is not a directly-certified field; swapping it must still be caught,
	// because Verify requires the certified NHI to encode the claimed session.
	forged := sig
	forged.SessionID = "s9"
	if err := Verify(ca.Root(), payload, forged); err == nil {
		t.Error("verified a signature whose SessionID does not match the certified NHI")
	}
}

func TestBind_RejectsEmptySubjectOrSession(t *testing.T) {
	binder := NewNHIBinder(NewDevCA())
	if _, err := binder.Bind("", "s1", interfaces.PersonaAuthor); err == nil {
		t.Error("bound an NHI to an empty subject")
	}
	if _, err := binder.Bind("alice", "", interfaces.PersonaAuthor); err == nil {
		t.Error("bound an NHI without a session")
	}
}

func TestBind_RejectsUnknownPersona(t *testing.T) {
	binder := NewNHIBinder(NewDevCA())
	for _, p := range []interfaces.Persona{"actuate", "admin", "", "AUTHOR"} {
		if _, err := binder.Bind("alice", "s1", p); err == nil {
			t.Errorf("bound an NHI with unknown persona %q", p)
		}
	}
	// The two valid personas are accepted.
	for _, p := range []interfaces.Persona{interfaces.PersonaAuthor, interfaces.PersonaOperate} {
		if _, err := binder.Bind("alice", "s1", p); err != nil {
			t.Errorf("rejected valid persona %q: %v", p, err)
		}
	}
}

func TestVerify_RejectsMalformedKeyLengths(t *testing.T) {
	ca := NewDevCA()
	signer, _ := NewNHIBinder(ca).Bind("alice", "s1", interfaces.PersonaAuthor)
	payload := []byte("commit")
	sig := signer.Sign(payload)

	// A wrong-length CA root must error, not panic.
	if err := Verify(ed25519.PublicKey{1, 2, 3}, payload, sig); err == nil {
		t.Error("verified against a malformed CA root key")
	}
	// A wrong-length certificate public key must error, not panic.
	bad := sig
	bad.Cert.Pub = ed25519.PublicKey{1, 2, 3}
	if err := Verify(ca.Root(), payload, bad); err == nil {
		t.Error("verified a signature with a malformed certificate public key")
	}
}
