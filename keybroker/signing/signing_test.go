package signing

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/console7/console7/sdk/interfaces"
)

// ecdsaCA is an in-process EC-P256 CA root (the same shape the KMS-backed root will take: sign the
// SHA-256 digest of the TBS, return an ASN.1 DER ECDSA signature). It lets the EC-P256 dispatch in
// verifyRoot be proven end-to-end — Bind/NewSinkSigner through the real binder, then Verify under
// the *ecdsa.PublicKey anchor — with no GCP/KMS dependency.
type ecdsaCA struct{ priv *ecdsa.PrivateKey }

func (c ecdsaCA) Sign(tbs []byte) ([]byte, error) {
	h := sha256.Sum256(tbs)
	return ecdsa.SignASN1(rand.Reader, c.priv, h[:])
}

// TestVerify_ECDSAP256Root proves the pluggable-root design works for a NON-ed25519 (EC-P256) root:
// a lineage Cert and a sink cert issued under an EC root verify under the EC public-key anchor, fail
// under a different EC key, and a typed-nil EC anchor fails closed (no panic).
func TestVerify_ECDSAP256Root(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa keygen: %v", err)
	}
	ca := ecdsaCA{priv: priv}
	payload := []byte("payload")

	signer, err := NewNHIBinder(ca).Bind("alice", "s1", interfaces.PersonaAuthor)
	if err != nil {
		t.Fatalf("Bind under EC root: %v", err)
	}
	sig := signer.Sign(payload)
	if err := Verify(&priv.PublicKey, payload, sig); err != nil {
		t.Errorf("lineage should verify under the EC-P256 anchor: %v", err)
	}
	// A DIFFERENT EC root must reject the chain.
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := Verify(&other.PublicKey, payload, sig); err == nil {
		t.Error("lineage verified under the WRONG EC-P256 root")
	}
	// A typed-nil EC anchor fails closed (verifyRoot guards the nil curve — no panic).
	if err := Verify((*ecdsa.PublicKey)(nil), payload, sig); err == nil {
		t.Error("a nil EC anchor should fail closed")
	}
	// A partially-decoded anchor (curve set, X/Y nil — e.g. from a malformed KMS PEM) must fail
	// CLOSED, not PANIC inside ecdsa.VerifyASN1.
	if err := Verify(&ecdsa.PublicKey{Curve: elliptic.P256()}, payload, sig); err == nil {
		t.Error("a partial (X/Y-nil) EC anchor should fail closed")
	}
	// A non-P256 curve is rejected (the arm pins EC-P256, the only EC root we issue).
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err := Verify(&p384.PublicKey, payload, sig); err == nil {
		t.Error("a non-P256 EC anchor should be rejected")
	}

	// The sink path verifies under the EC root too.
	ss, err := NewSinkSigner(ca, "evidence-sink")
	if err != nil {
		t.Fatalf("NewSinkSigner under EC root: %v", err)
	}
	csig, err := ss.SignCheckpoint(context.Background(), []byte("ckpt"))
	if err != nil {
		t.Fatalf("SignCheckpoint: %v", err)
	}
	if err := VerifySinkSignature(&priv.PublicKey, []byte("ckpt"), csig); err != nil {
		t.Errorf("sink signature should verify under the EC-P256 anchor: %v", err)
	}
}

// failCA is a CA whose root Sign always errors, to exercise the binder/sink-signer fail-closed paths
// (a real KMS-backed root can fail where the in-process DevCA cannot).
type failCA struct{}

func (failCA) Sign([]byte) ([]byte, error) { return nil, errors.New("signing: induced CA failure") }

// TestCASignError_FailsClosed: when the CA root cannot sign a certificate, neither an NHI binder nor
// a sink signer fabricates an unsigned identity — both surface the error.
func TestCASignError_FailsClosed(t *testing.T) {
	if _, err := NewNHIBinder(failCA{}).Bind("alice", "s1", interfaces.PersonaAuthor); err == nil {
		t.Error("Bind should fail closed when the CA root cannot sign the certificate")
	}
	if _, err := NewSinkSigner(failCA{}, "evidence-sink"); err == nil {
		t.Error("NewSinkSigner should fail closed when the CA root cannot sign the certificate")
	}
}

// TestVerify_UnknownAnchorTypeFailsClosed: a trust anchor that is not a recognised public-key type
// (nil here; a Cloud KMS EC-P256 root until its verify arm lands in the KMS adapter) is rejected —
// verifyRoot fails closed rather than accepting an unverifiable chain. SinkID() is exercised too.
func TestVerify_UnknownAnchorTypeFailsClosed(t *testing.T) {
	ca := NewDevCA()
	lineage, _ := NewNHIBinder(ca).Bind("alice", "s1", interfaces.PersonaAuthor)
	sig := lineage.Sign([]byte("payload"))
	// A valid signature still fails to verify under an unrecognised (non-ed25519) anchor.
	if err := Verify(nil, []byte("payload"), sig); err == nil {
		t.Error("Verify should fail closed for an unrecognised CA anchor type")
	}

	ss, err := NewSinkSigner(ca, "evidence-sink")
	if err != nil {
		t.Fatalf("NewSinkSigner: %v", err)
	}
	if ss.SinkID() != "evidence-sink" {
		t.Errorf("SinkID = %q, want evidence-sink", ss.SinkID())
	}
	csig, err := ss.SignCheckpoint(context.Background(), []byte("ckpt"))
	if err != nil {
		t.Fatalf("SignCheckpoint: %v", err)
	}
	if err := VerifySinkSignature(nil, []byte("ckpt"), csig); err == nil {
		t.Error("VerifySinkSignature should fail closed for an unrecognised CA anchor type")
	}
}

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

func TestSign_ReturnsIndependentCert(t *testing.T) {
	ca := NewDevCA()
	signer, _ := NewNHIBinder(ca).Bind("alice", "s1", interfaces.PersonaAuthor)
	payload := []byte("commit")
	// Mutating a returned signature's cert bytes must not corrupt the long-lived signer.
	sig1 := signer.Sign(payload)
	if len(sig1.Cert.Pub) > 0 {
		sig1.Cert.Pub[0] ^= 0xff
	}
	if len(sig1.Cert.CASig) > 0 {
		sig1.Cert.CASig[0] ^= 0xff
	}
	sig2 := signer.Sign(payload)
	if err := Verify(ca.Root(), payload, sig2); err != nil {
		t.Errorf("a later signature failed to verify — mutating a prior returned cert corrupted the signer: %v", err)
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

func TestSinkSign_Verifies(t *testing.T) {
	ca := NewDevCA()
	signer, err := NewSinkSigner(ca, "evidence-sink")
	if err != nil {
		t.Fatalf("NewSinkSigner: %v", err)
	}
	tbs := []byte("checkpoint-head-bytes")
	sig, err := signer.SignCheckpoint(context.Background(), tbs)
	if err != nil {
		t.Fatalf("SignCheckpoint: %v", err)
	}
	if sig.SinkID != "evidence-sink" {
		t.Errorf("sink signature id = %q, want evidence-sink", sig.SinkID)
	}
	if err := VerifySinkSignature(ca.Root(), tbs, sig); err != nil {
		t.Errorf("legitimate sink signature failed to verify: %v", err)
	}
}

func TestNewSinkSigner_RejectsEmptyID(t *testing.T) {
	if _, err := NewSinkSigner(NewDevCA(), ""); err == nil {
		t.Error("minted a sink signer with an empty id")
	}
}

func TestVerifySink_RejectsWrongPayload(t *testing.T) {
	ca := NewDevCA()
	signer, _ := NewSinkSigner(ca, "evidence-sink")
	sig, _ := signer.SignCheckpoint(context.Background(), []byte("original"))
	if err := VerifySinkSignature(ca.Root(), []byte("tampered"), sig); err == nil {
		t.Error("verified a sink signature against a different payload")
	}
}

func TestVerifySink_RejectsUntrustedCARoot(t *testing.T) {
	ca := NewDevCA()
	signer, _ := NewSinkSigner(ca, "evidence-sink")
	tbs := []byte("checkpoint")
	sig, _ := signer.SignCheckpoint(context.Background(), tbs)

	otherRoot, _, _ := ed25519.GenerateKey(nil)
	if err := VerifySinkSignature(otherRoot, tbs, sig); err == nil {
		t.Error("verified a sink certificate against an untrusted CA root")
	}
}

func TestVerifySink_RejectsForgedIdentity(t *testing.T) {
	ca := NewDevCA()
	signer, _ := NewSinkSigner(ca, "evidence-sink")
	tbs := []byte("checkpoint")
	sig, _ := signer.SignCheckpoint(context.Background(), tbs)

	// Swapping the claimed SinkID without re-minting the CA-signed cert must be caught by the
	// identity-consistency check (sig vs cert).
	forged := sig
	forged.SinkID = "rogue-sink"
	if err := VerifySinkSignature(ca.Root(), tbs, forged); err == nil {
		t.Error("verified a sink signature whose id differs from its certificate")
	}
}

func TestVerifySink_RejectsMalformedKeyLengths(t *testing.T) {
	ca := NewDevCA()
	signer, _ := NewSinkSigner(ca, "evidence-sink")
	tbs := []byte("checkpoint")
	sig, _ := signer.SignCheckpoint(context.Background(), tbs)

	if err := VerifySinkSignature(ed25519.PublicKey{1, 2, 3}, tbs, sig); err == nil {
		t.Error("verified against a malformed CA root key")
	}
	bad := sig
	bad.Cert.Pub = ed25519.PublicKey{1, 2, 3}
	if err := VerifySinkSignature(ca.Root(), tbs, bad); err == nil {
		t.Error("verified a sink signature with a malformed certificate public key")
	}
}

func TestSignCheckpoint_ReturnsIndependentCert(t *testing.T) {
	ca := NewDevCA()
	signer, _ := NewSinkSigner(ca, "sink")
	tbs := []byte("checkpoint")
	// Mutate the cert byte slices of a returned signature; the long-lived signer's own cert must
	// be unaffected, so a later signature still verifies.
	sig1, _ := signer.SignCheckpoint(context.Background(), tbs)
	if len(sig1.Cert.Pub) > 0 {
		sig1.Cert.Pub[0] ^= 0xff
	}
	if len(sig1.Cert.CASig) > 0 {
		sig1.Cert.CASig[0] ^= 0xff
	}
	sig2, _ := signer.SignCheckpoint(context.Background(), tbs)
	if err := VerifySinkSignature(ca.Root(), tbs, sig2); err != nil {
		t.Errorf("a later signature failed to verify — mutating a prior returned cert corrupted the signer: %v", err)
	}
}

func TestSinkCert_DistinctDomainFromLineageCert(t *testing.T) {
	ca := NewDevCA()
	// A lineage certificate the CA issued for a session NHI. Its CASig is over the lineage
	// domain ("c7-cert-v1"); reusing it as a sink certificate's CASig must fail, because the
	// sink verifier recomputes the bytes under the sink domain ("c7-sinkcert-v1").
	lineage := signerForSinkDomainTest(t, ca)
	crossed := SinkSignature{
		SinkID: lineage.NHI,
		Sig:    ed25519.Sign(lineage.priv, []byte("checkpoint")),
		Cert: SinkCert{
			SinkID: lineage.NHI,
			Pub:    lineage.cert.Pub,
			CASig:  lineage.cert.CASig, // a lineage-domain CA signature
		},
	}
	if err := VerifySinkSignature(ca.Root(), []byte("checkpoint"), crossed); err == nil {
		t.Error("a lineage certificate verified as a sink certificate (domain tags not separated)")
	}
}

// signerForSinkDomainTest returns a bound lineage SessionSigner so the cross-domain test can
// reach its CA-signed (lineage-domain) certificate and ephemeral key.
func signerForSinkDomainTest(t *testing.T, ca *DevCA) *SessionSigner {
	t.Helper()
	signer, err := NewNHIBinder(ca).Bind("alice", "s1", interfaces.PersonaAuthor)
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	return signer
}
