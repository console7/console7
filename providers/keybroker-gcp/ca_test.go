package keybrokergcp

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/console7/console7/keybroker/signing"
	"github.com/console7/console7/sdk/interfaces"
)

// TestCRC32C_Castagnoli locks the polynomial the KMS integrity checks rely on: a wrong table would
// silently make every CRC comparison pass against a corrupt value. The standard CRC32C("123456789")
// check vector is 0xE3069283. (The integrity-branch behaviour itself is exercised by the opt-in
// integration test against real KMS, mirroring providers/secrets-gcp's integration-only KMS adapter.)
func TestCRC32C_Castagnoli(t *testing.T) {
	if got := crc32c([]byte("123456789")); got != 0xE3069283 {
		t.Errorf("crc32c check vector = %#x, want 0xE3069283 (wrong polynomial table?)", got)
	}
}

// TestKMSCA_RoundTrip proves the KMS-backed CA satisfies signing.CA end to end (with the in-process
// fake, no GCP): a lineage cert and a sink cert issued under it verify under its EC-P256 anchor —
// exercising the A2 EC-P256 verifyRoot arm through the real binder/sink-signer.
func TestKMSCA_RoundTrip(t *testing.T) {
	ctx := context.Background()
	ca, err := NewWithPorts(ctx, NewInMemoryKMSSigner())
	if err != nil {
		t.Fatalf("NewWithPorts: %v", err)
	}
	ec, ok := ca.Root().(*ecdsa.PublicKey)
	if !ok || ec.Curve != elliptic.P256() {
		t.Fatalf("Root() = %T, want *ecdsa.PublicKey on P-256", ca.Root())
	}

	signer, err := signing.NewNHIBinder(ca).Bind("alice", "s1", interfaces.PersonaAuthor)
	if err != nil {
		t.Fatalf("Bind under KMS CA: %v", err)
	}
	sig := signer.Sign([]byte("payload"))
	if err := signing.Verify(ca.Root(), []byte("payload"), sig); err != nil {
		t.Errorf("lineage should verify under the KMS CA anchor: %v", err)
	}

	ss, err := signing.NewSinkSigner(ca, "evidence-sink")
	if err != nil {
		t.Fatalf("NewSinkSigner under KMS CA: %v", err)
	}
	csig, err := ss.SignCheckpoint(ctx, []byte("ckpt"))
	if err != nil {
		t.Fatalf("SignCheckpoint: %v", err)
	}
	if err := signing.VerifySinkSignature(ca.Root(), []byte("ckpt"), csig); err != nil {
		t.Errorf("sink signature should verify under the KMS CA anchor: %v", err)
	}
	if err := ca.Close(); err != nil { // no-op for a fake-wired CA
		t.Errorf("Close: %v", err)
	}
}

// TestKMSCA_FailClosed: a KMS signer that errors fails closed at construction (public key fetch) and
// at signing (Bind); an empty config is rejected.
func TestKMSCA_FailClosed(t *testing.T) {
	ctx := context.Background()
	failing := NewInMemoryKMSSigner()
	failing.SetFail(true)
	if _, err := NewWithPorts(ctx, failing); err == nil {
		t.Error("NewWithPorts should fail closed when the public key cannot be fetched")
	}

	s := NewInMemoryKMSSigner()
	ca, err := NewWithPorts(ctx, s)
	if err != nil {
		t.Fatalf("NewWithPorts: %v", err)
	}
	s.SetFail(true) // now the signer errors on Sign
	if _, err := signing.NewNHIBinder(ca).Bind("alice", "s1", interfaces.PersonaAuthor); err == nil {
		t.Error("Bind should fail closed when the KMS signer errors")
	}

	if err := (Config{}).validate(); err == nil {
		t.Error("empty KeyVersionName should be rejected")
	}
}

// TestParseECP256PublicKeyPEM_RejectsWrongKey: the anchor parser pins EC P-256 — an ed25519 key, a
// P-384 EC key, and non-PEM input are all rejected (the CA must be an EC_SIGN_P256_SHA256 key).
func TestParseECP256PublicKeyPEM_RejectsWrongKey(t *testing.T) {
	encode := func(pub any) string {
		der, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	}
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := parseECP256PublicKeyPEM(encode(edPub)); err == nil {
		t.Error("an ed25519 key should be rejected (not EC)")
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if _, err := parseECP256PublicKeyPEM(encode(&p384.PublicKey)); err == nil {
		t.Error("a P-384 key should be rejected (wrong curve)")
	}
	if _, err := parseECP256PublicKeyPEM("not a pem"); err == nil {
		t.Error("non-PEM input should be rejected")
	}
	// A genuine P-256 key parses.
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, err := parseECP256PublicKeyPEM(encode(&p256.PublicKey)); err != nil {
		t.Errorf("a P-256 key should parse: %v", err)
	}
}
