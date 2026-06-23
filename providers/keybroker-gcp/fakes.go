package keybrokergcp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

// InMemoryKMSSigner is a NON-PRODUCTION kmsAsymmetricSigner backed by a process-local EC-P256 key,
// standing in for Cloud KMS so the CA's Sign -> Root round-trip (and a binder/sink-signer certifying
// under it) can be exercised with no GCP project. It signs and exports the SAME key, so a signature
// it produces verifies under the public key it returns. It gives NONE of a real KMS/HSM's custody
// guarantees — never wire one into a deployment.
type InMemoryKMSSigner struct {
	priv *ecdsa.PrivateKey
	fail bool
}

var _ kmsAsymmetricSigner = (*InMemoryKMSSigner)(nil)

// NewInMemoryKMSSigner returns a fake signer with a freshly-generated EC-P256 key.
func NewInMemoryKMSSigner() *InMemoryKMSSigner {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic("keybrokergcp: crypto/rand failed generating the fake EC key: " + err.Error())
	}
	return &InMemoryKMSSigner{priv: priv}
}

// SetFail makes both ops return an error, to exercise the CA's fail-closed paths.
func (s *InMemoryKMSSigner) SetFail(fail bool) { s.fail = fail }

// SignDigest ECDSA-signs the digest with the in-process key, returning an ASN.1/DER signature (the
// shape Cloud KMS returns).
func (s *InMemoryKMSSigner) SignDigest(ctx context.Context, sha256Digest []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s.fail {
		return nil, errors.New("keybrokergcp/fake: induced SignDigest failure")
	}
	// Real KMS EC_SIGN_P256_SHA256 rejects a digest that is not 32 bytes; keep the fake honest so a
	// test can't pass with a wrong-length digest that real KMS would refuse.
	if len(sha256Digest) != sha256.Size {
		return nil, errors.New("keybrokergcp/fake: digest is not 32 bytes (SHA-256)")
	}
	return ecdsa.SignASN1(rand.Reader, s.priv, sha256Digest)
}

// PublicKeyPEM returns the in-process key's public half as a SubjectPublicKeyInfo PEM.
func (s *InMemoryKMSSigner) PublicKeyPEM(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if s.fail {
		return "", errors.New("keybrokergcp/fake: induced PublicKeyPEM failure")
	}
	der, err := x509.MarshalPKIXPublicKey(&s.priv.PublicKey)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), nil
}
