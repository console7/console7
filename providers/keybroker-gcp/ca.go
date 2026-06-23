package keybrokergcp

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/console7/console7/keybroker/signing"
)

// signTimeout bounds a single root-signing KMS call. CA.Sign (the signing.CA seam) takes no context
// — DevCA never needed one — so the KMS-backed Sign uses a bounded background context per call rather
// than rippling a context through CA.Sign/Bind/NewSinkSigner. A cert sign is a quick, infrequent op
// (one per session for the NHI cert, one per sink-signer); a fixed ceiling keeps it from hanging.
const signTimeout = 15 * time.Second

// Provider is the KMS-backed CA root: it satisfies keybroker/signing.CA (Sign) so an NHIBinder /
// SinkSigner certifies under it, and exposes the EC-P256 trust anchor via Root() for verifiers.
type Provider struct {
	kms    kmsAsymmetricSigner
	anchor *ecdsa.PublicKey
	// closer is the underlying KMS client New opened; NewWithPorts leaves it nil (Close is a no-op).
	closer io.Closer
}

// Compile-time assertion that Provider satisfies the keybroker CA seam.
var _ signing.CA = (*Provider)(nil)

// Sign signs a certificate TBS with the KMS root key: it hashes the TBS with SHA-256 and has KMS
// EC-P256-sign the digest, returning the ASN.1/DER signature signing.verifyRoot checks against
// Root(). It uses a bounded background context (see signTimeout).
func (p *Provider) Sign(tbs []byte) ([]byte, error) {
	h := sha256.Sum256(tbs)
	ctx, cancel := context.WithTimeout(context.Background(), signTimeout)
	defer cancel()
	return p.kms.SignDigest(ctx, h[:])
}

// Root returns the EC-P256 public key — the trust anchor a verifier pins. It is a *ecdsa.PublicKey,
// assignable to the crypto.PublicKey anchor signing.Verify / VerifySinkSignature take.
func (p *Provider) Root() crypto.PublicKey { return p.anchor }

// parseECP256PublicKeyPEM decodes a SubjectPublicKeyInfo PEM into an EC-P256 public key, failing
// closed on anything that is not exactly an EC P-256 key (the only algorithm this CA issues, and the
// only one signing.verifyRoot's EC arm accepts).
func parseECP256PublicKeyPEM(pemStr string) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("keybrokergcp: KMS public key is not valid PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("keybrokergcp: cannot parse KMS public key: %w", err)
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("keybrokergcp: KMS public key is %T, want an EC (P-256) key", pub)
	}
	if ec.Curve != elliptic.P256() {
		return nil, errors.New("keybrokergcp: KMS public key is not on curve P-256 (the CA must be an EC_SIGN_P256_SHA256 key)")
	}
	return ec, nil
}
