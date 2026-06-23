package keybrokergcp

import "context"

// kmsAsymmetricSigner is the single port the CA logic depends on; the cloud.google.com/go/kms client
// is confined to the adapter that satisfies it (kms_gcp.go) and to the in-process fake (fakes.go),
// so the CA's behaviour can be exercised with no GCP project or credentials. Both ops are scoped to
// one CryptoKeyVersion; the adapter carries the CRC32C integrity checks.
type kmsAsymmetricSigner interface {
	// SignDigest signs a 32-byte SHA-256 digest with the EC-P256 key version and returns the
	// ASN.1/DER ECDSA signature. (The CA computes the digest of the cert TBS; KMS signs the digest.)
	SignDigest(ctx context.Context, sha256Digest []byte) (signature []byte, err error)
	// PublicKeyPEM returns the key version's public key in PEM (SubjectPublicKeyInfo) form, which the
	// CA parses once at construction into the EC-P256 trust anchor Root() exposes.
	PublicKeyPEM(ctx context.Context) (pem string, err error)
}
