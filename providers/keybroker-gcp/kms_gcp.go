package keybrokergcp

import (
	"context"
	"errors"
	"fmt"
	"hash/crc32"

	kms "cloud.google.com/go/kms/apiv1"
	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// kmsAsymmetricGCP is the real kmsAsymmetricSigner: Cloud KMS AsymmetricSign + GetPublicKey against
// one EC_SIGN_P256_SHA256 key version. The root private key never leaves KMS; only the SHA-256 digest
// (in) and the DER signature (out) cross this boundary. The keybroker SA holds
// roles/cloudkms.signerVerifier on exactly this key (deploy/gcp/modules/keybroker-signing).
//
// Every call carries CRC32C integrity checksums in both directions (Cloud KMS best practice): a
// corrupted request is rejected by KMS, and a corrupted reply is rejected here before a bad signature
// or a bad public key is ever used — a corrupted root signature would otherwise produce evidence that
// never verifies (silent lineage breakage), and a corrupted public key would pin the wrong anchor.
type kmsAsymmetricGCP struct {
	client         *kms.KeyManagementClient
	keyVersionName string
}

var _ kmsAsymmetricSigner = (*kmsAsymmetricGCP)(nil)

// crc32cTable is the Castagnoli polynomial table Cloud KMS uses for its CRC32C checksums.
var crc32cTable = crc32.MakeTable(crc32.Castagnoli)

func crc32c(b []byte) int64 { return int64(crc32.Checksum(b, crc32cTable)) }

// SignDigest signs the SHA-256 digest with the key version, verifying KMS received the digest intact
// and that the returned signature arrived intact.
func (k *kmsAsymmetricGCP) SignDigest(ctx context.Context, sha256Digest []byte) ([]byte, error) {
	resp, err := k.client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{
		Name:         k.keyVersionName,
		Digest:       &kmspb.Digest{Digest: &kmspb.Digest_Sha256{Sha256: sha256Digest}},
		DigestCrc32C: wrapperspb.Int64(crc32c(sha256Digest)),
	})
	if err != nil {
		return nil, fmt.Errorf("keybrokergcp: KMS AsymmetricSign failed: %w", err)
	}
	// KMS confirms it received our digest intact; if not, the request was corrupted in transit.
	if !resp.GetVerifiedDigestCrc32C() {
		return nil, errors.New("keybrokergcp: KMS did not verify the request digest integrity (corrupt request) — refusing the signature")
	}
	// Confirm the returned signature arrived intact before it is used to certify lineage.
	if resp.GetSignatureCrc32C() == nil || crc32c(resp.GetSignature()) != resp.GetSignatureCrc32C().GetValue() {
		return nil, errors.New("keybrokergcp: KMS AsymmetricSign response failed integrity check (corrupt response)")
	}
	return resp.GetSignature(), nil
}

// PublicKeyPEM fetches the key version's public key, verifying the PEM arrived intact.
func (k *kmsAsymmetricGCP) PublicKeyPEM(ctx context.Context) (string, error) {
	resp, err := k.client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: k.keyVersionName})
	if err != nil {
		return "", fmt.Errorf("keybrokergcp: KMS GetPublicKey failed: %w", err)
	}
	if resp.GetPemCrc32C() == nil || crc32c([]byte(resp.GetPem())) != resp.GetPemCrc32C().GetValue() {
		return "", errors.New("keybrokergcp: KMS GetPublicKey response failed integrity check (corrupt response) — refusing to pin the anchor")
	}
	return resp.GetPem(), nil
}
