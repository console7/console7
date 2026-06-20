package secretsgcp

import (
	"context"
	"fmt"
	"hash/crc32"

	kms "cloud.google.com/go/kms/apiv1"
	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// kmsKEK is the real KEKWrapper: provider-side envelope encryption via Cloud KMS Encrypt/
// Decrypt against a single crypto key. The KEK never leaves KMS; only the DEK plaintext (in)
// and the wrapped DEK (out) cross this boundary. The workload SA holds
// roles/cloudkms.cryptoKeyEncrypterDecrypter on exactly this key (deploy/gcp/modules/secrets).
//
// Every call carries CRC32C integrity checksums in BOTH directions (Cloud KMS best practice):
// the request CRCs let KMS reject a corrupted request, and the response CRCs let us reject a
// corrupted reply. Without this, a rare request/response corruption could make a store report
// success while persisting a wrapped DEK that can never decrypt the sealed token — silent
// at-rest data loss. We verify and fail before the caller commits anything.
type kmsKEK struct {
	client  *kms.KeyManagementClient
	keyName string // the crypto-key resource id; KMS picks the primary version to encrypt.
}

var _ KEKWrapper = (*kmsKEK)(nil)

// crc32cTable is the Castagnoli polynomial table Cloud KMS uses for its CRC32C checksums.
var crc32cTable = crc32.MakeTable(crc32.Castagnoli)

func crc32c(b []byte) int64 { return int64(crc32.Checksum(b, crc32cTable)) }

// WrapDEK encrypts the DEK under the KEK, binding aad as Additional Authenticated Data. The
// returned version is the CryptoKeyVersion KMS used (recorded for audit); Decrypt does not
// need it because KMS resolves the version from the ciphertext.
func (k *kmsKEK) WrapDEK(ctx context.Context, dek, aad []byte) ([]byte, string, error) {
	resp, err := k.client.Encrypt(ctx, &kmspb.EncryptRequest{
		Name:                              k.keyName,
		Plaintext:                         dek,
		AdditionalAuthenticatedData:       aad,
		PlaintextCrc32C:                   wrapperspb.Int64(crc32c(dek)),
		AdditionalAuthenticatedDataCrc32C: wrapperspb.Int64(crc32c(aad)),
	})
	if err != nil {
		// Do not echo request bodies — only the operation and key — so DEK material cannot
		// reach a log via a wrapped error.
		return nil, "", fmt.Errorf("secretsgcp: KMS encrypt failed: %w", err)
	}
	// KMS confirms it received our plaintext/AAD intact; if not, the request was corrupted.
	if !resp.GetVerifiedPlaintextCrc32C() || !resp.GetVerifiedAdditionalAuthenticatedDataCrc32C() {
		return nil, "", fmt.Errorf("secretsgcp: KMS encrypt did not verify request integrity (corrupt request) — refusing to persist")
	}
	// Verify the response ciphertext arrived intact before we persist it.
	if resp.GetCiphertextCrc32C() == nil || crc32c(resp.GetCiphertext()) != resp.GetCiphertextCrc32C().GetValue() {
		return nil, "", fmt.Errorf("secretsgcp: KMS encrypt response failed integrity check (corrupt response) — refusing to persist")
	}
	return resp.GetCiphertext(), resp.GetName(), nil
}

// UnwrapDEK decrypts the wrapped DEK under the KEK, binding aad. A mismatched aad (e.g. a
// secret confused for another subject) fails authentication. kekVersion is unused — KMS
// resolves the version from the ciphertext — but is part of the port for the fake's benefit.
func (k *kmsKEK) UnwrapDEK(ctx context.Context, wrapped []byte, kekVersion string, aad []byte) ([]byte, error) {
	resp, err := k.client.Decrypt(ctx, &kmspb.DecryptRequest{
		Name:                              k.keyName,
		Ciphertext:                        wrapped,
		AdditionalAuthenticatedData:       aad,
		CiphertextCrc32C:                  wrapperspb.Int64(crc32c(wrapped)),
		AdditionalAuthenticatedDataCrc32C: wrapperspb.Int64(crc32c(aad)),
	})
	if err != nil {
		return nil, fmt.Errorf("secretsgcp: KMS decrypt failed: %w", err)
	}
	// Verify the recovered plaintext (the DEK) arrived intact, so a corrupted response can
	// never be used as a key.
	if resp.GetPlaintextCrc32C() == nil || crc32c(resp.GetPlaintext()) != resp.GetPlaintextCrc32C().GetValue() {
		return nil, fmt.Errorf("secretsgcp: KMS decrypt response failed integrity check (corrupt response)")
	}
	return resp.GetPlaintext(), nil
}
