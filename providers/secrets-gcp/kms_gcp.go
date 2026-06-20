package secretsgcp

import (
	"context"
	"fmt"

	kms "cloud.google.com/go/kms/apiv1"
	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
)

// kmsKEK is the real KEKWrapper: provider-side envelope encryption via Cloud KMS Encrypt/
// Decrypt against a single crypto key. The KEK never leaves KMS; only the DEK plaintext (in)
// and the wrapped DEK (out) cross this boundary. The workload SA holds
// roles/cloudkms.cryptoKeyEncrypterDecrypter on exactly this key (deploy/gcp/modules/secrets).
type kmsKEK struct {
	client  *kms.KeyManagementClient
	keyName string // the crypto-key resource id; KMS picks the primary version to encrypt.
}

var _ KEKWrapper = (*kmsKEK)(nil)

// WrapDEK encrypts the DEK under the KEK, binding aad as Additional Authenticated Data. The
// returned version is the CryptoKeyVersion KMS used (recorded for audit); Decrypt does not
// need it because KMS resolves the version from the ciphertext.
func (k *kmsKEK) WrapDEK(ctx context.Context, dek, aad []byte) ([]byte, string, error) {
	resp, err := k.client.Encrypt(ctx, &kmspb.EncryptRequest{
		Name:                        k.keyName,
		Plaintext:                   dek,
		AdditionalAuthenticatedData: aad,
	})
	if err != nil {
		// Do not echo request bodies — only the operation and key — so DEK material cannot
		// reach a log via a wrapped error.
		return nil, "", fmt.Errorf("secretsgcp: KMS encrypt failed: %w", err)
	}
	return resp.GetCiphertext(), resp.GetName(), nil
}

// UnwrapDEK decrypts the wrapped DEK under the KEK, binding aad. A mismatched aad (e.g. a
// secret confused for another subject) fails authentication. kekVersion is unused — KMS
// resolves the version from the ciphertext — but is part of the port for the fake's benefit.
func (k *kmsKEK) UnwrapDEK(ctx context.Context, wrapped []byte, kekVersion string, aad []byte) ([]byte, error) {
	resp, err := k.client.Decrypt(ctx, &kmspb.DecryptRequest{
		Name:                        k.keyName,
		Ciphertext:                  wrapped,
		AdditionalAuthenticatedData: aad,
	})
	if err != nil {
		return nil, fmt.Errorf("secretsgcp: KMS decrypt failed: %w", err)
	}
	return resp.GetPlaintext(), nil
}
