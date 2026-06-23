//go:build keybroker_gcp_integration

// Live integration check for the KMS-backed CA against a REAL Cloud KMS asymmetric-sign key. It is
// opt-in (build tag + env) and operator-run — never part of CI, which exercises the contract over the
// in-process fake (ca_test.go). It proves the real AsymmetricSign + GetPublicKey path: a lineage cert
// issued under the KMS root verifies under the KMS public key.
//
// PRE-FLIGHT:
//   - Deploy deploy/gcp/modules/keybroker-signing (an EC_SIGN_P256_SHA256 key) and grant the caller
//     roles/cloudkms.signerVerifier on it.
//   - export C7_KMS_KEY_VERSION=projects/<p>/locations/<r>/keyRings/<kr>/cryptoKeys/<k>/cryptoKeyVersions/1
//   - go test -tags keybroker_gcp_integration -run TestIntegration_KMSCASignVerify ./providers/keybroker-gcp/...
package keybrokergcp

import (
	"context"
	"os"
	"testing"

	"github.com/console7/console7/keybroker/signing"
	"github.com/console7/console7/sdk/interfaces"
)

func TestIntegration_KMSCASignVerify(t *testing.T) {
	keyVersion := os.Getenv("C7_KMS_KEY_VERSION")
	if keyVersion == "" {
		t.Skip("set C7_KMS_KEY_VERSION to a real EC_SIGN_P256_SHA256 CryptoKeyVersion to run this")
	}
	ctx := context.Background()
	ca, err := New(ctx, Config{KeyVersionName: keyVersion})
	if err != nil {
		t.Fatalf("New (real KMS): %v", err)
	}
	defer ca.Close()

	signer, err := signing.NewNHIBinder(ca).Bind("op@example.test", "live-sess", interfaces.PersonaAuthor)
	if err != nil {
		t.Fatalf("Bind under the real KMS CA: %v", err)
	}
	sig := signer.Sign([]byte("live-payload"))
	if err := signing.Verify(ca.Root(), []byte("live-payload"), sig); err != nil {
		t.Fatalf("lineage signed by the REAL KMS root failed to verify under its public key: %v", err)
	}
}
