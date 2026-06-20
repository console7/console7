package conformance

import (
	"testing"

	secretsgcp "github.com/console7/console7/providers/secrets-gcp"
	"github.com/console7/console7/sdk/devkit"
	"github.com/console7/console7/sdk/testkit"
)

// This run asserts the GCP reference SecretsProvider upholds the same four SECURITY contracts
// the devkit double does — but exercising providers/secrets-gcp's own logic. The provider is
// wired with its in-memory fakes (Cloud KMS + Secret Manager stand-ins) and the devkit
// SandboxRegistry as both the ownership Injector and the injection rig, so the contract checks
// run with no GCP project and no credentials. The cryptographic-boundary invariants (per-user
// key, no plaintext at rest, crypto-shred) are proven by the provider's own white-box tests
// (providers/secrets-gcp/provider_test.go); a green run here asserts the interface-observable
// behaviour only (sdk/testkit check doc; docs/THREAT-MODEL.md §1/§4).
func secretsGCPUnderTest() testkit.ProviderUnderTest {
	reg := devkit.NewSandboxRegistry()
	return testkit.ProviderUnderTest{
		Secrets:    secretsgcp.NewWithPorts(secretsgcp.NewInMemoryKEK(), secretsgcp.NewInMemoryStore(), reg, "console7", nil),
		SecretsRig: reg,
	}
}

// TestSecretsGCPConformance runs every SecretsProvider contract against the GCP reference
// provider (faked) and requires that none fail. The devkit run lives in TestHarnessWiring;
// this is the parallel run proving the real provider's logic conforms too.
func TestSecretsGCPConformance(t *testing.T) {
	res := testkit.Run(secretsGCPUnderTest())
	if len(res.Checked) == 0 {
		t.Fatal("expected the four SecretsProvider contracts to be checked, got none")
	}
	if len(res.Failed) != 0 {
		t.Fatalf("secrets-gcp conformance run reported %d contract failure(s): %v", len(res.Failed), res.Failed)
	}
}
