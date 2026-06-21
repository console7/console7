package conformance

import (
	"testing"

	cloudgcp "github.com/console7/console7/providers/cloud-gcp"
	"github.com/console7/console7/sdk/testkit"
)

// This run asserts the GCP reference CloudProvider upholds the CloudProvider SECURITY contract
// — a fresh handle per session/user/persona, narrow-only-never-widen egress that fails closed,
// and irreversible destruction (sdk/testkit checkCloud*). It exercises providers/cloud-gcp's own
// lifecycle logic wired over its in-memory fakes (NewWithPorts), so it needs no GCP project and
// no credentials: the kubectl/gcloud adapter is never reached. The MemCloud run in
// TestHarnessWiring proves the same contract against the devkit double; this is the parallel run
// proving the real provider's logic conforms too. The gVisor/VPC enforcement the real adapter
// drives is an integration concern (providers/cloud-gcp/integration_test.go, build-tagged).
func cloudGCPUnderTest(t *testing.T) testkit.ProviderUnderTest {
	t.Helper()
	p, err := cloudgcp.NewWithPorts(
		cloudgcp.NewInMemorySandboxRuntime(),
		cloudgcp.NewInMemoryEgressController(),
		"conf",
		nil,
	)
	if err != nil {
		t.Fatalf("conformance: build cloud-gcp provider: %v", err)
	}
	return testkit.ProviderUnderTest{Cloud: p}
}

// TestCloudGCPConformance runs the CloudProvider contract against the GCP reference provider and
// requires that it not fail.
func TestCloudGCPConformance(t *testing.T) {
	res := testkit.Run(cloudGCPUnderTest(t))
	if len(res.Checked) == 0 {
		t.Fatal("expected the CloudProvider contract to be checked, got none")
	}
	if len(res.Failed) != 0 {
		t.Fatalf("cloud-gcp conformance run reported %d contract failure(s): %v", len(res.Failed), res.Failed)
	}
}
