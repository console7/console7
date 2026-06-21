package conformance

import (
	"testing"

	inferencevertex "github.com/console7/console7/providers/inference-vertex"
	"github.com/console7/console7/sdk/testkit"
)

// This run asserts the GCP Vertex reference InferenceBackend upholds the InferenceBackend
// SECURITY contract — fail-closed mode handling and the attended/unattended subscription
// refusals (sdk/testkit checkInferenceResolve) — exercising providers/inference-vertex's own
// logic. Like the Anthropic backend the contract runs against in TestHarnessWiring, Resolve is
// a pure routing decision, so there is no in-memory double to swap: this wires the REAL
// provider with a configured project + region, and it needs no GCP project or credentials
// (Resolve makes no network call). Vertex refuses ALL subscription routing — stricter than the
// contract floor, which only requires refusing the unattended/multi-beneficiary cases — so it
// conforms cleanly. The regional/global/PSC endpoint resolution is proven by the provider's own
// white-box tests (providers/inference-vertex/provider_test.go).
func inferenceVertexUnderTest() testkit.ProviderUnderTest {
	p, err := inferencevertex.New(inferencevertex.Config{ProjectID: "conf-proj", Region: "us-east5"})
	if err != nil {
		panic("conformance: vertex inference backend: " + err.Error())
	}
	return testkit.ProviderUnderTest{Inference: p}
}

// TestInferenceVertexConformance runs the InferenceBackend contract against the Vertex
// reference provider and requires that it not fail. The devkit/Anthropic run lives in
// TestHarnessWiring; this is the parallel run proving the Vertex provider's logic conforms too.
func TestInferenceVertexConformance(t *testing.T) {
	res := testkit.Run(inferenceVertexUnderTest())
	if len(res.Checked) == 0 {
		t.Fatal("expected the InferenceBackend contract to be checked, got none")
	}
	if len(res.Failed) != 0 {
		t.Fatalf("inference-vertex conformance run reported %d contract failure(s): %v", len(res.Failed), res.Failed)
	}
}
