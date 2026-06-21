package conformance

import (
	"testing"

	"github.com/console7/console7/control-plane/evidence"
	"github.com/console7/console7/keybroker/signing"
	evidencegcs "github.com/console7/console7/providers/evidence-gcs"
	"github.com/console7/console7/sdk/testkit"
)

// This run asserts the GCS reference evidence backing upholds the same EvidenceSink SECURITY
// contracts the in-memory run does — but exercising providers/evidence-gcs's own Store logic. The
// REAL control-plane evidence Sink is wired over the evidence-gcs Store backed by its in-memory
// objectIO fake (a GCS stand-in), and seals checkpoints through a keybroker-minted sink signer, so
// the contract checks run with no GCS bucket and no credentials. The durable WORM guarantee a real
// bucket-lock gives (immutability, durability faults) is not modelled here; this asserts the
// interface-observable behaviour (monotonic AppendedAt ordering, distinct hashing, no-gap, fail-
// closed Stream ref check) against the provider's real codec + sequence→object logic. The codec's
// chain-hash fidelity is also proven directly in providers/evidence-gcs (provider_test.go).
func evidenceGCSUnderTest() testkit.ProviderUnderTest {
	evCA := signing.NewDevCA()
	sinkSigner, err := signing.NewSinkSigner(evCA, "conf-evidence-gcs-sink")
	if err != nil {
		panic("conformance: evidence-gcs sink signer mint failed: " + err.Error())
	}
	store := evidencegcs.NewWithObjectIO(evidencegcs.NewInMemoryObjectIO(), "records")
	return testkit.ProviderUnderTest{
		Evidence: evidence.New(store, sinkSigner, evCA.Root(), 0),
	}
}

// TestEvidenceGCSConformance runs every EvidenceSink contract against the real Sink backed by the
// GCS reference Store (faked) and requires that none fail. The in-memory-backed run lives in
// TestHarnessWiring; this is the parallel run proving the durable provider's logic conforms too.
func TestEvidenceGCSConformance(t *testing.T) {
	res := testkit.Run(evidenceGCSUnderTest())
	if len(res.Checked) == 0 {
		t.Fatal("expected the EvidenceSink contracts to be checked, got none")
	}
	if len(res.Failed) != 0 {
		t.Fatalf("evidence-gcs conformance run reported %d contract failure(s): %v", len(res.Failed), res.Failed)
	}
}
