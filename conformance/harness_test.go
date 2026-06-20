// Package conformance holds the CI-gated suite that asserts a provider
// implementation upholds the SECURITY contracts declared in sdk/interfaces. It
// drives the harness in sdk/testkit.
//
// Seven of the nine seams are asserted for real: CloudProvider, SecretsProvider,
// IdentityProvider, SCMProvider, InferenceBackend, and PolicySoR against their devkit
// in-memory providers, and EvidenceSink against the REAL control-plane/evidence sink (the
// production type, signing checkpoints through a keybroker-minted sink signer). The remaining
// two seams
// (PolicyEngine, ObserveGateway) have no implementation yet, so their cases skip until
// their providers land in Phases 2–3 (docs/ROADMAP.md; the full nine-seam suite is the
// Phase-5 deliverable). See conformance/README.md.
//
// SCOPE: the devkit providers are in-memory, so a green run asserts the BEHAVIOURAL
// contract invariants (expiry caps, attended-only refusals, fail-closed routing,
// protected-branch refusals, unverifiable-token rejection, default-deny/narrow-only
// egress, hash-chained WORM ordering) — not the cryptographic-boundary or syscall-
// isolation guarantees a real KMS/OIDC/GitHub-App/gVisor provider gives. That distinction
// is recorded in sdk/testkit (check doc) and docs/THREAT-MODEL.md §1/§4.
package conformance

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/console7/console7/control-plane/evidence"
	"github.com/console7/console7/keybroker/signing"
	"github.com/console7/console7/sdk/devkit"
	"github.com/console7/console7/sdk/interfaces"
	"github.com/console7/console7/sdk/testkit"
)

// providersUnderTest wires the Phase-0 dev/in-memory providers the suite exercises. The
// seams without an implementation are left nil, so their contract cases skip.
func providersUnderTest() testkit.ProviderUnderTest {
	reg := devkit.NewSandboxRegistry()
	// A throwaway IdP key: the Authenticate contract check presents an unverifiable
	// token and asserts it is rejected, so no matching private key is needed.
	idpPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic("conformance: idp keygen failed: " + err.Error())
	}
	// The EvidenceSink contracts run against the REAL control-plane evidence sink (the
	// production type), not the devkit double. It seals checkpoints through a keybroker-minted
	// sink signer; the Append/Stream contracts do not seal, but the signer must be wired.
	evCA := signing.NewDevCA()
	sinkSigner, err := signing.NewSinkSigner(evCA, "conf-evidence-sink")
	if err != nil {
		panic("conformance: sink signer mint failed: " + err.Error())
	}
	return testkit.ProviderUnderTest{
		Cloud:    devkit.NewMemCloud(reg),
		Secrets:  devkit.NewMemSecrets(reg),
		Identity: devkit.NewDevIdentity(idpPub, nil),
		SCM:      devkit.NewMemSCM(15 * time.Minute),
		Inference: devkit.NewPolicyInference(devkit.SeamPolicy{
			SubscriptionEndpoint: "https://subscription.internal/inference",
			OrgAPIEndpoint:       "https://vertex.internal/inference",
			SubscriptionEnabled:  true,
		}),
		PolicySoR: devkit.NewFixedPolicySoR(interfaces.RepoRef{Host: "github.com", Owner: "acme", Name: "app"}),
		Evidence:  evidence.NewInMemory(sinkSigner, evCA.Root(), 0),
		// The registry MemSecrets checks ownership against is also the rig the injection
		// contract uses to provision a real owned sandbox, and the store the MemCloud above
		// provisions into and wipes on destroy.
		SecretsRig: reg,
	}
}

// TestHarnessWiring runs every contract whose provider is supplied and requires that none
// fail. It is the aggregate gate over the per-method cases below.
func TestHarnessWiring(t *testing.T) {
	res := testkit.Run(providersUnderTest())
	if len(res.Checked) == 0 {
		t.Fatal("expected at least the four Phase-0 seams to be checked, got none")
	}
	if len(res.Failed) != 0 {
		t.Fatalf("conformance run reported %d contract failure(s): %v", len(res.Failed), res.Failed)
	}
}

// runContract asserts the single contract for iface.method against the providers under
// test. A missing provider skips (a later-phase seam); a violation fails.
func runContract(t *testing.T, iface, method string) {
	t.Helper()
	err := testkit.RunContract(context.Background(), providersUnderTest(), iface, method)
	if errors.Is(err, testkit.ErrProviderAbsent) {
		t.Skipf("%s.%s — no provider supplied yet (lands in a later phase, docs/ROADMAP.md)", iface, method)
	}
	if err != nil {
		t.Fatalf("%s.%s contract violated: %v", iface, method, err)
	}
}

// skipUnimplemented marks a contract case whose provider does not exist yet. Its seam
// lands in a later phase (docs/ROADMAP.md); until then the case is a placeholder that
// records the must-never clause it will assert.
func skipUnimplemented(t *testing.T, iface, method, mustNever string) {
	t.Helper()
	t.Skipf("conformance deferred — no %s implementation yet; %s.%s MUST NEVER %s (lands with its provider, docs/ROADMAP.md)", iface, iface, method, mustNever)
}
