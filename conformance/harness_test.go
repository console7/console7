// Package conformance holds the CI-gated suite that asserts a provider
// implementation upholds the SECURITY contracts declared in sdk/interfaces. It
// drives the harness in sdk/testkit.
//
// Phase 0: the four seams with an implementation (SecretsProvider, IdentityProvider,
// SCMProvider, InferenceBackend) are asserted for real against the in-memory devkit
// providers. The remaining seams (Cloud, Policy, PolicySoR, Evidence, Observe) have no
// implementation yet, so their cases skip until their providers land (docs/ROADMAP.md;
// the full nine-seam suite is the Phase-5 deliverable). See conformance/README.md.
//
// SCOPE: the devkit providers are in-memory, so a green run asserts the BEHAVIOURAL
// contract invariants (expiry caps, attended-only refusals, fail-closed routing,
// protected-branch refusals, unverifiable-token rejection) — not the cryptographic-
// boundary guarantees a real KMS/OIDC/GitHub-App provides. That distinction is recorded
// in sdk/testkit (check doc) and docs/THREAT-MODEL.md §1/§4.
package conformance

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/console7/console7/sdk/devkit"
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
	return testkit.ProviderUnderTest{
		Secrets:  devkit.NewMemSecrets(reg),
		Identity: devkit.NewDevIdentity(idpPub, nil),
		SCM:      devkit.NewMemSCM(15 * time.Minute),
		Inference: devkit.NewPolicyInference(devkit.SeamPolicy{
			SubscriptionEndpoint: "https://subscription.internal/inference",
			OrgAPIEndpoint:       "https://vertex.internal/inference",
			SubscriptionEnabled:  true,
		}),
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
