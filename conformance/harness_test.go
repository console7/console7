// Package conformance holds the CI-gated suite that asserts a provider
// implementation upholds the SECURITY contracts declared in sdk/interfaces. It
// drives the harness in sdk/testkit.
//
// SKELETON (P0): the test cases below are keyed one-to-one to the provider-interface
// methods and their must-never guarantees, but each is skipped — there is no
// assertion logic yet. They exist so the contract surface is enumerated and wired
// now; the assertions are filled in as the providers land (the full suite is a
// Phase-5 deliverable, docs/ROADMAP.md). See conformance/README.md.
package conformance

import (
	"testing"

	"github.com/console7/console7/sdk/testkit"
)

// providersUnderTest returns the providers a real conformance run would exercise.
// At P0 it returns the zero value (no providers wired); the per-method stubs skip,
// so the suite is green and the wiring compiles.
func providersUnderTest() testkit.ProviderUnderTest {
	return testkit.ProviderUnderTest{}
}

// TestHarnessWiring confirms the testkit harness is reachable from the suite. It is
// not a contract check — it asserts the scaffolding composes, nothing more.
func TestHarnessWiring(t *testing.T) {
	if res := testkit.Run(providersUnderTest()); len(res.Failed) != 0 {
		t.Fatalf("P0 skeleton harness must report no failures, got %d", len(res.Failed))
	}
}

// skipUnimplemented is the single place the P0 skip reason is stated, so every stub
// reads identically and the reason is changed once when the harness gains logic.
func skipUnimplemented(t *testing.T, iface, method, mustNever string) {
	t.Helper()
	t.Skipf("conformance not implemented at P0 — %s.%s MUST NEVER %s (see sdk/testkit; Phase 5)", iface, method, mustNever)
}
