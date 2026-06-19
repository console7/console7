package testkit

import "github.com/console7/console7/sdk/interfaces"

// ProviderUnderTest bundles the provider implementations a conformance run exercises.
// Every field is optional: a run asserts contracts only for the providers supplied,
// so an adopter shipping a single provider can conform just that one. The fields are
// the nine seams from ARCHITECTURE.md §5.
type ProviderUnderTest struct {
	Cloud     interfaces.CloudProvider
	Secrets   interfaces.SecretsProvider
	Identity  interfaces.IdentityProvider
	SCM       interfaces.SCMProvider
	Inference interfaces.InferenceBackend
	Policy    interfaces.PolicyEngine
	PolicySoR interfaces.PolicySoR
	Evidence  interfaces.EvidenceSink
	Observe   interfaces.ObserveGateway
}

// Contract names one provider-interface method whose SECURITY clause a conformance
// check must uphold. It is the unit the harness is keyed to: one Contract per
// must-never guarantee in sdk/interfaces.
type Contract struct {
	// Interface is the provider interface, e.g. "SecretsProvider".
	Interface string
	// Method is the method under contract, e.g. "MintEphemeral".
	Method string
	// MustNever restates, in one line, the guarantee the check asserts — e.g.
	// "never returns long-lived credential material to the control plane".
	MustNever string
}

// Contracts returns the full set of SECURITY contracts the conformance suite will
// assert, keyed to interface method.
//
// SKELETON: it returns nil at P0. The enumerated stub cases keyed to these contracts
// live under conformance/; this function is wired to return them once the harness
// gains assertion logic (Phase 5, docs/ROADMAP.md). It deliberately holds no logic
// yet.
func Contracts() []Contract {
	return nil
}

// Run will execute the conformance suite against the supplied providers and report
// which contracts hold.
//
// SKELETON: unimplemented at P0. It returns an empty result so callers and the
// conformance stubs compile and wire up now, with the assertions filled in later.
func Run(_ ProviderUnderTest) Result {
	return Result{}
}

// Result is the outcome of a conformance Run: the contracts checked and which
// failed. Empty at P0.
type Result struct {
	Checked []Contract
	Failed  []Contract
}
