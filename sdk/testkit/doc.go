// Package testkit is the Console7 conformance harness — the suite adopters and
// out-of-tree provider authors run to prove an implementation upholds the SECURITY
// contracts declared in sdk/interfaces (ARCHITECTURE.md §6.1, §6.3).
//
// At P0 scaffolding this is a SKELETON: it enumerates the provider-interface methods
// and the must-never clause each conformance check will assert, but contains NO
// assertion logic. The stub test cases keyed to these contracts live under
// conformance/. The harness fills in as the phases land (docs/ROADMAP.md); the
// full conformance suite is a Phase-5 deliverable.
package testkit
