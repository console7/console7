// Package interfaces defines the Console7 provider contracts — the "bring your own
// everything" seams from ARCHITECTURE.md §5. Each interface is a stable promise to
// adopters and out-of-tree connector authors: the canonical, system-of-record SDK
// is this Go module (docs/adr/0001-language.md).
//
// These are CONTRACTS ONLY. At P0 scaffolding there are deliberately NO
// implementations behind them — not in this package, not anywhere in core. The
// reference provider set lives under providers/ (added later); community providers
// live out-of-tree against this published module (ARCHITECTURE.md §6.1).
//
// # How to read the SECURITY contracts
//
// Every method carries a SECURITY clause stating what an implementation MUST NEVER
// do. These clauses are load-bearing, not advisory: they encode the GOAL.md tenets
// and the DESIGN.md MUST-requirements at the one place every adopter's code has to
// pass through. The conformance harness (sdk/testkit, conformance/) exists to
// assert each implementation upholds them.
//
// Two design rules run through all of them:
//
//   - Boundary controls are authoritative; in-band guards are defence-in-depth
//     (GOAL.md tenet 3). Where an interface says an implementation MUST enforce
//     something "at the boundary", a guard inside the sandbox or engine is never a
//     substitute for it.
//   - Least privilege, ephemeral by default (GOAL.md tenet 4). No method on any
//     interface is permitted to return, persist, or widen access to long-lived
//     credential material. The control plane holds no keys at rest (DESIGN.md §8).
package interfaces
