// Package signing binds the authenticated SSO subject to a per-session non-human
// identity (NHI) and cryptographically signs commits and produced artefacts by that
// identity. It is the cryptographic root of the lineage chain the orchestrator stamps:
// human Subject -> per-session NHI -> signed action (DESIGN.md §2.3; GOAL.md tenet 6).
//
// It lives in keybroker/ — the Tier-1, highest-isolation, key-handling artifact with a
// signing identity DISTINCT from the control-plane and sandbox images
// (ARCHITECTURE.md §6.4). It must never be fused into the control plane, which holds no
// keys at rest.
//
// NOTE on the system-of-record for lineage: DESIGN.md §2.3 stamps the human->NHI->action
// chain AT THE ORCHESTRATOR. Phase 0 has no orchestrator, so the SessionSigner stamps the
// lineage into each Signature itself and the broker assembles the SessionIdentity. The
// signer is the cryptographic ROOT of the chain, not its system-of-record stamping point;
// that stamping point moves to the orchestrator in a later phase (docs/ROADMAP.md).
//
// SECURITY: the implementation here is a DEV stand-in. DevCA is an in-process ed25519
// root that models an org CA / Sigstore-keyless issuer; per-session signing keys are
// ephemeral ed25519 keys held only inside a SessionSigner and never returned. It
// demonstrates the binding and the verifiable lineage chain, NOT a real keyless/CA
// trust root (transparency log, OIDC identity binding, key custody) — those are
// Phase-1+ (docs/ROADMAP.md).
package signing
