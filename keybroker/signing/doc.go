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
// The CA ROOT is pluggable behind the CA interface (Sign): DevCA is the in-process ed25519
// dev root; a KMS-backed EC-P256 root (the keybroker's hardened, out-of-process signing
// identity) implements the same interface, and the verifiers (Verify / VerifySinkSignature)
// take a crypto.PublicKey anchor and dispatch on its type. Only the ROOT algorithm varies;
// the per-session NHI keys and sink checkpoint keys stay ephemeral ed25519 LEAF keys minted
// by the binder/sink-signer and never returned.
//
// SECURITY: DevCA is a DEV stand-in — an in-process ed25519 root that models an org CA /
// Sigstore-keyless issuer. It demonstrates the binding and the verifiable lineage chain, NOT a
// real keyless/CA trust root (transparency log, OIDC identity binding, key custody). The
// KMS-backed root (a hardened, out-of-process key the control plane never holds) lands behind
// the CA interface above (docs/ROADMAP.md).
package signing
