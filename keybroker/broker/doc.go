// Package broker is the key broker's ephemeral-identity minting flow and per-user
// subscription vault. It sequences a session's credential dance — authenticate the human,
// bind a per-session non-human identity, mint short-lived cloud and SCM credentials — and
// brokers the subscription token into the owner's sandbox.
//
// It lives in keybroker/ — the Tier-1, highest-isolation, key-handling artifact (a
// distinct signing identity from the control-plane and sandbox images, ARCHITECTURE.md
// §6.4). It must never be fused into the control plane, which holds no keys at rest
// (DESIGN.md §8). The broker stores no long-lived cloud/SCM secrets (DESIGN.md §2.1).
//
// The broker is THIN orchestration over the provider seams (sdk/interfaces): it does not
// re-implement sealing, attended-injection, or routing checks — those are the seams'
// own MUST-NEVER guarantees, enforced at the seam so they cannot drift to a second copy
// here. The broker's job is to call the seams in the right order with the right facts and
// to carry the lineage the orchestrator will later stamp (Subject -> NHI -> action,
// DESIGN.md §2.3).
//
// Phase 0 wires the broker to the in-memory devkit seams for a bench; the real
// SecretsProvider/SCMProvider/IdentityProvider/InferenceBackend land in later phases
// (docs/ROADMAP.md).
package broker
