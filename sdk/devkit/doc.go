// Package devkit provides in-memory, NON-PRODUCTION implementations of the
// sdk/interfaces provider seams, for benches and tests.
//
// These implementations exist so first-party logic (the key broker, and later the
// orchestrator) can be exercised end to end without a cloud — they are the dev/
// in-memory subjects the conformance harness (sdk/testkit, conformance/) asserts
// against before any real provider lands. They are deliberately dependency-free and
// use only Go standard-library crypto (AES-256-GCM, ed25519) so a bench exercises the
// REAL contract shape — per-user envelope encryption, opaque credential refs, fail-
// closed routing — rather than a hollow stub.
//
// SECURITY: nothing here is a deployment target. The "KMS" is an in-process key, the
// "IdP" is an in-process verifying key, and the "sandbox" is a map. They model the
// behavioural invariants of each seam (no plaintext returned to the control plane,
// per-user keying, no pooling, attended-only injection, branch-scoped SCM tokens,
// fail-closed inference routing) — NOT the cryptographic-boundary guarantees a real
// KMS/HSM, OIDC chain, or GitHub App provides. Those are Phase-1+ (docs/ROADMAP.md).
// Never wire a devkit type into a control-plane or key-broker deployment.
//
// devkit is intentionally not one of the directories in ARCHITECTURE.md §6.3: it is
// SDK-adjacent test scaffolding, kept beside sdk/interfaces and sdk/testkit so that
// providers/ keeps meaning "the real cloud reference set" and testkit/ keeps meaning
// "the harness". It is excluded from the SDK's compatibility/semver promise.
//
// GUARD-RAIL (tracked): the types here satisfy the production interfaces, so nothing in
// the language stops `broker.New(devkit.NewMemSecrets(...), ...)` compiling. Phase 0 has
// no control-plane bootstrap to wire them into, so the risk is latent — but before any
// such wiring lands, devkit MUST be fenced off from release builds (a build tag such as
// `//go:build !console7_release`, or a move under an internal/test-only path). Until then
// the loud names (Mem*, Dev*) and this doc are the only barrier.
package devkit
