// Package secretsgcp is the Console7 reference SecretsProvider on GCP Cloud KMS +
// Secret Manager (ARCHITECTURE.md §5; DESIGN.md §2.1/§2.2/§8). It is an in-tree
// reference implementation of the sdk/interfaces.SecretsProvider seam; community
// providers live out-of-tree against the published SDK.
//
// # The envelope model
//
// The provider realises the same per-user envelope hierarchy as sdk/devkit.MemSecrets,
// swapping the in-process KEK for Cloud KMS and the in-memory maps for Secret Manager:
//
//	KEK            — one Cloud KMS crypto key (deploy/gcp/modules/secrets provisions it).
//	                 It never leaves KMS; the workload SA holds encrypt/decrypt on it ONLY.
//	per-user DEK   — a fresh random 32-byte data-encryption key minted PER SUBJECT on every
//	                 store, persisted only KEK-wrapped. No key is shared across subjects, so
//	                 pooling is impossible by construction, not by a runtime check.
//	sealed token   — the subscription token, AES-256-GCM-sealed under that user's DEK.
//
// Each subject's wrapped DEK + sealed token live in ONE Secret Manager secret
// (one version per store, so a re-login supersedes the prior). The KMS wrap binds the
// DEK to its owner via Additional Authenticated Data = the per-subject secret ID, so a
// swapped or confused secret fails to decrypt.
//
// SECURITY: there is deliberately NO exported method that returns plaintext credential
// material on the production type. MintEphemeral returns an opaque CredentialRef;
// InjectSubscriptionToken delivers plaintext only into the owning sandbox and returns nil;
// the control plane never sees a token. (The in-memory fakes expose test-only read hooks,
// but New never wires them.) That absence is the in-band half of the "no standing operator
// read path" invariant (DESIGN.md §2.2). The other half is a deployment posture this
// package does not itself enforce: the workload SA holds a read verb
// (secretmanager.versions.access), so the "no operator read path" guarantee ASSUMES no
// human/group is granted impersonation (iam.serviceAccounts.actAs / getAccessToken) on that
// SA — deploy/gcp/modules/secrets creates it with no such binding (see also
// docs/THREAT-MODEL.md external control dependencies).
//
// The per-subject secret ID is an UNSALTED SHA-256 of the subject. An identity holding the
// workload role could therefore confirm whether a *named* subject has bound a subscription
// (by accessing the deterministic secret ID for a guessed subject) — existence only, never
// plaintext. This is accepted because that role is granted ONLY to the workload SA (no human
// impersonation binding, and the role has no *.list verb at all), so there is no operator
// read or enumeration path; a keyed HMAC would only move the trust to a second stored key.
//
// # The GCP SDK is confined behind ports
//
// The provider logic (provider.go) depends only on the KEKWrapper, SecretStore, and
// Injector ports (ports.go); the cloud.google.com/go clients are confined to the
// adapters (kms_gcp.go, secretmanager_gcp.go) wired by New (new.go). Tests and the
// conformance harness wire the in-memory fakes (fakes.go) instead, so the contract logic
// runs under `go test ./...` with no GCP project and no credentials — the same
// logic-vs-fakes split MemSecrets proves. The exported ports + fakes also let out-of-tree
// providers conformance-test themselves.
//
// # Real vs deferred in this PR
//
//   - REAL: per-user DEK envelope, KMS wrap/unwrap with owner-bound AAD, Secret Manager
//     storage, attended/single-beneficiary + ownership injection gates, expiry-capped
//     ephemeral leases, crypto-shred on revoke.
//   - The production Injector (real data-plane sandbox delivery) now EXISTS — the
//     providers/cloud-gcp Provider satisfies the Injector seam (Owns/DeliverIfOwned, B5).
//     This convenience New still defaults to a fail-closed denyInjector; the ORCHESTRATOR wires
//     the cloud-gcp Provider in via NewWithPorts (B11/PART-A) (docs/THREAT-MODEL.md §1).
//   - DEFERRED: the GCP-native MintEphemeral backing (IAM Credentials GenerateAccessToken).
//     MintEphemeral is a real, expiry-capped lease bookkeeper today (as in MemSecrets); the
//     SA-impersonation token mint lands with the orchestrator/identity seam.
//   - RESIDUAL: revocation reaches the at-rest copy only; a token already injected into a
//     live sandbox is reaped by tearing the sandbox down (the CloudProvider's job), not by
//     this call. The process-local revocation tombstone is checked on mint, store, AND inject
//     (a strengthening over the in-memory reference, since the remote store's commit cannot be
//     held atomic with the tombstone check), but it is per-replica: cross-replica revocation
//     ordering is a single-replica simplification, and durable offboarding is the upstream
//     SCIM/identity control (docs/THREAT-MODEL.md §4). A re-login accumulates Secret Manager
//     versions (all sealed, all shredded together on revoke); pruning superseded versions is a
//     future hardening.
package secretsgcp
