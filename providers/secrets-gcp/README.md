# `providers/secrets-gcp/` — reference `SecretsProvider`

**Trust tier:** reference provider implementation (runs as part of the control plane).

Reference implementation of [`SecretsProvider`](../../sdk/interfaces/secrets.go) on **GCP
Cloud KMS + Secret Manager** (`ARCHITECTURE.md` §5; `DESIGN.md` §2.1/§2.2/§8). It realises
the same per-user envelope model as [`sdk/devkit.MemSecrets`](../../sdk/devkit/secrets_mem.go),
swapping the in-process KEK for Cloud KMS and the in-memory maps for Secret Manager.

## What it upholds

- **Per-user envelope, never pooled.** Every store mints a fresh 32-byte DEK, seals the
  subscription token under it (AES-256-GCM), and wraps the DEK under the Cloud KMS KEK. No
  key is shared across subjects, so pooling is impossible by construction.
- **Owner-bound wrap.** The KMS wrap binds the DEK to its owner via Additional Authenticated
  Data = the per-subject secret ID, so a swapped/confused secret fails to decrypt.
- **No operator read path.** There is no exported method that returns plaintext: `MintEphemeral`
  returns an opaque `CredentialRef`; `InjectSubscriptionToken` delivers only into the owning
  sandbox and returns `nil`. The workload SA has no human impersonation binding.
- **Attended, single-beneficiary injection** into the owning sandbox only; **fail-closed** on
  any KMS/decrypt error.
- **Crypto-shred on revoke.** `RevokeSubject` deletes the secret (and thus the only copy of the
  wrapped DEK), rendering the token unrecoverable; idempotent.

## Architecture — GCP SDK confined behind ports

The provider logic (`provider.go`) depends only on the `KEKWrapper`, `SecretStore`, and
`Injector` ports (`ports.go`). The `cloud.google.com/go` clients are confined to the adapters
(`kms_gcp.go`, `secretmanager_gcp.go`) wired by `New` (`new.go`). Tests and the conformance
harness wire the in-memory fakes (`fakes.go`) instead, so the contract logic runs under
`go test ./...` **with no GCP project and no credentials**. The exported ports + fakes also let
out-of-tree providers conformance-test themselves.

```
New(ctx, Config)            -> real Cloud KMS + Secret Manager adapters  (production)
NewWithPorts(kek, store, …) -> any ports, incl. the in-memory fakes      (tests/conformance)
```

## Wiring

```go
p, err := secretsgcp.New(ctx, secretsgcp.Config{
    ProjectID:       "console7-dev",
    KEKResourceName: "projects/console7-dev/locations/us-east4/keyRings/console7-secrets/cryptoKeys/console7-secrets-kek", // module output kms_crypto_key_id
    Region:          "us-east4", // must match the KMS key ring location
})
// defer p.Close()
```

The substrate (KEK, workload SA, Secret Manager API + least-privilege role) is provisioned by
[`deploy/gcp/modules/secrets`](../../deploy/gcp/modules/secrets).

## Real vs deferred

- **Real:** per-user DEK envelope, KMS wrap/unwrap with owner-bound AAD, Secret Manager
  storage/versioning, attended/single-beneficiary + ownership injection gates, expiry-capped
  ephemeral leases, crypto-shred on revoke.
- **Deferred:** the production `Injector` (real data-plane sandbox delivery) — until the sandbox
  PR lands, `New` wires a fail-closed `Injector`; the GCP-native `MintEphemeral` backing (IAM
  Credentials `GenerateAccessToken`) — today it is a real, expiry-capped lease bookkeeper, as in
  `MemSecrets`. See `doc.go` and `docs/THREAT-MODEL.md` §1/§4.

## Tests

```bash
go test ./providers/secrets-gcp/...   # white-box invariants on fakes (no credentials)
go test ./conformance/...             # TestSecretsGCPConformance — the four contracts on fakes
# opt-in, live (never in CI):
C7_GCP_PROJECT=… C7_KEK_RESOURCE=… C7_GCP_REGION=… go test -tags gcp_integration ./providers/secrets-gcp/...
```
