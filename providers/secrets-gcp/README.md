# `providers/secrets-gcp/` — reference `SecretsProvider`

**Trust tier:** reference provider implementation.

Reference implementation of [`SecretsProvider`](../../sdk/interfaces/secrets.go) on
**GCP Secret Manager + Cloud KMS** (`ARCHITECTURE.md` §5). Must uphold the SECURITY
contracts — never return long-lived or plaintext material to the control plane, mint
short-lived scoped credentials, store the subscription token only under a per-user
KMS key with no operator read path, never pool.

> P0: placeholder — no credentials, no implementation.
