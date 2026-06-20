# `modules/secrets` — `SecretsProvider` substrate (GCP Cloud KMS + workload identity)

The KMS substrate and workload identity the [`secrets-gcp`](../../../../providers/secrets-gcp)
reference `SecretsProvider` runs against. Upholds the SECURITY contract: **no operator
read path**, per-user keys minted **at runtime** (not here), never pooled.

Provisions:

- a **KMS key ring** and an auto-rotated **key-encryption key (KEK)** (`ENCRYPT_DECRYPT`,
  `prevent_destroy`) the provider uses for **provider-side envelope encryption** —
  wrapping per-user DEKs at runtime (the GCP analogue of `MemSecrets`' KEK/DEK model).
  It is **not** a Secret-Manager-configured CMEK, so the **workload SA** (not the Secret
  Manager service agent) holds encrypt/decrypt on it;
- a **least-privilege workload service account** the control plane impersonates, with
  encrypt/decrypt on **only** that KEK and **no human/group binding** — so the operator
  read path is closed for humans/groups by construction.

Deliberately **not** here: project/billing (human bootstrap), API enablement
(bootstrap), per-user secrets/keys (runtime provider code), the GKE Workload Identity
binding (the `gke` module — needs the cluster's KSA), and **the provider's Secret
Manager role bindings** (read + create/add-version/destroy) — those land **atomically
with `providers/secrets-gcp`**, where the exact least-privilege needs are known, rather
than guessed here ahead of the provider.

## Inputs

| Variable | Description |
|---|---|
| `project_id` | Existing GCP project to deploy into |
| `region` | Region for the KMS key ring |
| `name_prefix` | Resource-name + managed-secret naming prefix |
| `kms_rotation_period` | CMEK auto-rotation period in seconds |

## Outputs

| Output | Description |
|---|---|
| `workload_service_account_email` | The least-privilege secrets SA (GKE WI + Secret Manager bindings deferred) |
| `kms_crypto_key_id` | The secrets KEK (per-user-DEK envelope encryption) |
| `kms_key_ring_id` | The KMS key ring |
