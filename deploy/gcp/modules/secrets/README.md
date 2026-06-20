# `modules/secrets` — `SecretsProvider` infrastructure (GCP Secret Manager + Cloud KMS)

The static GCP infrastructure the [`secrets-gcp`](../../../../providers/secrets-gcp)
reference `SecretsProvider` runs against. Upholds the SECURITY contract: **no operator
read path**, scoped credentials, per-user keys minted **at runtime** (not here).

Provisions:

- a **KMS key ring** and an auto-rotated **CMEK** (`ENCRYPT_DECRYPT`) for Secret
  Manager envelope encryption (`prevent_destroy` — losing the key shreds every secret
  it wraps);
- a **least-privilege workload service account** the control plane impersonates, with
  encrypt/decrypt on **only** that CMEK and `secretmanager.secretAccessor` **scoped by
  IAM condition to Console7-managed secrets** (name prefix), and **no human/group
  binding** — so the operator read path is closed for humans/groups by construction.

Deliberately **not** here: project/billing creation (human bootstrap), API enablement
(bootstrap), per-user secrets/keys (runtime provider code), and the GKE Workload
Identity binding (the `gke` module — it needs the cluster's KSA).

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
| `workload_service_account_email` | The least-privilege secrets SA (GKE WI binding deferred) |
| `kms_crypto_key_id` | The Secret Manager CMEK |
| `kms_key_ring_id` | The KMS key ring |
