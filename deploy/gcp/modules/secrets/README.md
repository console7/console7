# `modules/secrets` — `SecretsProvider` substrate (GCP Cloud KMS + Secret Manager IAM)

The KMS substrate, workload identity, and Secret Manager access the
[`secrets-gcp`](../../../../providers/secrets-gcp) reference `SecretsProvider` runs
against. Upholds the SECURITY contract: **no operator read path**, per-user keys minted
**at runtime** (not here), never pooled.

Provisions:

- a **KMS key ring** and an auto-rotated **key-encryption key (KEK)** (`ENCRYPT_DECRYPT`,
  `prevent_destroy`) the provider uses for **provider-side envelope encryption** —
  wrapping per-user DEKs at runtime (the GCP analogue of `MemSecrets`' KEK/DEK model).
  It is **not** a Secret-Manager-configured CMEK, so the **workload SA** (not the Secret
  Manager service agent) holds encrypt/decrypt on it;
- a **least-privilege workload service account** the control plane impersonates, with
  encrypt/decrypt on **only** that KEK and **no human/group binding** — so the operator
  read path is closed for humans/groups by construction;
- the **Secret Manager API** (`secretmanager.googleapis.com`) and **two custom
  least-privilege roles** bound to that workload SA, split so the resource-scoped verbs
  are **name-prefix-conditioned**:
  - **create** (`secrets.create`) — project-wide, **unconditioned** (see note below);
  - **add/access/delete** (`versions.add` / `versions.access` / `secrets.delete`) —
    granted with an **IAM condition** restricting them to
    `resource.name.startsWith(".../secrets/<prefix>-sub-")`, so a compromised workload
    cannot read, re-version, or delete unrelated project secrets.

  There is deliberately **no `*.get`/`*.list`** (no enumeration) and **no
  `getIamPolicy`/`setIamPolicy`** (no self-grant); `roles/secretmanager.admin` would be
  far too broad.

> **Why create is unconditioned.** `secretmanager.secrets.create` is evaluated against
> the **project parent**, not the to-be-created secret, so a `resource.name` condition
> would deny *every* create. Create is therefore project-scoped; the
> blast-radius-limiting condition is applied to the resource-scoped verbs, which is where
> read/modify/delete of existing secrets actually happens.

Deliberately **not** here: project/billing (human bootstrap), `cloudkms` API enablement
(bootstrap prerequisite), per-user secrets/keys (runtime provider code), the GKE Workload
Identity binding (the `gke` module — needs the cluster's KSA), and the
`serviceAccountTokenCreator` grant for `MintEphemeral`'s GCP token mint (deferred with
that feature to the orchestrator/identity PR).

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
