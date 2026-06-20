# `deploy/gcp/` — GCP deployment target (reference)

**Trust tier:** deployment scaffolding (deploys into the **adopter's** GCP tenancy; the
maintainer runs nothing — `GOAL.md` tenet 1). Governed by the adoption model in
[`docs/adr/0002-adoption-deployment-model.md`](../../docs/adr/0002-adoption-deployment-model.md).

Reference Terraform for standing Console7 up in the adopter's **GCP** project. The
module is **consumed by pinned reference** (ADR-0002): an adopter's thin config repo
sources it at a pinned `?ref=`, supplies inputs, and applies under their own identity
via a keyless (Workload Identity Federation) pipeline. This subtree **never creates the
project or links billing** — that is the human bootstrap act (`bootstrap/`, a later
PR); the module always operates **within a pre-existing `project_id`**, so the same
module serves both new-project and existing-project adopters.

## Layout

| Path | Status | Provisions |
|---|---|---|
| `modules/secrets/` | **active** | KMS key ring + CMEK, least-privilege workload SA for `SecretsProvider` |
| `modules/networking/` | stub | default-deny egress perimeter (boundary-first sandbox PR) |
| `modules/gke/` | stub | gVisor node pool + Workload Identity (binds the secrets SA) |
| `modules/evidence/` | stub | GCS bucket-lock WORM behind the evidence `Store` seam |

## Prerequisites (bootstrap, not this module)

- The `cloudkms.googleapis.com` and `secretmanager.googleapis.com` APIs enabled.
- A GCS bucket for Terraform state, supplied at init via `-backend-config`.

## Use (until the adopter template repo lands)

```bash
terraform -chdir=deploy/gcp init -backend-config="bucket=<state-bucket>"
terraform -chdir=deploy/gcp apply -var="project_id=<project>"
```

`region` defaults to `us-east4`. **Never commit `*.tfvars` or state** — they may carry
project identifiers (see `.gitignore`). The `.terraform.lock.hcl` **is** committed (the
supply-chain pin).

## Notes

- **IaC gate:** `terraform fmt`/`validate` + **Trivy config** misconfiguration scan in
  CI (SHA-pinned actions, pinned tool versions). Trivy is the maintained successor to
  tfsec (same Terraform check set).
- **Secret-access scoping:** the workload SA is granted `secretmanager.secretAccessor`
  **scoped by IAM condition to Console7-managed secrets** (name prefix) and **no
  human/group** is granted any read path — the `SecretsProvider` "no operator read
  path" property holds for humans/groups by construction. The IAM condition uses the
  project number and is verified against the live project at first apply.
- **Deferred by design (not dropped):** project/billing creation (human bootstrap), API
  enablement (bootstrap), per-user keys/secrets (runtime provider code), and the GKE
  Workload Identity binding of the secrets SA (the `gke` module — it needs the cluster
  KSA, so the module only *outputs* the SA email to avoid a dangling reference).
