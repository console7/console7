# Console7 secrets substrate: a KMS key ring + a key-encryption key (KEK), and the
# least-privilege workload identity the control plane impersonates.
#
# The KEK is used by the SecretsProvider (providers/secrets-gcp) for PROVIDER-SIDE
# envelope encryption — wrapping per-user data-encryption keys at runtime (the GCP
# analogue of sdk/devkit MemSecrets' KEK-wrapped-per-user-DEK model, upholding the
# "per-user key, never pool" contract). It is NOT a Secret-Manager-configured CMEK, so
# the WORKLOAD SA (not the Secret Manager service agent) holds encrypt/decrypt on it.
#
# Scope: this module provisions the KMS substrate, the workload identity, AND (added
# atomically with providers/secrets-gcp) the Secret Manager API + the provider's own
# least-privilege Secret Manager role for that workload SA. The role grants exactly the
# verbs the provider calls (create / add-version / access / get / delete) and nothing
# else — no list, no getIamPolicy/setIamPolicy, so there is no enumeration or
# self-grant path.
#
# Prerequisite (bootstrap, not this module): cloudkms.googleapis.com enabled on the
# project; this module enables secretmanager.googleapis.com.

resource "google_kms_key_ring" "this" {
  project  = var.project_id
  name     = "${var.name_prefix}-secrets"
  location = var.region
}

# The key-encryption key (KEK) the provider uses for per-user-DEK envelope encryption.
# Auto-rotated; guarded against accidental destroy — losing it cryptographically shreds
# every per-user DEK (and thus every secret) it wraps.
resource "google_kms_crypto_key" "secrets" {
  name            = "${var.name_prefix}-secrets-kek"
  key_ring        = google_kms_key_ring.this.id
  purpose         = "ENCRYPT_DECRYPT"
  rotation_period = var.kms_rotation_period

  lifecycle {
    prevent_destroy = true
  }
}

# The identity the control plane assumes (via GKE Workload Identity, bound in the gke
# module — deferred, as it needs the cluster KSA). Created with NO human impersonation
# binding, so there is no operator read path by construction. Its Secret Manager role
# bindings land with providers/secrets-gcp.
resource "google_service_account" "workload" {
  project      = var.project_id
  account_id   = "${var.name_prefix}-cp-secrets"
  display_name = "Console7 control-plane secrets workload identity (least-privilege; no operator read path)"
}

# Encrypt/decrypt on ONLY this KEK — the workload SA wraps/unwraps per-user DEKs with it
# (provider-side envelope encryption); not project-wide KMS access.
resource "google_kms_crypto_key_iam_member" "workload_encrypt_decrypt" {
  crypto_key_id = google_kms_crypto_key.secrets.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${google_service_account.workload.email}"
}

# --- Secret Manager: API + the provider's least-privilege role (lands with secrets-gcp) ---

# The provider stores each user's sealed payload (KEK-wrapped DEK + GCM-sealed token) as one
# per-subject Secret Manager secret. Enable the API here; cloudkms is a bootstrap prerequisite.
resource "google_project_service" "secretmanager" {
  project = var.project_id
  service = "secretmanager.googleapis.com"

  # Don't disable the API on `terraform destroy` — other resources/users in the project may
  # depend on it, and re-enabling is slow.
  disable_on_destroy = false
}

# A custom role with EXACTLY the verbs providers/secrets-gcp calls — CreateSecret,
# AddSecretVersion, AccessSecretVersion, DeleteSecret — and nothing more. No
# roles/secretmanager.admin (which bundles setIamPolicy and a broad surface), no *.get/*.list
# (no enumeration or existence-probing beyond what the provider needs), no
# getIamPolicy/setIamPolicy (no self-grant). This verb set IS the least-privilege boundary; the
# predefined roles cannot express create+delete without admin, so a custom role is the only fit.
resource "google_project_iam_custom_role" "secrets_workload" {
  project     = var.project_id
  role_id     = "${replace(var.name_prefix, "-", "_")}_secrets_workload"
  title       = "Console7 secrets workload (least-privilege Secret Manager)"
  description = "Create/add-version/access/delete on the provider's per-user subscription secrets only. No get, no list, no IAM-policy verbs."
  stage       = "GA"
  permissions = [
    "secretmanager.secrets.create",
    "secretmanager.secrets.delete",
    "secretmanager.versions.add",
    "secretmanager.versions.access",
  ]
}

# Bind the custom role to the workload SA at project scope. A name-prefix IAM condition
# (resource.name.startsWith(".../secrets/<prefix>-sub-")) is deliberately NOT applied: the
# create verb is evaluated against the project parent, so such a condition would deny every
# secret create. The custom role's narrow verb set is the boundary; tightening to a condition on
# the non-create verbs is a possible future hardening once verified against live IAM.
resource "google_project_iam_member" "workload_secrets" {
  project = var.project_id
  role    = google_project_iam_custom_role.secrets_workload.id
  member  = "serviceAccount:${google_service_account.workload.email}"
}
