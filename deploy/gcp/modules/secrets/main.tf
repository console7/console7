# Console7 secrets infrastructure: a KMS key ring + CMEK for Secret Manager envelope
# encryption, and the least-privilege workload identity the control plane impersonates
# to reach secrets. Upholds the SecretsProvider SECURITY contract
# (providers/secrets-gcp): no operator read path, scoped access; per-user keys/secrets
# are minted at RUNTIME by the provider, never declared here.
#
# Prerequisite (bootstrap, not this module): cloudkms.googleapis.com and
# secretmanager.googleapis.com are already enabled on the project.

resource "google_kms_key_ring" "this" {
  project  = var.project_id
  name     = "${var.name_prefix}-secrets"
  location = var.region
}

# CMEK protecting Console7-managed Secret Manager material. Auto-rotated; guarded
# against accidental destroy — losing this key cryptographically shreds every secret
# it wraps.
resource "google_kms_crypto_key" "secrets" {
  name            = "${var.name_prefix}-secret-manager-cmek"
  key_ring        = google_kms_key_ring.this.id
  purpose         = "ENCRYPT_DECRYPT"
  rotation_period = var.kms_rotation_period

  lifecycle {
    prevent_destroy = true
  }
}

# The identity the control plane assumes (via GKE Workload Identity, bound in the gke
# module — deferred, as it needs the cluster KSA) to reach secrets. Created with NO
# human impersonation binding, so there is no operator read path by construction.
resource "google_service_account" "workload" {
  project      = var.project_id
  account_id   = "${var.name_prefix}-cp-secrets"
  display_name = "Console7 control-plane secrets workload identity (least-privilege; no operator read path)"
}

# Encrypt/decrypt on ONLY this CMEK — not project-wide KMS access.
resource "google_kms_crypto_key_iam_member" "workload_encrypt_decrypt" {
  crypto_key_id = google_kms_crypto_key.secrets.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${google_service_account.workload.email}"
}

# The project number is required for the Secret Manager IAM condition below — its
# resource.name uses the project NUMBER, not the ID.
data "google_project" "this" {
  project_id = var.project_id
}

# Secret access granted to the workload SA alone — never to a human or group, so the
# operator read path is closed for humans/groups by construction — and further scoped
# by IAM condition to Console7-managed secrets only (name prefix), upholding least
# privilege (tenet 5) and the "never pool" contract at the infra floor. The condition
# only narrows access, so a mis-specified expression fails closed (denies, never
# over-grants); verify against the live project at first apply.
resource "google_project_iam_member" "workload_secret_accessor" {
  project = var.project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.workload.email}"

  condition {
    title       = "console7-managed-secrets-only"
    description = "Restrict the workload SA to Console7-managed secrets by name prefix."
    expression  = "resource.name.startsWith(\"projects/${data.google_project.this.number}/secrets/${var.name_prefix}-\")"
  }
}
