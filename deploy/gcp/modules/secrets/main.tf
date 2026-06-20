# Console7 secrets substrate: a KMS key ring + a key-encryption key (KEK), and the
# least-privilege workload identity the control plane impersonates.
#
# The KEK is used by the SecretsProvider (providers/secrets-gcp) for PROVIDER-SIDE
# envelope encryption — wrapping per-user data-encryption keys at runtime (the GCP
# analogue of sdk/devkit MemSecrets' KEK-wrapped-per-user-DEK model, upholding the
# "per-user key, never pool" contract). It is NOT a Secret-Manager-configured CMEK, so
# the WORKLOAD SA (not the Secret Manager service agent) holds encrypt/decrypt on it.
#
# Scope: this module provisions the KMS substrate + the workload identity only. The
# provider's own least-privilege Secret Manager role bindings (create / add-version /
# access / destroy, name-prefix scoped) land atomically with providers/secrets-gcp,
# where the exact needs are known — not guessed here ahead of the provider.
#
# Prerequisite (bootstrap, not this module): cloudkms.googleapis.com enabled on the
# project (secretmanager.googleapis.com is enabled with the provider PR).

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
