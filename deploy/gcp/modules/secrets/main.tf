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
# least-privilege Secret Manager access for that workload SA — TWO custom roles granting
# exactly the verbs the provider calls (create; add-version / access / delete) and nothing
# else: no get, no list (no enumeration), no getIamPolicy/setIamPolicy (no self-grant). The
# resource-scoped verbs are IAM-conditioned to the provider's "<prefix>-sub-*" secrets; see
# the role/binding block below for why create is separate and unconditioned.
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

# --- Inference-lane token mint (lands with secrets-gcp InjectInferenceCredential) ---

# IAM Credentials API: the provider mints a short-lived GCP bearer for the in-tenancy inference lane
# (Vertex) via GenerateAccessToken, so the sandbox authenticates from a delivered token instead of
# the (denied) node metadata server. cloudkms is a bootstrap prerequisite; enable this here.
resource "google_project_service" "iamcredentials" {
  project = var.project_id
  service = "iamcredentials.googleapis.com"
  # Don't disable on destroy — other project users may depend on it and re-enabling is slow.
  disable_on_destroy = false
}

# SELF-IMPERSONATION: the workload SA mints short-lived, scope-capped access tokens for ITSELF
# (the control plane already runs AS this SA via GKE Workload Identity; GenerateAccessToken downscopes
# that identity to a deadline-capped token the sandbox uses for Vertex). tokenCreator is granted on
# THIS one SA (resource = the SA itself), never project-wide, so the mint capability is scoped to a
# single identity. The token carries cloud-platform scope but the SA's only Vertex binding is
# aiplatform.endpoints.predict (deploy/gcp/modules/inference-vertex), so the scope grants no more
# than that. Omit this binding and the Vertex lane stays fail-closed (the provider refuses to mint).
resource "google_service_account_iam_member" "workload_self_token_creator" {
  service_account_id = google_service_account.workload.name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = "serviceAccount:${google_service_account.workload.email}"
}

# --- Secret Manager: API + the provider's least-privilege roles (lands with secrets-gcp) ---

# The provider stores each user's sealed payload (KEK-wrapped DEK + GCM-sealed token) as one
# per-subject Secret Manager secret. Enable the API here; cloudkms is a bootstrap prerequisite.
resource "google_project_service" "secretmanager" {
  project = var.project_id
  service = "secretmanager.googleapis.com"

  # Don't disable the API on `terraform destroy` — other resources/users in the project may
  # depend on it, and re-enabling is slow.
  disable_on_destroy = false
}

# The workload SA's Secret Manager access is split into TWO least-privilege grants so the
# blast radius of a compromise (or a name-construction bug) is bounded to the provider's own
# `<prefix>-sub-*` secrets — not every secret in the project:
#
#   1. CREATE is granted project-wide and UNCONDITIONED, because secretmanager.secrets.create
#      is evaluated against the project PARENT, not the to-be-created secret — an IAM condition
#      on resource.name would deny every create.
#   2. The resource-scoped verbs (versions.add / versions.access / secrets.delete) are granted
#      with an IAM CONDITION restricting them to secret names under "<prefix>-sub-". These are
#      evaluated against the secret/version resource, so the condition holds. A compromised
#      workload therefore cannot read, re-version, or delete unrelated application secrets.
#
# Neither role includes *.get/*.list (no enumeration) or getIamPolicy/setIamPolicy (no
# self-grant); roles/secretmanager.admin is far too broad. Predefined roles cannot express
# create+delete without admin, so custom roles are the only least-privilege fit.

# Project number is needed to build the fully-qualified resource.name the IAM condition matches.
data "google_project" "this" {
  project_id = var.project_id
}

resource "google_project_iam_custom_role" "secrets_create" {
  project     = var.project_id
  role_id     = "${replace(var.name_prefix, "-", "_")}_secrets_create"
  title       = "Console7 secrets workload — create"
  description = "secretmanager.secrets.create only (parent-scoped; cannot be name-conditioned)."
  stage       = "GA"
  permissions = ["secretmanager.secrets.create"]
}

resource "google_project_iam_custom_role" "secrets_rw" {
  project     = var.project_id
  role_id     = "${replace(var.name_prefix, "-", "_")}_secrets_rw"
  title       = "Console7 secrets workload — add/access/delete"
  description = "versions.add / versions.access / secrets.delete on the provider's secrets only."
  stage       = "GA"
  permissions = [
    "secretmanager.versions.add",
    "secretmanager.versions.access",
    "secretmanager.secrets.delete",
  ]
}

# CREATE: project-wide, unconditioned (parent-scoped verb).
resource "google_project_iam_member" "workload_secrets_create" {
  project = var.project_id
  role    = google_project_iam_custom_role.secrets_create.id
  member  = "serviceAccount:${google_service_account.workload.email}"
}

# ADD/ACCESS/DELETE: restricted to the provider's managed secrets — the per-subject subscription
# tokens ("<prefix>-sub-*") AND the single shared org API credential ("<prefix>-org", the org-API
# lane; providers/secrets-gcp SetOrgCredential/InjectOrgCredential). The org clause is an EXACT
# secret match plus its versions subtree ("<prefix>-org/...") so it covers versions.add/access on the
# org secret WITHOUT re-widening to look-alikes (e.g. "<prefix>-organization" matches neither).
resource "google_project_iam_member" "workload_secrets_rw" {
  project = var.project_id
  role    = google_project_iam_custom_role.secrets_rw.id
  member  = "serviceAccount:${google_service_account.workload.email}"

  condition {
    title       = "console7-managed-secrets-only"
    description = "Restrict to the provider's per-subject secrets (<prefix>-sub-*) and the shared org credential (<prefix>-org)."
    expression  = <<-EOT
      resource.name.startsWith("projects/${data.google_project.this.number}/secrets/${var.name_prefix}-sub-") ||
      resource.name == "projects/${data.google_project.this.number}/secrets/${var.name_prefix}-org" ||
      resource.name.startsWith("projects/${data.google_project.this.number}/secrets/${var.name_prefix}-org/")
    EOT
  }
}
