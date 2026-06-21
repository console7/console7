provider "google" {
  project = var.project_id
  region  = var.region
}

module "secrets" {
  source = "./modules/secrets"

  project_id          = var.project_id
  region              = var.region
  name_prefix         = var.name_prefix
  kms_rotation_period = var.kms_rotation_period
}

# In-tenancy inference (Vertex AI): enables the API and grants the control-plane workload SA
# a predict-only role. Reuses the secrets module's workload SA — least privilege composes by
# adding one verb to the one identity, rather than minting a second SA. The APPLY identity
# already holds serviceUsageAdmin / iam.roleAdmin / projectIamAdmin (bootstrap), which is all
# this module's API-enable + custom-role + IAM-binding need.
module "inference_vertex" {
  source = "./modules/inference-vertex"

  project_id                     = var.project_id
  region                         = var.region
  name_prefix                    = var.name_prefix
  workload_service_account_email = module.secrets.workload_service_account_email
}

# Durable WORM evidence backing (GCS): the bucket the EvidenceSink commits records through, plus
# an append-only (create/get/list, no delete) grant to the same workload SA via an AUTHORITATIVE
# bucket policy — omitting delete blocks both delete AND overwrite on the append identity (GCS
# overwrite needs objects.delete), and the authoritative policy strips the default project-viewer
# object-read convenience grant. The retention LOCK is the authoritative WORM control against a
# privileged actor; it is plumbed through from the root var.evidence_retention_locked (default off),
# so the dogfood posture is tamper-EVIDENT (the Sink's hash-chain detects mutation) but a production
# deploy enables it WITHOUT editing module source by setting evidence_retention_locked = true
# (irreversible). The APPLY identity needs storage bucket-admin for create + retention (bootstrap.sh).
module "evidence" {
  source = "./modules/evidence"

  project_id                     = var.project_id
  region                         = var.region
  name_prefix                    = var.name_prefix
  workload_service_account_email = module.secrets.workload_service_account_email
  retention_seconds              = var.evidence_retention_seconds
  is_locked                      = var.evidence_retention_locked
}
