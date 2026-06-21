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
