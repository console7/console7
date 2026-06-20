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
