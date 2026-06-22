variable "project_id" {
  type        = string
  description = "Existing GCP project to deploy into (owns and is billed for the sandbox-image repository)."
}

variable "region" {
  type        = string
  description = "Location for the Artifact Registry repository. Images stay in this region (no egress of adopter artifacts; GOAL.md tenet 1)."
}

variable "name_prefix" {
  type        = string
  description = "Prefix used as the repository_id (kept consistent with the other deploy modules). The published image path is \"<region>-docker.pkg.dev/<project>/<name_prefix>/<image>\"."

  validation {
    condition     = can(regex("^[a-z]([a-z0-9-]{0,17}[a-z0-9])?$", var.name_prefix))
    error_message = "name_prefix must be 1-19 chars, start with a lowercase letter, contain only lowercase letters/digits/hyphens, and not end with a hyphen."
  }
}

variable "node_service_account_email" {
  type        = string
  description = "Email of the EXISTING GKE node SA (modules/gke's node_service_account_email output) to grant repo-scoped pull access to. This module adds roles/artifactregistry.reader on THIS repository only; it does not mint an identity and grants no push/delete/admin."
}
