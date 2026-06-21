variable "project_id" {
  type        = string
  description = "Existing GCP project to deploy into (owns and is billed for the inference)."
}

variable "region" {
  type        = string
  description = "Vertex AI location, e.g. \"us-east5\". Used to derive the regional endpoint host output; inference stays in this region."

  validation {
    # Mirror the provider's host-injection guard (providers/inference-vertex regionPattern):
    # the region is interpolated into the endpoint host, so bound it to GCP's location grammar.
    condition     = can(regex("^[a-z]+-[a-z]+[0-9]+$", var.region))
    error_message = "region must be a valid Vertex location like \"us-east5\" or \"europe-west1\"."
  }
}

variable "name_prefix" {
  type        = string
  description = "Prefix for the custom-role id (kept consistent with the other deploy modules)."

  validation {
    condition     = can(regex("^[a-z]([a-z0-9-]{0,17}[a-z0-9])?$", var.name_prefix))
    error_message = "name_prefix must be 1-19 chars, start with a lowercase letter, contain only lowercase letters/digits/hyphens, and not end with a hyphen."
  }
}

variable "workload_service_account_email" {
  type        = string
  description = "Email of the EXISTING control-plane/sandbox workload SA to grant Vertex predict to (e.g. modules/secrets' workload_service_account_email output). This module adds exactly one verb to that identity; it does not mint a new SA."
}
