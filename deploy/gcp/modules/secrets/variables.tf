variable "project_id" {
  type        = string
  description = "Existing GCP project to deploy into."
}

variable "region" {
  type        = string
  description = "Region for the KMS key ring."
}

variable "name_prefix" {
  type        = string
  description = "Prefix for resource names and the managed-secret naming convention. Bounded to keep the derived service-account account_id (\"<prefix>-cp-secrets\") within GCP's 30-char limit."

  validation {
    condition     = can(regex("^[a-z]([a-z0-9-]{0,17}[a-z0-9])?$", var.name_prefix))
    error_message = "name_prefix must be 1-19 chars, start with a lowercase letter, contain only lowercase letters/digits/hyphens, and not end with a hyphen."
  }
}

variable "kms_rotation_period" {
  type        = string
  description = "CMEK auto-rotation period in seconds (e.g. \"7776000s\")."
}
