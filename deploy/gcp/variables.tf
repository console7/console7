variable "project_id" {
  type        = string
  description = "Existing GCP project to deploy into. This module never creates the project or links billing — that is the human bootstrap act (ADR-0002), so the same module serves new-project and existing-project adopters."

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.project_id))
    error_message = "project_id must be a valid GCP project ID (6-30 chars: lowercase letter first, then letters/digits/hyphens)."
  }
}

variable "region" {
  type        = string
  description = "GCP region for regional resources (KMS key ring, etc.)."
  default     = "us-east4"
}

variable "name_prefix" {
  type        = string
  description = "Prefix for Console7-managed resource names and the managed-secret naming convention. Bounded so the derived service-account account_id stays within GCP's 30-char limit."
  default     = "console7"

  validation {
    condition     = can(regex("^[a-z]([a-z0-9-]{0,17}[a-z0-9])?$", var.name_prefix))
    error_message = "name_prefix must be 1-19 chars, start with a lowercase letter, contain only lowercase letters/digits/hyphens, and not end with a hyphen."
  }
}

variable "kms_rotation_period" {
  type        = string
  description = "Auto-rotation period for the Secret Manager CMEK, in seconds (must end in 's'). Default 90 days."
  default     = "7776000s"

  validation {
    condition     = can(regex("^[1-9][0-9]*s$", var.kms_rotation_period))
    error_message = "kms_rotation_period must be a positive number of seconds, e.g. \"7776000s\" (90 days)."
  }
}

variable "evidence_retention_seconds" {
  type        = number
  description = "Evidence-bucket object retention period in seconds (the WORM window). Default 7 years."
  default     = 220752000
}

variable "evidence_retention_locked" {
  type        = bool
  description = "Whether to LOCK the evidence bucket's retention policy. PRODUCTION MUST set this true to make the WORM guarantee authoritative against a privileged actor (GOAL.md tenet 3; tenet 7) — surfaced at the root so operators need not edit module source. IRREVERSIBLE (the policy can never be removed/shortened; the bucket cannot be destroyed until retention expires). Default false so dev/dogfood buckets stay destroyable, leaving the default posture tamper-evident, not tamper-resistant."
  default     = false
}
