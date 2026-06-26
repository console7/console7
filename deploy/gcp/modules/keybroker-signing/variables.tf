variable "project_id" {
  type        = string
  description = "Existing GCP project to deploy into."
}

variable "region" {
  type        = string
  description = "Region for the keybroker signing KMS key ring."
}

variable "name_prefix" {
  type        = string
  description = "Prefix for resource names. Bounded so the derived service-account account_id (\"<prefix>-keybroker\") stays within GCP's 30-char limit."

  validation {
    condition     = can(regex("^[a-z]([a-z0-9-]{0,17}[a-z0-9])?$", var.name_prefix))
    error_message = "name_prefix must be 1-19 chars, start with a lowercase letter, contain only lowercase letters/digits/hyphens, and not end with a hyphen."
  }
}

variable "kms_protection_level" {
  type        = string
  default     = "SOFTWARE"
  description = "Protection level for the signing key (SOFTWARE or HSM). This is the single most security-critical key in the system — its private half anchors the entire human->NHI->action lineage chain — so a Tier-1 PRODUCTION deploy SHOULD set HSM (the RUNBOOK calls this out). SOFTWARE is the lower-cost default for dogfood/PoC (and matches the secrets KEK), and is opt-up-able later without re-issuing already-signed evidence (a new HSM key is a new version/anchor)."

  validation {
    condition     = contains(["SOFTWARE", "HSM"], var.kms_protection_level)
    error_message = "kms_protection_level must be SOFTWARE or HSM."
  }
}

variable "require_hsm" {
  type        = bool
  default     = false
  description = "When true (a production deploy), the signing key MUST be HSM-backed — a plan-time precondition fails otherwise, so a production deploy cannot silently anchor lineage in a SOFTWARE key. Default false for dogfood/PoC (mirrors the evidence_retention_locked / destroy_protection prod-hardening knobs)."
}
