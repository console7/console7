variable "project_id" {
  type        = string
  description = "Existing GCP project to deploy into (owns and is billed for the evidence bucket)."
}

variable "region" {
  type        = string
  description = "Location for the evidence bucket. Evidence stays in this region (no egress of adopter data; GOAL.md tenet 1)."
}

variable "name_prefix" {
  type        = string
  description = "Prefix for the bucket name and the custom-role id (kept consistent with the other deploy modules)."

  validation {
    condition     = can(regex("^[a-z]([a-z0-9-]{0,17}[a-z0-9])?$", var.name_prefix))
    error_message = "name_prefix must be 1-19 chars, start with a lowercase letter, contain only lowercase letters/digits/hyphens, and not end with a hyphen."
  }
}

variable "workload_service_account_email" {
  type        = string
  description = "Email of the EXISTING control-plane workload SA to grant evidence object write/read to (e.g. modules/secrets' workload_service_account_email output). This module adds object create/get/list at bucket scope to that identity; it does not mint a new SA, and grants NO delete or overwrite."
}

variable "retention_seconds" {
  type        = number
  description = "Object retention period in seconds. While in force, objects cannot be deleted or overwritten — the durable WORM control under the hash-chain. Default 7 years (regulatory-evidence default); tune to the adopter's retention policy."
  default     = 220752000 # 7 years

  validation {
    condition     = var.retention_seconds > 0
    error_message = "retention_seconds must be positive (a retention policy is required for WORM)."
  }
}

variable "is_locked" {
  type        = bool
  description = "Whether to LOCK the retention policy. CONSEQUENCE: with the lock OFF (the default), the retention policy can be removed or shortened by any holder of storage.buckets.update (e.g. the deploy identity), after which committed evidence can be deleted — so the default posture is tamper-EVIDENT (the Sink's signed hash-chain detects mutation/truncation) but NOT tamper-RESISTANT against a privileged actor. Setting this true makes the WORM guarantee authoritative (GOAL.md tenet 3; tenet 7) but is IRREVERSIBLE: the policy can never be removed or shortened and objects under retention can never be deleted (terraform destroy of the bucket will fail until retention expires). Default false so dev/dogfood buckets stay destroyable; production sets this true deliberately."
  default     = false
}
