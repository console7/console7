variable "project_id" {
  type        = string
  description = "Existing GCP project to deploy the GKE cluster into."
}

variable "region" {
  type        = string
  description = "Region for the regional GKE cluster and the Cloud Router/NAT."
}

variable "name_prefix" {
  type        = string
  description = "Prefix for the cluster, node pools, node SA, router, and NAT names. Must match the networking/secrets modules' name_prefix."

  validation {
    condition     = can(regex("^[a-z]([a-z0-9-]{0,17}[a-z0-9])?$", var.name_prefix))
    error_message = "name_prefix must be 1-19 chars, start with a lowercase letter, contain only lowercase letters/digits/hyphens, and not end with a hyphen."
  }
}

variable "network_self_link" {
  type        = string
  description = "Self-link of the sandbox VPC (modules/networking.network_self_link)."
}

variable "subnetwork_self_link" {
  type        = string
  description = "Self-link of the sandbox subnet (modules/networking.subnetwork_self_link)."
}

variable "pods_range_name" {
  type        = string
  description = "Pod secondary-range NAME on the subnet (modules/networking.pods_range_name) — matched by name for the cluster's alias IPs."
}

variable "services_range_name" {
  type        = string
  description = "Service secondary-range NAME on the subnet (modules/networking.services_range_name)."
}

variable "sandbox_node_tag" {
  type        = string
  description = "Network tag stamped onto the SANDBOX node pool so the networking module's default-deny egress firewall applies to it (modules/networking.sandbox_node_tag). String-exact."

  validation {
    condition     = can(regex("^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$", var.sandbox_node_tag))
    error_message = "sandbox_node_tag must be a valid GCE network tag."
  }
}

variable "secrets_workload_service_account_email" {
  type        = string
  description = "Email of the control-plane secrets workload SA (modules/secrets.workload_service_account_email). The control-plane KSA is granted Workload-Identity-User on it so it can impersonate it — no key file."
}

variable "control_plane_ksa" {
  type        = string
  description = "Kubernetes namespace/serviceaccount the control plane runs as, bound to the secrets workload SA via Workload Identity, in \"<namespace>/<name>\" form."
  default     = "console7-system/console7-control-plane"

  validation {
    condition     = can(regex("^[a-z0-9]([a-z0-9-]*[a-z0-9])?/[a-z0-9]([a-z0-9-]*[a-z0-9])?$", var.control_plane_ksa))
    error_message = "control_plane_ksa must be \"<namespace>/<serviceaccount>\", each a valid DNS-1123 label."
  }
}

variable "master_ipv4_cidr" {
  type        = string
  description = "RFC-1918 /28 for the private cluster's hosted control-plane endpoint. Must not overlap the subnet or its secondary ranges."
  default     = "172.16.0.0/28"

  validation {
    condition     = can(cidrhost(var.master_ipv4_cidr, 0)) && tonumber(split("/", var.master_ipv4_cidr)[1]) == 28
    error_message = "master_ipv4_cidr must be a /28 CIDR, e.g. \"172.16.0.0/28\"."
  }
}

variable "master_authorized_cidrs" {
  type = list(object({
    cidr_block   = string
    display_name = string
  }))
  description = "Operator/CD source ranges allowed to reach the cluster's public control-plane endpoint (the keyless CD identity, an admin bastion). Empty = no external access to the control plane (only Google-internal). Production SHOULD scope this to the CD egress range, never 0.0.0.0/0."
  default     = []
}

variable "release_channel" {
  type        = string
  description = "GKE release channel (RAPID/REGULAR/STABLE) — auto-upgrade cadence. REGULAR balances currency and stability."
  default     = "REGULAR"

  validation {
    condition     = contains(["RAPID", "REGULAR", "STABLE"], var.release_channel)
    error_message = "release_channel must be RAPID, REGULAR, or STABLE."
  }
}

variable "sandbox_node_machine_type" {
  type        = string
  description = "Machine type for the gVisor sandbox node pool."
  default     = "e2-standard-4"
}

variable "control_node_machine_type" {
  type        = string
  description = "Machine type for the control-plane node pool."
  default     = "e2-standard-2"
}

variable "deletion_protection" {
  type        = bool
  description = "Block `terraform destroy` of the cluster. PRODUCTION SHOULD set true; default false so dev/dogfood clusters stay destroyable (matches evidence_retention_locked posture)."
  default     = false
}
