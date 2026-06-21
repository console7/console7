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

variable "sandbox_node_tag" {
  type        = string
  description = "Network tag the sandbox node pool (modules/gke, deferred) carries. The default-deny egress + metadata-deny firewall rules target this tag, so ONLY sandbox-tagged workloads are walled; the control-plane / egress-proxy nodes carry a different tag and keep their sanctioned NAT egress."
  default     = "console7-sandbox"

  validation {
    condition     = can(regex("^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$", var.sandbox_node_tag))
    error_message = "sandbox_node_tag must be a valid GCE network tag: 1-63 chars, lowercase letter first, lowercase letters/digits/hyphens, not ending in a hyphen."
  }
}

variable "sandbox_subnet_cidr" {
  type        = string
  description = "Primary CIDR for the sandbox subnet (node IPs)."
  default     = "10.0.0.0/20"

  # Network-address form (host bits zero): the subnetwork resource rejects host-bit-set CIDRs at
  # apply, so reject them at plan.
  validation {
    condition     = can(cidrhost(var.sandbox_subnet_cidr, 0)) && var.sandbox_subnet_cidr == format("%s/%s", try(cidrhost(var.sandbox_subnet_cidr, 0), ""), try(split("/", var.sandbox_subnet_cidr)[1], ""))
    error_message = "sandbox_subnet_cidr must be a valid CIDR in network-address form (host bits zero), e.g. \"10.0.0.0/20\"."
  }
}

variable "sandbox_pod_cidr" {
  type        = string
  description = "Secondary CIDR for GKE pod IPs in the sandbox subnet (modules/gke aliases this range)."
  default     = "10.4.0.0/14"

  validation {
    condition     = can(cidrhost(var.sandbox_pod_cidr, 0)) && var.sandbox_pod_cidr == format("%s/%s", try(cidrhost(var.sandbox_pod_cidr, 0), ""), try(split("/", var.sandbox_pod_cidr)[1], ""))
    error_message = "sandbox_pod_cidr must be a valid CIDR in network-address form (host bits zero), e.g. \"10.4.0.0/14\"."
  }
}

variable "sandbox_service_cidr" {
  type        = string
  description = "Secondary CIDR for GKE service (ClusterIP) addresses in the sandbox subnet."
  default     = "10.8.0.0/20"

  validation {
    condition     = can(cidrhost(var.sandbox_service_cidr, 0)) && var.sandbox_service_cidr == format("%s/%s", try(cidrhost(var.sandbox_service_cidr, 0), ""), try(split("/", var.sandbox_service_cidr)[1], ""))
    error_message = "sandbox_service_cidr must be a valid CIDR in network-address form (host bits zero), e.g. \"10.8.0.0/20\"."
  }
}

variable "gke_master_authorized_cidrs" {
  type = list(object({
    cidr_block   = string
    display_name = string
  }))
  description = "Source ranges allowed to reach the GKE control-plane public endpoint. GATING: the default (empty) is fail-CLOSED — the cluster control plane is UNREACHABLE from outside Google's network, so the keyless CD's `kubectl apply -f reaper.yaml` and providers/cloud-gcp's `gcloud container clusters get-credentials` will be REFUSED until you add the operator/CD egress range here. Set this to the CD egress CIDR (and any admin bastion); never 0.0.0.0/0."
  default     = []
}

variable "gke_control_plane_ksa" {
  type        = string
  description = "Kubernetes \"<namespace>/<serviceaccount>\" the control plane runs as, bound to the secrets workload SA via Workload Identity. Override if you run the control plane under a non-default KSA (else the WI binding targets a KSA that never exists and is inert)."
  default     = "console7-system/console7-control-plane"
}

variable "gke_deletion_protection" {
  type        = bool
  description = "Block `terraform destroy` of the GKE cluster. PRODUCTION SHOULD set true; default false so dev/dogfood clusters stay destroyable (mirrors evidence_retention_locked)."
  default     = false
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
