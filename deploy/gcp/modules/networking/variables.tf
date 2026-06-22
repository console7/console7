variable "project_id" {
  type        = string
  description = "Existing GCP project to deploy the sandbox VPC into."
}

variable "region" {
  type        = string
  description = "Region for the sandbox subnet, Cloud Router, and NAT."
}

variable "name_prefix" {
  type        = string
  description = "Prefix for the VPC, subnet, router, NAT, and firewall resource names. Same bound as the rest of the deploy so derived names stay valid."

  validation {
    condition     = can(regex("^[a-z]([a-z0-9-]{0,17}[a-z0-9])?$", var.name_prefix))
    error_message = "name_prefix must be 1-19 chars, start with a lowercase letter, contain only lowercase letters/digits/hyphens, and not end with a hyphen."
  }
}

variable "sandbox_node_tag" {
  type        = string
  description = "Network tag the sandbox node pool (modules/gke, PR-2) carries. The default-deny egress + metadata-deny firewall rules target THIS tag, so only sandbox-tagged workloads are walled — the control-plane / egress-proxy nodes carry a different tag and keep their sanctioned NAT egress."

  validation {
    condition     = can(regex("^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$", var.sandbox_node_tag))
    error_message = "sandbox_node_tag must be a valid GCE network tag: 1-63 chars, lowercase letter first, lowercase letters/digits/hyphens, not ending in a hyphen."
  }
}

variable "egress_proxy_port" {
  type        = number
  default     = 3128
  description = "TCP port the in-cluster forward proxy (Squid; deploy/gcp/modules/egress-proxy) listens on. The sandbox->proxy ALLOW firewall rule pins to it; it MUST match the per-session NetworkPolicy port and providers/cloud-gcp proxyPort (3128). Default 3128."

  validation {
    condition     = var.egress_proxy_port > 1024 && var.egress_proxy_port <= 65535
    error_message = "egress_proxy_port must be an unprivileged TCP port (1025-65535)."
  }
}

variable "subnet_cidr_range" {
  type        = string
  description = "Primary CIDR for the sandbox subnet (node IPs)."

  # Require network-address form (host bits zero): google_compute_subnetwork.ip_cidr_range rejects
  # e.g. "10.0.0.5/20" at APPLY, so reject it at PLAN where the error is cheap and local.
  validation {
    condition     = can(cidrhost(var.subnet_cidr_range, 0)) && var.subnet_cidr_range == format("%s/%s", try(cidrhost(var.subnet_cidr_range, 0), ""), try(split("/", var.subnet_cidr_range)[1], ""))
    error_message = "subnet_cidr_range must be a valid CIDR in network-address form (host bits zero), e.g. \"10.0.0.0/20\"."
  }
}

variable "pod_cidr_range" {
  type        = string
  description = "Secondary CIDR for GKE pod IPs (modules/gke aliases this range)."

  validation {
    condition     = can(cidrhost(var.pod_cidr_range, 0)) && var.pod_cidr_range == format("%s/%s", try(cidrhost(var.pod_cidr_range, 0), ""), try(split("/", var.pod_cidr_range)[1], ""))
    error_message = "pod_cidr_range must be a valid CIDR in network-address form (host bits zero), e.g. \"10.4.0.0/14\"."
  }
}

variable "service_cidr_range" {
  type        = string
  description = "Secondary CIDR for GKE service (ClusterIP) addresses."

  validation {
    condition     = can(cidrhost(var.service_cidr_range, 0)) && var.service_cidr_range == format("%s/%s", try(cidrhost(var.service_cidr_range, 0), ""), try(split("/", var.service_cidr_range)[1], ""))
    error_message = "service_cidr_range must be a valid CIDR in network-address form (host bits zero), e.g. \"10.8.0.0/20\"."
  }
}
