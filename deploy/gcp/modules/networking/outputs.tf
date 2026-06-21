output "network_self_link" {
  description = "Self-link of the sandbox VPC. modules/gke (PR-2) attaches the sandbox node pool to this network verbatim."
  value       = google_compute_network.sandbox.self_link
}

output "network_id" {
  description = "Resource ID of the sandbox VPC."
  value       = google_compute_network.sandbox.id
}

output "subnetwork_self_link" {
  description = "Self-link of the sandbox subnet. modules/gke attaches the node pool to this subnet."
  value       = google_compute_subnetwork.sandbox.self_link
}

# The range-name outputs derive from the SAME literal expressions that name the secondary ranges
# in main.tf — not a positional index into secondary_ip_range[] — so a future reorder of the
# blocks can never silently swap the pods/services ranges into the wrong GKE alias.
output "pods_range_name" {
  description = "Name of the pod secondary range. Wire into modules/gke ip_allocation_policy.cluster_secondary_range_name verbatim (string-exact — it is matched by name)."
  value       = "${var.name_prefix}-sandbox-pods"
}

output "services_range_name" {
  description = "Name of the service secondary range. Wire into modules/gke ip_allocation_policy.services_secondary_range_name verbatim (string-exact)."
  value       = "${var.name_prefix}-sandbox-services"
}

output "sandbox_node_tag" {
  description = "The network tag the default-deny egress + metadata-deny rules target. modules/gke MUST stamp this exact tag onto the sandbox node pool, or the wall does not apply (string-exact)."
  value       = var.sandbox_node_tag
}
