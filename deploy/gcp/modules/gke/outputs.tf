output "cluster_name" {
  description = "GKE cluster name. Wire into providers/cloud-gcp Config.Cluster verbatim (string-exact)."
  value       = google_container_cluster.sandbox.name
}

output "cluster_location" {
  description = "GKE cluster location (region). Wire into providers/cloud-gcp Config.Location verbatim."
  value       = google_container_cluster.sandbox.location
}

output "sandbox_node_pool" {
  description = "Name of the gVisor sandbox node pool. Wire into providers/cloud-gcp Config.NodePool verbatim — the provider preflights its workloadMetadataConfig.mode == GKE_METADATA (string-exact)."
  value       = google_container_node_pool.sandbox.name
}

output "control_node_pool" {
  description = "Name of the control-plane node pool."
  value       = google_container_node_pool.control.name
}

output "node_service_account_email" {
  description = "Email of the least-privilege node SA both pools run as."
  value       = google_service_account.nodes.email
}

output "nat_name" {
  description = "Name of the Cloud NAT serving the sanctioned (non-sandbox-tagged) egress path."
  value       = google_compute_router_nat.sandbox.name
}
