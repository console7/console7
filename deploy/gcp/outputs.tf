output "secrets_workload_service_account_email" {
  description = "Email of the least-privilege SA the control plane impersonates to reach secrets. The GKE Workload Identity binding is wired by the gke module (deferred)."
  value       = module.secrets.workload_service_account_email
}

output "secrets_kms_crypto_key_id" {
  description = "Resource ID of the secrets KEK (key-encryption key for provider-side per-user-DEK envelope encryption)."
  value       = module.secrets.kms_crypto_key_id
}

output "inference_vertex_endpoint_url" {
  description = "The in-tenancy regional Vertex inference endpoint URL (scheme-qualified). Seed the session's default-deny egress allowlist with this verbatim — the orchestrator matches the resolved BackendEndpoint.URL against the allowlist by exact string."
  value       = module.inference_vertex.endpoint_url
}

output "sandbox_network_self_link" {
  description = "Self-link of the sandbox VPC. modules/gke (deferred) attaches the sandbox node pool to this network."
  value       = module.networking.network_self_link
}

output "sandbox_subnetwork_self_link" {
  description = "Self-link of the sandbox subnet. modules/gke attaches the node pool here; its pod/service secondary ranges back the cluster's alias IPs."
  value       = module.networking.subnetwork_self_link
}

output "sandbox_pods_range_name" {
  description = "Pod secondary-range name. Wire into modules/gke ip_allocation_policy.cluster_secondary_range_name verbatim (string-exact — matched by name)."
  value       = module.networking.pods_range_name
}

output "sandbox_services_range_name" {
  description = "Service secondary-range name. Wire into modules/gke ip_allocation_policy.services_secondary_range_name verbatim (string-exact)."
  value       = module.networking.services_range_name
}

output "sandbox_node_tag" {
  description = "The network tag the default-deny egress + metadata-deny rules target. modules/gke MUST stamp this exact tag onto the sandbox node pool or the wall does not apply (string-exact)."
  value       = module.networking.sandbox_node_tag
}

output "evidence_bucket_name" {
  description = "Name of the durable WORM evidence bucket. Wire it into providers/evidence-gcs Config.Bucket so the EvidenceSink commits records here. Evidence stays in the adopter's tenancy (GOAL.md tenet 1)."
  value       = module.evidence.bucket_name
}
