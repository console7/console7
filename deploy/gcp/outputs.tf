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
