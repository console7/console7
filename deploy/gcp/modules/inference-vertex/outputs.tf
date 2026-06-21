output "vertex_predict_role_id" {
  description = "Resource ID of the least-privilege Vertex predict custom role bound to the workload SA."
  value       = google_project_iam_custom_role.vertex_predict.id
}

output "endpoint_url" {
  description = "The in-tenancy regional Vertex endpoint URL the providers/inference-vertex backend resolves to for this region. Emitted scheme-qualified to match BackendEndpoint.URL EXACTLY — the orchestrator's egress check (control-plane/orchestrator onAllowlist) compares the resolved URL to allowlist entries by exact string, so seed the session's default-deny allowlist with this value verbatim. Enabling predict here does not make it reachable (GOAL.md tenet 3). NOTE: reflects the regional host only; a Global or EndpointBaseURL (PSC/VPC-SC) deployment must allowlist its own configured endpoint instead."
  value       = "https://${var.region}-aiplatform.googleapis.com"
}
