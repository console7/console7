output "vertex_predict_role_id" {
  description = "Resource ID of the least-privilege Vertex predict custom role bound to the workload SA."
  value       = google_project_iam_custom_role.vertex_predict.id
}

output "endpoint_host" {
  description = "The in-tenancy regional Vertex endpoint host the providers/inference-vertex backend resolves to. The deploy root MUST add this to the session's default-deny egress allowlist — enabling predict here does not make it reachable (GOAL.md tenet 3)."
  value       = "${var.region}-aiplatform.googleapis.com"
}
