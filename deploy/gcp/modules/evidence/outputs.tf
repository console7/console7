output "bucket_name" {
  description = "Name of the durable WORM evidence bucket. Wire it into providers/evidence-gcs Config.Bucket so the EvidenceSink commits records here. Evidence stays in the adopter's tenancy and is never egressed to the maintainer (GOAL.md tenet 1)."
  value       = google_storage_bucket.evidence.name
}

output "bucket_url" {
  description = "The gs:// URL of the evidence bucket (operator convenience)."
  value       = google_storage_bucket.evidence.url
}

output "evidence_writer_role_id" {
  description = "Resource ID of the least-privilege append-only object-writer custom role bound to the workload SA at bucket scope (create/get/list only — no delete, no overwrite)."
  value       = google_project_iam_custom_role.evidence_writer.id
}
