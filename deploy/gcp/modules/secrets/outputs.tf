output "workload_service_account_email" {
  description = "Email of the least-privilege secrets workload SA (no human impersonation binding here; the GKE Workload Identity binding is deferred to the gke module)."
  value       = google_service_account.workload.email
}

output "kms_crypto_key_id" {
  description = "Resource ID of the secrets KEK (the key-encryption key the provider wraps per-user DEKs with)."
  value       = google_kms_crypto_key.secrets.id
}

output "kms_key_ring_id" {
  description = "Resource ID of the KMS key ring."
  value       = google_kms_key_ring.this.id
}
