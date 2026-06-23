output "signing_key_version" {
  description = "Full Cloud KMS CryptoKeyVersion resource id of the CA root signing key (version 1) — providers/keybroker-gcp Config.KeyVersionName. AsymmetricSign/GetPublicKey operate on a version, and the key's first version is created ENABLED with the key. Pins v1 deliberately (rotation is omitted so the anchor is stable); if a version is ever added, the consumer's pinned version + the verifiers' anchor must be updated together."
  value       = "${google_kms_crypto_key.nhi_ca.id}/cryptoKeyVersions/1"
}

output "keybroker_service_account_email" {
  description = "Email of the keybroker signing SA (distinct from the secrets workload SA; holds cloudkms.signerVerifier on the signing key only). Its GKE Workload Identity binding is deferred to the gke module / production wiring."
  value       = google_service_account.keybroker.email
}

output "kms_key_ring_id" {
  description = "Resource ID of the keybroker KMS key ring (distinct from the secrets key ring)."
  value       = google_kms_key_ring.this.id
}
