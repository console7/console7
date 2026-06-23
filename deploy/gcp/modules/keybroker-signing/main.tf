# Keybroker signing identity (ARCHITECTURE.md §6.4): the cryptographic root of the lineage chain
# (human Subject -> per-session NHI -> signed commit/checkpoint), provisioned as a Cloud KMS
# asymmetric-sign key whose PRIVATE key never leaves KMS. providers/keybroker-gcp consumes the key
# version here; the in-process ed25519 DevCA is the dev-only stand-in.
#
# DISTINCT from the secrets substrate, deliberately: a SEPARATE key ring (not the secrets KEK ring)
# AND a SEPARATE service account. The keybroker is a separately-hardened identity that signs lineage;
# the secrets workload SA decrypts per-user DEKs. Fusing them would let one identity both read secrets
# and forge lineage — the separation §6.4 requires. (Peeling the keybroker into its own deployment /
# image is the further §6.4 step; the key + identity separation lands here.)

resource "google_kms_key_ring" "this" {
  project  = var.project_id
  name     = "${var.name_prefix}-keybroker"
  location = var.region
}

# The CA root signing key: EC P-256 / SHA-256, the algorithm providers/keybroker-gcp pins and
# keybroker/signing.verifyRoot accepts. ASYMMETRIC_SIGN (the private half signs in KMS; the public
# half is the trust anchor verifiers pin). NOT auto-rotated: a rotated asymmetric key mints a new
# version with a NEW public key, which would change the pinned anchor; rotation is a deliberate,
# version-managed operation, not a cadence. prevent_destroy — destroying it makes every signed
# lineage record unverifiable (the anchor is gone).
resource "google_kms_crypto_key" "nhi_ca" {
  name     = "${var.name_prefix}-nhi-ca"
  key_ring = google_kms_key_ring.this.id
  purpose  = "ASYMMETRIC_SIGN"

  version_template {
    algorithm        = "EC_SIGN_P256_SHA256"
    protection_level = var.kms_protection_level
  }

  lifecycle {
    prevent_destroy = true
  }
}

# The keybroker's DISTINCT signing identity. Created with NO human-impersonation binding (no operator
# signing path by construction); the GKE Workload Identity binding (KSA -> this SA) is deferred to the
# gke module / production wiring, exactly as the secrets workload SA's binding is.
resource "google_service_account" "keybroker" {
  project      = var.project_id
  account_id   = "${var.name_prefix}-keybroker"
  display_name = "Console7 keybroker signing identity (distinct from the secrets substrate; ARCHITECTURE.md §6.4)"
}

# Sign + read-the-public-key on EXACTLY this one key — never project-wide KMS access, and never the
# encrypt/decrypt the secrets KEK grants. signerVerifier covers AsymmetricSign + GetPublicKey, the two
# operations providers/keybroker-gcp performs.
resource "google_kms_crypto_key_iam_member" "keybroker_sign" {
  crypto_key_id = google_kms_crypto_key.nhi_ca.id
  role          = "roles/cloudkms.signerVerifier"
  member        = "serviceAccount:${google_service_account.keybroker.email}"
}
