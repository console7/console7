# Console7 durable evidence backing: the GCS bucket the WORM evidence log lives in, plus the
# least-privilege object grant the control-plane workload identity needs to APPEND records — and
# NOTHING else (no delete, no overwrite).
#
# This module backs the providers/evidence-gcs reference Store, which the real EvidenceSink
# (control-plane/evidence) commits hash-chained, sink-signed records through. WORM holds at two
# trust levels: (1) the workload SA's grant below is create/get/list ONLY, and GCS requires
# storage.objects.delete to overwrite as well as to delete an object, so the APPEND identity can
# neither overwrite nor remove a committed record; (2) against a PRIVILEGED actor (the deploy
# identity can delete objects and remove an unlocked retention policy), the AUTHORITATIVE control
# is the retention policy + LOCK (GOAL.md tenet 3; tenet 7). The lock (is_locked) is off by
# default, so the default posture is tamper-EVIDENT (the Sink's hash-chain detects mutation) but
# not tamper-RESISTANT against a privileged actor — production sets is_locked=true. The provider's
# DoesNotExist precondition and the Sink's hash-chain are in-band defence-in-depth on top.
#
# Scope: enable storage.googleapis.com, create a hardened bucket with a retention policy, and bind
# ONE custom role granting ONLY object create/get/list to the EXISTING workload SA at bucket scope
# (passed in — this module does not mint a second identity). roles/storage.objectAdmin is
# deliberately NOT used: it carries delete + overwrite, which would break append-only.
#
# Prerequisite (human bootstrap, not this module): the project and billing exist, the workload SA
# (e.g. modules/secrets' "<prefix>-cp-secrets") is created, and the APPLY identity holds
# roles/storage.admin (bucket create + retention/lock) — bootstrap.sh grants it.
#
# Separation note: this bucket is a DISTINCT bucket from the operational database and from the
# Terraform state bucket (control-plane/evidence.Store SECURITY note; DESIGN.md §6).

resource "google_project_service" "storage" {
  project = var.project_id
  service = "storage.googleapis.com"

  # Don't disable the API on `terraform destroy` — other resources/users in the project may
  # depend on it, and re-enabling is slow.
  disable_on_destroy = false
}

# The evidence bucket. Hardened: uniform bucket-level access (IAM only, no per-object ACLs),
# public access prevented, versioning on, and a retention policy enforcing immutability. The
# bucket name is "<prefix>-evidence-<project_id>" to be globally unique without leaking more than
# the (already-known) project id.
resource "google_storage_bucket" "evidence" {
  project  = var.project_id
  name     = "${var.name_prefix}-evidence-${var.project_id}"
  location = var.region

  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  # Versioning + the provider's DoesNotExist (ifGenerationMatch=0) precondition keep exactly one
  # live generation per sequence slot: the precondition rejects an overwrite at write time, and if
  # one somehow occurred, versioning retains (does not lose) the prior generation. Count lists live
  # generations only (Query.Versions defaults false), so a sequence is never double-counted.
  versioning {
    enabled = true
  }

  # Retention is the durable WORM control against a privileged actor: while the policy is in force
  # (and crucially LOCKED), objects cannot be deleted or overwritten and the policy cannot be
  # removed. is_locked is off by default (see variables.tf for the tamper-evident-vs-resistant
  # consequence) so dev buckets stay destroyable; production locks it deliberately (irreversible).
  retention_policy {
    retention_period = var.retention_seconds
    is_locked        = var.is_locked
  }

  depends_on = [google_project_service.storage]
}

# A single custom role granting ONLY what the append-only Store calls: create a new object, read
# an object back, and list (for the Store's Len / Sink hydration). NO storage.objects.delete and
# NO storage.objects.update — committed history cannot be removed or rewritten even by a bug in
# the provider. NO *.setIamPolicy (no self-grant). roles/storage.objectAdmin bundles delete +
# overwrite and is the wrong fit; this custom role is the least-privilege one.
resource "google_project_iam_custom_role" "evidence_writer" {
  project     = var.project_id
  role_id     = "${replace(var.name_prefix, "-", "_")}_evidence_writer"
  title       = "Console7 evidence workload — append-only object writer"
  description = "storage.objects.create / get / list only. No delete, no overwrite, no IAM-policy verbs — append-only WORM."
  stage       = "GA"
  permissions = [
    "storage.objects.create",
    "storage.objects.get",
    "storage.objects.list",
  ]
}

# Bind the writer role to the EXISTING workload SA AT BUCKET SCOPE (google_storage_bucket_iam_member,
# not a project binding) — tighter than a project-level grant with a resource-name condition: the
# SA can append/read only within the evidence bucket, nothing else in the project.
resource "google_storage_bucket_iam_member" "workload_evidence_writer" {
  bucket = google_storage_bucket.evidence.name
  role   = google_project_iam_custom_role.evidence_writer.id
  member = "serviceAccount:${var.workload_service_account_email}"
}
