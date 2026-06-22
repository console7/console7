# Console7 sandbox-image registry: the Artifact Registry Docker repository the signed sandbox
# base-image (sandbox/base-image) is published to, plus a repo-SCOPED reader grant to the GKE node
# SA so — and ONLY so — the sandbox node pool can pull that image. NOTHING else.
#
# Why this module exists: the sandbox pod runs untrusted agent code from a DISTINCT, separately-
# signed image (CLAUDE.md trust-tier separation). That image has to live somewhere the kubelet can
# pull it; before this module there was no registry — the node SA carried a project-WIDE
# roles/artifactregistry.reader (modules/gke) that pointed at no repository. This module creates the
# one repository and narrows the node SA's read to it (least privilege, GOAL.md tenet 5): the node
# can pull the sandbox image and no other repo's images.
#
# Supply chain: the repo enforces IMMUTABLE TAGS, so a pushed tag can never be moved to different
# bytes — this is the integrity control THIS module provides. It is a defence-in-depth complement to
# the consumer-side digest pin (providers/cloud-gcp Config.SandboxImage, which rejects a tag-only
# reference so the kubelet content-addresses the exact @sha256 bytes — B3). The image's signing
# identity, SBOM, and SLSA provenance come from the release pipeline
# (.github/workflows/sandbox-image-release.yml), which keyless-signs the REFERENCE image on ghcr; an
# adopter VERIFIES it (scripts/verify-sandbox-image.sh) and MIRRORS the signed image into THIS repo
# at deploy time. This module owns only the repository + the pull grant.
#
# Prerequisite (human bootstrap, not this module): the project + billing exist, and the APPLY
# identity holds roles/artifactregistry.admin (repo create + repo IAM) — bootstrap.sh grants it.

resource "google_project_service" "artifactregistry" {
  project = var.project_id
  service = "artifactregistry.googleapis.com"

  # Don't disable the API on `terraform destroy` — other resources/users in the project may depend
  # on it, and re-enabling is slow (mirrors the other modules' API-enable posture).
  disable_on_destroy = false
}

# The sandbox-image repository. DOCKER format, regional (kept in-region with everything else — no
# egress of adopter artifacts; GOAL.md tenet 1). The repository_id is the name_prefix, so a pushed
# image is "<region>-docker.pkg.dev/<project>/<prefix>/<image>" (e.g. .../console7/sandbox-base).
resource "google_artifact_registry_repository" "sandbox" {
  project       = var.project_id
  location      = var.region
  repository_id = var.name_prefix
  format        = "DOCKER"
  description   = "Console7 sandbox base-image (untrusted-agent runtime, distinct signing identity). Pulled by the GKE sandbox node pool only."

  # Immutable tags: a tag, once pushed, cannot be reassigned to different bytes. This closes the
  # tag-mutation window at the registry — an attacker who can push cannot silently swap the image a
  # floating reference resolves to. It is the registry-side integrity control; the authoritative
  # consumer-side control is the content-addressed digest pin (Config.SandboxImage @sha256, which
  # rejects a tag-only reference — B3).
  docker_config {
    immutable_tags = true
  }

  depends_on = [google_project_service.artifactregistry]
}

# Repo-SCOPED reader for the GKE node SA: the sandbox node pool can pull from THIS repository and no
# other. Replaces the project-wide roles/artifactregistry.reader the gke module used to grant (which
# pointed at no repo). The node SA email is created in modules/gke and passed in — this module mints
# no identity. roles/artifactregistry.reader is read-only (no push, no delete, no repo admin).
resource "google_artifact_registry_repository_iam_member" "node_reader" {
  project    = var.project_id
  location   = google_artifact_registry_repository.sandbox.location
  repository = google_artifact_registry_repository.sandbox.repository_id
  role       = "roles/artifactregistry.reader"
  member     = "serviceAccount:${var.node_service_account_email}"
}
