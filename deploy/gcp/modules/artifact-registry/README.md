# `modules/artifact-registry` — sandbox-image repository

**Trust tier:** infrastructure substrate (no secrets, no untrusted code runs here).

Creates the one Artifact Registry **Docker** repository the signed **sandbox base-image**
(`sandbox/base-image`, the untrusted-agent runtime) is published to, and grants the GKE node SA
**repo-scoped** pull access to it — replacing the project-wide `roles/artifactregistry.reader` the
`gke` module used to grant against no repository.

## What it owns

- Enables `artifactregistry.googleapis.com`.
- One `DOCKER` repository named `<name_prefix>` in `<region>`, with **immutable tags** (a pushed
  tag can never be moved to different bytes).
- `roles/artifactregistry.reader` for the **passed-in** node SA, scoped to **this repository only**
  (least privilege; GOAL.md tenet 5). It mints no identity and grants no push/delete/admin.

## What it does NOT own

- **Signing, SBOM, provenance** — those live in the release pipeline
  (`.github/workflows/sandbox-image-release.yml`), which keyless-signs the reference image on ghcr.
  The image's distinct signing identity is a separate artifact from this repository (CLAUDE.md
  trust-tier separation), and is enforced (not asserted) by that pipeline's wrong-identity-rejection
  test.
- **Push credentials** — this module grants no writer. The adopter mirrors the verified, signed
  image into this repo at deploy time (`scripts/verify-sandbox-image.sh` first); the release
  pipeline itself publishes only to ghcr.

## Wiring

Root `deploy/gcp` instantiates it after `gke` (it consumes `module.gke.node_service_account_email`).
The published image path is `<region>-docker.pkg.dev/<project>/<name_prefix>/<image>`; the
digest-pinned reference (`…/<image>@sha256:…`) flows into `providers/cloud-gcp`
`Config.SandboxImage` (B3) — which **rejects a tag-only reference**, the authoritative consumer-side
supply-chain control (content-addressed at the kubelet). The registry's `immutable_tags` is the
complementary registry-side control.

## Prerequisite (human bootstrap)

The project + billing exist and the APPLY identity holds `roles/artifactregistry.admin` (repo create
+ repo IAM) — `bootstrap.sh` grants it.
