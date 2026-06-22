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

- **Signing, SBOM, provenance** — those will live in the **forthcoming** release pipeline
  (`.github/workflows/sandbox-image-release.yml`, not yet built). The image's distinct signing
  identity is a separate artifact from this repository (CLAUDE.md trust-tier separation).
- **Push credentials** — the (forthcoming) release pipeline authenticates via WIF keyless; this
  module grants no writer.

## Wiring

Root `deploy/gcp` instantiates it after `gke` (it consumes `module.gke.node_service_account_email`).
The published image path is `<region>-docker.pkg.dev/<project>/<name_prefix>/<image>`; the
digest-pinned reference (`…/<image>@sha256:…`) will flow into `providers/cloud-gcp`
`Config.SandboxImage` when the engine-image wiring lands. That field — which will reject a tag-only
reference, the intended authoritative consumer-side supply-chain control — does **not exist yet**;
the registry's `immutable_tags` is the integrity control in place today.

## Prerequisite (human bootstrap)

The project + billing exist and the APPLY identity holds `roles/artifactregistry.admin` (repo create
+ repo IAM) — `bootstrap.sh` grants it.
