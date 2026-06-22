#!/usr/bin/env bash
# CO-05 (supply chain) — verify a Console7 sandbox base image was signed KEYLESS by the pinned
# release identity (the .github/workflows/sandbox-image-release.yml workflow on a sandbox-image/v*
# tag), via Sigstore. This is the same verification the release pipeline runs and the check an
# ADOPTER MUST run before mirroring the image into their in-tenancy Artifact Registry (the "distinct
# signing identity" guarantee — ARCHITECTURE.md §6.4 — enforced, not asserted).
#
# The reference is required to be DIGEST-pinned (@sha256:...): a tag is mutable and not what the
# kubelet content-addresses, so verifying a tag would prove nothing about the bytes that run. This
# mirrors the consumer-side rule providers/cloud-gcp Config.SandboxImage enforces (B3).
#
# Usage: scripts/verify-sandbox-image.sh <registry/image@sha256:...>
# Requires: cosign (https://github.com/sigstore/cosign) on PATH. Network reach to Sigstore + registry.
#
# The pinned trust anchors below match the workflow env (COSIGN_IDENTITY_REGEXP/COSIGN_OIDC_ISSUER).
# An adopter who rebuilds + re-signs the image under THEIR OWN identity overrides them via the env
# vars of the same name (documented in sandbox/base-image/README.md).
set -euo pipefail

IMAGE="${1:-}"
if [[ -z "$IMAGE" ]]; then
  echo "usage: $0 <registry/image@sha256:...>" >&2
  exit 2
fi
if [[ "$IMAGE" != *"@sha256:"* ]]; then
  echo "error: image reference must be digest-pinned (…@sha256:…); got '$IMAGE'" >&2
  echo "       a tag is mutable — verify the exact bytes the kubelet will run." >&2
  exit 2
fi

command -v cosign >/dev/null 2>&1 || { echo "error: cosign not found on PATH" >&2; exit 1; }

# Defaults pin the MAINTAINER reference-release identity; override for a self-rebuilt image.
IDENTITY_REGEXP="${COSIGN_IDENTITY_REGEXP:-^https://github\.com/console7/console7/\.github/workflows/sandbox-image-release\.yml@refs/tags/sandbox-image/v}"
OIDC_ISSUER="${COSIGN_OIDC_ISSUER:-https://token.actions.githubusercontent.com}"

exec cosign verify \
  --certificate-identity-regexp "$IDENTITY_REGEXP" \
  --certificate-oidc-issuer "$OIDC_ISSUER" \
  "$IMAGE"
