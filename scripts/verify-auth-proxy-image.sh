#!/usr/bin/env bash
# CO-05 (supply chain) — verify a Console7 Vertex auth-proxy image was signed KEYLESS by the pinned
# release identity (the .github/workflows/auth-proxy-image-release.yml workflow on an auth-proxy/v*
# tag), via Sigstore. This is the same verification the release pipeline runs and the check an
# ADOPTER MUST run before mirroring the image into their in-tenancy Artifact Registry.
#
# The auth-proxy HOLDS a Vertex credential (it mints + attaches a Google bearer from the pod's own
# Workload Identity), so it is a DISTINCT, separately-signed artifact from the untrusted sandbox base
# image (the "distinct signing identity" guarantee — ARCHITECTURE.md §6.4 — enforced, not asserted).
#
# The reference is required to be DIGEST-pinned (@sha256:...): a tag is mutable and not what the
# kubelet content-addresses, so verifying a tag would prove nothing about the bytes that run.
#
# Usage: scripts/verify-auth-proxy-image.sh <registry/image@sha256:...>
# Requires: cosign on PATH (the release pipeline signs via the sigstore/cosign-installer v4.1.2
# action) — https://github.com/sigstore/cosign. Network reach to Sigstore (Fulcio/Rekor/TUF) + the
# registry. Unlike the in-CI identity self-test, this performs FULL verification (tlog + SCT): an
# adopter wants the complete transparency proof, not just the pin.
#
# The pinned trust anchors below match the workflow env (COSIGN_IDENTITY_REGEXP/COSIGN_OIDC_ISSUER).
# An adopter who rebuilds + re-signs the image under THEIR OWN identity overrides them via the env
# vars of the same name (documented in sandbox/vertex-auth-proxy/README.md).
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
IDENTITY_REGEXP="${COSIGN_IDENTITY_REGEXP:-^https://github\.com/console7/console7/\.github/workflows/auth-proxy-image-release\.yml@refs/tags/auth-proxy/v}"
OIDC_ISSUER="${COSIGN_OIDC_ISSUER:-https://token.actions.githubusercontent.com}"

exec cosign verify \
  --certificate-identity-regexp "$IDENTITY_REGEXP" \
  --certificate-oidc-issuer "$OIDC_ISSUER" \
  "$IMAGE"
