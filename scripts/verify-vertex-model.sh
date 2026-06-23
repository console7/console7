#!/usr/bin/env bash
# Phase-1 EXIT (Vertex lane) — operator preflight: confirm the @-form Vertex publisher model id you
# intend to pin (cloud-gcp Config.VertexModel) is actually SERVED in your project + region BEFORE the
# billed live run. The pinned engine's DEFAULT model 404s, and a Vertex model id is a DIFFERENT
# namespace from the Anthropic-API "-"-snapshot form, so a wrong/unavailable id surfaces as a
# confusing in-sandbox failure mid-run — catch it here instead (the @1.0.44-default-404 lesson,
# applied to Vertex).
#
# It lists the Anthropic publisher models Vertex serves in the region and checks your pinned id is
# among them. It mints a short-lived token the same way the provider's adapter does (gcloud auth
# print-access-token, i.e. the caller's ADC), so run it as / impersonating the workload SA that holds
# aiplatform.endpoints.predict. It is READ-ONLY (a models.list GET) — no inference is billed.
#
# Usage: scripts/verify-vertex-model.sh <project_id> <region> <vertex-model-id@YYYYMMDD>
#   e.g. scripts/verify-vertex-model.sh my-proj us-east5 claude-haiku-4-5@20251001
# Requires: gcloud (authenticated as / impersonating the workload SA) + curl on PATH.
set -euo pipefail

PROJECT="${1:-}"
REGION="${2:-}"
MODEL="${3:-}"
if [[ -z "$PROJECT" || -z "$REGION" || -z "$MODEL" ]]; then
  echo "usage: $0 <project_id> <region> <vertex-model-id@YYYYMMDD>" >&2
  exit 2
fi
if [[ "$MODEL" != *"@"* ]]; then
  echo "error: model id %q is not the Vertex @-date form (e.g. claude-haiku-4-5@20251001); the" >&2
  echo "       Anthropic-API \"-\"-snapshot form does NOT route through Vertex." >&2
  printf '       got: %s\n' "$MODEL" >&2
  exit 2
fi

# The model id Vertex's publisher-model resource uses is the part before "@" (the "@date" is the
# version pinned at invocation, not part of the resource name).
MODEL_BASE="${MODEL%@*}"
HOST="${REGION}-aiplatform.googleapis.com"
if [[ "$REGION" == "global" ]]; then
  HOST="aiplatform.googleapis.com"
fi

TOKEN="$(gcloud auth print-access-token)"
URL="https://${HOST}/v1/publishers/anthropic/models?view=PUBLISHER_MODEL_VIEW_BASIC"

echo "Querying Anthropic publisher models served by Vertex in ${PROJECT}/${REGION} ..."
RESP="$(curl -fsS -H "Authorization: Bearer ${TOKEN}" -H "x-goog-user-project: ${PROJECT}" "$URL")"

if grep -q "publishers/anthropic/models/${MODEL_BASE}" <<<"$RESP"; then
  echo "OK: ${MODEL_BASE} is served by Vertex in ${REGION}. Pin Config.VertexModel=${MODEL}."
  exit 0
fi

echo "FAIL: ${MODEL_BASE} is NOT in the Anthropic publisher models Vertex serves in ${REGION}." >&2
echo "Available anthropic model ids (resource names):" >&2
grep -oE "publishers/anthropic/models/[a-z0-9.-]+" <<<"$RESP" | sort -u >&2 || true
exit 1
