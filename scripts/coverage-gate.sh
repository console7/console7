#!/usr/bin/env bash
# CO-17 / CO-15 — per-package test-coverage floor gate.
#
# The Go toolchain has no native changed-lines coverage mode, so we ratchet on
# per-package floors instead (see docs/dev/code-quality-enforcement-plan.md §3).
# Each floor is set at the measured baseline and only ever moves UP: lowering a
# floor requires a RISKS-register entry (CO-17 tracks debt, never silently absorbs
# it). A package that drops below its floor — or stops reporting coverage — fails CI.
#
# Portable to bash 3.2 (stock macOS) so it doubles as the local pre-pr-review check.
#
# Usage: scripts/coverage-gate.sh [coverage-profile-path]
set -euo pipefail

profile="${1:-coverage.out}"

# "<import-path> <floor-percent>", one per line. Baseline measured 2026-06-21
# (cloud-gcp relaxed 67->64 for the integration-only kubeEngineRunner adapter; RISKS R-4).
# Floors only ever move UP. cloud-gcp ratcheted 64->70 (2026-06-22): the B5 Injector
# (Owns/DeliverIfOwned/denyDeliverer) + B6 workspaceSeedScript/shquote/isProtectedBranch are
# genuinely CI-unit-tested (injector_test.go, seed_test.go) — that coverage is NOT integration-only
# slack (R-4), so the floor must capture it or the gate is vacuous over the new fail-closed code.
# Packages not listed (sdk/interfaces, sdk/testkit, conformance) carry no test suite
# of their own yet and are exercised indirectly; add a floor when they gain one.
floors="
github.com/console7/console7/control-plane/evidence 89
github.com/console7/console7/control-plane/orchestrator 76
github.com/console7/console7/keybroker/broker 74
github.com/console7/console7/keybroker/signing 94
github.com/console7/console7/providers/keybroker-gcp 54
github.com/console7/console7/providers/cloud-gcp 70
github.com/console7/console7/providers/evidence-gcs 54
github.com/console7/console7/providers/inference-anthropic 100
github.com/console7/console7/providers/inference-vertex 100
github.com/console7/console7/providers/scm-github 60
github.com/console7/console7/providers/secrets-gcp 63
github.com/console7/console7/sandbox/policyhelper 90
github.com/console7/console7/sandbox/policyhelper/cmd/policyhelper 60
github.com/console7/console7/sandbox/policyhelper/cmd/tripwire 70
github.com/console7/console7/sandbox/vertex-auth-proxy 66
github.com/console7/console7/sdk/devkit 86
"
# vertex-auth-proxy: the testable handler (proxy.go: /v1 rewrite, bearer attach,
# fail-closed 503-no-forward, upstream resolution) is fully unit-covered; the floor
# sits below 100 only for main.go's run() — ambient ADC (google.DefaultTokenSource)
# + ListenAndServe — which needs a real metadata server/network, exercised in deploy,
# not CI. Same class as the policyhelper cmd/* main packages above.

echo "Running test suite with coverage ..."
# -count=1 disables the test cache so coverage is freshly measured every run.
# Run explicitly (not in a `$(...)` capture) so the suite output is always surfaced
# AND a failing suite fails the gate loudly — never relying on a `set -e` assignment
# abort that a future refactor could silently turn fail-open.
log="$(mktemp)"
trap 'rm -f "$log"' EXIT
if ! go test -count=1 -covermode=atomic -coverprofile="$profile" ./... >"$log" 2>&1; then
  cat "$log"
  echo "::error::test suite failed — see output above"
  exit 1
fi
cat "$log"
test_output="$(cat "$log")"

echo
echo "Enforcing per-package coverage floors ..."
fail=0
# Process substitution keeps the loop in the current shell so `fail` survives it.
while read -r pkg floor; do
  [ -z "$pkg" ] && continue
  pct="$(printf '%s\n' "$test_output" | awk -v p="$pkg" '
    $2 == p { for (i = 1; i <= NF; i++) if ($i == "coverage:") { sub(/%/, "", $(i+1)); print $(i+1) } }')"
  # Fail CLOSED on anything that is not a bare number: empty (package absent from the
  # output), or non-numeric like "[no" from a "coverage: [no statements]" line — a
  # floored package that loses all its statements must trip the gate, not skip it.
  case "$pct" in
    '' | *[!0-9.]*)
      echo "::error::$pkg — coverage not reported as a number (got '${pct:-<none>}'); floor ${floor}%"
      fail=1
      continue
      ;;
  esac
  if awk "BEGIN { exit !($pct < $floor) }"; then
    echo "::error::$pkg — coverage ${pct}% is below floor ${floor}%"
    fail=1
  else
    echo "ok  $pkg — ${pct}% >= ${floor}%"
  fi
done < <(printf '%s\n' "$floors")

if [ "$fail" -ne 0 ]; then
  echo
  echo "Coverage gate FAILED. Raise the missing tests, or — if a floor is being"
  echo "deliberately relaxed — record the reason in the RISKS register (CO-17)."
  exit 1
fi
echo
echo "Coverage gate passed."
