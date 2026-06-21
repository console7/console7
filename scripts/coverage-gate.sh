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

# "<import-path> <floor-percent>", one per line. Baseline measured 2026-06-21.
# Packages not listed (sdk/interfaces, sdk/testkit, conformance) carry no test suite
# of their own yet and are exercised indirectly; add a floor when they gain one.
floors="
github.com/console7/console7/control-plane/evidence 89
github.com/console7/console7/control-plane/orchestrator 76
github.com/console7/console7/keybroker/broker 74
github.com/console7/console7/keybroker/signing 94
github.com/console7/console7/providers/evidence-gcs 54
github.com/console7/console7/providers/inference-anthropic 100
github.com/console7/console7/providers/inference-vertex 100
github.com/console7/console7/providers/scm-github 60
github.com/console7/console7/providers/secrets-gcp 63
github.com/console7/console7/sdk/devkit 86
"

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
