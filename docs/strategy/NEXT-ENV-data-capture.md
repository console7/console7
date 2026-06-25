# Handoff — capturing the live CVE/health data (broader-access env)

> Scratch handoff for resuming the dependency-lifecycle-model work in an
> environment with broader egress. This branch
> (`claude/dependency-maintainability-model-4n4xum`) is **disposable** —
> squash/cherry-pick what's worth keeping. Companion: this directory's
> `dependency-lifecycle-model.md` + `../../scripts/dep-lifecycle-model.py`.

## What's already done (no access needed — committed here)

- **Structural axes — measured & final.** Module graph fan-out (concentration),
  build-reachability (203 closure / 53 reachable / 10 direct), per-module reachable
  LoC, licences, and the **two-lever substitutability index** (A: opacity/IP ×
  vendor-count; B: reachable-KLoC × licence). All computed offline from `go mod graph`
  + `go list -deps -json` + the module cache. `python3 scripts/dep-lifecycle-model.py`.
- **Track-record model — built, runs on illustrative data.** `--track` ingests an
  observations ledger (`dep-track-record.example.json`) and reports noise/signal
  series, ρ, trends, MTTR, verdicts.

## What's blocked here, and the verdict on each

Two axes are NOT yet evidenced because the live feeds are **egress-policy-blocked
(403)** in this sandbox. Confirmed via `curl -sS "$HTTPS_PROXY/__agentproxy/status"`:

| Source | Host | Feeds | Status here |
|---|---|---|---|
| Go vuln DB (`govulncheck`) | `vuln.go.dev:443` | **signal** (reachable CVEs) | 403 blocked |
| OSV | `api.osv.dev:443` | **noise** (CVE inflow + dates) | 403 blocked |
| deps.dev | `api.deps.dev:443` | **H** (OpenSSF Scorecard) | not tried (assume blocked) |
| Go module proxy | `proxy.golang.org` | libyear (version dates) | **already allowlisted** ✓ |

No source needs auth — all public, read-only. The only data leaving is package
names+versions of a public OSS repo. (On-model: these are exactly what an adopter's
default-deny egress allowlists for the supply-chain lane.)

## To capture in the new env

### 0. Toolchain gotcha (cost me a cycle)
`govulncheck` must be **built with go1.25.x**, or its type-checker rejects this
module's go1.25 source ("package requires newer Go version"). Force it:
```bash
GOTOOLCHAIN=go1.25.11 go install golang.org/x/vuln/cmd/govulncheck@v1.1.4   # CI-pinned ver
go version "$(go env GOPATH)/bin/govulncheck"   # must report go1.25.x
```

### 1. Signal — reachable CVEs (govulncheck)
```bash
"$(go env GOPATH)/bin/govulncheck" -json ./... > /tmp/govuln.json
```
Parse: a finding with a trace whose last frame is in our code = **reachable** (signal).
OSV IDs present in scanned modules but with no called trace = present-but-unreached
(noise that is NOT signal). Expectation: Console7 is pinned `govulncheck`-clean
(`go.mod` header), so **signal should be ~0 at t0** — capture that as the real first
observation, don't assume it.

### 2. Noise — CVE inflow + dates (OSV)
For each of the 10 direct modules (and ideally the 53 reachable):
```bash
curl -s -X POST https://api.osv.dev/v1/query -H 'Content-Type: application/json' \
  -d '{"package":{"ecosystem":"Go","name":"google.golang.org/grpc"}}'
```
Bucket each advisory by its `published` date into periods → the **noise** series.
`/v1/querybatch` does all modules in one call.

### 3. Health/drift — H axis
- **libyear** (doable here already): `proxy.golang.org/<mod>/@v/list` + `/@v/<ver>.info`
  give version timestamps → drift = sum of (latest_release_date − pinned_date).
- **Scorecard**: `curl -s "https://api.deps.dev/v3/systems/go/packages/<url-enc mod>"`
  → versions + OpenSSF Scorecard. Wire into the `H` term (currently held =1).

### 4. Where it all lands
Write captured observations to `docs/strategy/dep-track-record.json` (same schema as
the `.example.json`), then `dep-lifecycle-model.py --track docs/strategy/dep-track-record.json`.
Replace the offline `H=1` and the structural-only `R` with the live signal once
captured. Ideally make capture a scheduled CI job (egress is open in Actions —
`.github/workflows/dep-scan.yml` already runs `govulncheck` there) that appends a
period each run, so the ledger self-populates as evidence rather than a manual pull.

## Open refinements worth doing with the data
- `R` is build-reachability (binary, module-level); upgrade to govulncheck's
  per-symbol call-path reachability (the real leading indicator).
- KLoC overstates rebuild cost for **generated/spec-backed** `code` (protobuf stubs,
  OAuth2) — discount Lever B when a generator/spec exists.
- Calibrate the carry-cost weights and `MTTR_SLA_DAYS` against real incident history.
- The licence detector is conservative (BSD-3 reads as "unknown"); tighten with SPDX.
