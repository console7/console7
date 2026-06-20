# Plan — Code-quality enforcement (coverage + maintainability gates)

**Status:** delivered — Sprint 1 (#33) and Sprint 2 (#34) merged; Sprint 3 lands via
this PR. On merge, CO-17 is **Adopt**: `golangci-lint run ./...` gates whole-tree,
coverage floors ratchet, and `docs/RISKS.md` tracks exceptions.
**Owner:** maintainers
**Implements:** CO-17 (code quality, maintainability, tech debt), CO-7.1 (SAST),
CO-15 (functional QA), CO-12.8 (`.claude/` skills are code)
**Created:** 2026-06-21

---

## 1. Why this exists

Two enforcement gaps were found while reviewing CI posture (the SonarCloud
"is it redundant?" question). Neither is exotic; both are things the repo already
*intended* to have:

1. **Test coverage is measured but never gated.** `go.yml` runs `go test ./...` with
   no `-coverprofile` and no floor. Coverage today ranges **59.7 % → 100 %** across
   packages and can silently regress to zero without failing a PR.
2. **Maintainability is neither measured nor gated.** Cognitive/cyclomatic
   complexity, duplication, function/file length, nesting depth, dead code, and
   doc-comment rules have **no signal in CI at all**. `gofmt` is formatting only;
   `go vet` is a narrow correctness linter; CodeQL is security SAST. None of them
   score maintainability.

**Gap #2 is a standing compliance gap, not a nice-to-have.** CO-17 of the SDLC
standard states: *"Lint (`gofmt`, `go vet`, `golangci-lint`) wired as a blocking gate
the moment `go.mod` lands; tech debt tracked in a RISKS register."* `go.mod` has
landed (multiple provider packages now exist); `golangci-lint` has not. The repo is
out of conformance with its own CO-17. This plan closes that.

**We caught this early — deliberately note the scale.** The codebase is **~6.2 kLOC
of non-test Go** (6,785 lines across 8 packages). A one-off remediation to a clean
baseline is tractable now and compounds badly if deferred. Enforcing
"clean-as-you-code" on a dirty baseline is not credibly defensible long-term — agents
and humans learn to route around a gate that was born red. So the plan pairs the gate
with a remediation sprint that makes the baseline clean *before* whole-tree
enforcement turns on.

## 2. Objective

A two-tier code-quality regime, consistent with tenet 2 (boundary/CI controls are
authoritative; in-band guards are defence-in-depth):

- **CI gate = the control of record.** A PR that breaches a quality threshold does not
  merge, irrespective of what any agent or human did.
- **`pre-pr-review` skill + (optional) local hook = defence-in-depth.** The same
  linters run before push so agents fix in-loop instead of bouncing off red CI.

Both tiers run the **same `.golangci.yml`** — one source of truth.

## 3. Design decisions (settled)

| Decision | Choice | Rationale |
|---|---|---|
| Enforcement scope | **Clean-as-you-code** (`golangci-lint --new-from-rev=origin/main`) for the lint gate | Gate new/changed lines; do not block on legacy debt. Same model Sonar's "clean as you code" uses. |
| Baseline integrity | **One-off remediation sprint before whole-tree flip** | Clean-as-you-code is only defensible if the baseline is actually clean. Remediate now at 6.2 kLOC, then the grandfather window closes. |
| Coverage enforcement | **Per-package floors set at today's values**, ratcheting | Go toolchain has no native changed-lines coverage mode; per-package floors give the same ratchet without a bespoke diff-coverage script. True per-diff coverage can be added later if wanted. |
| Linter runner | **`golangci-lint`** (SHA-pinned action + pinned binary version) | Native, in-tree, no SaaS / no external repo access — fits the repo's minimize-external-surface posture. Supersedes the SonarCloud option (security axis was redundant to CodeQL; maintainability axis is delivered here). |
| Tech-debt tracking | **RISKS register** entry for any threshold we consciously relax | CO-17 requires debt be tracked, not silently absorbed. |

### 3.1 Linter set + starting thresholds

Enable, grouped by the quality axis each one enforces:

| Axis | Linter(s) | Starting threshold |
|---|---|---|
| Cyclomatic complexity | `gocyclo` / `cyclop` | 15 |
| Cognitive complexity | `gocognit` | 20 |
| Duplication | `dupl` | 100 tokens |
| Function length | `funlen` | 80 lines / 40 statements |
| Nesting depth | `nestif` | 5 |
| Dead code / smells | `staticcheck`, `unused` | default rulesets |
| Unchecked errors | `errcheck`, `ineffassign` | on |
| Doc / style | `revive` | exported-symbol doc rules |
| Security (overlap w/ CodeQL) | `gosec` | default; CodeQL remains the SAST of record |

Thresholds are a **starting proposal**; Sprint 2 calibrates them against real measured
worst-case values so targets are evidence-based, not guessed.

## 4. Sprints

### Sprint 1 — Stand up the gate (non-blocking on legacy)
**Exit:** the gate exists and runs, but only judges changed lines.

- Add `.golangci.yml` with the §3.1 linter set + starting thresholds.
- Add a `golangci-lint` job to `.github/workflows/go.yml` (SHA-pinned action, pinned
  binary version, `--new-from-rev=origin/main`, guarded on `go.mod` presence like the
  existing jobs).
- Add a coverage step: `go test -coverprofile` + per-package floors set at **today's**
  numbers (evidence ≥ 89, signing ≥ 94, orchestrator ≥ 76, broker ≥ 74, devkit ≥ 86,
  secrets-gcp ≥ 63, scm-github ≥ 59, inference-anthropic = 100). Calibrate exact
  floors against a fresh measurement at implementation time.
- **Outcome:** new code is held to the bar from day one; the existing 6.2 kLOC is
  grandfathered and CI stays green.

### Sprint 2 — One-off remediation of the existing 6.2 kLOC
**Exit:** the whole tree passes `golangci-lint run ./...` (not just `--new-from-rev`)
at the agreed thresholds; clean-as-you-code becomes defensible because the baseline is
genuinely clean.

- Measure whole-tree worst-case per linter; **calibrate final thresholds** from
  evidence (tighten the §3.1 starting values where the code already clears them).
- Remediate breaches across all 8 packages — split complex functions, de-duplicate,
  add missing exported-doc comments, fix unchecked errors. Mechanical and low-risk at
  this size; each package can be its own small PR or a focused sweep.
- Any breach we **decline** to fix (justified, e.g. an irreducibly complex generated
  shim) → explicit `//nolint` with a reason **and** a RISKS-register line. No silent
  suppressions.
- Re-run `pre-pr-review` per package touched (substantive logic edits).

### Sprint 3 — Flip to whole-tree enforcement + lock it in
**Exit:** CO-17 fully satisfied; the gate is the control of record.

- Switch the CI lint job from `--new-from-rev` to whole-tree
  (`golangci-lint run ./...`) now that the baseline is clean — closes the
  grandfather window so legacy debt can't creep back in under the diff filter.
- Teach the **`pre-pr-review` skill** to run the same `golangci-lint` config locally
  before push (defence-in-depth tier). Optionally add a `pre-commit` /
  `PreToolUse(Bash)` hook later.
- Record CO-17 as **Adopt** (from "Target → Adopt at first code") in the SDLC
  standard's control table; add the RISKS-register section if not already present.
- Dev-session ledger entries per repo convention across the sprint PRs.

## 5. Scope / sequencing notes

- **Separate from open work.** This lands on its own branch off `main`, independent of
  PR #32 (`inference-anthropic`). Do not pile onto an unrelated provider PR.
- **Small reviewable PRs.** Sprint 1 is one PR. Sprint 2 is per-package PRs (or a small
  number of focused sweeps). Sprint 3 is one PR (flip + skill + standard update).
- **`pre-pr-review` before every push** — this touches CI and `.claude/` skills, which
  CLAUDE.md flags as substantive-by-default.
- **CodeQL stays.** It remains the SAST of record; `gosec` is additive overlap, not a
  replacement.

## 6. Non-goals

- **No SonarCloud / external quality SaaS.** Its security axis is redundant to CodeQL +
  govulncheck; its maintainability axis is delivered in-tree here without granting a
  third party standing repo access. We forgo the proprietary single "maintainability
  rating" dashboard deliberately — we keep every underlying signal that feeds it.
- **No true per-diff coverage tooling** in this plan (per-package floors instead). Can
  be revisited if package-granularity proves too coarse.
- **No threshold-chasing for its own sake.** Thresholds are calibrated from real code
  (Sprint 2), and conscious exceptions are tracked, not banned.

## 7. Open items to confirm at implementation time

- Exact per-package coverage floors (measure fresh — numbers above are from the
  2026-06-21 snapshot and will drift).
- Final calibrated lint thresholds (Sprint 2 evidence).
- Whether to add the local `pre-commit`/`PreToolUse` hook in Sprint 3 or defer it.
