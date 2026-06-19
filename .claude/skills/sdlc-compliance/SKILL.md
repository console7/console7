---
name: sdlc-compliance
description: How to comply with the Console7 Repository SDLC Standard when changing this repo. Use before committing, opening a PR, adding a dependency, or adding/editing a .claude/ skill or agent in the console7 repository.
---

# Console7 SDLC compliance

This repository is governed by **`docs/standards/console7-sdlc-standard.md`** — a
Tier-1 (× S1 Engineered + S5 Agentic) tailoring of a 19-control-objective secure-SDLC
standard, bound to the **OpenSSF** posture (Scorecard, OSPS Baseline Level 3, Best
Practices Badge silver). The standard is enforced by CI gates and branch protection;
this skill is the quick "how do I stay compliant" reference.

## Every change

- **Branch + PR, never `main`.** Open a feature branch; open a PR. No direct push to
  `main` (CO-4.1/4.4). The Bash guard blocks direct/force pushes to main.
- **Signed + DCO sign-off.** `git commit -S -s -m "…"`. `-S` signs (identity);
  `-s` adds the `Signed-off-by` Developer Certificate of Origin line (inbound IP).
  Both are required (CO-4; the Bash guard blocks un-signed-off commits).
- **Map each change to its doc section / CO** in the PR body (CO-14.2 traceability) —
  this is the project's standing rule, and what the PR template asks for.
- **Small, reviewable PRs.** An interface change, its reference implementation, and
  its conformance test land in one atomic PR.
- **Review before you push.** For a substantive change, run the **`pre-pr-review`**
  skill (local adversarial correctness + security + spec-alignment fan-out) and
  reconcile findings before `git push` — defence-in-depth that front-runs the
  authoritative Codex/CI/human review (tenet 2), not a replacement. The Bash guard
  prints a non-blocking reminder on feature-branch pushes that touch non-doc files.

## Adding or changing a dependency (CO-5 / CO-12.7)

- Route installs through **Socket Firewall**: `sfw npm ci`, `sfw pip install …` — or
  use a lockfile-faithful install. Bare `npm install` / `pip install` is blocked.
- **Pin** everything: Go deps to released versions (no `@latest`); GitHub Actions to a
  full commit SHA; commit the lockfile (`go.sum`). Run `govulncheck` for Go.
- A new dependency is a supply-chain decision — prefer the standard library / an
  already-present dependency before adding one.

## Adding or changing a .claude/ skill, agent, command, or hook (CO-12.7 / 12.8)

- **First-party / self-authored only.** Do not reference a remote or marketplace
  `source:` — the governance gate (`scripts/audit-skill-provenance.sh`) blocks it.
- These are **code**: version-controlled, reviewed in a PR, attributable, rollback-
  capable. Treat any third-party prompt/skill as a reviewed, version-pinned in-repo
  dependency, never a live fetch.

## Before you say "done"

- Did the change touch credentials? It must not — no secrets in code, tests, or
  fixtures; use the `SecretsProvider` seam and fakes (CO-8).
- Will the gates pass? secret-scan, Scorecard, SAST/semgrep, governance gate, and
  (when Go code exists) lint + `govulncheck` + CodeQL. If a gate would fail, fix the
  cause — do not seek to bypass it (the gate is the control of record, tenet 2).
- Is anything you deferred recorded as a **dated** accepted-gap (§5 of the standard),
  not a silent omission?
