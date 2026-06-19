<!--
Console7 is a Tier-1 public OSS control plane governed by
docs/standards/console7-sdlc-standard.md. Keep PRs small and reviewable.
-->

## What & why

<!-- One-line summary + the problem/need. -->

## Maps to (doc section / CO)

<!-- Map each change to the doc section it implements (CLAUDE.md rule) and cite
     the control objective(s) it satisfies (CO-14.2 traceability). e.g.
     - ARCHITECTURE.md §5 — adds SCMProvider stub
     - CO-5.5 — pins the new action to a commit SHA -->

-

## Checklist

- [ ] **Branch + PR** (not a direct push to `main`); commits **signed + DCO** (`git commit -S -s`).
- [ ] **No secrets** added (code, tests, fixtures); used fakes / the `SecretsProvider` seam (CO-8).
- [ ] **Dependencies**: any new dep routed via Socket Firewall / lockfile-faithful, pinned, and justified (CO-5).
- [ ] **Agentic artifacts** (`.claude/` skills/agents/hooks): first-party/self-authored only (CO-12.7).
- [ ] **Gates green** (secret-scan, governance gate, Scorecard; + lint/`govulncheck`/CodeQL once Go code exists). Fix the cause of any failure — do not bypass.
- [ ] Anything deferred is recorded as a **dated** accepted-gap (standard §5), not a silent omission.
- [ ] **Did not redesign** a tenet/requirement; if I think one is wrong, I said so here rather than deviating.

## Deploy impact

<!-- Does merging this deploy anything / change runtime posture? (Today: no deploy
     path exists from this repo.) -->
