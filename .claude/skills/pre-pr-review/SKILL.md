---
name: pre-pr-review
description: For a substantive (non-doc) change to the console7 repo — provider interfaces, Go/shell logic, CI workflows, .claude/ hooks/skills, deploy config — run a local adversarial review (correctness + security + spec-alignment) and reconcile findings before `git push`. Defence-in-depth that front-runs the authoritative Codex/CI/human gates; skip for pure docs, comments, or typos.
---

# Pre-PR adversarial review (Console7)

This is a **shift-left, defence-in-depth** review you run **before pushing** a
substantive change. It does **not** replace the controls of record — CI gates,
Socket/Codex review, and the human admin-merge stay authoritative (`GOAL.md` tenet 2:
in-band guards are defence-in-depth, never the control of record). Its job is to
catch — locally, in one pass — the issues that would otherwise cost a push + a
~15–20-minute external review round-trip, and to stop you shipping avoidable bugs
*into* the independent reviewer.

> **Why this exists.** On PR #13 the author leaned on Codex to find problems; Codex
> ran three rounds and caught a real issue each time, including two P1 correctness
> bugs introduced in the prior round. A local adversarial pass front-runs that. It
> also dogfoods the product: Console7 is "evidence over attestation; independent
> verification" — our own pipeline should model it. See the
> `console7-pre-commit-review-gap` memory.

## When to run it

- **Run** for substantive changes: provider interfaces / SECURITY contracts, any Go
  or shell logic, CI workflows, `.claude/` hooks/skills, deploy config — anything
  with correctness or security consequence.
- **Skip** (proportionality, `GOAL.md` tenet 8) for pure docs, comments, typos,
  formatting, or trivial renames. State that you skipped and why.

## How to run it — three independent adversarial lenses

The method is fixed; the *mechanism* depends on what your harness exposes. Run all
three lenses over the **diff** (`git diff main...HEAD` or the staged diff), each
prompted to **find deviations — not to bless the change**. Independence is the point:
a fresh reader catches what the author rationalized, and one lens catches what another
misses (on the PR that motivated this skill, the correctness lens caught a DCO-bypass
the security lens had test-passed over).

1. **Correctness** — logic bugs, fail-open defaults, zero-value traps, empty-input /
   boundary / ordering errors, error handling. *"Assume it is wrong; prove where."*
2. **Security / threat** — given `docs/DESIGN.md` §10 + `GOAL.md` tenets: *"Which
   abuse class (control-plane-as-target, lethal trifecta, cross-tier escalation,
   subscription misuse, sub-agent lineage, supply chain) could this weaken? Does
   anything return/persist long-lived credentials, widen scope, or fail open?"*
3. **Spec-alignment** — given `GOAL.md`, `docs/DESIGN.md`, `docs/ARCHITECTURE.md`,
   and the SDLC standard: *"Does this deviate from a tenet or doc section? In
   particular, does any SECURITY docstring claim a guarantee the signature/type
   cannot actually enforce?"* — the exact class Codex kept finding (a contract
   promising what its inputs can't support).

Pick the mechanism your harness offers, in order of preference:

- **Sub-agent fan-out (richest).** If your harness can spawn sub-agents (e.g. an
  `Agent` / `Task` tool), launch the three lenses concurrently in **one message**,
  giving each the diff and the docs it needs. Tool names vary by harness — use
  whatever yours exposes.
- **One-command Workflow (opt-in).** `.claude/workflows/pre-pr-review.mjs` runs the
  same three lenses and synthesizes them; it requires opting into the Workflow tool.
- **Built-in skills (always available, the guaranteed fallback).** Run `/code-review`
  (correctness) and `/security-review` (security) — these ship with Claude Code — and
  do the spec-alignment lens yourself against the doc section the change maps to.

Then **reconcile every finding before pushing**: fix it, or record a reasoned
dismissal (as you would for a Codex finding — see `console7-repo-workflow`). Only
then `git push`.

## Relationship to the other guards

- The **Bash guard** (`.claude/hooks/guard-bash.sh`) prints a **non-blocking**
  reminder when you `git push` a feature branch that changed non-doc files. It is a
  nudge, not a gate — it never blocks a push for "not reviewed", because making
  self-review blocking would turn an in-band check into a false control of record
  (tenet 2). The hard blocks in that guard are for unambiguous violations only.
- The **authoritative** review remains CI + Socket/Codex + the maintainer's
  admin-merge. This skill makes those rounds cheaper, not redundant.
