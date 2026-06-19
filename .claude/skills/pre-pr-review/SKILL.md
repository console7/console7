---
name: pre-pr-review
description: Run a local adversarial review fan-out (correctness + security + spec-alignment) on a substantive change BEFORE pushing/opening a PR in the console7 repo. Use after staging/committing code or security-relevant contracts and before `git push`. Defence-in-depth that front-runs the authoritative Codex/CI/human gates; skip for pure docs/typos.
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

## How to run it — an adversarial fan-out

In **one message**, spawn three review sub-agents (the `Agent` tool) so they run
concurrently. Give each the **diff** (`git diff main...HEAD` or the staged diff) and
the **normative docs it needs**, and prompt each to **find deviations — not to bless
the change**. Independence is the point: a fresh reader catches what the author
rationalized.

1. **Correctness reviewer** — logic bugs, fail-open defaults, zero-value traps,
   boundary/ordering errors, error handling. Prompt: *"Find correctness bugs in this
   diff. Assume it is wrong; prove where. Check zero values, empty inputs, and
   off-by-one/ordering."*
2. **Security / threat reviewer** — give it `docs/DESIGN.md` §10 + `GOAL.md` tenets.
   Prompt: *"Which abuse class (control-plane-as-target, lethal trifecta, cross-tier
   escalation, subscription misuse, sub-agent lineage, supply chain) could this
   weaken? Does anything return/persist long-lived credentials, widen scope, or fail
   open?"*
3. **Spec-alignment reviewer** — give it `GOAL.md`, `docs/DESIGN.md`,
   `docs/ARCHITECTURE.md`, and the SDLC standard. Prompt: *"Does this deviate from a
   tenet or doc section? In particular: does any SECURITY docstring claim a guarantee
   the signature/type cannot actually enforce?"* — this last is the exact class Codex
   kept finding (a contract promising what its inputs can't support).

Then **reconcile every finding before pushing**: fix it, or record a reasoned
dismissal (as you would for a Codex finding — see `console7-repo-workflow`). Only
then `git push`.

For a one-command version, an opt-in Workflow fan-out is provided at
`.claude/workflows/pre-pr-review.mjs` (runs the same three lenses and synthesizes);
it requires the user to opt into the Workflow tool. The `Agent`-tool fan-out above
needs no opt-in and is the default.

## Lightweight alternative

For a smaller substantive change, the built-in `/code-review` and `/security-review`
skills cover the correctness and security lenses; add a quick spec-alignment check
against the doc section the change maps to. Reconcile, then push.

## Relationship to the other guards

- The **Bash guard** (`.claude/hooks/guard-bash.sh`) prints a **non-blocking**
  reminder when you `git push` a feature branch that changed non-doc files. It is a
  nudge, not a gate — it never blocks a push for "not reviewed", because making
  self-review blocking would turn an in-band check into a false control of record
  (tenet 2). The hard blocks in that guard are for unambiguous violations only.
- The **authoritative** review remains CI + Socket/Codex + the maintainer's
  admin-merge. This skill makes those rounds cheaper, not redundant.
