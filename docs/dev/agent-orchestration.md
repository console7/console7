# Dev-time agent orchestration — when to use `claude -p` sub-claudes vs `Workflow`/`Agent`

> **Scope:** this is about **how we develop Console7** with Claude Code — our own
> agent tooling. It is *not* about how the Console7 *product* orchestrates the engine
> for adopters (that is `docs/ARCHITECTURE.md`). Don't conflate the two.

Two orchestration mechanisms are available when building this repo. They are
**different tools for different task shapes**, not competitors — pick by the shape of
the work, not by habit.

## The two mechanisms

| | `claude -p` **sub-claude** | **`Workflow` / `Agent`** tool |
|---|---|---|
| Unit of work | A **full** Claude Code session (its own hooks, agents, permission mode; can open its own PR, self-recover) | An in-process subagent that returns a result (text or schema-validated object) to its orchestrator |
| Lifespan | Long, autonomous (minutes; lands a PR) | Bounded; ends when it returns |
| Control flow | Boss prose + monitoring | Deterministic — pipeline / parallel / loop, structured-output schemas, concurrency cap, journal + resume |
| Audit trail | The session JSONL **is** the trail; needs manifest discipline to stay tracked | Journal/resume *state* in-harness; the *result* is held by the orchestrator, not a committed file |
| Tooling | Global: `~/.claude/bin/sub-claude-long` (+ `sub-claude-filter`) | In-session `Workflow` / `Agent` tools |
| Best for | Long, parallel, repo-spanning **implementation** that should each land a PR | Bounded, structured **analysis / review / search / planning** |

## Decision rule

- **Default to `Workflow` / `Agent`.** For building Console7 this is the common case:
  reviews, multi-lens analysis, fan-out search, planning panels, audits. No `/tmp`
  plumbing or manifest discipline. It fits the repo's cadence (small reviewable PRs,
  one roadmap phase-gate per PR, heavy CI/Codex/human gates). Within this default:
  the **`Agent`-tool fan-out is always available** (no opt-in) and is the baseline;
  the **`Workflow` tool is the opt-in deterministic upgrade** (pipeline/parallel/loop,
  structured-output schemas, journal + resume) and **requires the user to opt in**.
  The canonical example already in-tree is **`.claude/workflows/pre-pr-review.mjs`**
  (the `Workflow` form) with the `.claude/skills/pre-pr-review` skill documenting the
  `Agent`-tool fan-out as its no-opt-in default.
- **Reach for a `claude -p` sub-claude** only for long, autonomous, *independent*
  **implementation** runs you want to parallelize and have each land its own PR (the
  classic boss-spawns-implementers pattern). Console7's cadence needs this **less**
  than a multi-repo sprint does — but it is the right tool when two or more independent
  PRs can be built concurrently. When you use it, log the run in the
  [dev-session ledger](../dev-sessions.md) (see the `dev-session-ledger` skill).

## Do not

- **Don't** use a sub-claude for review/analysis — that is what the `Workflow` already
  does, more cheaply and deterministically.
- **Don't** expect `Workflow`/`Agent` subagents to land their own PRs — they are not
  full sessions; they return results to *you*, and *you* commit.
- **Don't** let any orchestration weaken the independent gates. Human merge, CI, and
  Codex stay authoritative and **independent of the agents that produced the change**
  (tenet 2; and, once we dogfood Console7-on-Console7, the bootstrapping guardrail —
  the tool is never the sole gate on its own changes).

## Governance note

Anything added under `.claude/` (skills, agents, hooks, workflows) is **code** and is
reviewed as such — first-party / self-authored only (CO-12.7 / CO-12.8), enforced by
`scripts/audit-skill-provenance.sh`. Your *personal* orchestration (spawn helpers, a
private ledger) can instead live in `~/.claude/` and stay out of the repo.
