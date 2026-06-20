---
name: dev-session-ledger
description: Log an agent run that builds the console7 repo to the append-only dev-session ledger (docs/dev-sessions.jsonl). Use when opening, merging, or closing a PR produced by a Claude Code session — especially a `claude -p` sub-claude run — to keep the queryable who/model/cost/verdict trail (CO-12.4/CO-14). Skip for trivial human-only edits.
---

# Dev-session ledger

Maintains [`docs/dev-sessions.jsonl`](../../../docs/dev-sessions.jsonl) — the
append-only, queryable index of the agent runs that build Console7. The full schema,
rationale, and field table live in [`docs/dev-sessions.md`](../../../docs/dev-sessions.md);
read it once. This skill is the **procedure**.

This is dev-process metadata, not product evidence: **no secrets, no credentials, no
transcript content** ever go in the ledger.

## When to log

- **On PR open** — append one entry with `status: "open"`.
- **On merge / close** — update that entry (or append a superseding line with the same
  `session_id` and a later `status`) to `merged` / `closed`, filling `cost_usd`,
  `files_changed`, `tests_added`, and the `review` verdicts now known.
  - **PR-safe path (you cannot commit to `main`).** By merge time the branch is often
    already merged/deleted, so the terminal-status update **rides a *subsequent* PR** —
    piggyback it on the *next* dev-session entry, or batch a small ledger-sweep PR.
    An entry legitimately sitting at `status:"open"` until the next PR sweeps it is
    **expected, not a gap**. Never commit the update straight to `main` to "finalize"
    it.
- Most valuable for **`claude -p` sub-claude runs** — their final `result` event
  carries `cost_usd` cleanly. For interactive sessions, cost is best-effort; omit it
  rather than guess.
- **Skip** for trivial human-only edits (typo, formatting) — proportionality.

## How to log

1. **Find the `session_id`** (the join key back to the raw transcript) **with an
   explicit identifier, not an mtime guess.** Picking "the most recently modified
   `*.jsonl`" is unsafe — a parallel session, a second worktree, or a reviewer session
   can be the newest writer, so you'd record the wrong run's UUID.
   - **`claude -p` sub-claude:** use the UUID you **assigned** at spawn
     (`--session-id "$SUB_UUID"`). Unambiguous.
   - **Interactive run:** use the harness's reported current-session id. If you must
     locate the transcript under `~/.claude/projects/<project-slug>/`, **confirm it by
     a unique marker from this session** (e.g. `grep -l "<this branch name>" *.jsonl`),
     never by mtime alone.
2. **Append one line** to `docs/dev-sessions.jsonl` matching the schema in
   `docs/dev-sessions.md`. Required: `session_id`, `date`, `branch`, `status`. Record
   `model` to mirror the commit `Co-Authored-By` trailer. One compact JSON object per
   line — no pretty-printing.
3. **Commit it** with the change it describes (or as a follow-up commit on the same
   branch once the PR number is known), signed + DCO (`git commit -S -s`).

## Conventions

- **Append-only** in spirit: prefer a superseding line over rewriting history; small
  in-place status edits on a not-yet-merged entry are fine before push.
- Keep entries one-per-line so `git diff`, `grep`, and `jq` stay clean.
- This ledger never gates anything — git history, CI, Codex, and the human merge
  remain the authoritative trail and gates.
