# Dev-session ledger (`dev-sessions.jsonl`)

A **queryable, append-only record of the agent runs that build Console7** — one JSON
object per line in [`dev-sessions.jsonl`](dev-sessions.jsonl). It is the curated index
over the raw per-session transcripts the Claude Code harness already writes to
`~/.claude/projects/<project>/<session-id>.jsonl`.

## Why this exists

- **Lineage of user → prompt → actions for the *dev process*.** Git history (signed +
  DCO) and PRs are the strong, public, tamper-evident trail of *what changed*. This
  ledger adds the *who/how* as **data**: which session produced a PR, with which model,
  at what cost, under which work-order, and with what review verdict — the per-run
  aggregate that git history alone does not make queryable.
- **CO-12.4 / CO-14 evidence.** "AI use logged" is already met by `Co-Authored-By`
  commit trailers (model per commit) + the harness transcripts; this ledger is the
  queryable supplement, not a replacement.

It deliberately mirrors — far more lightly — Linden's `docs/completed-sessions.jsonl`.

## When to append

Append **one entry when a branch's PR is opened** (status `open`), and update it (or
append a superseding entry — see *Conventions*) **when the PR merges or is closed**.
The [`dev-session-ledger`](../.claude/skills/dev-session-ledger/SKILL.md) skill carries
the procedure. It is **most useful for `claude -p` sub-claude runs** (whose `result`
event carries `cost_usd` cleanly); for interactive sessions, cost is best-effort.

This is dev-process metadata, **not** product evidence — it carries no secrets, no
credentials, and no transcript content. Anything sensitive stays out.

## Schema

Each line is a JSON object. Required: `session_id`, `date`, `branch`, `status`.
All others are best-effort.

| Field | Type | Notes |
|---|---|---|
| `session_id` | string | The harness transcript UUID (`~/.claude/projects/<project>/<id>.jsonl`), or the sub-claude UUID. The join key back to the raw trail. |
| `date` | string | ISO-8601 date the run started. |
| `branch` | string | Feature branch. |
| `pr` | number\|null | PR number once opened. |
| `pr_url` | string\|null | Full PR URL once opened. |
| `plan` | string\|null | The plan / work-order slug the run executed, if any. Slug or repo-relative path only — **never an absolute local path** (`~/…`, `/Users/…`). |
| `model` | string | Model ID (e.g. `claude-opus-4-8`). Mirrors the commit `Co-Authored-By` trailer. |
| `cost_usd` | number\|null | From the `claude -p` `result` event; best-effort/omitted for interactive. **Deliberate public disclosure** — this repo is public, so per-run and aggregate dev spend become queryable; that is intended transparency. Omit it (null) when unknown — an absent value is not a bug. |
| `files_changed` | number\|null | |
| `tests_added` | number\|null | |
| `review` | object\|null | `{ "pre_pr_review": "clean\|reconciled", "codex": "pending\|clean\|reconciled\|n/a" }`. `codex`: `pending` = fired, verdict not in yet; `clean` = ran, no findings; `reconciled` = ran, findings fixed; `n/a` = did not run. (Codex auto-fires on PR open — `n/a` is rare.) |
| `status` | string | `open` \| `merged` \| `closed`. |
| `notes` | string\|null | One-line public prose (e.g. residuals tracked). **No secrets, no verbatim prompt/transcript text, no internal hostnames, no absolute local paths.** |

### Example line

```json
{"session_id":"0f3e778d-eba6-4ed2-9c82-e0b4b8b70ed9","date":"2026-06-20","branch":"chore/dev-orchestration-and-ledger","pr":19,"pr_url":"https://github.com/console7/console7/pull/19","plan":"flickering-wobbling-tide","model":"claude-opus-4-8","cost_usd":null,"files_changed":5,"tests_added":0,"review":{"pre_pr_review":"clean","codex":"pending"},"status":"open","notes":"dev-enablement: orchestration rule + this ledger"}
```

## Conventions

- **Append-only.** Prefer appending a superseding entry (same `session_id`, later
  `status`) over rewriting history, so the file reads as a log. Small in-place status
  edits on a not-yet-merged entry are fine before push.
- **`cost_usd` lives on the terminal row only.** When you supersede a row to change
  status, carry `cost_usd` on the latest row and leave it `null` on the superseded
  one — so a per-session sum never double-counts. (The dedup query below is robust
  either way.)
- **One line per JSON object**, no pretty-printing — keeps `git diff` and
  `grep`/`jq` clean.
- Query with `jq`. Because a session may have multiple rows (status changes), take the
  **last row per `session_id`** before summing; the trailing `// 0` keeps an empty
  ledger at `0`, not `null`. Total logged cost:
  `jq -s 'group_by(.session_id) | map(last.cost_usd // 0) | add // 0' docs/dev-sessions.jsonl`.
