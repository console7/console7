# `control-plane/ui/` — front end (thin `c7` CLI today)

**Trust tier:** Tier-1 (control plane). **Thin; holds no secrets.**

A thin client of the orchestrator: it builds a `LaunchRequest`, calls `orchestrator.Run`,
and renders the launch + the terminal result — the proposed PR and the evidence-chain
verdict. (`Run` is synchronous and returns one terminal `Summary`, so "watch" is staged log
lines around the call, not a streamed event bus — see Deferred.) The browser is a governed
window onto a real server-side session, not the session itself (`DESIGN.md` §1.1).

## What's here (B10)

- **`cli.go`** — the testable core: `LaunchSpec` (flag-derived) → validated
  `orchestrator.LaunchRequest`, and `Launch(...)` which drives one session and writes its
  lifecycle/PR/evidence verdict. It depends only on the orchestrator surface (a `Runner`
  interface) so it is unit-tested without wiring the seam spine.
- **`cmd/c7/`** — the `c7 launch` binary. It wires a **NON-PRODUCTION dev spine** (the
  in-memory `devkit` seams) so a full governed session runs locally and in CI:

  ```
  $ c7 launch --repo acme/widgets --branch c7/sess-1 --prompt "fix the README typo"
  session c7-…: launching (org-API lane, branch c7/sess-1)...
  session c7-…: inference resolved -> https://api.anthropic.com
  session c7-…: PROPOSED commit 46fc14a (1 file) signed by NHI nhi/c7-…/author
  session c7-…:   PR: https://github.com/acme/widgets/pull/1
  session c7-…: evidence chain VERIFIED (9 records)
  ```

## Deferred

- **Production wiring** — the real GCP/GitHub/Anthropic seams + an **SSO-obtained** authn
  token (instead of the dev assertion) behind the same `ui.Launch` surface; exercised by the
  operator-run **B11** live PoC.
- **The browser gateway** — SSO login + **SSE** streaming of the live session to a browser
  (`ARCHITECTURE.md` §2). The orchestrator's `Run` is synchronous today, so the CLI stages
  progress around the call rather than streaming an event bus; a real event stream is the
  web-gateway follow-up. May use web tooling in its own build (`docs/adr/0001-language.md`).
