# CLAUDE.md — working context for Console7

Console7 is an open-source, self-hosted control plane for running Claude Code agents
inside an enterprise's own cloud, under enterprise policy. You are helping build it.

## The normative documents — read before working

These are the specification. Implement to them; do not redesign them.

- `GOAL.md` — mission, design tenets, non-goals, success criteria, north-star prompt.
- `docs/DESIGN.md` — the normative spec (MUST/SHOULD requirements, with rationale).
- `docs/ARCHITECTURE.md` — components, trust boundaries, provider interfaces,
  repository & artifact layout (§6), session lifecycle.
- `docs/ROADMAP.md` — phased delivery and exit criteria. **Work the current phase.**

> The north-star prompt in `GOAL.md` is *orientation*, not a single build
> instruction. Do not attempt to build the whole product in one task. Work to the
> roadmap phase, in small reviewable steps.

## How to work here

- Work to the **current roadmap phase** and its exit criteria. Do not pull work
  forward from later phases without being asked.
- **Small, reviewable PRs.** Never commit to `main` directly. Open a feature branch
  and a PR whose description **maps each change to the doc section it implements**.
- Everything composes against `sdk/interfaces`. An interface change, its reference
  implementation, and its conformance test land in **one atomic PR**.
- If you believe a requirement or tenet is **wrong**, say so in the PR description
  and propose the change. **Do not silently deviate.** A deviation from a tenet is a
  regression, not a trade-off (this is the project's stance on itself, too).

## Non-negotiable tenets (condensed from GOAL.md)

1. **The adopter's tenancy is the trust boundary.** No maintainer-hosted path, no
   mandatory phone-home, no egress of adopter data/code/credentials/sessions.
2. **Boundary controls are authoritative; in-band guards are defence-in-depth.**
   Least-privilege identity + default-deny egress are the controls of record;
   permission rules, hooks, and `CLAUDE.md`-style guidance are layers on top. If they
   disagree, the boundary wins.
3. **Scope follows the artefact, not the author.** A session's reach derives from the
   *target's* tier × stratum, resolved from the policy system-of-record
   (authoritative), never from an in-repo file (intent only).
4. **Least privilege, ephemeral by default.** Store no long-lived cloud/SCM secrets.
   Mint short-lived identities at session start.
5. **Observe is not actuate.** Agents propose changes as PRs; the pipeline actuates
   under a human. No session holds author + approve + actuate. No standing
   production-write credential exists.
6. **Evidence over attestation; lineage unbroken** (human → per-session NHI →
   action), stamped at the orchestrator, signed.
7. **One human, one credential, one beneficiary.** Subscription credentials back only
   attended, single-user sessions; anything orchestrated/headless uses org API keys.
8. **Wrap the genuine Claude Code engine; do not reimplement the agent.**

## Security hygiene for THIS repository

This repo is a Tier-1 system **and** public open source. Act accordingly.

- **Never commit secrets** — no API keys, tokens, OAuth tokens, private keys, `.env`
  files, cloud credentials, or Terraform state. Assume everything here is public.
- **No real credentials anywhere** — not in code, tests, or fixtures. Use fakes and
  the `SecretsProvider` seam.
- **Control-plane code holds no keys at rest.** The credential broker / signing
  component is a separate, hardened artifact (`keybroker/`).
- The **sandbox base image** (runs untrusted agent code) and the **control-plane
  image** are distinct artifacts with distinct signing identities. Don't fuse them.
- Commits are **signed**; `main` is protected; changes land via reviewed PR.

## What NOT to do

- Don't reimplement the Claude Code agent — orchestrate it (CLI / Agent SDK).
- Don't add any maintainer-hosted, SaaS, or phone-home path.
- Don't let a session's scope come from an in-repo file.
- Don't grant any persona a standing production-write credential.
- Don't bury long-tail provider implementations in core — reference set only;
  community providers live out-of-tree against the published SDK.

See `docs/BOOTSTRAP.md` for the first tasks.
