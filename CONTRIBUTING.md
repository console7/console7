# Contributing to Console7

Thanks for your interest. Console7 is an **open-source, self-hosted control plane**
for running coding/operations agents inside an enterprise's own cloud. It is a
**Tier-1, security-sensitive, public** codebase and it **governs itself** — so
contributions follow the same controls the product enforces. This guide is the short
version; the authoritative posture is
[`docs/standards/console7-sdlc-standard.md`](docs/standards/console7-sdlc-standard.md).

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).

## Before you start

- **Read the normative docs** — `GOAL.md`, `docs/DESIGN.md`, `docs/ARCHITECTURE.md`,
  `docs/ROADMAP.md`. Implement *to* them; do not redesign them. **Work the current
  roadmap phase.**
- If you believe a requirement or tenet is **wrong**, say so in the PR description and
  propose the change. Do **not** silently deviate — a deviation from a tenet is a
  regression, not a trade-off.

## The contribution flow

1. **Open an issue** first for anything non-trivial, so design is agreed before code.
2. **Branch + PR — never push to `main`.** Keep PRs **small and reviewable**. An
   interface change, its reference implementation, and its conformance test land in
   **one atomic PR**.
3. **Sign and sign-off every commit:** `git commit -S -s`.
   - `-S` cryptographically signs the commit (required on protected branches).
   - `-s` adds the **Developer Certificate of Origin** sign-off (see below).
   - Construct commit messages via a file (`-F`) so an in-message pattern doesn't
     trip the local Bash guard.
4. **Map each change to the doc section / control objective (CO) it implements** in
   the PR body — the PR template asks for this (CO-14.2 traceability).
5. **Pass the gates.** secret-scan, the CO-12.7 governance gate, Socket, the DCO
   check, and (once Go code exists) lint, `govulncheck`, and CodeQL. **Fix the cause
   of any failure — do not seek to bypass a gate** (it is the control of record).
6. A maintainer reviews and merges. Every finding from an automated reviewer
   (e.g. Codex) is reconciled per-finding before merge.

## Developer Certificate of Origin (DCO)

Console7 uses the [DCO](https://developercertificate.org/) — a lightweight assertion
that you wrote, or have the right to submit, the code you contribute. There is **no
CLA**. Add the sign-off to every commit:

```
git commit -S -s -m "…"
```

This appends a trailer to your commit message:

```
Signed-off-by: Your Name <your.email@example.com>
```

The name/email must be real and match your commit author identity. The `dco` workflow
verifies every commit in a PR carries it; a PR with an unsigned-off commit will fail
the check. Contributions are accepted under the repository's
[Apache-2.0 license](LICENSE).

## Supply-chain expectations (CO-5)

- **Don't `curl … | sh`.** Download, review, pin, then run.
- **Route package installs through Socket Firewall** (`sfw …`) or a lockfile-faithful
  install (`npm ci`, `--frozen-lockfile`); never a bare `npm install` / `pip install`.
- **Pin everything:** Go dependencies to released versions (commit `go.sum`); GitHub
  Actions to a full commit SHA. Prefer the standard library / an existing dependency
  before adding a new one, and justify any new dependency in the PR.
- **`.claude/` skills, agents, hooks are code** — first-party/self-authored only
  (CO-12.7); never reference a remote/marketplace source.

## Never commit secrets

No API keys, tokens, private keys, `.env` files, cloud credentials, or Terraform
state — assume everything here is public. Use fakes and the `SecretsProvider` seam.
Secret scanning blocks on detection.

## Local setup

Install [Socket Firewall](https://socket.dev) once so the local guard's allow-path
works: `npm i -g sfw`. The repo's `.claude/` settings wire a `PreToolUse` guard and a
`SessionStart` orientation hook for agent sessions; they are defence-in-depth, not the
control of record.

## Questions / security

- General questions → open a discussion or issue.
- **Security vulnerabilities → do not open a public issue.** Follow
  [`SECURITY.md`](SECURITY.md) (GitHub Security Advisories or `security@naanya.biz`).
