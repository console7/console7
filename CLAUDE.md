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

## Current state (read this first)

The repository is a **docs-only skeleton**. There is **no source code yet** — only
the normative docs, `LICENSE`, `SECURITY.md`, and `docs/adr/0001-language.md`. The
directory tree in `ARCHITECTURE.md` §6.3 (`sdk/`, `control-plane/`, `keybroker/`,
`sandbox/`, `providers/`, `deploy/`, `conformance/`) **does not exist on disk** —
it is the target layout to be created.

The next unit of work is **P0 scaffolding** — the kickoff prompt in
`docs/BOOTSTRAP.md` ("scaffolding only; implement NOTHING behind the interfaces"):
create the §6.3 tree, define the `sdk/interfaces` provider contracts as typed Go
interfaces with SECURITY docstrings, scaffold the conformance harness, add
`docs/THREAT-MODEL.md`. Drive subsequent work down the prompt ladder, one roadmap
phase-gate per PR.

## Architecture in one screen

Full detail is in `ARCHITECTURE.md`; this is the orientation so you don't have to
reconstruct it. **Everything runs in the adopter's cloud tenancy; the only boundary
crossing is model inference** to the adopter-chosen backend.

- **Control plane** (Tier-1, hardened, modular monolith, **holds no keys at rest**):
  Web-CLI UI + API gateway → **Orchestrator** (session lifecycle, *stamps lineage*
  human→NHI→action, cross-repo coordination) → **PDP** (resolves the *target's*
  tier × stratum → session profile) → **Inference Router**, **DLP**, **Evidence
  Sink** (WORM, hash-chained, signed). Lives in `control-plane/`.
- **Key broker** (peeled out early, separately hardened, **distinct signing
  identity**): ephemeral identity minting + per-user subscription-token vault +
  SSO→NHI binding and commit/artefact signing. Lives in `keybroker/`. Never fuse it
  with the control plane.
- **Data plane** (per-session, ephemeral, **untrusted**): the gVisor/microVM
  **sandbox** wrapping the genuine Claude Code engine (`policyHelper` renders locked
  managed-settings + PreToolUse hooks), the **default-deny egress proxy** (the
  *authoritative* perimeter), and the operate-lane **Observe Gateway**. Lives in
  `sandbox/`. Distinct base-image artifact.
- **Provider seams** (the "bring-your-own" contract surface, in `sdk/interfaces`):
  `CloudProvider`, `SecretsProvider`, `IdentityProvider`, `SCMProvider`,
  `InferenceBackend`, `PolicyEngine`, `PolicySoR`, `EvidenceSink`, `ObserveGateway`.
  Reference implementations (GCP/GitHub/Vertex/OPA/GCS) live in `providers/` —
  **reference set only**; community providers live out-of-tree against the published
  SDK.

Monorepo **core + a standalone published SDK + an out-of-tree ecosystem**. Distinct
trust tiers ship as **distinct, separately-signed artifacts** (control-plane image /
key-broker image / sandbox base image / SDK packages). An interface change, its
reference implementation, and its conformance test land in **one atomic PR** — this
is why core is a monorepo.

## Build, test, lint (Go)

The implementation language is **Go** (`docs/adr/0001-language.md`) — it covers the
SDK, control plane, key broker, sandbox control-side helpers, and reference
providers. It does **not** cover the wrapped Claude Code engine (Node/Python, run
as-is in the sandbox and reached over its CLI / Agent SDK) or the `control-plane/ui`
front end (may use web tooling in its own build).

There is **no `go.mod` or build tooling yet** — it gets created during P0
scaffolding. Once a Go module exists, the canonical commands are the standard
toolchain (use these; no custom wrappers exist):

```bash
go build ./...                       # build everything
go test ./...                        # run all tests
go test ./sdk/...                    # run one package tree
go test -run TestName ./path/to/pkg  # run a single test
go vet ./...                         # vet
gofmt -l .                           # list unformatted files (CI-gated)
```

The published SDK = a **Go module**; any npm/PyPI/crate packages are generated
bindings, not reimplementations. When you add the module, prefer a tight dependency
surface — this is a Tier-1, public, security-sensitive codebase.

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
- Commits are **signed and DCO-signed-off** (`git commit -S -s`); `main` is protected;
  changes land via reviewed PR.

## SDLC standard — this repo governs itself

This repository is governed by **[`docs/standards/console7-sdlc-standard.md`](docs/standards/console7-sdlc-standard.md)**
— a **Tier-1 × (S1 Engineered + S5 Agentic)** tailoring of a 19-control-objective
secure-SDLC standard, bound to the **OpenSSF** posture (Scorecard, OSPS Baseline L3,
Best Practices Badge silver). It governs **the engineering of this repo**, distinct
from the *product's* control objectives (those are in `ROADMAP.md`). Read it before
substantive work; cite the CO(s) a change satisfies in the PR body (CO-14.2).

The standard is **self-enforcing for agent sessions** — you'll observe it by default:

- **`.claude/settings.json` hooks.** A `SessionStart` hook prints the posture; a
  `PreToolUse(Bash)` guard (`.claude/hooks/guard-bash.sh`) **blocks** direct/force
  push to `main`, un-signed-off commits, `curl|sh`, and un-vetted dependency installs.
  These are *in-band* convenience (tenet 2); the CI gates + branch protection are the
  controls of record.
- **Skills.** `.claude/skills/sdlc-compliance` and `.claude/skills/supply-chain-policy`
  are the self-authored how-to references; they auto-load when relevant.
- **Supply chain (CO-5/CO-12.7).** Route installs through **Socket Firewall**
  (`sfw …`) or a lockfile-faithful install; **pin** everything (Go releases; actions
  to full SHA); never `curl … | sh`. `.claude/` skills/agents/hooks are **code** —
  first-party/self-authored only, enforced by `scripts/audit-skill-provenance.sh`.
- **Gates.** secret-scan, OpenSSF Scorecard (private for now), SAST (semgrep now,
  CodeQL when Go lands), the governance gate, and — once Go code exists — lint +
  `govulncheck`. Fix a failing gate's cause; never seek to bypass it.

## What NOT to do

- Don't reimplement the Claude Code agent — orchestrate it (CLI / Agent SDK).
- Don't add any maintainer-hosted, SaaS, or phone-home path.
- Don't let a session's scope come from an in-repo file.
- Don't grant any persona a standing production-write credential.
- Don't bury long-tail provider implementations in core — reference set only;
  community providers live out-of-tree against the published SDK.

See `docs/BOOTSTRAP.md` for the first tasks.
