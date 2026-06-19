# Console7

**Console7 is an open-source control plane for running coding and operations agents
(Claude Code) inside your own cloud, under your own policy.** It gives staff a
hosted "web-CLI" — the ergonomics of Claude Code on the web — while keeping every
sensitive thing inside your tenancy: the sandbox, the credentials, the logs, the
evidence. It is built to *enable* a modernised SDLC, not collide with one.

It is designed, from the first commit, as a product an enterprise runs itself.

## The consumption model: bring your own everything

- **Bring your own cloud.** Console7 deploys into *your* GCP / AWS / Azure tenancy.
  The maintainer runs nothing for you and never sees your data, code, or sessions.
- **Bring your own subscription.** A user signs into their *own* Claude
  subscription for their *own* interactive work — one human, one credential, one
  beneficiary. Console7 hosts the CLI; it does not pool or broker seats.
- **Bring your own keys.** Org-scale and automated work runs on *your* Anthropic
  API keys via the backend you choose — Vertex, Bedrock, or direct — and on *your*
  cloud and SCM credentials, minted short-lived and never stored long-term.

Nothing leaves your tenancy except model inference, to the backend you select.

## The doctrine in one screen

1. **Your tenancy is the trust boundary.** We host nothing for you; no phone-home
   of your data.
2. **Boundary controls are authoritative; in-band guards are defence-in-depth.**
   Least-privilege identity and a default-deny egress perimeter are the real
   controls. Agent permission rules, hooks, and `CLAUDE.md` are layers on top —
   never the perimeter. If layers disagree, the boundary wins.
3. **Scope follows the artefact, not the author.** A session's reach is derived
   from the target's criticality tier × authoring stratum, not from who launched it.
4. **Least privilege, ephemeral by default.** Console7 stores no long-lived cloud or
   SCM secrets; it mints short-lived identities at session start.
5. **Observe is not actuate.** Operations agents read production telemetry and
   *propose* changes as pull requests; the pipeline actuates, under a human.
6. **Evidence over attestation.** Unbroken lineage from human → non-human identity
   → every tool call and commit, recorded immutably.
7. **Proportionate.** Rigour scales to consequence. Over-control is a finding too.
8. **It governs itself.** Console7 is a Tier-1 system and a credible supply-chain
   citizen: signed builds, SBOM, provenance.

## Two lanes

- **Author** — develop. Repo-scoped, opens pull requests, **no** production reach.
- **Operate** — read-only production telemetry → diagnose → **propose** a PR/IaC
  change. No path to mutate production. (There is deliberately no "actuate" lane;
  actuation is the pipeline's job under human approval.)

## Documents

| Doc | What it is |
|-----|------------|
| [`GOAL.md`](./GOAL.md) | Mission, design tenets, non-goals, success criteria, and a reusable north-star prompt |
| [`docs/DESIGN.md`](./docs/DESIGN.md) | Detailed, normative design specification |
| [`docs/ARCHITECTURE.md`](./docs/ARCHITECTURE.md) | Components, trust boundaries, provider interfaces, session lifecycle |
| [`docs/ROADMAP.md`](./docs/ROADMAP.md) | Phased delivery, exit criteria, control-objective onramp |
| [`docs/BOOTSTRAP.md`](./docs/BOOTSTRAP.md) | How to start building: the scoped kickoff prompt and prompt ladder |
| [`CLAUDE.md`](./CLAUDE.md) | Standing context + guardrails for the agent building Console7 |

**Getting started building Console7:** see [`docs/BOOTSTRAP.md`](./docs/BOOTSTRAP.md) —
lock the repo down, then drive from the prompt ladder, not the north-star prompt.

## Status & licensing

Pre-alpha — design phase. Licensed under **Apache-2.0** (permissive,
patent grant, enterprise-friendly) — see [`LICENSE`](./LICENSE). Security
disclosure policy: see [`SECURITY.md`](./SECURITY.md). Console7 ships **no
credentials** and stores **no long-lived secrets** — a precondition for being
trusted in someone else's tenancy.

## Relationship to upstream

Console7 **wraps the genuine Claude Code engine** (headless CLI / Agent SDK); it does
not reimplement the agent. Anthropic's Managed Agents *self-hosted sandboxes* are
adjacent prior art — they keep orchestration on Anthropic's side while tool
execution runs in your infrastructure. Console7's distinguishing choice is that the
**orchestration and control plane also run in your tenancy**. Evaluate both.
