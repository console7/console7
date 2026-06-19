# `control-plane/orchestrator/` — session lifecycle & lineage

**Trust tier:** Tier-1 (control plane). Holds no keys at rest.

Owns session lifecycle: calls the PDP for the profile, asks the key broker for
identities, provisions the sandbox, and **stamps the unbroken lineage**
(human Subject → per-session NHI → every tool call, sub-agent action, and artefact)
**at the orchestrator** — because the engine's sub-agent lineage is leaky and cannot
be the sole source of attribution (`DESIGN.md` §2.3, §10.5). Coordinates cross-repo
sessions and emits events to the evidence sink (`ARCHITECTURE.md` §2).

> Phase 1 (bench spine): `orchestrator.go` runs the session lifecycle end to end —
> resolve profile (via the PDP/`PolicySoR` seam) → mint NHI + creds (key broker) →
> provision sandbox with default-deny egress → resolve inference → inject subscription →
> sign the commit → open a PR (PR-only exit) → emit signed, hash-chained evidence at every
> step → teardown. It composes the in-memory devkit seams on a bench (no cloud yet); the
> real `CloudProvider`/egress wall, engine wrap, and KMS signing land in later Phase-1 PRs
> (docs/ROADMAP.md). Holds no keys — every credential/signature comes from the key broker.
