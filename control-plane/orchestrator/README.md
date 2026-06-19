# `control-plane/orchestrator/` — session lifecycle & lineage

**Trust tier:** Tier-1 (control plane). Holds no keys at rest.

Owns session lifecycle: calls the PDP for the profile, asks the key broker for
identities, provisions the sandbox, and **stamps the unbroken lineage**
(human Subject → per-session NHI → every tool call, sub-agent action, and artefact)
**at the orchestrator** — because the engine's sub-agent lineage is leaky and cannot
be the sole source of attribution (`DESIGN.md` §2.3, §10.5). Coordinates cross-repo
sessions and emits events to the evidence sink (`ARCHITECTURE.md` §2).

> P0: placeholder — no implementation.
