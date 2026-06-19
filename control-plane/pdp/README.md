# `control-plane/pdp/` — policy decision service

**Trust tier:** Tier-1 (control plane). Holds no keys at rest.

Resolves the **target's** tier × stratum (from the `PolicySoR`) into a **session
profile** — egress allowlist, autonomy ceiling, persona constraints, human-gate flag
— and applies **take-the-max + step-up** across multiple targets (`DESIGN.md` §1.3,
§4.2). Integrates a `PolicyEngine` (OPA/Cedar). **Scope follows the artefact, not the
launcher**, and the PDP does **not** own the system of record (`DESIGN.md` §4.1).

> Phase 1 (minimal): `ResolveProfile` (currently in `../orchestrator/pdp.go`) resolves the
> target's tier × stratum through the `PolicySoR` seam and derives a fixed single-lane
> `SessionProfile` (author × T3), failing closed on an unresolved target. The full
> tier × stratum → profile policy — autonomy-ceiling/human-gate matrices, take-the-max +
> step-up across targets, `PolicyEngine` integration — is Phase 3 (docs/ROADMAP.md).
