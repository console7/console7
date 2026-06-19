# `control-plane/pdp/` — policy decision service

**Trust tier:** Tier-1 (control plane). Holds no keys at rest.

Resolves the **target's** tier × stratum (from the `PolicySoR`) into a **session
profile** — egress allowlist, autonomy ceiling, persona constraints, human-gate flag
— and applies **take-the-max + step-up** across multiple targets (`DESIGN.md` §1.3,
§4.2). Integrates a `PolicyEngine` (OPA/Cedar). **Scope follows the artefact, not the
launcher**, and the PDP does **not** own the system of record (`DESIGN.md` §4.1).

> P0: placeholder — no implementation.
