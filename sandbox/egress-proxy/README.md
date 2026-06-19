# `sandbox/egress-proxy/` — default-deny egress perimeter helper

**Trust tier:** data plane (control-side helper for the boundary).

Control-side helper for the **authoritative** network control: **default-deny at the
sandbox boundary**, via an **out-of-band** proxy / network perimeter (e.g. VPC
Service Controls) — **not** the engine's in-process proxy, which only constrains
well-behaved clients (`DESIGN.md` §5.2). The allowlist composes the inference
endpoint, approved registries / artefact chokepoint, approved internal services, and
approved MCP domains; anything else is denied and the attempt is visible. Removing a
leg of the lethal trifecta is the central abuse-case mitigation (`DESIGN.md` §5.3).
Drives the perimeter side of the `CloudProvider` seam.

> P0: placeholder — no implementation.
