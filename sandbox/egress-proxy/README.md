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

## Make the wall unbypassable (requirements)

The perimeter is only authoritative if it cannot be side-stepped from inside the
sandbox. Independent analysis of an adjacent platform (see `docs/THREAT-MODEL.md` →
*Prior art*) gives a concrete blueprint; the implementation MUST realise it:

- **No in-sandbox DNS for arbitrary names.** Resolution of non-allowlisted domains
  MUST fail; do not ship the sandbox a general resolver.
- **Network-gateway deny, not just a proxy env var.** Direct TCP to any
  non-allowlisted destination MUST be dropped at the gateway/perimeter — egress
  routing MUST NOT depend on the workload honouring `HTTP(S)_PROXY` (a hostile or
  buggy client ignores it).
- **Block cloud metadata / IMDS** (e.g. `169.254.169.254`) at the gateway, regardless
  of `no_proxy` — it is a credential-theft and SSRF vector.
- **Defence-in-depth layering** — gVisor syscall interception + perimeter firewall +
  (where present) a proxy — so no single bypass defeats egress control.
- **No maintainer-injected destinations.** The allowlist is **wholly adopter-composed
  and auditable**; Console7 MUST NOT silently add hosts (`GOAL.md` tenet 1) — the exact
  anti-pattern the adjacent platform exhibited.

> P0: placeholder — requirements only, no implementation.
