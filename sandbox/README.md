# `sandbox/` — the data plane (untrusted by default)

**Trust tier:** data plane — per-session, **ephemeral, untrusted**. It **runs
untrusted agent code**. **Artifact:** sandbox base image, signed · SBOM · provenance
· **distinct build identity** from the control-plane and key-broker images — *the
thing that runs untrusted code must not share a build identity with the thing that
holds the keys* (`ARCHITECTURE.md` §6.4; `DESIGN.md` §8). **Do not fuse with the
control plane.**

- [`base-image/`](base-image/) — wraps the **genuine** Claude Code engine + tooling
  (we orchestrate it, we do not reimplement it — `GOAL.md` tenet 8); `policyHelper`
  renders the composed, **locked** managed-settings + PreToolUse hooks per session.
- [`egress-proxy/`](egress-proxy/) — control-side helper for the **default-deny**
  egress perimeter. The perimeter is the **authoritative** network control and is
  **out-of-band** (the cloud enforces; this configures) — *not* the engine's
  in-process proxy (`DESIGN.md` §5.2).
- [`observe-gateway/`](observe-gateway/) — operate-lane redacting, query-audited
  telemetry façade (`DESIGN.md` §5.4).

Isolation is **gVisor or a microVM**, enforced at the kernel/syscall boundary, with
ephemeral workspaces by default (`DESIGN.md` §5.1). In-sandbox hooks and the operate
tripwire are **defence-in-depth**, never the control of record — the boundary wins
(`GOAL.md` tenet 3).

> P0 scaffolding: directory tree and responsibilities only — **no implementation.**
