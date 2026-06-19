# `sandbox/observe-gateway/` — operate-lane telemetry façade

**Trust tier:** data plane (operate lane).

The **redacting, query-audited, rate-limited** façade over production telemetry for
the operate lane — **not raw log-store credentials** (`DESIGN.md` §5.4). Redaction
depth and the right to attach scale with the target's tier; high-tier targets MUST be
reached through it, lower-tier MAY use direct read-only CLI inside the perimeter. The
operate session's cloud identity is **read-only** (IAM is the authoritative mutation
block); a **PreToolUse mutating-command tripwire** runs as fail-closed
defence-in-depth and emits any mutating attempt as an incident. Drives the
`ObserveGateway` seam.

> P0: placeholder — no implementation.
