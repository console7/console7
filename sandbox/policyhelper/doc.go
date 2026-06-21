// Package policyhelper renders the composed, LOCKED managed-settings + PreToolUse hooks a
// session's wrapped Claude Code engine runs under, from the session's resolved SessionProfile
// (ARCHITECTURE.md §8; DESIGN.md §1.4, §5.4). It is the in-sandbox, in-band layer of Console7's
// defence-in-depth — NEVER the control of record. The authoritative controls are the boundary:
// least-privilege identity and the default-deny egress perimeter (GOAL.md tenet 3). If the
// rendered settings and the boundary ever disagree, the boundary wins; these settings exist to
// add a second layer (and, for the operate lane, the heuristic mutating-command tripwire DESIGN.md
// §5.4 requires), not to be relied on alone.
//
// # What it renders
//
// Render(profile) returns a managed-settings.json (the Claude Code "managed settings" tier, which
// has the HIGHEST precedence and cannot be overridden by user/project settings — the engine reads
// it from a root-owned, read-only path the agent cannot write) plus the hook scripts it references:
//
//   - persona-derived tool permissions (author = development-capable with self-modification and
//     obvious-actuation denials; operate = read-only — every mutating tool denied);
//   - a PreToolUse mutating-command tripwire on the operate lane (heuristic, fail-closed, denies
//     in-sandbox — DESIGN.md §5.4);
//   - lockdown fields: bypass-permissions mode disabled, and the engine's non-essential outbound
//     traffic / auto-update / telemetry disabled (tenet 1 — the engine must not phone home or
//     mutate its own pinned version from inside the sandbox).
//
// The output is deterministic (stable field/array order) so a session's settings are reproducible
// and the conformance/white-box tests are stable.
//
// # Real vs deferred in this PR (PR-3)
//
//   - REAL: the full render for author and operate personas, the lockdown fields, the operate
//     tripwire hook + script, and the consistency invariant (every hook the settings reference is
//     emitted in Rendered.Hooks).
//   - DEFERRED: the tripwire's "emit an INCIDENT to the evidence sink" half (DESIGN.md §5.4) needs
//     the engine wired into the orchestrator with a callback to the EvidenceSink; the orchestrator
//     stays synthetic in this PR, so the script denies in-sandbox and marks the incident on stderr,
//     and the evidence emission lands when the engine is wrapped end to end (a clean follow-up).
//   - DEFERRED: the full per-tier autonomy matrix is Phase 3; Phase 1 is author × T3/S1
//     (control-plane/orchestrator.ResolveProfile), so tier currently shapes only the conservative
//     defaults, not a rich matrix.
package policyhelper
