package policyhelper

import (
	"encoding/json"
	"fmt"

	"github.com/console7/console7/sdk/interfaces"
)

// HooksDir is the root-owned, read-only directory in the sandbox base image where the rendered
// hooks live (a baked binary, TripwirePath). The agent cannot write here (the managed-settings deny
// rules forbid it in-band, and the image mounts it read-only out-of-band).
const HooksDir = "/etc/console7/hooks"

// ManagedSettingsPath is where the base image writes the rendered managed-settings.json — the
// Claude Code "managed settings" location, the highest-precedence tier the agent cannot override.
const ManagedSettingsPath = "/etc/claude-code/managed-settings.json"

// Rendered is the output of Render: the managed-settings.json bytes. The hooks it references are
// BAKED binaries in the base image (TripwirePath), not rendered files, so there is nothing else to
// write — the base image's entrypoint writes ManagedSettings to ManagedSettingsPath before
// launching the engine.
type Rendered struct {
	// ManagedSettings is the LOCKED managed-settings.json (deterministic, indented).
	ManagedSettings []byte
}

// --- the managed-settings.json shape (a subset of Claude Code's schema; struct-typed for stable
// field order, so the rendered JSON is deterministic) ---

type managedSettings struct {
	Permissions permissions       `json:"permissions"`
	Hooks       hookSet           `json:"hooks"`
	Env         map[string]string `json:"env"`
	// disableBypassPermissionsMode = "disable" stops the agent from switching off permission
	// prompts/rules at runtime — the locked rules below must actually bind.
	DisableBypassPermissionsMode string `json:"disableBypassPermissionsMode"`
	// cleanupPeriodDays 0: keep no local transcript retention inside the ephemeral sandbox (the
	// durable, signed record is the WORM evidence sink, not the engine's local history).
	CleanupPeriodDays int `json:"cleanupPeriodDays"`
}

type permissions struct {
	Allow       []string `json:"allow"`
	Deny        []string `json:"deny"`
	DefaultMode string   `json:"defaultMode"`
}

type hookSet struct {
	PreToolUse []hookMatcher `json:"PreToolUse,omitempty"`
}

type hookMatcher struct {
	Matcher string    `json:"matcher"`
	Hooks   []hookCmd `json:"hooks"`
}

type hookCmd struct {
	Type    string `json:"type"`
	Command string `json:"command"`
}

// lockedEnv disables the engine's non-essential outbound traffic, auto-update, and telemetry. The
// sandbox engine is PINNED in the image (DESIGN.md §1.4) and must not phone home or mutate its own
// version from inside the sandbox (tenet 1 — no egress of adopter data; the default-deny perimeter
// would block these anyway, this is the in-band layer that also stops the attempts at the source).
func lockedEnv() map[string]string {
	return map[string]string{
		"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
		"DISABLE_AUTOUPDATER":                      "1",
		"DISABLE_TELEMETRY":                        "1",
		"DISABLE_ERROR_REPORTING":                  "1",
	}
}

// commonDeny is the defence-in-depth denial set both personas carry: the agent may not rewrite its
// own locked guards (the read-only mount is the authoritative control; this is the in-band echo),
// nor disable the permission system. These are NOT the boundary — they are a second layer.
func commonDeny() []string {
	return []string{
		"Read(" + HooksDir + "/**)",
		"Edit(" + HooksDir + "/**)",
		"Write(" + HooksDir + "/**)",
		"Edit(" + ManagedSettingsPath + ")",
		"Write(" + ManagedSettingsPath + ")",
		"Edit(/etc/claude-code/**)",
		"Write(/etc/claude-code/**)",
	}
}

// Render composes the locked managed-settings + hooks for profile. It fails closed on an
// unrecognised persona (a session profile the renderer does not understand must not run under
// default-permissive settings).
func Render(profile interfaces.SessionProfile) (Rendered, error) {
	var perms permissions
	var hooks hookSet

	switch profile.Persona {
	case interfaces.PersonaAuthor:
		perms = authorPermissions()
	case interfaces.PersonaOperate:
		perms = operatePermissions()
		// The operate lane MAY use read-only CLI inside the perimeter (DESIGN.md §5.4), so Bash is
		// allowed — and gated by the PreToolUse mutating-command tripwire the same clause REQUIRES.
		// The tripwire is a baked binary (TripwirePath); nothing else to render.
		hooks.PreToolUse = []hookMatcher{{
			Matcher: "Bash",
			Hooks:   []hookCmd{{Type: "command", Command: TripwirePath}},
		}}
	default:
		return Rendered{}, fmt.Errorf("policyhelper: unrecognised persona %q — refusing to render default-permissive settings (fail closed)", profile.Persona)
	}

	ms := managedSettings{
		Permissions:                  perms,
		Hooks:                        hooks,
		Env:                          lockedEnv(),
		DisableBypassPermissionsMode: "disable",
		CleanupPeriodDays:            0,
	}
	b, err := json.MarshalIndent(ms, "", "  ")
	if err != nil {
		return Rendered{}, fmt.Errorf("policyhelper: marshal managed-settings: %w", err)
	}
	b = append(b, '\n')
	return Rendered{ManagedSettings: b}, nil
}

// authorPermissions: development-capable. The author persona writes code and proposes it as a PR;
// it holds NO production-write credential (the boundary), so these in-band rules just add a second
// layer — allow the development toolset, deny self-modification (commonDeny) and the most obvious
// actuation/escape attempts (merging its own PR, force-pushing). "Observe is not actuate; no
// session holds author + approve + actuate" (DESIGN.md §1.2/§5.4) is enforced by the pipeline +
// the SCM least-privilege token, not here.
func authorPermissions() permissions {
	return permissions{
		Allow: []string{
			"Read", "Grep", "Glob", "LS",
			"Edit", "Write", "MultiEdit", "NotebookEdit",
			"Bash", "WebSearch",
		},
		Deny: append(commonDeny(),
			"Bash(gh pr merge:*)",
			"Bash(git push --force:*)",
			"Bash(git push -f:*)",
		),
		DefaultMode: "default",
	}
}

// operatePermissions: READ-ONLY (DESIGN.md §5.4 — the operate session cannot mutate; its cloud
// identity is read-only, the authoritative control). In-band, deny every file-mutating tool, and
// ALLOW Bash for read-only CLI (DESIGN.md §5.4: "MAY use direct read-only CLI inside the perimeter")
// while GATING it through the PreToolUse mutating-command tripwire (wired in Render). The session
// proposes changes as PRs, never actuates. This is the in-band second layer; IAM (the read-only
// cloud identity) is the control of record.
func operatePermissions() permissions {
	return permissions{
		Allow: []string{
			"Read", "Grep", "Glob", "LS", "WebSearch", "Bash",
		},
		Deny: append(commonDeny(),
			"Edit", "Write", "MultiEdit", "NotebookEdit",
		),
		DefaultMode: "default",
	}
}
