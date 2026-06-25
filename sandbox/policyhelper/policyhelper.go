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

// NOTE on schema fidelity: this is a SUBSET of Claude Code's managed-settings schema, and the
// exact field placement/names below (the permissions nesting, the managed-only lockouts, the
// filesystem-root "//" path anchor) MUST be validated against the PINNED engine version when the
// orchestrator is wired to invoke the genuine engine (deferred in this PR — the lifecycle stays
// synthetic, so nothing here is yet exercised by a real engine). They are the in-band, second-layer
// guards (the boundary is authoritative); getting them exactly right is a correctness, not a
// security-of-record, matter — but a misplaced field is a silent no-op, so it is treated as a bug.
type managedSettings struct {
	Permissions permissions       `json:"permissions"`
	Hooks       hookSet           `json:"hooks"`
	Env         map[string]string `json:"env"`
	// allowManagedHooksOnly / allowManagedPermissionRulesOnly: make the engine ignore hooks and
	// permission rules contributed by LOWER-precedence (project/user) settings. Without them, an
	// untrusted target repo's .claude/settings.json can still register its own PreToolUse hooks
	// (arbitrary shell, OUTSIDE the operate tripwire) and add auto-approve allow rules the deny set
	// does not cover — i.e. the "locked" policy would not actually be locked against repo content.
	AllowManagedHooksOnly           bool `json:"allowManagedHooksOnly"`
	AllowManagedPermissionRulesOnly bool `json:"allowManagedPermissionRulesOnly"`
	// cleanupPeriodDays 0: keep no local transcript retention inside the ephemeral sandbox (the
	// durable, signed record is the WORM evidence sink, not the engine's local history).
	CleanupPeriodDays int `json:"cleanupPeriodDays"`
	// gcpAuthRefresh is a Claude Code setting whose value is a SHELL COMMAND the engine runs to refresh
	// Google credentials when it detects Vertex/GCP token expiry (the gcloud-auth-refresh hook). On the
	// Console7 Vertex lane the sandbox holds NO GCP credential and never authenticates to Vertex itself
	// (the per-session auth-proxy attaches the bearer; cloud-gcp engineRunScript sets
	// CLAUDE_CODE_SKIP_VERTEX_AUTH=1), so there is nothing to refresh — and a refresh command is
	// arbitrary command execution. We pin it EMPTY in the managed (highest-precedence) tier so a target
	// repo's .claude/settings.json cannot define one (defence-in-depth, tenet 2; the boundary — the
	// credential-free sandbox + the auth-proxy — is the authoritative control). Always rendered (no
	// omitempty), so the locked-empty value is present at the highest tier even when the lane is Vertex.
	GCPAuthRefresh string `json:"gcpAuthRefresh"`
}

type permissions struct {
	Allow       []string `json:"allow"`
	Deny        []string `json:"deny"`
	DefaultMode string   `json:"defaultMode"`
	// disableBypassPermissionsMode lives UNDER permissions (alongside defaultMode) in Claude Code's
	// schema; "disable" stops the agent switching off permission prompts/rules at runtime so the
	// locked allow/deny actually bind.
	DisableBypassPermissionsMode string `json:"disableBypassPermissionsMode"`
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
//
// Paths are anchored at the FILESYSTEM ROOT with a leading "//": in Claude Code's permission-path
// syntax "/etc/..." is PROJECT-root-relative, while "//etc/..." is the absolute /etc — these rules
// must bind to the real root-owned locked files, not a coincidental project-relative "etc/" dir. The
// constants stay real filesystem paths (the cmd writes to them); we prepend the extra "/" here only.
func commonDeny() []string {
	return []string{
		"Read(/" + HooksDir + "/**)",
		"Edit(/" + HooksDir + "/**)",
		"Write(/" + HooksDir + "/**)",
		"Edit(/" + ManagedSettingsPath + ")",
		"Write(/" + ManagedSettingsPath + ")",
		"Edit(//etc/claude-code/**)",
		"Write(//etc/claude-code/**)",
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

	// Lock out runtime bypass of the permission system (under permissions, alongside defaultMode).
	perms.DisableBypassPermissionsMode = "disable"

	ms := managedSettings{
		Permissions:                     perms,
		Hooks:                           hooks,
		Env:                             lockedEnv(),
		AllowManagedHooksOnly:           true,
		AllowManagedPermissionRulesOnly: true,
		CleanupPeriodDays:               0,
		// Pin the GCP-auth-refresh COMMAND empty in the managed tier (highest precedence) so a target
		// repo cannot inject one — see the field doc. Explicit (not relying on the zero value) so the
		// intent is unmistakable and a future reorder cannot silently drop it.
		GCPAuthRefresh: "",
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
