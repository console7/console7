package policyhelper

import (
	"bytes"
	"encoding/json"
	"slices"
	"testing"

	"github.com/console7/console7/sdk/interfaces"
)

func authorProfile() interfaces.SessionProfile {
	return interfaces.SessionProfile{
		Persona:         interfaces.PersonaAuthor,
		Target:          interfaces.TierStratum{Tier: interfaces.Tier3, Stratum: interfaces.Stratum1},
		EgressAllowlist: []string{"https://a.internal"},
		AutonomyCeiling: "supervised",
		MaxTTL:          0,
	}
}

func operateProfile() interfaces.SessionProfile {
	p := authorProfile()
	p.Persona = interfaces.PersonaOperate
	return p
}

// parsed is the subset of managed-settings.json the tests assert against.
type parsed struct {
	Permissions struct {
		Allow                        []string `json:"allow"`
		Deny                         []string `json:"deny"`
		DisableBypassPermissionsMode string   `json:"disableBypassPermissionsMode"`
	} `json:"permissions"`
	Hooks struct {
		PreToolUse []struct {
			Matcher string `json:"matcher"`
			Hooks   []struct {
				Type    string `json:"type"`
				Command string `json:"command"`
			} `json:"hooks"`
		} `json:"PreToolUse"`
	} `json:"hooks"`
	Env                             map[string]string `json:"env"`
	AllowManagedHooksOnly           bool              `json:"allowManagedHooksOnly"`
	AllowManagedPermissionRulesOnly bool              `json:"allowManagedPermissionRulesOnly"`
	GCPAuthRefresh                  *string           `json:"gcpAuthRefresh"`
}

func mustParse(t *testing.T, r Rendered) parsed {
	t.Helper()
	if !json.Valid(r.ManagedSettings) {
		t.Fatalf("managed-settings is not valid JSON:\n%s", r.ManagedSettings)
	}
	var p parsed
	if err := json.Unmarshal(r.ManagedSettings, &p); err != nil {
		t.Fatalf("unmarshal managed-settings: %v", err)
	}
	return p
}

func TestRender_RejectsUnknownPersona(t *testing.T) {
	if _, err := Render(interfaces.SessionProfile{Persona: "saboteur"}); err == nil {
		t.Fatal("expected an unrecognised persona to fail closed")
	}
	if _, err := Render(interfaces.SessionProfile{Persona: ""}); err == nil {
		t.Fatal("expected the zero persona to fail closed")
	}
}

func TestRender_LockdownFieldsOnEveryPersona(t *testing.T) {
	for _, prof := range []interfaces.SessionProfile{authorProfile(), operateProfile()} {
		r, err := Render(prof)
		if err != nil {
			t.Fatalf("render %s: %v", prof.Persona, err)
		}
		p := mustParse(t, r)
		if p.Permissions.DisableBypassPermissionsMode != "disable" {
			t.Errorf("%s: bypass-permissions mode not disabled: %q", prof.Persona, p.Permissions.DisableBypassPermissionsMode)
		}
		// Lower-scope (project/user) hooks + permission rules must be locked out, so an untrusted
		// target repo's .claude/settings.json cannot inject hooks or auto-approve rules.
		if !p.AllowManagedHooksOnly || !p.AllowManagedPermissionRulesOnly {
			t.Errorf("%s: managed-only lockouts not set (hooks=%v rules=%v) — repo settings could inject",
				prof.Persona, p.AllowManagedHooksOnly, p.AllowManagedPermissionRulesOnly)
		}
		// The engine must not phone home / auto-update / mutate its pinned version from in-sandbox.
		for _, k := range []string{"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "DISABLE_AUTOUPDATER", "DISABLE_TELEMETRY"} {
			if p.Env[k] != "1" {
				t.Errorf("%s: lockdown env %s not set to 1 (got %q)", prof.Persona, k, p.Env[k])
			}
		}
		// Neither persona may rewrite its own locked guards (defence-in-depth echo of the read-only
		// mount). The rule is anchored at the filesystem root ("//" prefix on the absolute path).
		if !slices.Contains(p.Permissions.Deny, "Write(/"+ManagedSettingsPath+")") {
			t.Errorf("%s: deny set does not protect the managed-settings path", prof.Persona)
		}
	}
}

// TestRender_LocksOutGCPAuthRefresh proves the managed-settings pin gcpAuthRefresh to an EMPTY value
// at the highest-precedence (managed) tier on EVERY persona. gcpAuthRefresh is a SHELL COMMAND the
// engine runs on GCP/Vertex token expiry; the Vertex-lane sandbox is credential-free (the auth-proxy
// holds the bearer, the engine runs with CLAUDE_CODE_SKIP_VERTEX_AUTH=1), so a refresh command is
// pure command-execution surface a target repo's .claude/settings.json must not be able to define.
// The key must be PRESENT (so the managed tier overrides any lower-tier value) and EMPTY (no command).
func TestRender_LocksOutGCPAuthRefresh(t *testing.T) {
	for _, prof := range []interfaces.SessionProfile{authorProfile(), operateProfile()} {
		r, err := Render(prof)
		if err != nil {
			t.Fatalf("render %s: %v", prof.Persona, err)
		}
		// Assert against the RAW JSON too: the key must literally appear (a managed-tier override only
		// binds if the key is emitted), and it must be empty.
		if !bytes.Contains(r.ManagedSettings, []byte(`"gcpAuthRefresh"`)) {
			t.Errorf("%s: managed-settings does not emit gcpAuthRefresh — a repo refresh command would not be overridden:\n%s", prof.Persona, r.ManagedSettings)
		}
		p := mustParse(t, r)
		if p.GCPAuthRefresh == nil {
			t.Errorf("%s: gcpAuthRefresh absent from managed-settings (must be present-and-empty to lock out a repo value)", prof.Persona)
			continue
		}
		if *p.GCPAuthRefresh != "" {
			t.Errorf("%s: gcpAuthRefresh must be locked EMPTY (no command), got %q", prof.Persona, *p.GCPAuthRefresh)
		}
	}
}

func TestRender_AuthorIsDevelopmentCapable(t *testing.T) {
	r, err := Render(authorProfile())
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	p := mustParse(t, r)
	for _, want := range []string{"Edit", "Write", "Bash"} {
		if !slices.Contains(p.Permissions.Allow, want) {
			t.Errorf("author missing dev permission %q", want)
		}
	}
	// Author must NOT carry the operate read-only blanket denials of Edit/Write.
	for _, mut := range []string{"Edit", "Write"} {
		if slices.Contains(p.Permissions.Deny, mut) {
			t.Errorf("author wrongly denies the mutating tool %q (that is the operate lane)", mut)
		}
	}
	// Obvious actuation/escape is denied in-band (the boundary is the real control).
	if !slices.Contains(p.Permissions.Deny, "Bash(gh pr merge:*)") {
		t.Error("author does not deny self-merge")
	}
	// Author has no PreToolUse tripwire.
	if len(p.Hooks.PreToolUse) != 0 {
		t.Errorf("author should render no PreToolUse hooks, got %d", len(p.Hooks.PreToolUse))
	}
}

func TestRender_OperateIsReadOnlyWithTripwire(t *testing.T) {
	r, err := Render(operateProfile())
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	p := mustParse(t, r)
	// Read-only: every file-mutating tool denied; no write tool allowed.
	for _, mut := range []string{"Edit", "Write", "MultiEdit", "NotebookEdit"} {
		if !slices.Contains(p.Permissions.Deny, mut) {
			t.Errorf("operate does not deny the mutating tool %q (must be read-only)", mut)
		}
		if slices.Contains(p.Permissions.Allow, mut) {
			t.Errorf("operate wrongly ALLOWS the mutating tool %q", mut)
		}
	}
	if !slices.Contains(p.Permissions.Allow, "Read") {
		t.Error("operate cannot Read — it must observe to diagnose")
	}
	// The PreToolUse mutating-command tripwire MUST be wired on Bash (DESIGN.md §5.4).
	if len(p.Hooks.PreToolUse) != 1 || p.Hooks.PreToolUse[0].Matcher != "Bash" {
		t.Fatalf("operate is missing the PreToolUse Bash tripwire: %+v", p.Hooks.PreToolUse)
	}
	// The hook invokes the baked tripwire BINARY (TripwirePath), not a rendered script.
	if got := p.Hooks.PreToolUse[0].Hooks[0].Command; got != TripwirePath {
		t.Errorf("tripwire hook command = %q, want %q", got, TripwirePath)
	}
	// Bash is allowed for operate (read-only CLI, gated by the tripwire — DESIGN.md §5.4).
	if !slices.Contains(p.Permissions.Allow, "Bash") {
		t.Error("operate should allow Bash (gated by the tripwire)")
	}
}

func TestRender_Deterministic(t *testing.T) {
	a, err := Render(operateProfile())
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	b, err := Render(operateProfile())
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if !bytes.Equal(a.ManagedSettings, b.ManagedSettings) {
		t.Error("managed-settings render is not deterministic")
	}
}
