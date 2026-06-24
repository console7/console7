package cloudgcp

import (
	"strings"
	"testing"

	"github.com/console7/console7/sdk/interfaces"
)

func seedTask(branch string) interfaces.EngineTask {
	return interfaces.EngineTask{
		Repo:   interfaces.RepoRef{Host: "github.com", Owner: "acme", Name: "widgets"},
		Branch: branch,
	}
}

func TestWorkspaceSeedScript_Scaffolding(t *testing.T) {
	s, err := workspaceSeedScript("/workspace", seedTask("c7/session-abc"), "")
	if err != nil {
		t.Fatalf("workspaceSeedScript: %v", err)
	}
	for _, want := range []string{
		"cd '/workspace'",
		"git init -q",
		"git symbolic-ref HEAD 'refs/heads/c7/session-abc'",
		"git remote add origin 'https://github.com/acme/widgets.git'",
		".git/info/exclude",
		"echo '.claude/'", // the engine's dotfiles are excluded from the proposed commit
	} {
		if !strings.Contains(s, want) {
			t.Errorf("seed script missing %q\n---\n%s", want, s)
		}
	}
	// With NO bundle, the script must NOT do any git network/transfer I/O — it is a pure scaffold.
	for _, forbidden := range []string{"git clone", "git fetch", "git pull"} {
		if strings.Contains(s, forbidden) {
			t.Errorf("no-bundle seed script unexpectedly transfers content (%q)\n%s", forbidden, s)
		}
	}
}

func TestWorkspaceSeedScript_WithBundle(t *testing.T) {
	// When the control plane hands in a base bundle, the seed fetches the base content FROM THE LOCAL
	// BUNDLE FILE (never the network), branches the working branch off it, and removes the bundle so it
	// is never committed. The remote URL (github.com) is still only recorded, never reached.
	bp := "/workspace/.console7-base.bundle"
	s, err := workspaceSeedScript("/workspace", seedTask("c7/session-abc"), bp)
	if err != nil {
		t.Fatalf("workspaceSeedScript(bundle): %v", err)
	}
	for _, want := range []string{
		"git init -q",
		"git fetch -q '" + bp + "' 'refs/heads/*:refs/heads/c7base/*'", // fetch from the FILE, not origin
		`if [ "$c7n" != "1" ]`,                // fail closed unless EXACTLY ONE base head (no silent-wrong-base)
		"git checkout -q -B 'c7/session-abc'", // branch the working branch off the base
		"rm -f '" + bp + "'",                  // bundle never lands in the commit
	} {
		if !strings.Contains(s, want) {
			t.Errorf("bundle seed script missing %q\n---\n%s", want, s)
		}
	}
	// The fetch must target the local bundle PATH, never the origin remote (no SCM egress from the sandbox).
	if strings.Contains(s, "git fetch -q origin") || strings.Contains(s, "git fetch origin") {
		t.Errorf("bundle seed must fetch the local file, never origin:\n%s", s)
	}
	// With a base checked out, there is no unborn-HEAD symbolic-ref (checkout -B sets the branch).
	if strings.Contains(s, "git symbolic-ref HEAD") {
		t.Errorf("bundle seed should checkout -B the base, not set an unborn HEAD:\n%s", s)
	}
}

func TestWorkspaceSeedScript_Validation(t *testing.T) {
	for _, tc := range []struct {
		name string
		task interfaces.EngineTask
	}{
		{"missing host", interfaces.EngineTask{Repo: interfaces.RepoRef{Owner: "a", Name: "b"}, Branch: "feat"}},
		{"missing owner", interfaces.EngineTask{Repo: interfaces.RepoRef{Host: "github.com", Name: "b"}, Branch: "feat"}},
		{"missing name", interfaces.EngineTask{Repo: interfaces.RepoRef{Host: "github.com", Owner: "a"}, Branch: "feat"}},
		{"missing branch", seedTask("")},
		{"blank branch", seedTask("   ")},
		{"protected main", seedTask("main")},
		{"protected Master (case)", seedTask("Master")},
		{"protected production", seedTask("production")},
	} {
		if _, err := workspaceSeedScript("/workspace", tc.task, ""); err == nil {
			t.Errorf("%s: expected a validation error", tc.name)
		}
	}
}

func TestIsProtectedBranch(t *testing.T) {
	for _, b := range []string{"main", "MASTER", " trunk ", "develop", "production", "release"} {
		if !isProtectedBranch(b) {
			t.Errorf("%q should be protected", b)
		}
	}
	for _, b := range []string{"feat/x", "fix-123", "c7/session-abc", "mainline"} {
		if isProtectedBranch(b) {
			t.Errorf("%q should NOT be protected", b)
		}
	}
}

func TestEngineRunScript_Shape(t *testing.T) {
	// The Anthropic-API lane (and the zero value, which defaults to it).
	for _, kind := range []interfaces.BackendKind{interfaces.BackendAnthropicAPI, interfaces.BackendUnspecified} {
		s, err := engineRunScript(credentialPath, engineLane{kind: kind})
		if err != nil {
			t.Fatalf("engineRunScript(kind=%d): %v", kind, err)
		}
		for _, want := range []string{
			"test -s /run/console7/credential",          // fail CLOSED unless the credential is present + non-empty
			`_c7cred="$(cat /run/console7/credential)"`, // read ONCE, standalone (set -e aborts a failed read)
			`[ -n "$_c7cred" ]`,                         // ...and explicitly reject an empty value (TOCTOU close)
			"exit 1",                                    // never runs the engine unauthenticated
			`ANTHROPIC_API_KEY="$_c7cred" claude -p --permission-mode default`, // injected by NAME, not argv
		} {
			if !strings.Contains(s, want) {
				t.Errorf("Anthropic lane (kind=%d) missing %q\n---\n%s", kind, want, s)
			}
		}
		if strings.Contains(s, "CLAUDE_CODE_USE_VERTEX") {
			t.Errorf("Anthropic lane must NOT set Vertex env:\n%s", s)
		}
		assertCredFailClosedOrder(t, s)
	}
}

func TestEngineRunScript_VertexLane(t *testing.T) {
	s, err := engineRunScript(credentialPath, engineLane{
		kind:          interfaces.BackendVertex,
		vertexProject: "acme-prod-123",
		vertexRegion:  "us-east5",
		vertexModel:   "claude-haiku-4-5@20251001",
	})
	if err != nil {
		t.Fatalf("Vertex lane: %v", err)
	}
	for _, want := range []string{
		"CLAUDE_CODE_USE_VERTEX=1",
		"CLAUDE_CODE_SKIP_VERTEX_AUTH=1",
		`ANTHROPIC_VERTEX_PROJECT_ID='acme-prod-123'`,
		`CLOUD_ML_REGION='us-east5'`,
		`ANTHROPIC_MODEL='claude-haiku-4-5@20251001'`,
		`CLOUDSDK_AUTH_ACCESS_TOKEN="$_c7cred"`, // the minted GCP bearer, read from the in-pod file
		"claude -p --permission-mode default",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("Vertex lane missing %q\n---\n%s", want, s)
		}
	}
	// The Vertex lane authenticates with a GCP bearer, NEVER an ANTHROPIC_API_KEY, and the token still
	// comes from the in-pod file (never argv), with the same fail-closed read order as the Anthropic lane.
	if strings.Contains(s, "ANTHROPIC_API_KEY") {
		t.Errorf("Vertex lane must NOT set ANTHROPIC_API_KEY:\n%s", s)
	}
	if claudeAt := strings.Index(s, "claude -p"); claudeAt < 0 || strings.Contains(s[claudeAt:], "$(cat") {
		t.Errorf("Vertex token must reach claude via the prefix env, never re-read after claude:\n%s", s)
	}
	assertCredFailClosedOrder(t, s)
}

func TestEngineRunScript_VertexFailClosed(t *testing.T) {
	cases := []struct {
		name string
		lane engineLane
	}{
		{"missing project", engineLane{kind: interfaces.BackendVertex, vertexRegion: "us-east5", vertexModel: "m@20251001"}},
		{"missing region", engineLane{kind: interfaces.BackendVertex, vertexProject: "acme-prod-123", vertexModel: "m@20251001"}},
		{"missing model", engineLane{kind: interfaces.BackendVertex, vertexProject: "acme-prod-123", vertexRegion: "us-east5"}},
		{"injection in project", engineLane{kind: interfaces.BackendVertex, vertexProject: "a'; rm -rf /; '", vertexRegion: "us-east5", vertexModel: "m@20251001"}},
		{"api-format model", engineLane{kind: interfaces.BackendVertex, vertexProject: "acme-prod-123", vertexRegion: "us-east5", vertexModel: "claude-haiku-4-5-20251001"}},
		{"unknown lane", engineLane{kind: interfaces.BackendKind(99)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := engineRunScript(credentialPath, tc.lane); err == nil {
				t.Error("expected fail-closed error, got nil")
			}
		})
	}
}

// assertCredFailClosedOrder asserts the safe-under-dash credential read order: standalone read -> a
// non-empty guard -> the engine, and that the credential reaches claude only via a prefix env var
// (never a --flag in /proc/<pid>/cmdline).
func assertCredFailClosedOrder(t *testing.T, s string) {
	t.Helper()
	claudeAt := strings.Index(s, "claude -p")
	if claudeAt < 0 || strings.Contains(s, "--api-key") {
		t.Errorf("credential must reach claude only via the prefix env var, never argv/flag:\n%s", s)
		return
	}
	readAt := strings.Index(s, `_c7cred="$(cat`)
	guardAt := strings.Index(s, `[ -n "$_c7cred" ]`)
	if readAt < 0 || guardAt < 0 || readAt >= guardAt || guardAt >= claudeAt {
		t.Errorf("fail-closed order must be: standalone read -> non-empty guard -> engine:\n%s", s)
	}
}

func TestShquote_EscapesInjection(t *testing.T) {
	// A value carrying a single quote (or shell metacharacters) is wrapped so it cannot break out of
	// its argument.
	got := shquote(`x'; rm -rf /; echo '`)
	if !strings.HasPrefix(got, "'") || !strings.HasSuffix(got, "'") {
		t.Fatalf("not single-quoted: %s", got)
	}
	// The embedded single quote is escaped as '\'' (close-quote, escaped-quote, reopen-quote).
	if !strings.Contains(got, `'\''`) {
		t.Errorf("embedded single quote not escaped: %s", got)
	}
}
