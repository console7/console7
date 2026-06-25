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
		"echo '.claude/'",      // the engine's dotfiles are excluded from the proposed commit
		"echo '.claude.json*'", // ...including its project-state file and its .backup sibling (one glob)
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
	// The F2c-2c/2d flip: the Vertex lane points the engine at THIS session's auth-proxy (resolved base
	// URL) and EMPTIES the inherited Squid proxy env so the engine dials the auth-proxy directly (the
	// engine ignores NO_PROXY) — the SANDBOX holds NO Vertex credential (the bearer lives in the
	// auth-proxy), so there is NO CLOUDSDK_AUTH_ACCESS_TOKEN and NO in-pod credential read on this lane.
	const baseURL = "http://10.4.5.6:8080"
	s, err := engineRunScript(credentialPath, engineLane{
		kind:             interfaces.BackendVertex,
		vertexProject:    "acme-prod-123",
		vertexRegion:     "us-east5",
		vertexModel:      "claude-haiku-4-5@20251001",
		authProxyBaseURL: baseURL,
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
		`ANTHROPIC_VERTEX_BASE_URL='` + baseURL + `'`,       // engine → auth-proxy (the bearer-attaching gateway)
		"HTTP_PROXY= HTTPS_PROXY= http_proxy= https_proxy=", // proxy env cleared → dial the auth-proxy DIRECTLY
		"claude -p --permission-mode default",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("Vertex lane missing %q\n---\n%s", want, s)
		}
	}
	// The retired R-9 lever and the in-sandbox credential read are GONE on the Vertex lane: no bearer
	// ever enters the sandbox, and the credential-file plumbing is for the org-API/subscription lanes only.
	for _, forbidden := range []string{
		"CLOUDSDK_AUTH_ACCESS_TOKEN", // the retired R-9 lever (engine 1.0.44 never read it)
		"ANTHROPIC_API_KEY",          // the Vertex lane carries no Anthropic key
		"_c7cred",                    // no in-pod credential read on the Vertex lane
		credentialPath,               // ...so the credential file is never touched
	} {
		if strings.Contains(s, forbidden) {
			t.Errorf("Vertex lane must NOT contain %q (sandbox is credential-free on this lane):\n%s", forbidden, s)
		}
	}
}

// TestEngineRunScript_AnthropicStillReadsCredential proves the org-API/subscription lanes STILL read
// the in-pod credential file — the F2c-2c flip dropped that read on the VERTEX lane ONLY.
func TestEngineRunScript_AnthropicStillReadsCredential(t *testing.T) {
	for _, kind := range []interfaces.BackendKind{interfaces.BackendAnthropicAPI, interfaces.BackendUnspecified} {
		s, err := engineRunScript(credentialPath, engineLane{kind: kind})
		if err != nil {
			t.Fatalf("engineRunScript(kind=%d): %v", kind, err)
		}
		if !strings.Contains(s, `_c7cred="$(cat `+credentialPath+`)"`) {
			t.Errorf("Anthropic-lane (kind=%d) must STILL read the in-pod credential file:\n%s", kind, s)
		}
		// The Anthropic lane must NOT carry the Vertex base URL, nor clear the proxy env — it keeps the
		// pod's HTTP_PROXY=Squid (the proxy-clear is the Vertex lane's direct-to-auth-proxy mechanism only).
		if strings.Contains(s, "ANTHROPIC_VERTEX_BASE_URL") || strings.Contains(s, "HTTP_PROXY=") {
			t.Errorf("Anthropic-lane (kind=%d) must not carry Vertex/auth-proxy env (incl. the proxy-clear):\n%s", kind, s)
		}
	}
}

func TestEngineRunScript_VertexFailClosed(t *testing.T) {
	const baseURL = "http://10.4.5.6:8080"
	cases := []struct {
		name string
		lane engineLane
	}{
		{"missing project", engineLane{kind: interfaces.BackendVertex, vertexRegion: "us-east5", vertexModel: "m@20251001", authProxyBaseURL: baseURL}},
		{"missing region", engineLane{kind: interfaces.BackendVertex, vertexProject: "acme-prod-123", vertexModel: "m@20251001", authProxyBaseURL: baseURL}},
		{"missing model", engineLane{kind: interfaces.BackendVertex, vertexProject: "acme-prod-123", vertexRegion: "us-east5", authProxyBaseURL: baseURL}},
		{"injection in project", engineLane{kind: interfaces.BackendVertex, vertexProject: "a'; rm -rf /; '", vertexRegion: "us-east5", vertexModel: "m@20251001", authProxyBaseURL: baseURL}},
		{"api-format model", engineLane{kind: interfaces.BackendVertex, vertexProject: "acme-prod-123", vertexRegion: "us-east5", vertexModel: "claude-haiku-4-5-20251001", authProxyBaseURL: baseURL}},
		// F2c-2c: an unresolvable/missing/wrong-shape auth-proxy base URL fails closed — the engine
		// must never be pointed at a broken endpoint (it would silently hit the denied metadata server).
		{"missing base url", engineLane{kind: interfaces.BackendVertex, vertexProject: "acme-prod-123", vertexRegion: "us-east5", vertexModel: "m@20251001"}},
		{"non-http base url", engineLane{kind: interfaces.BackendVertex, vertexProject: "acme-prod-123", vertexRegion: "us-east5", vertexModel: "m@20251001", authProxyBaseURL: "https://10.4.5.6:8080"}},
		{"wrong-port base url", engineLane{kind: interfaces.BackendVertex, vertexProject: "acme-prod-123", vertexRegion: "us-east5", vertexModel: "m@20251001", authProxyBaseURL: "http://10.4.5.6:3128"}},
		{"non-ip base url", engineLane{kind: interfaces.BackendVertex, vertexProject: "acme-prod-123", vertexRegion: "us-east5", vertexModel: "m@20251001", authProxyBaseURL: "http://evil.example.com:8080"}},
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
