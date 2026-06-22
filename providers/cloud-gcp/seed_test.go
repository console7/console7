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
	s, err := workspaceSeedScript("/workspace", seedTask("c7/session-abc"))
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
	// The script must NOT fetch/clone — content seeding is the live B11 step (no token/egress here).
	for _, forbidden := range []string{"git clone", "git fetch", "git pull"} {
		if strings.Contains(s, forbidden) {
			t.Errorf("seed script unexpectedly performs network I/O (%q) — that is B11\n%s", forbidden, s)
		}
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
		if _, err := workspaceSeedScript("/workspace", tc.task); err == nil {
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
