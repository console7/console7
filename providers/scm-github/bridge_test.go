package scmgithub

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/console7/console7/sdk/interfaces"
)

var bridgeRepo = interfaces.RepoRef{Host: "github.com", Owner: "acme", Name: "widgets"}

func TestFetchRepoBundle_SuccessAndReadScoped(t *testing.T) {
	p, auth, _ := newTestProviderWithGit()
	b, err := p.FetchRepoBundle(context.Background(), bridgeRepo, "main")
	if err != nil {
		t.Fatalf("FetchRepoBundle: %v", err)
	}
	if len(b) == 0 {
		t.Fatal("expected a non-empty bundle")
	}
	// The clone token must be least-privilege READ (never write/pull_requests).
	if lvl := auth.LastRequest().Permissions["contents"]; lvl != "read" {
		t.Errorf("FetchRepoBundle should mint contents:read, got %q", lvl)
	}
	if _, ok := auth.LastRequest().Permissions["pull_requests"]; ok {
		t.Error("FetchRepoBundle must not request pull_requests")
	}
}

func TestFetchRepoBundle_Validation(t *testing.T) {
	p, _, _ := newTestProviderWithGit()
	ctx := context.Background()
	cases := []struct {
		name string
		repo interfaces.RepoRef
		base string
	}{
		{"missing owner", interfaces.RepoRef{Host: "github.com", Name: "w"}, "main"},
		{"wrong host", interfaces.RepoRef{Host: "evil.example", Owner: "a", Name: "w"}, "main"},
		{"empty base", bridgeRepo, ""},
	}
	for _, tc := range cases {
		if _, err := p.FetchRepoBundle(ctx, tc.repo, tc.base); err == nil {
			t.Errorf("%s: expected an error", tc.name)
		}
	}
}

func TestPushBranch_SuccessPushesWorkingBranchWriteScoped(t *testing.T) {
	p, auth, git := newTestProviderWithGit()
	err := p.PushBranch(context.Background(), interfaces.PushBranchRequest{
		Subject: "u@x", SessionID: "s1", Repo: bridgeRepo, Branch: "c7/work",
		Bundle: []byte("working-branch-bundle"), SessionDeadline: time.Now().Add(20 * time.Minute),
	})
	if err != nil {
		t.Fatalf("PushBranch: %v", err)
	}
	pushes := git.Pushes()
	if len(pushes) != 1 {
		t.Fatalf("expected exactly one push, got %d", len(pushes))
	}
	if pushes[0].Branch != "c7/work" {
		t.Errorf("pushed the wrong branch: %q", pushes[0].Branch)
	}
	if pushes[0].Token == "" {
		t.Error("provider must hand the transport a non-empty token")
	}
	// The push token must be least-privilege contents:WRITE, never pull_requests (the sandbox token
	// must not be able to open/merge a PR).
	if lvl := auth.LastRequest().Permissions["contents"]; lvl != "write" {
		t.Errorf("PushBranch should mint contents:write, got %q", lvl)
	}
	if _, ok := auth.LastRequest().Permissions["pull_requests"]; ok {
		t.Error("PushBranch must not request pull_requests")
	}
}

func TestPushBranch_RefusesProtectedBranch(t *testing.T) {
	p, _, git := newTestProviderWithGit()
	for _, b := range []string{"main", "master"} {
		if err := p.PushBranch(context.Background(), interfaces.PushBranchRequest{
			Subject: "u@x", SessionID: "s1", Repo: bridgeRepo, Branch: b,
			Bundle: []byte("x"), SessionDeadline: time.Now().Add(20 * time.Minute),
		}); err == nil {
			t.Errorf("PushBranch must refuse the protected branch %q", b)
		}
	}
	if len(git.Pushes()) != 0 {
		t.Error("no push should have reached the transport for a protected branch")
	}
}

func TestPushBranch_Validation(t *testing.T) {
	p, _, _ := newTestProviderWithGit()
	ctx := context.Background()
	future := time.Now().Add(20 * time.Minute)
	cases := []struct {
		name string
		req  interfaces.PushBranchRequest
	}{
		{"missing subject", interfaces.PushBranchRequest{SessionID: "s", Repo: bridgeRepo, Branch: "c7/w", Bundle: []byte("x"), SessionDeadline: future}},
		{"missing session", interfaces.PushBranchRequest{Subject: "u", Repo: bridgeRepo, Branch: "c7/w", Bundle: []byte("x"), SessionDeadline: future}},
		{"wrong host", interfaces.PushBranchRequest{Subject: "u", SessionID: "s", Repo: interfaces.RepoRef{Host: "evil", Owner: "a", Name: "w"}, Branch: "c7/w", Bundle: []byte("x"), SessionDeadline: future}},
		{"empty branch", interfaces.PushBranchRequest{Subject: "u", SessionID: "s", Repo: bridgeRepo, Branch: "", Bundle: []byte("x"), SessionDeadline: future}},
		{"option-injection branch", interfaces.PushBranchRequest{Subject: "u", SessionID: "s", Repo: bridgeRepo, Branch: "--upload-pack=x", Bundle: []byte("x"), SessionDeadline: future}},
		{"ref-metachar branch", interfaces.PushBranchRequest{Subject: "u", SessionID: "s", Repo: bridgeRepo, Branch: "c7/work~1", Bundle: []byte("x"), SessionDeadline: future}},
		{"empty bundle", interfaces.PushBranchRequest{Subject: "u", SessionID: "s", Repo: bridgeRepo, Branch: "c7/w", Bundle: nil, SessionDeadline: future}},
		{"past deadline", interfaces.PushBranchRequest{Subject: "u", SessionID: "s", Repo: bridgeRepo, Branch: "c7/w", Bundle: []byte("x"), SessionDeadline: time.Now().Add(-time.Minute)}},
	}
	for _, tc := range cases {
		if err := p.PushBranch(ctx, tc.req); err == nil {
			t.Errorf("%s: expected an error", tc.name)
		}
	}
}

func TestBridge_FailClosedWithoutGitTransport(t *testing.T) {
	// A provider wired with no git transport must fail closed on both bridge methods, never panic.
	p := NewWithPorts(NewInMemoryAppAuth(), NewInMemoryPullRequests(), nil, 15*time.Minute)
	if _, err := p.FetchRepoBundle(context.Background(), bridgeRepo, "main"); err == nil {
		t.Error("FetchRepoBundle must fail closed with no git transport")
	}
	if err := p.PushBranch(context.Background(), interfaces.PushBranchRequest{
		Subject: "u", SessionID: "s", Repo: bridgeRepo, Branch: "c7/w",
		Bundle: []byte("x"), SessionDeadline: time.Now().Add(time.Minute),
	}); err == nil {
		t.Error("PushBranch must fail closed with no git transport")
	}
}

// TestGitCLI_TokenNeverInArgv is the security-critical unit test: the installation token must reach
// git via the child ENV (a credential helper), NEVER as a command-line argument (a `ps`-visible
// leak) and never embedded in the remote URL.
func TestGitCLI_TokenNeverInArgv(t *testing.T) {
	const tok = "super-secret-installation-token"
	args := gitGlobalArgs(tok, "/some/dir")
	for _, a := range args {
		if strings.Contains(a, tok) {
			t.Fatalf("token leaked into git argv: %q", a)
		}
	}
	// The credential helper must be present (so git can authenticate), and it must read the secret
	// from the env var, not contain the token literal.
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "credential.helper=") {
		t.Error("expected a credential.helper config in the git args")
	}
	if strings.Contains(gitCredHelper, tok) {
		t.Error("the credential helper script must not contain a token literal")
	}
	if !strings.Contains(gitCredHelper, "C7_GIT_TOKEN") || !strings.Contains(gitCredHelper, "$1") {
		t.Error("the credential helper must read the token from $C7_GIT_TOKEN and gate on the get op")
	}
	// The token IS in the child env, and interactive prompting is disabled (fail closed).
	env := gitEnv(tok)
	var hasTok, noPrompt bool
	for _, e := range env {
		if e == "C7_GIT_TOKEN="+tok {
			hasTok = true
		}
		if e == "GIT_TERMINAL_PROMPT=0" {
			noPrompt = true
		}
	}
	if !hasTok {
		t.Error("token must be in the child env (C7_GIT_TOKEN)")
	}
	if !noPrompt {
		t.Error("GIT_TERMINAL_PROMPT=0 must be set to fail closed, not hang")
	}
	// With no token (e.g. the local init/fetch steps), no credential helper and no token env.
	if a := gitGlobalArgs("", "/d"); strings.Contains(strings.Join(a, " "), "credential.helper") {
		t.Error("no credential helper should be configured without a token")
	}
}
