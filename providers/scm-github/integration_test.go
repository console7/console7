//go:build github_integration

// Opt-in live integration test against a real GitHub App + repository. It is NEVER part of the CI
// gate — it compiles only under `-tags github_integration` and skips unless the environment names
// an App, a private key, and a repo. It exercises the REAL App-JWT auth, installation resolution,
// and repository-scoped + permission-narrowed installation-token mint. Opening a real pull request
// is additionally gated (it needs a head branch already ahead of base) and off by default.
//
// Run:
//
//	C7_GH_APP_ID=123456 \
//	C7_GH_PRIVATE_KEY_FILE=/path/to/app-private-key.pem \
//	C7_GH_REPO=console7/console7-deploy \
//	go test -tags github_integration -run TestIntegration ./providers/scm-github/...
//
// To also open a live PR (creates a real PR — use a throwaway head branch ahead of base):
//
//	... C7_GH_HEAD=console7-itest C7_GH_BASE=main C7_GH_OPEN_PR=1 go test -tags github_integration ...
package scmgithub

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/console7/console7/sdk/interfaces"
)

func integrationConfig(t *testing.T) (Config, interfaces.RepoRef) {
	t.Helper()
	appIDStr := os.Getenv("C7_GH_APP_ID")
	keyFile := os.Getenv("C7_GH_PRIVATE_KEY_FILE")
	repoStr := os.Getenv("C7_GH_REPO")
	if appIDStr == "" || keyFile == "" || repoStr == "" {
		t.Skip("set C7_GH_APP_ID, C7_GH_PRIVATE_KEY_FILE, C7_GH_REPO to run the live integration test")
	}
	appID, err := strconv.ParseInt(appIDStr, 10, 64)
	if err != nil {
		t.Fatalf("C7_GH_APP_ID is not an integer: %v", err)
	}
	pem, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatalf("reading C7_GH_PRIVATE_KEY_FILE: %v", err)
	}
	owner, name, ok := strings.Cut(repoStr, "/")
	if !ok {
		t.Fatalf("C7_GH_REPO must be owner/name, got %q", repoStr)
	}
	cfg := Config{AppID: appID, PrivateKeyPEM: pem}
	if instStr := os.Getenv("C7_GH_INSTALLATION_ID"); instStr != "" {
		inst, err := strconv.ParseInt(instStr, 10, 64)
		if err != nil {
			t.Fatalf("C7_GH_INSTALLATION_ID is not an integer: %v", err)
		}
		cfg.InstallationID = inst
	}
	if base := os.Getenv("C7_GH_BASE_URL"); base != "" {
		cfg.BaseURL = base
	}
	return cfg, interfaces.RepoRef{Host: "github.com", Owner: owner, Name: name}
}

func TestIntegration_MintWorkingCredential(t *testing.T) {
	cfg, repo := integrationConfig(t)
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	now := time.Now()
	deadline := now.Add(30 * time.Minute)
	ref, err := p.MintWorkingCredential(ctx, interfaces.WorkingCredentialRequest{
		Subject:         "itest@example.test",
		SessionID:       interfaces.SessionID("itest-" + randHex(4)),
		Repo:            repo,
		Branch:          "console7-itest-" + randHex(4),
		SessionDeadline: deadline,
	})
	if err != nil {
		t.Fatalf("MintWorkingCredential (real installation token mint): %v", err)
	}
	if ref.Ref == "" {
		t.Fatal("expected an opaque credential ref")
	}
	if !ref.Expiry.After(now) || ref.Expiry.After(deadline) {
		t.Fatalf("expiry %v is not within (now, deadline]", ref.Expiry)
	}
}

func TestIntegration_OpenPullRequest(t *testing.T) {
	if os.Getenv("C7_GH_OPEN_PR") != "1" {
		t.Skip("set C7_GH_OPEN_PR=1 (plus C7_GH_HEAD ahead of C7_GH_BASE) to open a live PR")
	}
	cfg, repo := integrationConfig(t)
	head := os.Getenv("C7_GH_HEAD")
	base := os.Getenv("C7_GH_BASE")
	if head == "" || base == "" {
		t.Skip("set C7_GH_HEAD and C7_GH_BASE to open a live PR")
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	pr, err := p.OpenPullRequest(context.Background(), interfaces.PullRequest{
		Repo:  repo,
		Head:  head,
		Base:  base,
		Title: "console7 integration test PR",
		Body:  "Opened by providers/scm-github integration test; safe to close.",
	})
	if err != nil {
		t.Fatalf("OpenPullRequest: %v", err)
	}
	if pr.Number == 0 || pr.URL == "" {
		t.Fatalf("expected a populated PRRef, got %+v", pr)
	}
	t.Logf("opened PR #%d: %s", pr.Number, pr.URL)
}
