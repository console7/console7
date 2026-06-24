//go:build scm_github_preflight

// Operator preflight (NOT run in CI — build-tagged): validate a REAL GitHub App end to end through
// this provider before a billable live run, so an App misconfig (wrong permission, not installed on
// the target repo, wrong installation id) surfaces locally in seconds rather than at the last step
// of the exit run.
//
//	C7_GH_APP_ID=… C7_GH_INSTALLATION_ID=… C7_GH_APP_KEY_FILE=…/key.pem C7_PREFLIGHT_REPO=owner/name \
//	  go test -tags scm_github_preflight -run TestPreflight_RealApp -v ./providers/scm-github/
package scmgithub_test

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	scmgithub "github.com/console7/console7/providers/scm-github"
	"github.com/console7/console7/sdk/interfaces"
)

func TestPreflight_RealApp(t *testing.T) {
	appID, _ := strconv.ParseInt(os.Getenv("C7_GH_APP_ID"), 10, 64)
	instID, _ := strconv.ParseInt(os.Getenv("C7_GH_INSTALLATION_ID"), 10, 64)
	keyPath := os.Getenv("C7_GH_APP_KEY_FILE")
	repoEnv := os.Getenv("C7_PREFLIGHT_REPO")
	if appID == 0 || instID == 0 || keyPath == "" || repoEnv == "" {
		t.Skip("set C7_GH_APP_ID / C7_GH_INSTALLATION_ID / C7_GH_APP_KEY_FILE / C7_PREFLIGHT_REPO (owner/name)")
	}
	parts := strings.SplitN(repoEnv, "/", 2)
	if len(parts) != 2 {
		t.Fatalf("C7_PREFLIGHT_REPO must be owner/name, got %q", repoEnv)
	}
	pem, err := os.ReadFile(keyPath) //nolint:gosec // operator-supplied key path, preflight only
	if err != nil {
		t.Fatalf("read App key %q: %v", keyPath, err)
	}

	p, err := scmgithub.New(scmgithub.Config{AppID: appID, InstallationID: instID, PrivateKeyPEM: pem})
	if err != nil {
		t.Fatalf("scmgithub.New (App auth setup): %v", err)
	}
	ctx := context.Background()
	repo := interfaces.RepoRef{Host: "github.com", Owner: parts[0], Name: parts[1]}

	// 1. Mint a contents:WRITE working credential — proves the App authenticates (JWT → installation
	// token), is installed on this repo, the installation id matches, and contents:write is GRANTED
	// (GitHub refuses to elevate a token beyond the App's grant, so this fails if write is missing).
	ref, err := p.MintWorkingCredential(ctx, interfaces.WorkingCredentialRequest{
		Subject: "preflight@console7", SessionID: "preflight", Repo: repo, Branch: "c7/preflight-probe",
		SessionDeadline: time.Now().Add(10 * time.Minute),
	})
	if err != nil {
		t.Fatalf("MintWorkingCredential (contents:write) — App auth/install/permission problem: %v", err)
	}
	t.Logf("✓ contents:write token minted (App auth + install + write grant OK); expiry=%s", ref.Expiry)

	// 2. Fetch the base branch as a bundle — proves contents:READ + a real authenticated git clone of
	// the (private) repo via the gitCLI transport, the exact path the live bridge's FetchRepoBundle uses.
	b, err := p.FetchRepoBundle(ctx, repo, "main")
	if err != nil {
		t.Fatalf("FetchRepoBundle(main) — authenticated clone failed: %v", err)
	}
	if len(b) == 0 {
		t.Fatal("FetchRepoBundle returned an empty bundle")
	}
	t.Logf("✓ cloned %s@main over the App and bundled it: %d bytes — SCM bridge auth/clone path verified", repoEnv, len(b))
}
