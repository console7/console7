package scmgithub

import (
	"context"
	"time"

	"github.com/console7/console7/sdk/interfaces"
)

// The provider logic (provider.go) depends only on these two ports; the GitHub SDK
// (go-github, ghinstallation) is confined to the adapter that satisfies them (ghapp_auth.go,
// github_pr.go) and to the in-memory fakes (fakes.go). They are exported so the conformance
// harness — and out-of-tree providers — can assemble a fully-faked provider via NewWithPorts
// with no GitHub App and no network.

// InstallationTokenRequest asks the App-auth port for a short-lived installation token scoped
// to ONE repository. The provider never widens it: it passes exactly the repo from the
// working-credential request and the least-privilege permission set needed to push a working
// branch and open a pull request (DefaultPermissions).
type InstallationTokenRequest struct {
	// Repo is the single repository the token must be scoped to.
	Repo interfaces.RepoRef
	// Permissions is the least-privilege GitHub App permission set the token is narrowed to
	// (e.g. {"contents":"write","pull_requests":"write"}). The adapter passes it through to the
	// installation-token mint so GitHub issues a permission-narrowed token; it MUST reject a
	// permission outside its allowlist rather than silently widen or drop it.
	Permissions map[string]string
}

// AppAuth confines GitHub App identity and installation-token minting. The real adapter
// (ghapp_auth.go) authenticates as the App (a JWT signed with the App private key) and exchanges
// it for a repository-scoped, permission-narrowed installation access token; the in-memory fake
// (fakes.go) returns a deterministic opaque token. The App private key never crosses this
// boundary — only the minted, short-lived installation token comes out.
type AppAuth interface {
	// MintInstallationToken returns a short-lived installation access token scoped to req.Repo
	// with req.Permissions, plus the absolute time it expires (GitHub caps this at ~1h).
	//
	// SECURITY: it MUST fail — returning no token — if the App is not installed on the repo or
	// the requested scoping/permissions are refused, never a partial or over-broad token. The
	// returned token is durable material; the provider holds it behind an opaque ref and never
	// returns it to a caller (DESIGN.md §2.1, §2.3).
	MintInstallationToken(ctx context.Context, req InstallationTokenRequest) (token string, expiry time.Time, err error)
}

// PullRequestOpener confines the pull-request REST call. The real adapter (github_pr.go)
// authenticates as the installation and calls go-github's PullRequests.Create; the in-memory
// fake records the request and returns a synthetic ref.
type PullRequestOpener interface {
	// CreatePullRequest opens a pull request proposing pr.Head into pr.Base and returns its URL
	// and number. The provider has already refused head==base and a protected head before
	// calling.
	//
	// SECURITY: the implementation MUST open a pull request ONLY — it MUST NOT merge, approve,
	// or otherwise actuate it, and MUST NOT push directly to or mutate a protected/default
	// branch. Author, approve, and actuate are separated; a session holds only author
	// (DESIGN.md §7; GOAL.md tenet 6).
	CreatePullRequest(ctx context.Context, pr interfaces.PullRequest) (url string, number int, err error)
}
