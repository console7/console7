package scmgithub

import (
	"context"
	"fmt"
	"time"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/google/go-github/v88/github"

	"github.com/console7/console7/sdk/interfaces"
)

// ghApp is the real adapter satisfying BOTH provider ports (AppAuth here, PullRequestOpener in
// github_pr.go) over a single GitHub App identity. The GitHub SDK (go-github, ghinstallation)
// lives ONLY in these adapter files; the provider logic never imports it.
type ghApp struct {
	// appsTransport authenticates as the App (a JWT signed with the App private key). It mints
	// installation tokens (here) and backs the per-PR installation transport (github_pr.go).
	appsTransport *ghinstallation.AppsTransport
	// appClient is a go-github client authenticated as the App — it resolves installations and
	// creates installation tokens. It cannot itself act on repository contents.
	appClient *github.Client
	// fixedInstall, if non-zero, is the installation to mint against; otherwise it is resolved
	// per-repo.
	fixedInstall int64
	// perms is the least-privilege permission set used when this adapter mints its own token for
	// opening a pull request (CreatePullRequest).
	perms map[string]string
	// baseURL points the installation client at GitHub Enterprise Server when set.
	baseURL string
}

var _ AppAuth = (*ghApp)(nil)

// MintInstallationToken mints a repository-scoped, permission-narrowed installation access token.
// It fails (returning no token) if the App is not installed on the repo or a permission is outside
// the allowlist — never a partial or over-broad token.
func (g *ghApp) MintInstallationToken(ctx context.Context, req InstallationTokenRequest) (string, time.Time, error) {
	instID, err := g.installationID(ctx, req.Repo)
	if err != nil {
		return "", time.Time{}, err
	}
	perms, err := toInstallationPermissions(req.Permissions)
	if err != nil {
		return "", time.Time{}, err
	}
	tok, _, err := g.appClient.Apps.CreateInstallationToken(ctx, instID, &github.InstallationTokenOptions{
		Repositories: []string{req.Repo.Name},
		Permissions:  perms,
	})
	if err != nil {
		return "", time.Time{}, fmt.Errorf("scmgithub: CreateInstallationToken: %w", err)
	}
	token := tok.GetToken()
	if token == "" {
		return "", time.Time{}, fmt.Errorf("scmgithub: GitHub returned an empty installation token")
	}
	return token, tok.GetExpiresAt().Time, nil
}

// installationID resolves the App installation that owns the repo, using the fixed installation
// when configured, otherwise looking it up so one App can serve several repos.
func (g *ghApp) installationID(ctx context.Context, repo interfaces.RepoRef) (int64, error) {
	if g.fixedInstall != 0 {
		return g.fixedInstall, nil
	}
	inst, _, err := g.appClient.Apps.GetRepositoryInstallation(ctx, repo.Owner, repo.Name)
	if err != nil {
		return 0, fmt.Errorf("scmgithub: resolving App installation on %s/%s: %w", repo.Owner, repo.Name, err)
	}
	return inst.GetID(), nil
}

// toInstallationPermissions translates the provider's least-privilege permission map into the
// typed go-github form, REJECTING any permission key outside a tight allowlist AND any access
// level beyond read/write — so a Config.Permissions override cannot widen the grant (e.g. to
// "admin") past least privilege; it can only narrow or re-shape within the allowlist. Fail closed
// — the GitHub analogue of secrets-gcp's prefix-scoped IAM.
func toInstallationPermissions(perms map[string]string) (*github.InstallationPermissions, error) {
	out := &github.InstallationPermissions{}
	for k, v := range perms {
		if v != "read" && v != "write" {
			return nil, fmt.Errorf("scmgithub: GitHub App permission %q has unsupported access level %q (allowed: read, write)", k, v)
		}
		val := v
		switch k {
		case "contents":
			out.Contents = github.Ptr(val)
		case "pull_requests":
			out.PullRequests = github.Ptr(val)
		case "metadata":
			out.Metadata = github.Ptr(val)
		default:
			return nil, fmt.Errorf("scmgithub: unsupported GitHub App permission %q (allowlist: contents, pull_requests, metadata)", k)
		}
	}
	return out, nil
}
