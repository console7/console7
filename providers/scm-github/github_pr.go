package scmgithub

import (
	"context"
	"fmt"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/google/go-github/v88/github"

	"github.com/console7/console7/sdk/interfaces"
)

var _ PullRequestOpener = (*ghApp)(nil)

// CreatePullRequest opens a pull request as the installation. OpenPullRequest carries no
// credential, so this adapter mints its OWN repository-scoped installation token (via the App
// transport) for the call. The token is narrowed to pullRequestPermissions (pull_requests:write
// only — NOT contents:write): opening a PR does not need write access to contents, so the
// actuation-adjacent token stays minimal. It opens a PR ONLY — it never merges, approves, or
// actuates (author/approve/actuate stay separated; GOAL.md tenet 6).
//
// NOTE: this token is necessarily NOT session-bound — the OpenPullRequest seam carries no Subject
// or SessionID — so the human->NHI lineage stamped at MintWorkingCredential does not extend to the
// PR-open call. This is an interface-shape residual, documented in doc.go, not a silent gap.
func (g *ghApp) CreatePullRequest(ctx context.Context, pr interfaces.PullRequest) (string, int, error) {
	instID, err := g.installationID(ctx, pr.Repo)
	if err != nil {
		return "", 0, err
	}
	// pull_requests:write only, intersected with the granted ceiling so a narrowed
	// Config.Permissions tightens (or fails closed) PR opening rather than being overridden.
	perms, err := toInstallationPermissions(intersectPermissions(pullRequestPermissions, g.perms))
	if err != nil {
		return "", 0, err
	}

	// An installation transport scoped to this single repo + the least-privilege permission set,
	// so the token minted for the PR call cannot reach other repos or verbs.
	itr := ghinstallation.NewFromAppsTransport(g.appsTransport, instID)
	itr.InstallationTokenOptions = &github.InstallationTokenOptions{
		Repositories: []string{pr.Repo.Name},
		Permissions:  perms,
	}

	client, err := newGitHubClient(itr, g.baseURL)
	if err != nil {
		return "", 0, err
	}
	created, _, err := client.PullRequests.Create(ctx, pr.Repo.Owner, pr.Repo.Name, &github.NewPullRequest{
		Title: github.Ptr(pr.Title),
		Head:  github.Ptr(pr.Head),
		Base:  github.Ptr(pr.Base),
		Body:  github.Ptr(pr.Body),
	})
	if err != nil {
		return "", 0, fmt.Errorf("scmgithub: PullRequests.Create: %w", err)
	}
	return created.GetHTMLURL(), created.GetNumber(), nil
}
