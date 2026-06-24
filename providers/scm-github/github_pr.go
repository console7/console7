package scmgithub

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/google/go-github/v88/github"

	"github.com/console7/console7/sdk/interfaces"
)

// prCreateAttempts / prCreateBackoff bound the retry on GitHub's post-push eventual-consistency 422
// ("not all refs are readable"): when the control plane pushes the head branch and immediately opens
// the PR, the PR API can briefly not yet see the just-pushed ref. We retry only that transient.
const prCreateAttempts = 6
const prCreateBackoff = 750 * time.Millisecond

// isTransientRefRace reports whether err is GitHub's "the head ref I just pushed isn't readable yet"
// 422 — a timing race after a push, safe to retry (NOT a genuine validation failure like head==base).
func isTransientRefRace(err error) bool {
	return err != nil && strings.Contains(err.Error(), "not all refs are readable")
}

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
	newPR := &github.NewPullRequest{
		Title: github.Ptr(pr.Title),
		Head:  github.Ptr(pr.Head),
		Base:  github.Ptr(pr.Base),
		Body:  github.Ptr(pr.Body),
	}
	// Retry ONLY the post-push eventual-consistency race (the head ref we just pushed isn't readable
	// by the PR API yet); any other error (e.g. a genuine validation failure) returns immediately.
	for attempt := 1; ; attempt++ {
		created, _, err := client.PullRequests.Create(ctx, pr.Repo.Owner, pr.Repo.Name, newPR)
		if err == nil {
			return created.GetHTMLURL(), created.GetNumber(), nil
		}
		if attempt >= prCreateAttempts || !isTransientRefRace(err) {
			return "", 0, fmt.Errorf("scmgithub: PullRequests.Create: %w", err)
		}
		select {
		case <-ctx.Done():
			return "", 0, ctx.Err()
		case <-time.After(time.Duration(attempt) * prCreateBackoff):
		}
	}
}
