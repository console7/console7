package scmgithub

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"time"

	"github.com/console7/console7/sdk/interfaces"
)

// This file provides NON-PRODUCTION in-memory implementations of the AppAuth and
// PullRequestOpener ports so the provider's contract logic can be exercised with no GitHub App
// and no network — by this package's white-box tests, by the conformance harness, and by
// out-of-tree providers wanting the same coverage. They model the OBSERVABLE behaviour (a
// short-lived opaque token, a recorded PR) but give none of GitHub's real scoping. Never wire one
// into a deployment.

// InMemoryAppAuth is a fake AppAuth that returns a deterministic opaque token and a future
// expiry, recording the last request so a test can assert the provider requested least-privilege,
// repo-scoped minting. SetFail makes it error, to exercise the provider's fail-closed path.
type InMemoryAppAuth struct {
	mu      sync.Mutex
	fail    bool
	expiry  time.Time
	ttl     time.Duration
	counter int
	lastReq InstallationTokenRequest
}

var _ AppAuth = (*InMemoryAppAuth)(nil)

// NewInMemoryAppAuth returns a fake App-auth port that mints tokens valid for one hour.
func NewInMemoryAppAuth() *InMemoryAppAuth {
	return &InMemoryAppAuth{ttl: time.Hour}
}

// SetFail makes MintInstallationToken return an error, to exercise the mint-time fail-closed path.
func (a *InMemoryAppAuth) SetFail(fail bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.fail = fail
}

// SetExpiry pins the absolute expiry the fake returns, so an expiry-capping test is deterministic.
// A zero value (the default) means "now + 1h" computed at mint time.
func (a *InMemoryAppAuth) SetExpiry(t time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.expiry = t
}

// MintInstallationToken returns a fresh opaque token and its expiry. The token is distinct per
// call (a counter) so a test can prove a new ref does not reuse a prior token.
func (a *InMemoryAppAuth) MintInstallationToken(ctx context.Context, req InstallationTokenRequest) (string, time.Time, error) {
	if err := ctx.Err(); err != nil {
		return "", time.Time{}, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.fail {
		return "", time.Time{}, errors.New("scmgithub/fake: induced MintInstallationToken failure")
	}
	a.lastReq = req
	a.counter++
	exp := a.expiry
	if exp.IsZero() {
		exp = time.Now().Add(a.ttl)
	}
	return "fake-installation-token-" + strconv.Itoa(a.counter), exp, nil
}

// LastRequest returns the most recent mint request, for test inspection (e.g. asserting the
// provider passed a single-repo scope and the least-privilege permission set).
func (a *InMemoryAppAuth) LastRequest() InstallationTokenRequest {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.lastReq
}

// InMemoryPullRequests is a fake PullRequestOpener backed by a slice. It records each opened PR
// (so a test can assert no hidden merge/actuation path) and returns a synthetic ref. SetFail
// makes it error, to exercise the provider's fail-closed path.
type InMemoryPullRequests struct {
	mu   sync.Mutex
	fail bool
	prs  []interfaces.PullRequest
}

var _ PullRequestOpener = (*InMemoryPullRequests)(nil)

// NewInMemoryPullRequests returns an empty fake PR opener.
func NewInMemoryPullRequests() *InMemoryPullRequests {
	return &InMemoryPullRequests{}
}

// SetFail makes CreatePullRequest return an error, to exercise the open-time fail-closed path.
func (o *InMemoryPullRequests) SetFail(fail bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.fail = fail
}

// CreatePullRequest records the PR and returns a synthetic URL and a sequential number. It
// deliberately does NOT merge, approve, or otherwise actuate.
func (o *InMemoryPullRequests) CreatePullRequest(ctx context.Context, pr interfaces.PullRequest) (string, int, error) {
	if err := ctx.Err(); err != nil {
		return "", 0, err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.fail {
		return "", 0, errors.New("scmgithub/fake: induced CreatePullRequest failure")
	}
	o.prs = append(o.prs, pr)
	number := len(o.prs)
	url := "https://" + pr.Repo.Host + "/" + pr.Repo.Owner + "/" + pr.Repo.Name + "/pull/" + strconv.Itoa(number)
	return url, number, nil
}

// Count reports how many PRs have been opened — a test inspection hook to assert no hidden
// actuation path mutated state beyond opening.
func (o *InMemoryPullRequests) Count() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.prs)
}
