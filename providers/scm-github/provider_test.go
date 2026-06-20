package scmgithub

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/console7/console7/sdk/interfaces"
)

var testRepo = interfaces.RepoRef{Host: "github.com", Owner: "acme", Name: "app"}

func newTestProvider() (*Provider, *InMemoryAppAuth, *InMemoryPullRequests) {
	auth := NewInMemoryAppAuth()
	pr := NewInMemoryPullRequests()
	return NewWithPorts(auth, pr, 15*time.Minute), auth, pr
}

func TestMintWorkingCredential_ShortLivedRepoScoped(t *testing.T) {
	p, auth, _ := newTestProvider()
	now := time.Now()
	ref, err := p.MintWorkingCredential(context.Background(), interfaces.WorkingCredentialRequest{
		Subject:         "sso|alice",
		SessionID:       "s1",
		Repo:            testRepo,
		Branch:          "feature/x",
		SessionDeadline: now.Add(30 * time.Minute),
	})
	if err != nil {
		t.Fatalf("MintWorkingCredential: %v", err)
	}
	if ref.Ref == "" || !strings.HasPrefix(ref.Ref, "scm-") {
		t.Fatalf("expected an opaque scm- ref, got %q", ref.Ref)
	}
	if !ref.Expiry.After(now) {
		t.Fatalf("expected a future expiry, got %v", ref.Expiry)
	}
	// The adapter must have been asked for a single-repo, least-privilege scope. The working
	// credential needs contents:write ONLY — never pull_requests (the sandbox token must not be
	// able to open/merge PRs; OpenPullRequest mints its own narrower token).
	got := auth.LastRequest()
	if got.Repo != testRepo {
		t.Fatalf("mint request repo = %+v, want %+v", got.Repo, testRepo)
	}
	if got.Permissions["contents"] != "write" {
		t.Fatalf("working credential did not request contents:write: %v", got.Permissions)
	}
	if _, hasPR := got.Permissions["pull_requests"]; hasPR {
		t.Fatalf("working credential must NOT request pull_requests: %v", got.Permissions)
	}
	if len(got.Permissions) != 1 {
		t.Fatalf("working credential requested more than contents: %v", got.Permissions)
	}
}

func TestMintWorkingCredential_RefusesForeignHost(t *testing.T) {
	p, auth, _ := newTestProvider() // expectedHost defaults to github.com
	_, err := p.MintWorkingCredential(context.Background(), interfaces.WorkingCredentialRequest{
		Subject:         "sso|alice",
		SessionID:       "s1",
		Repo:            interfaces.RepoRef{Host: "ghe.example.com", Owner: "acme", Name: "app"},
		Branch:          "feature/x",
		SessionDeadline: time.Now().Add(30 * time.Minute),
	})
	if err == nil {
		t.Fatal("expected refusal for a repo on a host the provider does not serve")
	}
	if (auth.LastRequest().Repo != interfaces.RepoRef{}) {
		t.Fatal("a token was minted for a foreign-host repo")
	}
}

func TestOpenPullRequest_RefusesForeignHost(t *testing.T) {
	p, _, prOpener := newTestProvider()
	_, err := p.OpenPullRequest(context.Background(), interfaces.PullRequest{
		Repo: interfaces.RepoRef{Host: "ghe.example.com", Owner: "acme", Name: "app"},
		Head: "feature/x",
		Base: "main",
	})
	if err == nil {
		t.Fatal("expected refusal for a PR on a host the provider does not serve")
	}
	if prOpener.Count() != 0 {
		t.Fatal("a PR was opened for a foreign-host repo")
	}
}

// If the session deadline passes while the (remote) mint is in flight, the provider must re-read
// the clock after the mint and fail closed rather than record an already-expired credential.
func TestMintWorkingCredential_RechecksDeadlineAfterMint(t *testing.T) {
	p, _, _ := newTestProvider()
	base := time.Now()
	deadline := base.Add(5 * time.Minute)
	// First p.now() (pre-mint) sees base (deadline still ahead); second (post-mint) sees a time
	// past the deadline, as if the mint took long enough for the session to end.
	times := []time.Time{base, base.Add(10 * time.Minute)}
	i := 0
	p.now = func() time.Time {
		t := times[i]
		if i < len(times)-1 {
			i++
		}
		return t
	}
	if _, err := p.MintWorkingCredential(context.Background(), interfaces.WorkingCredentialRequest{
		Subject:         "sso|alice",
		SessionID:       "s1",
		Repo:            testRepo,
		Branch:          "feature/x",
		SessionDeadline: deadline,
	}); err == nil {
		t.Fatal("expected fail-closed when the deadline passes during the mint")
	}
	p.mu.Lock()
	n := len(p.leases)
	p.mu.Unlock()
	if n != 0 {
		t.Fatalf("expected no lease recorded when the deadline passed during mint, got %d", n)
	}
}

func TestIntersectPermissions(t *testing.T) {
	ceiling := map[string]string{"contents": "write", "pull_requests": "write"}
	if got := intersectPermissions(map[string]string{"contents": "write"}, ceiling); got["contents"] != "write" || len(got) != 1 {
		t.Fatalf("contents:write ∩ full ceiling = %v, want {contents:write}", got)
	}
	// A request is capped DOWN to a narrower ceiling.
	if got := intersectPermissions(map[string]string{"pull_requests": "write"}, map[string]string{"pull_requests": "read"}); got["pull_requests"] != "read" {
		t.Fatalf("write ∩ read ceiling = %v, want read", got)
	}
	// A permission the ceiling does not grant is dropped (downstream fails closed).
	if got := intersectPermissions(map[string]string{"pull_requests": "write"}, map[string]string{"contents": "write"}); len(got) != 0 {
		t.Fatalf("ungranted permission should be dropped, got %v", got)
	}
}

// The opaque ref must NEVER be (or contain) the durable installation token; the token is stashed
// behind the ref and held, not returned.
func TestMintWorkingCredential_NeverReturnsDurableToken(t *testing.T) {
	p, _, _ := newTestProvider()
	ref, err := p.MintWorkingCredential(context.Background(), interfaces.WorkingCredentialRequest{
		Subject:         "sso|alice",
		SessionID:       "s1",
		Repo:            testRepo,
		Branch:          "feature/x",
		SessionDeadline: time.Now().Add(30 * time.Minute),
	})
	if err != nil {
		t.Fatalf("MintWorkingCredential: %v", err)
	}
	p.mu.Lock()
	lease, ok := p.leases[ref.Ref]
	p.mu.Unlock()
	if !ok {
		t.Fatal("expected the ref to index a held lease")
	}
	if len(lease.token) == 0 {
		t.Fatal("expected the durable token to be held behind the ref")
	}
	if ref.Ref == string(lease.token) || strings.Contains(ref.Ref, string(lease.token)) {
		t.Fatalf("returned ref leaks the durable token: ref=%q token=%q", ref.Ref, lease.token)
	}
}

func TestMintWorkingCredential_CapsToSessionDeadline(t *testing.T) {
	p, auth, _ := newTestProvider()
	now := time.Now()
	deadline := now.Add(2 * time.Minute) // sooner than the 15m ttl and the 1h fake token expiry
	auth.SetExpiry(now.Add(time.Hour))
	ref, err := p.MintWorkingCredential(context.Background(), interfaces.WorkingCredentialRequest{
		Subject:         "sso|alice",
		SessionID:       "s1",
		Repo:            testRepo,
		Branch:          "feature/x",
		SessionDeadline: deadline,
	})
	if err != nil {
		t.Fatalf("MintWorkingCredential: %v", err)
	}
	if ref.Expiry.After(deadline) {
		t.Fatalf("expiry %v outlives the session deadline %v", ref.Expiry, deadline)
	}
	if !ref.Expiry.Equal(deadline) {
		t.Fatalf("expected expiry capped to the deadline %v, got %v", deadline, ref.Expiry)
	}
}

func TestMintWorkingCredential_CapsToGitHubTokenExpiry(t *testing.T) {
	p, auth, _ := newTestProvider()
	now := time.Now()
	ghExpiry := now.Add(5 * time.Minute) // sooner than 15m ttl and the 1h session deadline
	auth.SetExpiry(ghExpiry)
	ref, err := p.MintWorkingCredential(context.Background(), interfaces.WorkingCredentialRequest{
		Subject:         "sso|alice",
		SessionID:       "s1",
		Repo:            testRepo,
		Branch:          "feature/x",
		SessionDeadline: now.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("MintWorkingCredential: %v", err)
	}
	if !ref.Expiry.Equal(ghExpiry) {
		t.Fatalf("expected expiry capped to the GitHub token expiry %v, got %v", ghExpiry, ref.Expiry)
	}
}

func TestMintWorkingCredential_RefusesMissingDeadlineOrLineage(t *testing.T) {
	p, _, _ := newTestProvider()
	now := time.Now()
	good := interfaces.WorkingCredentialRequest{
		Subject:         "sso|alice",
		SessionID:       "s1",
		Repo:            testRepo,
		Branch:          "feature/x",
		SessionDeadline: now.Add(30 * time.Minute),
	}
	cases := map[string]func(r interfaces.WorkingCredentialRequest) interfaces.WorkingCredentialRequest{
		"zero deadline": func(r interfaces.WorkingCredentialRequest) interfaces.WorkingCredentialRequest {
			r.SessionDeadline = time.Time{}
			return r
		},
		"past deadline": func(r interfaces.WorkingCredentialRequest) interfaces.WorkingCredentialRequest {
			r.SessionDeadline = now.Add(-time.Minute)
			return r
		},
		"empty subject": func(r interfaces.WorkingCredentialRequest) interfaces.WorkingCredentialRequest {
			r.Subject = ""
			return r
		},
		"empty session": func(r interfaces.WorkingCredentialRequest) interfaces.WorkingCredentialRequest {
			r.SessionID = ""
			return r
		},
		"empty branch": func(r interfaces.WorkingCredentialRequest) interfaces.WorkingCredentialRequest {
			r.Branch = ""
			return r
		},
		"partial repo": func(r interfaces.WorkingCredentialRequest) interfaces.WorkingCredentialRequest {
			r.Repo.Name = ""
			return r
		},
		"no repo at all": func(r interfaces.WorkingCredentialRequest) interfaces.WorkingCredentialRequest {
			r.Repo = interfaces.RepoRef{}
			return r
		},
	}
	for name, mut := range cases {
		if _, err := p.MintWorkingCredential(context.Background(), mut(good)); err == nil {
			t.Errorf("%s: expected an error, got none", name)
		}
	}
}

func TestMintWorkingCredential_RefusesProtectedBranch(t *testing.T) {
	auth := NewInMemoryAppAuth()
	pr := NewInMemoryPullRequests()
	p := NewWithPorts(auth, pr, 15*time.Minute, "release")
	now := time.Now()
	for _, branch := range []string{"main", "master", "release"} {
		_, err := p.MintWorkingCredential(context.Background(), interfaces.WorkingCredentialRequest{
			Subject:         "sso|alice",
			SessionID:       "s1",
			Repo:            testRepo,
			Branch:          branch,
			SessionDeadline: now.Add(30 * time.Minute),
		})
		if err == nil {
			t.Errorf("branch %q: expected refusal for a protected branch", branch)
		}
	}
}

// A protected-branch refusal must short-circuit BEFORE any token is minted (no remote side effect
// for a request we are going to reject).
func TestMintWorkingCredential_ProtectedBranchMintsNoToken(t *testing.T) {
	p, auth, _ := newTestProvider()
	_, err := p.MintWorkingCredential(context.Background(), interfaces.WorkingCredentialRequest{
		Subject:         "sso|alice",
		SessionID:       "s1",
		Repo:            testRepo,
		Branch:          "main",
		SessionDeadline: time.Now().Add(30 * time.Minute),
	})
	if err == nil {
		t.Fatal("expected refusal for the protected branch main")
	}
	if (auth.LastRequest().Repo != interfaces.RepoRef{}) {
		t.Fatal("a token was minted for a request that should have been refused before minting")
	}
}

func TestMintWorkingCredential_FailsClosedWhenAuthErrors(t *testing.T) {
	p, auth, _ := newTestProvider()
	auth.SetFail(true)
	ref, err := p.MintWorkingCredential(context.Background(), interfaces.WorkingCredentialRequest{
		Subject:         "sso|alice",
		SessionID:       "s1",
		Repo:            testRepo,
		Branch:          "feature/x",
		SessionDeadline: time.Now().Add(30 * time.Minute),
	})
	if err == nil {
		t.Fatal("expected a fail-closed error when App auth fails")
	}
	if ref.Ref != "" {
		t.Fatalf("expected no credential ref on mint failure, got %q", ref.Ref)
	}
	p.mu.Lock()
	n := len(p.leases)
	p.mu.Unlock()
	if n != 0 {
		t.Fatalf("expected no lease recorded on mint failure, got %d", n)
	}
}

func TestMintWorkingCredential_RefusesCancelledContext(t *testing.T) {
	p, _, _ := newTestProvider()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.MintWorkingCredential(ctx, interfaces.WorkingCredentialRequest{
		Subject:         "sso|alice",
		SessionID:       "s1",
		Repo:            testRepo,
		Branch:          "feature/x",
		SessionDeadline: time.Now().Add(30 * time.Minute),
	}); err == nil {
		t.Fatal("expected an error for a cancelled context")
	}
}

func TestOpenPullRequest_RecordsButNeverActuates(t *testing.T) {
	p, _, prOpener := newTestProvider()
	ref, err := p.OpenPullRequest(context.Background(), interfaces.PullRequest{
		Repo:  testRepo,
		Head:  "feature/x",
		Base:  "main",
		Title: "propose x",
	})
	if err != nil {
		t.Fatalf("OpenPullRequest: %v", err)
	}
	if ref.Number == 0 || ref.URL == "" {
		t.Fatalf("expected a populated PRRef, got %+v", ref)
	}
	if prOpener.Count() != 1 {
		t.Fatalf("expected exactly one opened PR, got %d", prOpener.Count())
	}
}

func TestOpenPullRequest_RefusesDirectMutation(t *testing.T) {
	p, _, prOpener := newTestProvider()
	cases := []interfaces.PullRequest{
		{Repo: testRepo, Head: "main", Base: "main"},    // head == base
		{Repo: testRepo, Head: "main", Base: "develop"}, // head is protected
		{Repo: testRepo, Head: "feature/x", Base: ""},   // missing base
		{Repo: testRepo, Head: "", Base: "main"},        // missing head
	}
	for i, pr := range cases {
		if _, err := p.OpenPullRequest(context.Background(), pr); err == nil {
			t.Errorf("case %d: expected refusal for %+v", i, pr)
		}
	}
	if prOpener.Count() != 0 {
		t.Fatalf("expected no PR recorded for refused proposals, got %d", prOpener.Count())
	}
}

func TestOpenPullRequest_FailsClosedWhenOpenerErrors(t *testing.T) {
	p, _, prOpener := newTestProvider()
	prOpener.SetFail(true)
	ref, err := p.OpenPullRequest(context.Background(), interfaces.PullRequest{
		Repo: testRepo,
		Head: "feature/x",
		Base: "main",
	})
	if err == nil {
		t.Fatal("expected a fail-closed error when the opener fails")
	}
	if ref.Number != 0 || ref.URL != "" {
		t.Fatalf("expected an empty PRRef on failure, got %+v", ref)
	}
}

// Each mint records a distinct lease bound to its own subject/session, so two sessions never
// share a credential.
func TestMintWorkingCredential_PerSessionLeases(t *testing.T) {
	p, _, _ := newTestProvider()
	now := time.Now()
	mk := func(subj interfaces.Subject, sess interfaces.SessionID) interfaces.CredentialRef {
		ref, err := p.MintWorkingCredential(context.Background(), interfaces.WorkingCredentialRequest{
			Subject:         subj,
			SessionID:       sess,
			Repo:            testRepo,
			Branch:          "feature/x",
			SessionDeadline: now.Add(30 * time.Minute),
		})
		if err != nil {
			t.Fatalf("MintWorkingCredential(%s/%s): %v", subj, sess, err)
		}
		return ref
	}
	a := mk("sso|alice", "s1")
	b := mk("sso|bob", "s2")
	if a.Ref == b.Ref {
		t.Fatal("two sessions got the same credential ref")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.leases[a.Ref].subject != "sso|alice" || p.leases[a.Ref].session != "s1" {
		t.Fatal("lease A not bound to its subject/session")
	}
	if bytes.Equal(p.leases[b.Ref].token, p.leases[a.Ref].token) {
		t.Fatal("two sessions share the same underlying token")
	}
}

// RevokeRef eagerly shreds a held token at session end: the lease is removed and its token bytes
// are zeroed.
func TestRevokeRef_ShredsHeldToken(t *testing.T) {
	p, _, _ := newTestProvider()
	ref, err := p.MintWorkingCredential(context.Background(), interfaces.WorkingCredentialRequest{
		Subject:         "sso|alice",
		SessionID:       "s1",
		Repo:            testRepo,
		Branch:          "feature/x",
		SessionDeadline: time.Now().Add(30 * time.Minute),
	})
	if err != nil {
		t.Fatalf("MintWorkingCredential: %v", err)
	}
	p.mu.Lock()
	held := p.leases[ref.Ref].token // same backing array the provider holds
	p.mu.Unlock()
	if !p.RevokeRef(ref.Ref) {
		t.Fatal("RevokeRef reported no lease for a freshly-minted ref")
	}
	p.mu.Lock()
	_, stillThere := p.leases[ref.Ref]
	p.mu.Unlock()
	if stillThere {
		t.Fatal("lease survived RevokeRef")
	}
	if !bytes.Equal(held, make([]byte, len(held))) {
		t.Fatal("RevokeRef did not zero the held token bytes")
	}
	if p.RevokeRef(ref.Ref) {
		t.Fatal("RevokeRef reported a lease for an already-revoked ref")
	}
}

// A mint evicts leases that have already expired, so stale tokens do not accumulate in memory.
func TestMintWorkingCredential_EvictsExpiredLeases(t *testing.T) {
	p, _, _ := newTestProvider()
	base := time.Now()
	p.now = func() time.Time { return base }
	first, err := p.MintWorkingCredential(context.Background(), interfaces.WorkingCredentialRequest{
		Subject:         "sso|alice",
		SessionID:       "s1",
		Repo:            testRepo,
		Branch:          "feature/x",
		SessionDeadline: base.Add(1 * time.Minute), // expires soon
	})
	if err != nil {
		t.Fatalf("first mint: %v", err)
	}
	// Advance past the first lease's expiry, then mint again — the sweep should evict the first.
	p.now = func() time.Time { return base.Add(2 * time.Minute) }
	if _, err := p.MintWorkingCredential(context.Background(), interfaces.WorkingCredentialRequest{
		Subject:         "sso|bob",
		SessionID:       "s2",
		Repo:            testRepo,
		Branch:          "feature/y",
		SessionDeadline: base.Add(30 * time.Minute),
	}); err != nil {
		t.Fatalf("second mint: %v", err)
	}
	p.mu.Lock()
	_, firstThere := p.leases[first.Ref]
	n := len(p.leases)
	p.mu.Unlock()
	if firstThere {
		t.Fatal("expired lease was not evicted on the next mint")
	}
	if n != 1 {
		t.Fatalf("expected exactly the live lease to remain, got %d", n)
	}
}

func TestOpenPullRequest_RefusesMissingRepo(t *testing.T) {
	p, _, prOpener := newTestProvider()
	if _, err := p.OpenPullRequest(context.Background(), interfaces.PullRequest{
		Head: "feature/x",
		Base: "main",
	}); err == nil {
		t.Fatal("expected refusal for a missing repo")
	}
	if prOpener.Count() != 0 {
		t.Fatalf("a PR was opened for a malformed request, count=%d", prOpener.Count())
	}
}

// The permission allowlist must reject both an unknown key and an over-broad access level, so a
// Config.Permissions override cannot widen past least privilege.
func TestToInstallationPermissions_RejectsWidening(t *testing.T) {
	if _, err := toInstallationPermissions(map[string]string{"contents": "admin"}); err == nil {
		t.Error("expected rejection of an over-broad access level (admin)")
	}
	if _, err := toInstallationPermissions(map[string]string{"administration": "write"}); err == nil {
		t.Error("expected rejection of an out-of-allowlist permission key")
	}
	if _, err := toInstallationPermissions(DefaultPermissions); err != nil {
		t.Errorf("DefaultPermissions should be accepted: %v", err)
	}
	if _, err := toInstallationPermissions(pullRequestPermissions); err != nil {
		t.Errorf("pullRequestPermissions should be accepted: %v", err)
	}
}

func TestParseRSAPrivateKey_RejectsGarbage(t *testing.T) {
	if _, err := parseRSAPrivateKey([]byte("not a pem")); err == nil {
		t.Fatal("expected an error for non-PEM input")
	}
}

func TestConfigNormalize_RequiresAppIDAndKey(t *testing.T) {
	if _, _, err := (Config{PrivateKeyPEM: []byte("x")}).normalize(); err == nil {
		t.Error("expected an error for a missing AppID")
	}
	if _, _, err := (Config{AppID: 1}).normalize(); err == nil {
		t.Error("expected an error for a missing private key")
	}
}
