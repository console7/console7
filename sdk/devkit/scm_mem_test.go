package devkit

import (
	"context"
	"testing"
	"time"

	"github.com/console7/console7/sdk/interfaces"
)

func TestMemSCM_MintWorkingCredential_ShortLivedBranchScoped(t *testing.T) {
	s := NewMemSCM(10 * time.Minute)
	ref, err := s.MintWorkingCredential(context.Background(), interfaces.WorkingCredentialRequest{
		Subject:         "alice",
		SessionID:       "s1",
		Repo:            interfaces.RepoRef{Host: "github.com", Owner: "acme", Name: "app"},
		Branch:          "feature/x",
		SessionDeadline: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("MintWorkingCredential: %v", err)
	}
	if ref.Ref == "" {
		t.Error("CredentialRef.Ref must be set")
	}
	if ref.Expiry.IsZero() || ref.Expiry.Before(time.Now()) {
		t.Errorf("credential must be short-lived with a future expiry, got %v", ref.Expiry)
	}
}

func TestMemSCM_MintWorkingCredential_CapsToSessionDeadline(t *testing.T) {
	s := NewMemSCM(1 * time.Hour) // TTL far longer than the deadline.
	deadline := time.Now().Add(2 * time.Minute)
	ref, err := s.MintWorkingCredential(context.Background(), interfaces.WorkingCredentialRequest{
		Subject: "alice", SessionID: "s1",
		Repo:            interfaces.RepoRef{Host: "github.com", Owner: "acme", Name: "app"},
		Branch:          "feature/x",
		SessionDeadline: deadline,
	})
	if err != nil {
		t.Fatalf("MintWorkingCredential: %v", err)
	}
	if ref.Expiry.After(deadline) {
		t.Errorf("SCM credential expiry %v outlives the session deadline %v", ref.Expiry, deadline)
	}
}

func TestMemSCM_MintWorkingCredential_RefusesMissingDeadlineOrLineage(t *testing.T) {
	s := NewMemSCM(10 * time.Minute)
	repo := interfaces.RepoRef{Host: "github.com", Owner: "acme", Name: "app"}
	future := time.Now().Add(time.Hour)
	cases := []struct {
		name string
		req  interfaces.WorkingCredentialRequest
	}{
		{"zero deadline", interfaces.WorkingCredentialRequest{Subject: "alice", SessionID: "s1", Repo: repo, Branch: "feature/x"}},
		{"past deadline", interfaces.WorkingCredentialRequest{Subject: "alice", SessionID: "s1", Repo: repo, Branch: "feature/x", SessionDeadline: time.Now().Add(-time.Minute)}},
		{"empty subject", interfaces.WorkingCredentialRequest{SessionID: "s1", Repo: repo, Branch: "feature/x", SessionDeadline: future}},
		{"empty session", interfaces.WorkingCredentialRequest{Subject: "alice", Repo: repo, Branch: "feature/x", SessionDeadline: future}},
		{"empty repo", interfaces.WorkingCredentialRequest{Subject: "alice", SessionID: "s1", Branch: "feature/x", SessionDeadline: future}},
		{"partial repo", interfaces.WorkingCredentialRequest{Subject: "alice", SessionID: "s1", Repo: interfaces.RepoRef{Host: "github.com"}, Branch: "feature/x", SessionDeadline: future}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := s.MintWorkingCredential(context.Background(), tc.req); err == nil {
				t.Error("expected refusal, got nil")
			}
		})
	}
}

func TestMemSCM_MintWorkingCredential_RefusesProtectedBranch(t *testing.T) {
	s := NewMemSCM(10*time.Minute, "release")
	for _, branch := range []string{"main", "master", "release"} {
		t.Run(branch, func(t *testing.T) {
			if _, err := s.MintWorkingCredential(context.Background(), interfaces.WorkingCredentialRequest{
				Subject: "alice", SessionID: "s1",
				Repo:            interfaces.RepoRef{Host: "github.com", Owner: "acme", Name: "app"},
				Branch:          branch,
				SessionDeadline: time.Now().Add(time.Hour),
			}); err == nil {
				t.Errorf("minted a credential scoped to protected branch %q", branch)
			}
		})
	}
}

func TestMemSCM_OpenPullRequest_RecordsButNeverActuates(t *testing.T) {
	s := NewMemSCM(10 * time.Minute)
	pr := interfaces.PullRequest{
		Repo:  interfaces.RepoRef{Host: "github.com", Owner: "acme", Name: "app"},
		Head:  "feature/x",
		Base:  "main",
		Title: "Propose change",
	}
	ref, err := s.OpenPullRequest(context.Background(), pr)
	if err != nil {
		t.Fatalf("OpenPullRequest: %v", err)
	}
	if ref.Number != 1 || ref.URL == "" {
		t.Errorf("unexpected PRRef %+v", ref)
	}
	if s.OpenPRCount() != 1 {
		t.Errorf("expected exactly one opened PR, got %d", s.OpenPRCount())
	}
}

func TestMemSCM_OpenPullRequest_RefusesDirectMutation(t *testing.T) {
	s := NewMemSCM(10 * time.Minute)
	repo := interfaces.RepoRef{Host: "github.com", Owner: "acme", Name: "app"}
	cases := []struct {
		name string
		pr   interfaces.PullRequest
	}{
		{"head equals base", interfaces.PullRequest{Repo: repo, Head: "main", Base: "main"}},
		{"head is protected", interfaces.PullRequest{Repo: repo, Head: "master", Base: "main"}},
		{"missing branches", interfaces.PullRequest{Repo: repo, Head: "", Base: "main"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := s.OpenPullRequest(context.Background(), tc.pr); err == nil {
				t.Error("expected refusal, got nil")
			}
		})
	}
	if s.OpenPRCount() != 0 {
		t.Errorf("refused PRs were recorded: count=%d", s.OpenPRCount())
	}
}

func TestMemSCM_FetchRepoBundle(t *testing.T) {
	s := NewMemSCM(10 * time.Minute)
	repo := interfaces.RepoRef{Host: "github.com", Owner: "acme", Name: "app"}
	b, err := s.FetchRepoBundle(context.Background(), repo, "main")
	if err != nil || len(b) == 0 {
		t.Fatalf("FetchRepoBundle: err=%v len=%d", err, len(b))
	}
	for _, tc := range []struct {
		name string
		repo interfaces.RepoRef
		base string
	}{
		{"missing repo", interfaces.RepoRef{Host: "github.com", Owner: "acme"}, "main"},
		{"empty base", repo, ""},
	} {
		if _, err := s.FetchRepoBundle(context.Background(), tc.repo, tc.base); err == nil {
			t.Errorf("%s: expected an error", tc.name)
		}
	}
}

func TestMemSCM_PushBranch(t *testing.T) {
	s := NewMemSCM(10*time.Minute, "release")
	repo := interfaces.RepoRef{Host: "github.com", Owner: "acme", Name: "app"}
	future := time.Now().Add(10 * time.Minute)
	// Happy path records the working branch.
	if err := s.PushBranch(context.Background(), interfaces.PushBranchRequest{
		Subject: "alice", SessionID: "s1", Repo: repo, Branch: "c7/work", Bundle: []byte("wb"), SessionDeadline: future,
	}); err != nil {
		t.Fatalf("PushBranch: %v", err)
	}
	if got := s.PushedBranches(); len(got) != 1 || got[0] != "c7/work" {
		t.Errorf("push not recorded: %v", got)
	}
	// Fail-closed cases must record nothing.
	for _, tc := range []struct {
		name string
		req  interfaces.PushBranchRequest
	}{
		{"protected main", interfaces.PushBranchRequest{Subject: "a", SessionID: "s", Repo: repo, Branch: "main", Bundle: []byte("x"), SessionDeadline: future}},
		{"protected release", interfaces.PushBranchRequest{Subject: "a", SessionID: "s", Repo: repo, Branch: "release", Bundle: []byte("x"), SessionDeadline: future}},
		{"missing lineage", interfaces.PushBranchRequest{Repo: repo, Branch: "c7/w", Bundle: []byte("x"), SessionDeadline: future}},
		{"empty bundle", interfaces.PushBranchRequest{Subject: "a", SessionID: "s", Repo: repo, Branch: "c7/w", Bundle: nil, SessionDeadline: future}},
		{"past deadline", interfaces.PushBranchRequest{Subject: "a", SessionID: "s", Repo: repo, Branch: "c7/w", Bundle: []byte("x"), SessionDeadline: time.Now().Add(-time.Minute)}},
	} {
		if err := s.PushBranch(context.Background(), tc.req); err == nil {
			t.Errorf("%s: expected an error", tc.name)
		}
	}
	if got := s.PushedBranches(); len(got) != 1 {
		t.Errorf("refused pushes were recorded: %v", got)
	}
}
