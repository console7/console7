package devkit

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"time"

	"github.com/console7/console7/sdk/interfaces"
)

// defaultProtected are branch names always treated as protected/default, so a session
// can never be issued a credential that pushes to them even if the adopter forgot to
// configure protection. Allowlist-style: callers may add more, never remove these.
var defaultProtected = map[string]bool{"main": true, "master": true}

// MemSCM is an in-memory, NON-PRODUCTION SCMProvider. It models the GitHub-App default:
// short-lived, repo-scoped, branch-restricted working credentials, and PR-as-the-only-
// exit (never a direct push/merge to a protected branch, never a self-approve). It does
// not talk to a real SCM; it records leases and opened PRs so a bench can assert the
// invariants.
type MemSCM struct {
	mu        sync.Mutex
	leases    map[string]scmLease
	prs       []interfaces.PullRequest
	pushed    []interfaces.PushBranchRequest
	protected map[string]bool
	ttl       time.Duration
	now       func() time.Time
}

type scmLease struct {
	subject interfaces.Subject
	session interfaces.SessionID
	repo    interfaces.RepoRef
	branch  string
	expiry  time.Time
}

var _ interfaces.SCMProvider = (*MemSCM)(nil)

// NewMemSCM returns a MemSCM. extraProtected names additional protected branches beyond
// the always-protected main/master. ttl bounds working-credential lifetime.
func NewMemSCM(ttl time.Duration, extraProtected ...string) *MemSCM {
	prot := make(map[string]bool, len(defaultProtected)+len(extraProtected))
	for b := range defaultProtected {
		prot[b] = true
	}
	for _, b := range extraProtected {
		prot[b] = true
	}
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	return &MemSCM{
		leases:    make(map[string]scmLease),
		protected: prot,
		ttl:       ttl,
		now:       time.Now,
	}
}

// MintWorkingCredential issues a short-lived, repo-scoped, branch-restricted credential
// lease and returns an opaque CredentialRef — never a durable token. It refuses to bind
// a credential to a protected/default branch.
func (s *MemSCM) MintWorkingCredential(ctx context.Context, req interfaces.WorkingCredentialRequest) (interfaces.CredentialRef, error) {
	if err := ctx.Err(); err != nil {
		return interfaces.CredentialRef{}, err
	}
	// The credential MUST be bound to the per-session identity for lineage; refuse to
	// mint an unattributable one (DESIGN.md §2.3).
	if req.Subject == "" || req.SessionID == "" {
		return interfaces.CredentialRef{}, errors.New("devkit: MintWorkingCredential requires a subject and session for lineage")
	}
	if req.Branch == "" {
		return interfaces.CredentialRef{}, errors.New("devkit: MintWorkingCredential requires a working branch")
	}
	// The credential MUST be repo-scoped (SECURITY contract); refuse a zero RepoRef so a
	// missing-repo wiring bug cannot produce an unscoped/unusable token.
	if req.Repo.Host == "" || req.Repo.Owner == "" || req.Repo.Name == "" {
		return interfaces.CredentialRef{}, errors.New("devkit: MintWorkingCredential requires a fully-specified repo")
	}
	now := s.now()
	// Like every minted credential, the SCM token must die with the session: cap its
	// expiry to no later than min(now+ttl, SessionDeadline) and refuse an absent/past
	// deadline rather than issue one that could outlive the session (DESIGN.md §2.1).
	if req.SessionDeadline.IsZero() || !req.SessionDeadline.After(now) {
		return interfaces.CredentialRef{}, errors.New("devkit: MintWorkingCredential requires a SessionDeadline in the future")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.protected[req.Branch] {
		// Push MUST be restricted to a working branch; never a protected/default one.
		return interfaces.CredentialRef{}, errors.New("devkit: refusing to scope a working credential to a protected branch")
	}
	expiry := now.Add(s.ttl)
	if req.SessionDeadline.Before(expiry) {
		expiry = req.SessionDeadline
	}
	ref := "scm-" + randHex(12) // opaque; no durable token material.
	s.leases[ref] = scmLease{
		subject: req.Subject,
		session: req.SessionID,
		repo:    req.Repo,
		branch:  req.Branch,
		expiry:  expiry,
	}
	return interfaces.CredentialRef{Ref: ref, Expiry: expiry}, nil
}

// OpenPullRequest records a proposed change as a PR. It is the only sanctioned exit for a
// session's change. It refuses anything that would amount to a direct push to or merge of
// a protected branch (head protected, or head == base), and it never merges or approves.
func (s *MemSCM) OpenPullRequest(ctx context.Context, pr interfaces.PullRequest) (interfaces.PRRef, error) {
	if err := ctx.Err(); err != nil {
		return interfaces.PRRef{}, err
	}
	if pr.Head == "" || pr.Base == "" {
		return interfaces.PRRef{}, errors.New("devkit: OpenPullRequest requires head and base branches")
	}
	if pr.Head == pr.Base {
		// Proposing a branch onto itself is a direct mutation, not a proposal.
		return interfaces.PRRef{}, errors.New("devkit: refusing a pull request whose head equals its base")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.protected[pr.Head] {
		// The session must have worked on a working branch, not a protected one.
		return interfaces.PRRef{}, errors.New("devkit: refusing a pull request opened from a protected branch")
	}
	// Record the PR. We deliberately do NOT merge, approve, or otherwise actuate it —
	// author/approve/actuate are separated; a session holds only author.
	s.prs = append(s.prs, pr)
	number := len(s.prs)
	url := "https://" + pr.Repo.Host + "/" + pr.Repo.Owner + "/" + pr.Repo.Name + "/pull/" + strconv.Itoa(number)
	return interfaces.PRRef{URL: url, Number: number}, nil
}

// OpenPRCount reports how many PRs have been opened — a test inspection hook to assert no
// hidden merge/actuation path mutated state beyond opening.
func (s *MemSCM) OpenPRCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.prs)
}

// FetchRepoBundle returns a deterministic synthetic bundle for the base branch (no real SCM). It
// models the observable contract — non-empty content out — so the orchestrator's seed-the-sandbox
// step has a payload on the bench.
func (s *MemSCM) FetchRepoBundle(ctx context.Context, repo interfaces.RepoRef, baseBranch string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if repo.Host == "" || repo.Owner == "" || repo.Name == "" {
		return nil, errors.New("devkit: FetchRepoBundle requires a fully-specified repo")
	}
	if baseBranch == "" {
		return nil, errors.New("devkit: FetchRepoBundle requires a base branch")
	}
	return []byte("devkit-mem-base-bundle:" + repo.Host + "/" + repo.Owner + "/" + repo.Name + "@" + baseBranch), nil
}

// PushBranch records a control-plane-side push of the working branch. It enforces the same lineage
// and protected-branch invariants as MintWorkingCredential, refuses an empty bundle, and never
// merges/actuates — it only records that the branch would be pushed.
func (s *MemSCM) PushBranch(ctx context.Context, req interfaces.PushBranchRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if req.Subject == "" || req.SessionID == "" {
		return errors.New("devkit: PushBranch requires a subject and session for lineage")
	}
	if req.Repo.Host == "" || req.Repo.Owner == "" || req.Repo.Name == "" {
		return errors.New("devkit: PushBranch requires a fully-specified repo")
	}
	if req.Branch == "" {
		return errors.New("devkit: PushBranch requires a working branch")
	}
	if len(req.Bundle) == 0 {
		return errors.New("devkit: PushBranch requires a non-empty bundle")
	}
	now := s.now()
	if req.SessionDeadline.IsZero() || !req.SessionDeadline.After(now) {
		return errors.New("devkit: PushBranch requires a SessionDeadline in the future")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.protected[req.Branch] {
		return errors.New("devkit: refusing to push to a protected branch")
	}
	s.pushed = append(s.pushed, req)
	return nil
}

// PushedBranches returns the working branches pushed so far — a test hook to assert the push
// happened (exactly once, of the working branch) before OpenPullRequest.
func (s *MemSCM) PushedBranches() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.pushed))
	for _, p := range s.pushed {
		out = append(out, p.Branch)
	}
	return out
}
