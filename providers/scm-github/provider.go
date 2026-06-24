package scmgithub

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/console7/console7/sdk/interfaces"
)

// defaultProtected are branch names always treated as protected/default, so a session can never
// be issued a credential scoped to push to them even if the adopter forgot to configure
// protection. Allowlist-style: callers may add more (Config.ProtectedBranches), never remove
// these. NOTE: this in-band refusal is DEFENCE-IN-DEPTH. A GitHub installation token cannot be
// branch-scoped at the token level, so the authoritative "push only to the working branch"
// control is the repo's branch-protection ruleset (adopter-side) and ultimately the default-deny
// egress boundary — not this map (GOAL.md tenet 2; see doc.go).
var defaultProtected = map[string]bool{"main": true, "master": true}

// DefaultTTL bounds working-credential lifetime when Config.TTL is unset. The effective expiry is
// the earliest of now+TTL, the GitHub token expiry (~1h), and the session deadline.
const DefaultTTL = 15 * time.Minute

// DefaultExpectedHost is the SCM host a Provider scopes to when Config.BaseURL is unset.
const DefaultExpectedHost = "github.com"

// DefaultPermissions is the GitHub App's GRANTED permission CEILING — what the adopter's App is
// installed with (contents + pull_requests, write). It is NOT the per-operation grant: each
// operation requests the still-narrower subset it actually needs, intersected with this ceiling
// (so narrowing Config.Permissions tightens every operation, never widens it). The adapter rejects
// any permission key outside its allowlist and any level beyond read/write.
var DefaultPermissions = map[string]string{"contents": "write", "pull_requests": "write"}

// workingCredentialPermissions is the per-operation subset a working credential needs: contents
// write to push the branch — NOT pull_requests (the sandbox token must not be able to open/merge
// PRs; OpenPullRequest mints its own narrower token). Intersected with the granted ceiling.
var workingCredentialPermissions = map[string]string{"contents": "write"}

// pullRequestPermissions is the per-operation subset OpenPullRequest needs: pull_requests write to
// open the PR, plus contents READ — GitHub must read the head + base refs to validate the PR, and a
// pull_requests-only token cannot (it fails with 422 "not all refs are readable"). contents is READ,
// never write (the push already happened; the PR-open token must not be able to mutate contents).
// Intersected with the granted ceiling, so an adopter who narrows below this tightens (or fails
// closed) PR opening rather than being silently overridden. Minimal for an actuation-adjacent token
// (GOAL.md tenets 4, 6).
var pullRequestPermissions = map[string]string{"pull_requests": "write", "contents": "read"}

// readContentsPermissions is the per-operation subset FetchRepoBundle needs: contents READ only (to
// clone the base) — never write, never pull_requests. Intersected with the granted ceiling.
var readContentsPermissions = map[string]string{"contents": "read"}

// permLevels ranks GitHub App access levels so a per-operation request can be intersected DOWN to
// the granted ceiling (never up).
var permLevels = map[string]int{"read": 1, "write": 2}

// intersectPermissions returns, for each requested permission, the LOWER of the requested and the
// granted level, dropping any permission the ceiling does not grant at all. The result is never
// broader than either input — so a per-operation request stays least-privilege and an adopter's
// narrowed Config.Permissions tightens every operation (a dropped/insufficient permission makes
// the downstream GitHub call fail closed rather than act over-privileged).
func intersectPermissions(requested, granted map[string]string) map[string]string {
	out := make(map[string]string, len(requested))
	for k, want := range requested {
		have, ok := granted[k]
		if !ok {
			continue // not in the ceiling — drop it (fail closed downstream)
		}
		if permLevels[have] < permLevels[want] {
			out[k] = have
		} else {
			out[k] = want
		}
	}
	return out
}

// Provider is the GitHub reference SCMProvider. Its logic depends only on the AppAuth and
// PullRequestOpener ports; New wires the real ghinstallation + go-github adapter, while
// NewWithPorts wires the in-memory fakes for tests/conformance.
//
// It holds the minted installation token behind an opaque ref in an ephemeral, mutex-guarded
// lease book and NEVER returns it to a caller. The book is bounded: every mint first evicts
// expired leases (zeroing their token bytes), and RevokeRef shreds a lease eagerly at session end
// — so a stale installation token does not linger in process memory (GOAL.md tenet 4). Delivery
// of a held token into the owning sandbox git client is the data-plane path that does not exist
// yet (see doc.go); until the sandbox PR lands, the lease book is the seam that path will redeem
// against.
//
// auth, pr, protected, perms, expectedHost, ttl, and now are write-once at construction and read
// without the lock; only leases is mutated after construction and is guarded by mu.
type Provider struct {
	auth         AppAuth
	pr           PullRequestOpener
	git          GitTransport
	protected    map[string]bool
	perms        map[string]string
	expectedHost string
	ttl          time.Duration
	now          func() time.Time

	mu     sync.Mutex
	leases map[string]scmLease
}

// scmLease records one minted working credential. token is the durable installation token; it is
// held here as bytes (so it can be zeroed on eviction) and is NEVER part of the returned
// CredentialRef (the caller gets only the opaque ref and the expiry).
type scmLease struct {
	subject interfaces.Subject
	session interfaces.SessionID
	repo    interfaces.RepoRef
	branch  string
	token   []byte
	expiry  time.Time
}

// Compile-time assertion that Provider satisfies the seam.
var _ interfaces.SCMProvider = (*Provider)(nil)

// NewWithPorts assembles a Provider from explicit ports. It is the seam tests and the conformance
// harness use to wire the in-memory fakes (and that New uses to wire the real adapter). ttl
// defaults to DefaultTTL; extraProtected names protected branches beyond the always-protected
// main/master; permissions default to DefaultPermissions.
func NewWithPorts(auth AppAuth, pr PullRequestOpener, git GitTransport, ttl time.Duration, extraProtected ...string) *Provider {
	prot := make(map[string]bool, len(defaultProtected)+len(extraProtected))
	for b := range defaultProtected {
		prot[b] = true
	}
	for _, b := range extraProtected {
		if b != "" {
			prot[b] = true
		}
	}
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	return &Provider{
		auth:         auth,
		pr:           pr,
		git:          git,
		protected:    prot,
		perms:        DefaultPermissions,
		expectedHost: DefaultExpectedHost,
		ttl:          ttl,
		now:          time.Now,
		leases:       make(map[string]scmLease),
	}
}

// validateWorkingCredentialRequest fails closed on any malformed mint request BEFORE
// any remote work: it requires lineage (subject + session), a working branch, a
// fully-specified repo on the host this provider serves, a future session deadline,
// and a non-protected branch. `now` is the caller's single clock read so the deadline
// check matches the one the mint path later re-validates against.
func (p *Provider) validateWorkingCredentialRequest(ctx context.Context, req interfaces.WorkingCredentialRequest, now time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// The credential MUST be bound to the per-session identity for lineage; refuse to mint an
	// unattributable one (DESIGN.md §2.3).
	if req.Subject == "" || req.SessionID == "" {
		return errors.New("scmgithub: MintWorkingCredential requires a subject and session for lineage")
	}
	if req.Branch == "" {
		return errors.New("scmgithub: MintWorkingCredential requires a working branch")
	}
	// The credential MUST be repo-scoped; refuse a zero RepoRef so a missing-repo wiring bug
	// cannot produce an unscoped token request.
	if req.Repo.Host == "" || req.Repo.Owner == "" || req.Repo.Name == "" {
		return errors.New("scmgithub: MintWorkingCredential requires a fully-specified repo")
	}
	// Refuse a repo on a different SCM host than this provider serves: the adapter scopes the token
	// by owner/name against ITS configured endpoint, so a homonymous repo on another host
	// (github.com vs a GHES instance) would otherwise be minted instead of failing closed.
	if req.Repo.Host != p.expectedHost {
		return fmt.Errorf("scmgithub: repo host %q is not the host this provider serves (%q)", req.Repo.Host, p.expectedHost)
	}
	// Like every minted credential, the SCM token must die with the session: refuse an
	// absent/past deadline rather than mint one that could outlive the session (DESIGN.md §2.1).
	if req.SessionDeadline.IsZero() || !req.SessionDeadline.After(now) {
		return errors.New("scmgithub: MintWorkingCredential requires a SessionDeadline in the future")
	}
	// Refuse a protected/default branch before any remote work. Push MUST be restricted to a
	// working branch (in-band defence-in-depth; the authoritative restriction is the repo ruleset
	// + egress boundary). protected is immutable post-construction, so no lock is needed.
	if p.protected[req.Branch] {
		return errors.New("scmgithub: refusing to scope a working credential to a protected branch")
	}
	return nil
}

// MintWorkingCredential mints a short-lived, repo-scoped, least-privilege installation token,
// holds it behind an opaque ref, and returns only that ref plus its expiry — never the durable
// token. It refuses to scope a credential to a protected/default branch, and caps the expiry to
// no later than the session deadline so the SCM token dies with the session like every other
// minted credential.
func (p *Provider) MintWorkingCredential(ctx context.Context, req interfaces.WorkingCredentialRequest) (interfaces.CredentialRef, error) {
	now := p.now()
	if err := p.validateWorkingCredentialRequest(ctx, req, now); err != nil {
		return interfaces.CredentialRef{}, err
	}

	// Mint the real, repo-scoped, least-privilege installation token. The working credential needs
	// only contents:write (to push the branch) — NOT pull_requests; that is intersected with the
	// granted ceiling so a narrowed Config.Permissions tightens it. Fail closed: a mint error yields
	// NO credential, so no partial/over-broad token can leak to the caller.
	token, ghExpiry, err := p.auth.MintInstallationToken(ctx, InstallationTokenRequest{
		Repo:        req.Repo,
		Permissions: intersectPermissions(workingCredentialPermissions, p.perms),
	})
	if err != nil {
		return interfaces.CredentialRef{}, fmt.Errorf("scmgithub: minting installation token: %w", err)
	}
	if token == "" {
		return interfaces.CredentialRef{}, errors.New("scmgithub: App auth returned an empty installation token")
	}

	// Re-read the clock AFTER the (remote) mint: if the session deadline passed while the mint was
	// in flight, fail closed rather than record a token whose lease already outlived the session.
	now = p.now()
	if !req.SessionDeadline.After(now) {
		return interfaces.CredentialRef{}, errors.New("scmgithub: session deadline passed during token mint; refusing to record an expired credential")
	}
	// Cap expiry to the earliest of now+ttl, the GitHub token expiry, and the absolute session
	// deadline.
	expiry := now.Add(p.ttl)
	if !ghExpiry.IsZero() && ghExpiry.Before(expiry) {
		expiry = ghExpiry
	}
	if req.SessionDeadline.Before(expiry) {
		expiry = req.SessionDeadline
	}
	// A credential that is already expired is useless and must not be presented as valid; fail
	// closed rather than hand back a dead ref (e.g. a GitHub token expiry already in the past).
	if !expiry.After(now) {
		return interfaces.CredentialRef{}, errors.New("scmgithub: minted token expires at or before now; refusing to issue a dead credential")
	}

	ref := "scm-" + randHex(12) // opaque; the durable token is held below, NEVER returned.
	p.mu.Lock()
	// Bound the lease book: evict (and zero) any leases that have expired before recording the new
	// one, so stale installation tokens do not accumulate in memory.
	p.sweepExpiredLocked(now)
	p.leases[ref] = scmLease{
		subject: req.Subject,
		session: req.SessionID,
		repo:    req.Repo,
		branch:  req.Branch,
		token:   []byte(token),
		expiry:  expiry,
	}
	p.mu.Unlock()
	return interfaces.CredentialRef{Ref: ref, Expiry: expiry}, nil
}

// RevokeRef eagerly shreds the IN-PROCESS held token for a credential ref — zeroing the token
// bytes and removing the lease — and reports whether a lease was found. It is NOT part of the
// SCMProvider interface; it is the hook the session-lifecycle owner SHOULD call at session end to
// honor "revoked when the session ends" (sdk/interfaces/scm.go) rather than waiting for the lazy
// expiry sweep.
//
// NOT YET WIRED: the broker's session-release path does not call this today, so until it does, the
// in-process copy is reaped by the expiry sweep (bounded — the lease expiry is capped to the
// session deadline). And note the SCOPE: this clears only Console7's in-memory copy. Revoking the
// GitHub-side installation token itself before its ~1h expiry (Apps.RevokeInstallationToken) is
// part of the deferred data-plane teardown, alongside the sandbox redemption path (doc.go).
func (p *Provider) RevokeRef(ref string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	l, ok := p.leases[ref]
	if !ok {
		return false
	}
	zero(l.token)
	delete(p.leases, ref)
	return true
}

// sweepExpiredLocked evicts leases whose credential has expired, zeroing the held token bytes.
// The caller MUST hold p.mu.
func (p *Provider) sweepExpiredLocked(now time.Time) {
	for ref, l := range p.leases {
		if !l.expiry.After(now) {
			zero(l.token)
			delete(p.leases, ref)
		}
	}
}

// zero overwrites b in place so dropped token material does not linger in memory.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// OpenPullRequest records a proposed change as a pull request — the only sanctioned exit for a
// session's change. It refuses anything that would amount to a direct mutation (head == base) or
// a push from a protected branch, and it never merges or approves (the adapter opens a PR only).
func (p *Provider) OpenPullRequest(ctx context.Context, pr interfaces.PullRequest) (interfaces.PRRef, error) {
	if err := ctx.Err(); err != nil {
		return interfaces.PRRef{}, err
	}
	if pr.Repo.Host == "" || pr.Repo.Owner == "" || pr.Repo.Name == "" {
		// Mirror MintWorkingCredential: refuse a malformed repo before any remote call.
		return interfaces.PRRef{}, errors.New("scmgithub: OpenPullRequest requires a fully-specified repo")
	}
	if pr.Repo.Host != p.expectedHost {
		return interfaces.PRRef{}, fmt.Errorf("scmgithub: repo host %q is not the host this provider serves (%q)", pr.Repo.Host, p.expectedHost)
	}
	if pr.Head == "" || pr.Base == "" {
		return interfaces.PRRef{}, errors.New("scmgithub: OpenPullRequest requires head and base branches")
	}
	if pr.Head == pr.Base {
		// Proposing a branch onto itself is a direct mutation, not a proposal.
		return interfaces.PRRef{}, errors.New("scmgithub: refusing a pull request whose head equals its base")
	}
	// protected is immutable post-construction, so no lock is needed.
	if p.protected[pr.Head] {
		// The session must have worked on a working branch, not a protected one. (A protected
		// BASE is correct and expected — that is exactly what proposing a PR into main means.)
		return interfaces.PRRef{}, errors.New("scmgithub: refusing a pull request opened from a protected branch")
	}

	url, number, err := p.pr.CreatePullRequest(ctx, pr)
	if err != nil {
		return interfaces.PRRef{}, fmt.Errorf("scmgithub: opening pull request: %w", err)
	}
	if number == 0 && url == "" {
		return interfaces.PRRef{}, errors.New("scmgithub: pull-request opener returned an empty ref")
	}
	return interfaces.PRRef{URL: url, Number: number}, nil
}

// FetchRepoBundle clones the base branch with a short-lived contents:READ installation token and
// returns it as a git bundle, for the control plane to seed into the sandbox (cloud.go
// EngineTask.RepoBundle). The token is minted least-privilege and handed to the git transport; it is
// never returned to the caller. The sandbox never fetches from the SCM itself.
func (p *Provider) FetchRepoBundle(ctx context.Context, repo interfaces.RepoRef, baseBranch string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if repo.Host == "" || repo.Owner == "" || repo.Name == "" {
		return nil, errors.New("scmgithub: FetchRepoBundle requires a fully-specified repo")
	}
	if repo.Host != p.expectedHost {
		return nil, fmt.Errorf("scmgithub: repo host %q is not the host this provider serves (%q)", repo.Host, p.expectedHost)
	}
	if strings.TrimSpace(baseBranch) == "" {
		return nil, errors.New("scmgithub: FetchRepoBundle requires a base branch")
	}
	if !isSafeRefName(baseBranch) {
		return nil, fmt.Errorf("scmgithub: FetchRepoBundle base branch %q is not a safe ref name", baseBranch)
	}
	if p.git == nil {
		return nil, errors.New("scmgithub: no git transport configured (FetchRepoBundle unavailable)")
	}
	token, _, err := p.auth.MintInstallationToken(ctx, InstallationTokenRequest{
		Repo:        repo,
		Permissions: intersectPermissions(readContentsPermissions, p.perms),
	})
	if err != nil {
		return nil, fmt.Errorf("scmgithub: minting read token for base fetch: %w", err)
	}
	if token == "" {
		return nil, errors.New("scmgithub: App auth returned an empty installation token")
	}
	return p.git.CloneBundle(ctx, p.remoteURL(repo), baseBranch, token)
}

// PushBranch pushes the session's working branch (carried as a git bundle) to the remote with a
// short-lived contents:WRITE token, capped to the session deadline and refused for a protected
// branch — the control-plane half of the push→PR bridge. The push credential stays here; it is
// never returned nor delivered to the sandbox (tenet 6).
func (p *Provider) PushBranch(ctx context.Context, req interfaces.PushBranchRequest) error {
	if err := p.validatePushBranchRequest(ctx, req); err != nil {
		return err
	}
	token, _, err := p.auth.MintInstallationToken(ctx, InstallationTokenRequest{
		Repo:        req.Repo,
		Permissions: intersectPermissions(workingCredentialPermissions, p.perms),
	})
	if err != nil {
		return fmt.Errorf("scmgithub: minting push token: %w", err)
	}
	if token == "" {
		return errors.New("scmgithub: App auth returned an empty installation token")
	}
	return p.git.PushBundle(ctx, p.remoteURL(req.Repo), req.Branch, req.Bundle, token)
}

// validatePushBranchRequest fails closed on any malformed push request before any remote work:
// lineage (subject + session), a fully-specified repo on this host, a non-protected working branch,
// a non-empty bundle, a future session deadline, and a configured git transport.
func (p *Provider) validatePushBranchRequest(ctx context.Context, req interfaces.PushBranchRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if req.Subject == "" || req.SessionID == "" {
		return errors.New("scmgithub: PushBranch requires a subject and session for lineage")
	}
	if req.Repo.Host == "" || req.Repo.Owner == "" || req.Repo.Name == "" {
		return errors.New("scmgithub: PushBranch requires a fully-specified repo")
	}
	if req.Repo.Host != p.expectedHost {
		return fmt.Errorf("scmgithub: repo host %q is not the host this provider serves (%q)", req.Repo.Host, p.expectedHost)
	}
	if req.Branch == "" {
		return errors.New("scmgithub: PushBranch requires a working branch")
	}
	if !isSafeRefName(req.Branch) {
		return fmt.Errorf("scmgithub: PushBranch working branch %q is not a safe ref name", req.Branch)
	}
	// Refuse a protected/default branch — the change is proposed via a PR, never pushed onto a
	// protected ref (tenet 6). protected is immutable post-construction.
	if p.protected[req.Branch] {
		return errors.New("scmgithub: refusing to push to a protected branch")
	}
	if len(req.Bundle) == 0 {
		return errors.New("scmgithub: PushBranch requires a non-empty working-branch bundle")
	}
	if req.SessionDeadline.IsZero() || !req.SessionDeadline.After(p.now()) {
		return errors.New("scmgithub: PushBranch requires a SessionDeadline in the future")
	}
	if p.git == nil {
		return errors.New("scmgithub: no git transport configured (PushBranch unavailable)")
	}
	return nil
}

// remoteURL is the HTTPS git URL for repo on the host this provider serves.
func (p *Provider) remoteURL(repo interfaces.RepoRef) string {
	return fmt.Sprintf("https://%s/%s/%s.git", repo.Host, repo.Owner, repo.Name)
}

// isSafeRefName rejects a branch name that could be mistaken for a git OPTION (a leading '-' —
// argument injection into the shelled `git`) or that is not a well-formed ref. This is defence in
// depth AT THE SEAM, independent of the orchestrator's own validation, so the git transport never
// receives a hostile branch even if a caller forgot to validate (a close cousin of git
// check-ref-format). The branch is otherwise orchestrator-set, never agent-set.
func isSafeRefName(s string) bool {
	if s == "" || strings.HasPrefix(s, "-") || strings.HasPrefix(s, "/") || strings.HasSuffix(s, "/") {
		return false
	}
	if strings.Contains(s, "..") || strings.HasSuffix(s, ".lock") {
		return false
	}
	for _, r := range s {
		if r <= ' ' || r == 0x7f { // control characters and space
			return false
		}
		switch r {
		case '~', '^', ':', '?', '*', '[', '\\':
			return false
		}
	}
	return true
}

// randHex returns 2n hex chars of crypto-random data for an opaque, unguessable credential ref.
func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("scmgithub: crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}
