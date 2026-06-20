package scmgithub

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
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

// DefaultPermissions is the least-privilege GitHub App permission set a working credential is
// narrowed to: write access to repository contents (to push the working branch) and to pull
// requests (to open the proposal). Nothing else — no admin, no workflow, no secrets. This is the
// real least-privilege lever the GitHub side offers (the analogue of secrets-gcp's prefix-scoped
// IAM); the adapter rejects any permission key outside its allowlist and any level beyond
// read/write. A Config.Permissions override may narrow or re-shape within those bounds, never
// beyond them.
var DefaultPermissions = map[string]string{"contents": "write", "pull_requests": "write"}

// pullRequestPermissions is the still-narrower set used when OpenPullRequest mints its own token:
// opening a PR needs only pull_requests:write, NOT contents:write (the working-credential path
// already did the push). Keeping the PR-open token minimal limits what an actuation-adjacent token
// can do (GOAL.md tenets 4, 6).
var pullRequestPermissions = map[string]string{"pull_requests": "write"}

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
// auth, pr, protected, perms, ttl, and now are write-once at construction and read without the
// lock; only leases is mutated after construction and is guarded by mu.
type Provider struct {
	auth      AppAuth
	pr        PullRequestOpener
	protected map[string]bool
	perms     map[string]string
	ttl       time.Duration
	now       func() time.Time

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
func NewWithPorts(auth AppAuth, pr PullRequestOpener, ttl time.Duration, extraProtected ...string) *Provider {
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
		auth:      auth,
		pr:        pr,
		protected: prot,
		perms:     DefaultPermissions,
		ttl:       ttl,
		now:       time.Now,
		leases:    make(map[string]scmLease),
	}
}

// MintWorkingCredential mints a short-lived, repo-scoped, least-privilege installation token,
// holds it behind an opaque ref, and returns only that ref plus its expiry — never the durable
// token. It refuses to scope a credential to a protected/default branch, and caps the expiry to
// no later than the session deadline so the SCM token dies with the session like every other
// minted credential.
func (p *Provider) MintWorkingCredential(ctx context.Context, req interfaces.WorkingCredentialRequest) (interfaces.CredentialRef, error) {
	if err := ctx.Err(); err != nil {
		return interfaces.CredentialRef{}, err
	}
	// The credential MUST be bound to the per-session identity for lineage; refuse to mint an
	// unattributable one (DESIGN.md §2.3).
	if req.Subject == "" || req.SessionID == "" {
		return interfaces.CredentialRef{}, errors.New("scmgithub: MintWorkingCredential requires a subject and session for lineage")
	}
	if req.Branch == "" {
		return interfaces.CredentialRef{}, errors.New("scmgithub: MintWorkingCredential requires a working branch")
	}
	// The credential MUST be repo-scoped; refuse a zero RepoRef so a missing-repo wiring bug
	// cannot produce an unscoped token request.
	if req.Repo.Host == "" || req.Repo.Owner == "" || req.Repo.Name == "" {
		return interfaces.CredentialRef{}, errors.New("scmgithub: MintWorkingCredential requires a fully-specified repo")
	}
	now := p.now()
	// Like every minted credential, the SCM token must die with the session: refuse an
	// absent/past deadline rather than mint one that could outlive the session (DESIGN.md §2.1).
	if req.SessionDeadline.IsZero() || !req.SessionDeadline.After(now) {
		return interfaces.CredentialRef{}, errors.New("scmgithub: MintWorkingCredential requires a SessionDeadline in the future")
	}
	// Refuse a protected/default branch before any remote work. Push MUST be restricted to a
	// working branch (in-band defence-in-depth; the authoritative restriction is the repo ruleset
	// + egress boundary). protected is immutable post-construction, so no lock is needed.
	if p.protected[req.Branch] {
		return interfaces.CredentialRef{}, errors.New("scmgithub: refusing to scope a working credential to a protected branch")
	}

	// Mint the real, repo-scoped, least-privilege installation token. Fail closed: a mint error
	// yields NO credential, so no partial/over-broad token can leak to the caller.
	token, ghExpiry, err := p.auth.MintInstallationToken(ctx, InstallationTokenRequest{
		Repo:        req.Repo,
		Permissions: p.perms,
	})
	if err != nil {
		return interfaces.CredentialRef{}, fmt.Errorf("scmgithub: minting installation token: %w", err)
	}
	if token == "" {
		return interfaces.CredentialRef{}, errors.New("scmgithub: App auth returned an empty installation token")
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

// RevokeRef eagerly shreds the held token for a credential ref — zeroing the token bytes and
// removing the lease — and reports whether a lease was found. It is NOT part of the SCMProvider
// interface; the session-lifecycle owner calls it at session end to honor "revoked when the
// session ends" (sdk/interfaces/scm.go) rather than waiting for the lazy expiry sweep.
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

// randHex returns 2n hex chars of crypto-random data for an opaque, unguessable credential ref.
func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("scmgithub: crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}
