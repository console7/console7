package interfaces

import (
	"context"
	"time"
)

// PullRequest is a proposed change emitted by a session. Agents propose; the
// pipeline actuates under a human (GOAL.md tenet 6).
type PullRequest struct {
	Repo  RepoRef
	Head  string // the working branch the session pushed to.
	Base  string // the target branch the change is proposed against.
	Title string
	Body  string
}

// PRRef is an opaque reference to an opened pull request.
type PRRef struct {
	URL    string
	Number int
}

// WorkingCredentialRequest asks for a short-lived SCM credential bound to a session.
// It carries the authenticated subject and the session so the issued credential
// anchors the SSO -> per-session non-human-identity lineage (DESIGN.md §2.3) and can
// be revoked when the session ends, rather than degrading into a bare repo/branch
// token.
type WorkingCredentialRequest struct {
	Subject   Subject
	SessionID SessionID
	Repo      RepoRef
	// Branch is the working branch; push MUST be restricted to it.
	Branch string
	// SessionDeadline is the authoritative ABSOLUTE time the session ends. As with
	// EphemeralRequest, the provider MUST cap the credential's expiry to no later than
	// this so an SCM token, like every other minted credential, dies with the session
	// and cannot outlive it (DESIGN.md §2.1; GOAL.md tenet 4). A duration-only TTL is
	// insufficient — a token minted late in a short session would otherwise outlive it.
	SessionDeadline time.Time
}

// PushBranchRequest is a CONTROL-PLANE-side push of the engine's working branch to the remote.
// The engine produced the commit INSIDE the sandbox and the CloudProvider returned it as a git
// bundle (EngineResult.CommitBundle); the control plane — never the sandbox — pushes it here with a
// short-lived, branch-scoped credential, so no push credential or SCM egress ever enters the
// untrusted sandbox (GOAL.md tenet 6; cloud.go EngineResult.CommitBundle).
type PushBranchRequest struct {
	Subject   Subject
	SessionID SessionID
	Repo      RepoRef
	// Branch is the working branch to push; it MUST NOT be a protected/default branch (the change
	// is proposed via a PR, never pushed onto a protected ref — tenet 6).
	Branch string
	// Bundle is the working-branch git bundle (the engine's commit plus its base ancestry) the
	// implementation fetches and pushes. It is CONTENT-BEARING (the actual diff leaving the
	// tenancy boundary on OpenPullRequest); the push path is the pre-egress DLP enforcement point.
	Bundle []byte
	// SessionDeadline is the absolute session end. The implementation MUST refuse to push for an
	// already-ended session (an ephemerality guard — no action past the deadline). Note the push
	// credential here is used ONCE and dropped within the call (it is never leased/retained, unlike
	// MintWorkingCredential), so its in-process lifetime is the push itself — stronger than a TTL cap
	// (DESIGN.md §2.1; least privilege / ephemeral, GOAL.md tenet 5).
	SessionDeadline time.Time
}

// SCMProvider abstracts repository clone, branch, pull-request, and short-lived
// token issuance (ARCHITECTURE.md §5; default ref: GitHub App). The SCM identity is
// minted per session and scoped to the working branch (DESIGN.md §2.1).
type SCMProvider interface {
	// MintWorkingCredential issues a short-lived, per-install, repo-scoped SCM
	// credential for a session and returns only an opaque, expiring reference.
	//
	// SECURITY: the credential MUST be short-lived, scoped to req.Repo, and bound to
	// req.Subject's per-session identity (req.SessionID) so lineage is preserved and
	// it dies with the session; push MUST be restricted to req.Branch — it MUST NEVER
	// be able to push to a protected/default branch (DESIGN.md §2.1, §2.3). The
	// implementation MUST return a CredentialRef, NEVER a durable token, and MUST
	// ensure the sandbox git client never sees long-lived credential material.
	MintWorkingCredential(ctx context.Context, req WorkingCredentialRequest) (CredentialRef, error)

	// OpenPullRequest opens a pull request proposing the session's change.
	//
	// SECURITY: this is the ONLY sanctioned path by which a session's change leaves
	// the sandbox. The implementation MUST NOT push directly to, merge into, or
	// otherwise mutate a protected/default branch, and MUST NOT self-approve or
	// actuate the PR — author, approve, and actuate are separated and no session
	// holds more than the first (DESIGN.md §7; GOAL.md tenet 6).
	OpenPullRequest(ctx context.Context, pr PullRequest) (PRRef, error)

	// FetchRepoBundle returns the base branch's content as a git bundle, for the control plane to
	// seed into the sandbox (cloud.go EngineTask.RepoBundle) so the engine works a real checkout.
	// This is a CONTROL-PLANE read — the sandbox never fetches from the SCM itself.
	//
	// SECURITY: the implementation MUST use a short-lived, least-privilege (contents:read) credential
	// and MUST NOT return any durable token to the caller — only the bundle bytes (the adopter's own
	// repo content, moving within the tenancy). It serves the host this provider is scoped to.
	FetchRepoBundle(ctx context.Context, repo RepoRef, baseBranch string) ([]byte, error)

	// PushBranch pushes the session's working branch (carried as a git bundle) to the remote, so
	// OpenPullRequest then has a head to propose. It is the CONTROL-PLANE half of the push→PR bridge.
	//
	// SECURITY: the implementation MUST mint a short-lived credential capped to req.SessionDeadline,
	// push ONLY req.Branch, REFUSE a protected/default branch, and never merge/approve/actuate. The
	// push credential stays in the control plane — it is never returned nor delivered to the sandbox
	// (GOAL.md tenet 6; PushBranchRequest).
	PushBranch(ctx context.Context, req PushBranchRequest) error
}
