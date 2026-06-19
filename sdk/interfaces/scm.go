package interfaces

import "context"

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

// SCMProvider abstracts repository clone, branch, pull-request, and short-lived
// token issuance (ARCHITECTURE.md §5; default ref: GitHub App). The SCM identity is
// minted per session and scoped to the working branch (DESIGN.md §2.1).
type SCMProvider interface {
	// MintWorkingCredential issues a short-lived, per-install, repo-scoped SCM
	// credential for a session and returns only an opaque, expiring reference.
	//
	// SECURITY: the credential MUST be short-lived and scoped to the single repo,
	// and push MUST be restricted to the session's working branch — it MUST NEVER be
	// able to push to a protected/default branch (DESIGN.md §2.1). The implementation
	// MUST return a CredentialRef, NEVER a durable token, and MUST ensure the sandbox
	// git client never sees long-lived credential material.
	MintWorkingCredential(ctx context.Context, repo RepoRef, branch string) (CredentialRef, error)

	// OpenPullRequest opens a pull request proposing the session's change.
	//
	// SECURITY: this is the ONLY sanctioned path by which a session's change leaves
	// the sandbox. The implementation MUST NOT push directly to, merge into, or
	// otherwise mutate a protected/default branch, and MUST NOT self-approve or
	// actuate the PR — author, approve, and actuate are separated and no session
	// holds more than the first (DESIGN.md §7; GOAL.md tenet 6).
	OpenPullRequest(ctx context.Context, pr PullRequest) (PRRef, error)
}
