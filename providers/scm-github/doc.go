// Package scmgithub is the Console7 reference SCMProvider on a GitHub App (ARCHITECTURE.md §5;
// DESIGN.md §2.1/§2.3/§7). It is an in-tree reference implementation of the
// sdk/interfaces.SCMProvider seam; community providers live out-of-tree against the published
// SDK. It realises the same behaviour as sdk/devkit.MemSCM — short-lived, repo-scoped,
// branch-restricted working credentials and pull-request-as-the-only-exit — backed by real GitHub
// App installation tokens instead of an in-memory lease book.
//
// # What this provider actually controls (and what it does not)
//
// The honest scope matters here (GOAL.md tenet 2: boundary controls are authoritative; in-band
// guards are defence-in-depth). What this provider CAN enforce is GitHub-side:
//
//   - a SHORT-LIVED installation token (GitHub caps it at ~1h; the provider caps it further to the
//     earliest of a configured TTL, the GitHub expiry, and the session deadline, so it dies with
//     the session — DESIGN.md §2.1; GOAL.md tenet 4);
//   - REPO-SCOPED minting (the mint REQUESTS scoping to the single requested repository — GitHub
//     enforces the Repositories narrowing server-side; the provider does not re-verify the result);
//   - LEAST-PRIVILEGE permissions (contents:write + pull_requests:write only — DefaultPermissions;
//     OpenPullRequest narrows further to pull_requests:write. The adapter rejects any permission
//     key outside its allowlist AND any level beyond read/write, so a Config.Permissions override
//     can narrow or re-shape but never widen past least privilege);
//   - PR-ONLY exit (OpenPullRequest opens a pull request and never merges, approves, or actuates —
//     author/approve/actuate stay separated, GOAL.md tenet 6);
//   - refusal to scope a credential to, or open a PR from, a protected/default branch.
//
// What this provider CANNOT authoritatively control is the wire. A GitHub installation token
// cannot be branch-scoped at the token level: once the sandbox holds a contents:write token it can
// technically address any unprotected ref. "Push only to the working branch" is therefore enforced
// authoritatively by the repo's branch-protection RULESET (adopter-configured) and ultimately by
// the default-deny EGRESS boundary (the cloud-gcp + sandbox PR), with this provider's protected-
// branch refusal and least-privilege scoping as defence-in-depth on top. The README's setup
// checklist states the ruleset the adopter must apply; we do not overclaim that the token is the
// control.
//
// # The GitHub SDK is confined behind ports
//
// The provider logic (provider.go) depends only on the AppAuth and PullRequestOpener ports
// (ports.go); the go-github and ghinstallation clients are confined to the adapter (ghapp_auth.go,
// github_pr.go) wired by New (new.go). Tests and the conformance harness wire the in-memory fakes
// (fakes.go) instead, so the contract logic runs under `go test ./...` with no GitHub App and no
// network — the same logic-vs-fakes split secrets-gcp and MemSCM prove. The exported ports + fakes
// also let out-of-tree providers conformance-test themselves.
//
// # No durable token leaves the provider
//
// MintWorkingCredential returns only an opaque, expiring CredentialRef. The durable installation
// token is held behind that ref in an ephemeral, mutex-guarded lease book and is NEVER returned to
// a caller — the sandbox git client must never see long-lived credential material (DESIGN.md
// §2.3). The provider is a key-handling component (it runs in the key broker, not the control
// plane). The lease book is BOUNDED: every mint first evicts expired leases (zeroing their token
// bytes), and the (non-interface) RevokeRef shreds a lease eagerly at session end, so a stale
// token does not linger in process memory past its usefulness (GOAL.md tenet 4).
//
// # Real vs deferred in this PR
//
//   - REAL: GitHub App JWT auth, repository-scoped + permission-narrowed installation-token mint,
//     expiry capping to the session, protected-branch refusal, PR-only exit via go-github.
//   - DEFERRED: delivery (redemption) of the held token into the owning sandbox git client — the
//     data-plane path that does not exist until the sandbox PR. The lease book is the seam that
//     path redeems against; no method exports the token today.
//   - RESIDUAL (boundary, not this package): authoritative branch-push restriction is the repo
//     ruleset + egress wall; this provider's branch refusal and least-privilege token are
//     defence-in-depth (GOAL.md tenet 2).
//   - RESIDUAL (interface shape): OpenPullRequest carries no Subject/SessionID, so the token it
//     mints to open the PR cannot be bound to the session — the human->NHI lineage stamped at
//     MintWorkingCredential does not extend to the PR-open call. The token is minimised
//     (pull_requests:write only) to limit the blast radius of that unavoidable gap.
package scmgithub
