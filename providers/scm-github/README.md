# `providers/scm-github/` — reference `SCMProvider`

**Trust tier:** reference provider implementation (runs in the key broker — it handles
short-lived token material).

Reference implementation of [`SCMProvider`](../../sdk/interfaces/scm.go) on a **GitHub App**
(`ARCHITECTURE.md` §5; `DESIGN.md` §2.1/§2.3/§7). It realises the same behaviour as
[`sdk/devkit.MemSCM`](../../sdk/devkit/scm_mem.go) — short-lived, repo-scoped, branch-restricted
working credentials and pull-request-as-the-only-exit — backed by real GitHub App installation
tokens via [`go-github`](https://github.com/google/go-github) +
[`ghinstallation`](https://github.com/bradleyfalzon/ghinstallation).

## What it upholds (and what it cannot)

The boundary is what we actually control (GOAL.md tenet 2 — boundary controls are authoritative,
in-band guards are defence-in-depth). GitHub-side, this provider **does** enforce:

- **Short-lived.** The installation token (GitHub caps it ~1h) is capped further to the earliest
  of a configured TTL, the GitHub expiry, and the **session deadline** — it dies with the session.
- **Host + repo scoped.** A `RepoRef` on a host the provider doesn't serve is refused. The mint
  always resolves the installation per-repo by owner+name (a fixed `Config.InstallationID` is an
  assertion — a mismatch fails closed), then *requests* GitHub's `Repositories` narrowing, which
  GitHub enforces server-side.
- **Per-operation least-privilege.** `DefaultPermissions` is the *granted ceiling* (what the App is
  installed with). Each operation requests only the subset it needs, **intersected** with that
  ceiling: a working credential gets `contents: write` **only** (it can't open/merge PRs);
  `OpenPullRequest` mints a separate `pull_requests: write`-only token. The adapter rejects any key
  outside its allowlist **and** any level beyond `read`/`write`, so a `Config.Permissions` override
  only ever tightens — never widens.
- **No durable token leaves the provider.** `MintWorkingCredential` returns only an opaque,
  expiring `CredentialRef`; the token is held behind that ref and never returned to a caller.
- **PR-only exit.** `OpenPullRequest` opens a PR and never merges, approves, or actuates; it
  refuses a protected-branch head and a `head == base` direct mutation.

What it **cannot** authoritatively control is the wire: a GitHub installation token can't be
branch-scoped at the token level. **"Push only to the working branch" is enforced authoritatively
by the repo's branch-protection ruleset (adopter-side) and ultimately by the default-deny egress
boundary** (the cloud-gcp + sandbox PR) — this provider's protected-branch refusal and
least-privilege scoping are defence-in-depth on top. See `doc.go`.

## Architecture — GitHub SDK confined behind ports

The provider logic (`provider.go`) depends only on the `AppAuth` and `PullRequestOpener` ports
(`ports.go`). The `go-github` / `ghinstallation` clients are confined to the adapter
(`ghapp_auth.go`, `github_pr.go`) wired by `New` (`new.go`). Tests and the conformance harness wire
the in-memory fakes (`fakes.go`) instead, so the contract logic runs under `go test ./...` **with no
GitHub App and no network**. The exported ports + fakes also let out-of-tree providers
conformance-test themselves.

```
New(cfg)                 -> real ghinstallation + go-github adapter   (production)
NewWithPorts(auth, pr, …) -> any ports, incl. the in-memory fakes      (tests/conformance)
```

## GitHub App setup (adopter, out-of-band)

The GitHub App is registered by the adopter (App creation is not cleanly Terraform-able), so this
provider ships no `deploy/` change. Configure the App as:

- **Permissions:** Repository → **Contents: Read & write**, **Pull requests: Read & write**.
  Nothing else.
- **Installation:** install it on **only** the repositories sessions may target (least privilege).
- **Branch protection:** on each repo, a ruleset that **requires a pull request** to merge into the
  default/protected branches and **blocks direct pushes** to them — this is the authoritative
  branch restriction the token cannot provide.
- **Private key:** store the App private key in the adopter secret store (the
  [`SecretsProvider`](../secrets-gcp) seam) and pass it as `Config.PrivateKeyPEM`. **Never** commit
  it.

## Wiring

```go
p, err := scmgithub.New(scmgithub.Config{
    AppID:         123456,
    PrivateKeyPEM: pem, // from the adopter secret store, never a committed file
    // InstallationID optional: omit to resolve per-repo so one App serves several repos.
})
```

## Real vs deferred

- **Real:** GitHub App JWT auth, installation resolution, repository-scoped + permission-narrowed
  installation-token mint, expiry capping to the session, protected-branch refusal, PR-only exit.
- **Deferred:** delivery (redemption) of the held token into the owning sandbox git client — the
  data-plane path that lands with the sandbox PR. The lease book is the seam it redeems against; no
  method exports the token today.
- **Residual (boundary, not this package):** authoritative branch-push restriction is the repo
  ruleset + egress wall. See `doc.go`.

## Tests

```bash
go test ./providers/scm-github/...   # white-box invariants on fakes (no credentials)
go test ./conformance/...            # TestSCMGitHubConformance — the two contracts on fakes
# opt-in, live (never in CI):
C7_GH_APP_ID=… C7_GH_PRIVATE_KEY_FILE=… C7_GH_REPO=owner/name \
  go test -tags github_integration ./providers/scm-github/...
```
