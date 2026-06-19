# `providers/scm-github/` — reference `SCMProvider`

**Trust tier:** reference provider implementation.

Reference implementation of [`SCMProvider`](../../sdk/interfaces/scm.go) on a **GitHub
App** (`ARCHITECTURE.md` §5): short-lived, per-install, repo-scoped installation
tokens with push restricted to the working branch; change emitted as a pull request.
Must uphold the SECURITY contracts — no durable token to the sandbox git client, no
push to a protected branch, no self-approve/actuate.

> P0: placeholder — no credentials, no implementation.
