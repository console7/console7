# `keybroker/broker/` — ephemeral identity minting + subscription vault

**Trust tier:** Tier-1, highest isolation (key-handling).

Mints short-lived cloud/SCM identities (workload-identity federation / OIDC, GitHub
App installation tokens) from the adopter's secrets manager at session start, scoped
to the session and expiring with it (`DESIGN.md` §2.1). Manages the **per-user
subscription-token vault**: the token lives under a per-user KMS key, is injected
**only** into that user's sandbox, is **unreadable by platform operators**, and is
**never pooled** (`DESIGN.md` §2.2; `GOAL.md` tenet 7). Drives the `SecretsProvider`
and `SCMProvider` seams. **Stores no long-lived cloud/SCM secrets.**

> P0: placeholder — no credentials, no implementation.
