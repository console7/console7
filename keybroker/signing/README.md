# `keybroker/signing/` — SSO → NHI binding + commit/artefact signing

**Trust tier:** Tier-1, highest isolation (key-handling).

Binds the authenticated SSO subject to a **per-session non-human identity** and
**cryptographically signs commits and produced artefacts** by the session identity
(Sigstore-keyless or an org CA) (`DESIGN.md` §2.3). This is the cryptographic root of
the lineage chain the orchestrator stamps. A **distinct signing identity** from the
control-plane and sandbox artifacts (`ARCHITECTURE.md` §6.4).

> P0: placeholder — no keys, no implementation.
