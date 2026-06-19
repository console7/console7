# `keybroker/` — the separately-hardened key & signing artifact

**Trust tier:** Tier-1, **highest isolation** — this is the one component that holds
keys. **Artifact:** key-broker / signing image, signed · SBOM · provenance ·
**separately scoped**, with a **distinct signing identity** from both the
control-plane and sandbox images (`ARCHITECTURE.md` §6.4; `DESIGN.md` §8).

**Peeled out of the control plane early, by design** (`ARCHITECTURE.md` §6.2):
Console7 holds the keys to many sandboxes and mints identities, so
control-plane-as-target is the headline abuse case (`DESIGN.md` §10.1). Isolating the
key-handling component limits what a control-plane compromise actually reaches.
**Never fuse this with the control plane.**

- [`broker/`](broker/) — ephemeral identity minting (WIF/OIDC, GitHub App tokens) and
  the per-user subscription-token vault. Stores **no** long-lived cloud/SCM secrets;
  the one stored credential (subscription OAuth) is per-user KMS-encrypted, injected
  only into its owner's sandbox, never operator-readable, never pooled.
- [`signing/`](signing/) — binds the SSO subject to a per-session non-human identity
  and signs commits/artefacts (Sigstore-keyless / org CA).

> P0 scaffolding: directory tree and responsibilities only. **No credentials, no key
> material, no implementation** — and none ever committed to the repo.
