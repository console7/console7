# `control-plane/` — the Tier-1 modular monolith

**Trust tier:** Tier-1, hardened, pristine — **holds no keys at rest** and **never
executes untrusted code**. **Artifact:** control-plane image(s), signed · SBOM ·
provenance, a **distinct build identity** from the sandbox base image
(`ARCHITECTURE.md` §6.4; `DESIGN.md` §8).

Ship as a **modular monolith** initially (`ARCHITECTURE.md` §6.2): few moving parts
is a feature for something an enterprise self-hosts, patches, and assures. Resist
premature microservice decomposition. The one principled split — the credential
broker and signing service — is peeled out into [`../keybroker/`](../keybroker/),
**not** fused in here, because control-plane-as-target is the headline abuse case
(`DESIGN.md` §10.1).

Modules (`ARCHITECTURE.md` §2, §6.3):

- [`ui/`](ui/) — web-CLI front end + API gateway; authenticates against the adopter
  IdP, streams the live session. Thin; holds no secrets.
- [`orchestrator/`](orchestrator/) — session lifecycle; **stamps lineage**
  (human → NHI → action); cross-repo coordination; emits evidence.
- [`pdp/`](pdp/) — policy decision service: resolves the **target's** tier × stratum
  into a session profile; take-the-max + step-up across targets.
- [`inference-router/`](inference-router/) — subscription vs org-API; backend
  selection; enforces the attended/unattended seam.
- [`dlp/`](dlp/) — pre-egress secret/PII/classification scanner.
- [`evidence/`](evidence/) — WORM writer + SIEM stream.

> P0 scaffolding: directory tree and responsibilities only — **no implementation.**
