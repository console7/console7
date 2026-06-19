# Console7 — Threat Model & Abuse-Case Register

> **Status: placeholder (P0 scaffolding).** This document is a skeleton. The headings
> below are the **load-bearing abuse classes** the design must hold against; the
> bodies are filled in as the corresponding surface is built, one section per phase
> (`docs/ROADMAP.md`). The credential/identity surface (§1, §4) is the first to be
> completed — it is the Phase-0 exit criterion ("a written threat model for this
> surface").

This is the published **threat model / abuse-case register** that `DESIGN.md` §9 and
`GOAL.md` tenet 10 require. It is the *living* companion to **`DESIGN.md` §10 (Threat
model spine)** — §10 states the load-bearing classes and their design mitigations;
this register expands each into assets, actors, attack paths, the controls of record
vs defence-in-depth, residual risk, and the evidence that proves the control holds.
**When the two disagree, `DESIGN.md` is normative and this document is corrected.**

Cross-cutting framing (from `DESIGN.md` and `GOAL.md`):

- **Three descending layers of assurance** — **boundary** (authoritative, out-of-band)
  > **in-sandbox enforcement** (non-overridable but in-band) > **guidance**
  (model-facing). When layers disagree, the higher-assurance layer wins; nothing
  in-sandbox or in guidance is ever the control of record (`DESIGN.md` reading note;
  `GOAL.md` tenet 3).
- **Scope follows the artefact, not the author** (`GOAL.md` tenet 4) — a session's
  reach derives from the target's tier × stratum, resolved from the policy
  system-of-record, never from an in-repo file.

Each section will be completed against this template: **Assets · Actors / entry
points · Attack paths · Controls of record · Defence-in-depth · Residual risk ·
Evidence / conformance**.

---

## Cross-cutting: in-sandbox readable material

Independent analysis of an adjacent platform (Anthropic Managed Agents — self-hosted
sandboxes; see *Prior art* below) is a useful red-team mirror. It confirms that, in a
gVisor-style sandbox, **environment variables, mounted files, and the agent's own
system prompt are readable by the agent process** — and therefore by a prompt-injected
agent. Console7 keeps cloud/SCM credentials *structurally* out of the sandbox
(ephemeral, broker-minted, injected via the credential path — never the agent's
address space; `DESIGN.md` §2.1, §8). But two things unavoidably live where the agent
can read them, and the threat model must treat them as **exposed, not secret**:

- **The subscription OAuth token (abuse class #4).** It MUST be injected into the
  user's own sandbox to back their interactive CLI (`DESIGN.md` §2.2), so a
  prompt-injected agent in that session can read it. The mitigations are therefore
  *blast-radius* mitigations, not concealment: it is the user's **own** token,
  per-user isolated, **never pooled** (`GOAL.md` tenet 2); the **default-deny egress
  wall** (class #2, `DESIGN.md` §5.2) denies the exfiltration path; **pre-egress DLP**
  (`DESIGN.md` §6) scans for it leaving. Removing a leg of the trifecta is the control,
  because the token cannot be hidden from its own session.
- **Session metadata (tier, egress allowlist, NHI / session IDs, org identifiers).**
  The adjacent platform leaked these via an in-sandbox-readable JWT. Console7 enforces
  egress **out-of-band at the perimeter** (`DESIGN.md` §5.2), so the allowlist is not a
  secret the sandbox needs — but the design SHOULD **minimise what identifying
  metadata is readable in-sandbox**: do not mount the policy profile, target tier, or
  org-scoped tokens where the agent can read and act on them. Tracked as a Phase-1
  sandbox-hardening requirement; see `sandbox/egress-proxy/` and `sandbox/base-image/`.

## Prior art & build-vs-adopt (Anthropic Managed Agents)

`ARCHITECTURE.md` §9 names Anthropic's **Managed Agents — self-hosted sandboxes** as
adjacent prior art. Independent analysis of that platform both **validates** Console7's
core choices and sharpens where Console7 **differs**:

- *Validates* — decoupled session-log / orchestration / sandbox with the sandbox
  treated as untrusted; **credentials injected outside the sandbox**, never in the
  agent's address space; **append-only** session audit; **multi-layer, unbypassable
  egress** (no in-sandbox DNS, network-gateway filtering, cloud-metadata/IMDS blocked).
  These are Console7 requirements too (classes #2/#6 below; `DESIGN.md` §5–6, §8).
- *Differs* — the adjacent platform **silently added maintainer-controlled hosts to
  the egress allowlist** and runs **TLS inspection on its own (maintainer-side) control
  plane**, and ships **maximally permissive defaults**. Console7's tenets forbid exactly
  these: **no maintainer-injected egress / no phone-home** (`GOAL.md` tenet 1); the
  egress allowlist is **wholly adopter-composed and auditable**; inference-path
  visibility and DLP run in the **adopter's** tenancy, not the maintainer's; defaults
  are **conservative and policy-derived** (default-deny, autonomy ceiling, human-gate
  by tier). This is the in-tenant-orchestration case `ARCHITECTURE.md` §9 makes.

---

## 1. Control-plane-as-target

*(`DESIGN.md` §10.1)* — Console7 holds the keys to many sandboxes and mints
identities; a compromise of the control plane is the headline abuse case.

> Mitigation spine to expand: §2 (no long-lived secrets; per-user isolation; operator
> cannot read tokens), §8 (self-governance), the key-broker/signing split into a
> separately-hardened artifact (`ARCHITECTURE.md` §6.2, §6.4), strict blast-radius
> limits. **To be filled in (Phase 0 surface).**

## 2. Lethal trifecta / indirect prompt injection

*(`DESIGN.md` §10.2)* — untrusted repo or dependency content steering an agent to
exfiltrate over an *allowed* egress path (private-data access + egress capability +
exposure to untrusted content).

> Mitigation spine to expand: §5.2–5.3 (default-deny egress removes a leg; no
> production data by default), §6 (pre-egress DLP), §4.3 (MCP allowlist). The egress
> leg must be **unbypassable** (no in-sandbox DNS, network-gateway filtering of
> non-allowlisted destinations, IMDS/metadata blocked) — see the *In-sandbox readable
> material* note above and the `sandbox/egress-proxy/` + `providers/cloud-gcp/`
> requirements. **To be filled in.**

## 3. Cross-tier escalation

*(`DESIGN.md` §10.3)* — launching from a permissive repo to reach a stricter one; a
permissive origin conferring a stricter target's access.

> Mitigation spine to expand: §4.2 (take-the-max + step-up); resolution from the
> target's tier × stratum, not the launcher's. **To be filled in.**

## 4. Subscription-credential misuse / unattended drift

*(`DESIGN.md` §10.4)* — a seat token used for service-like or multi-beneficiary work.

> Mitigation spine to expand: §3 (policy-enforced attended/unattended seam), §2.2
> (per-user isolation, no pooling); one human, one credential, one beneficiary
> (`GOAL.md` tenet 2). Note the token is **agent-readable in its own sandbox** (see
> the *In-sandbox readable material* note above): the controls are blast-radius
> (own-token, no-pooling) + egress-denial + DLP, not concealment. **To be filled in
> (Phase 0 surface).**

## 5. Sub-agent lineage break

*(`DESIGN.md` §10.5)* — attribution lost where the engine spawns sub-agents.

> Mitigation spine to expand: §2.3 (orchestrator-stamped lineage; managed permission
> rules and hooks apply to sub-agent sessions). **To be filled in.**

## 6. Platform supply-chain compromise

*(`DESIGN.md` §10.6)* — compromise of Console7's own build/release or dependencies.

> Mitigation spine to expand: §8 (pinned upstream, canaried upgrades, signed builds,
> SBOM, provenance, isolated build runners, distinct artifacts by trust tier). This
> repo's own SDLC standard (`docs/standards/console7-sdlc-standard.md`) is the
> first-line control. **To be filled in.**

---

## External control dependencies (assumptions)

Console7's posture relies on controls it does not itself own (`DESIGN.md` §11);
adopters MUST provide them and the threat model MUST state them: endpoint control
(MDM/EDR/egress), the network perimeter (e.g. VPC Service Controls), the policy
system-of-record (adopter GRC), and SCM branch protection. **To be expanded with the
trust assumptions each abuse class above leans on.**
