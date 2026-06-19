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
> production data by default), §6 (pre-egress DLP), §4.3 (MCP allowlist). **To be
> filled in.**

## 3. Cross-tier escalation

*(`DESIGN.md` §10.3)* — launching from a permissive repo to reach a stricter one; a
permissive origin conferring a stricter target's access.

> Mitigation spine to expand: §4.2 (take-the-max + step-up); resolution from the
> target's tier × stratum, not the launcher's. **To be filled in.**

## 4. Subscription-credential misuse / unattended drift

*(`DESIGN.md` §10.4)* — a seat token used for service-like or multi-beneficiary work.

> Mitigation spine to expand: §3 (policy-enforced attended/unattended seam), §2.2
> (per-user isolation, no pooling); one human, one credential, one beneficiary
> (`GOAL.md` tenet 7). **To be filled in (Phase 0 surface).**

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
