# Console7 — Threat Model & Abuse-Case Register

> **Status: in progress.** The headings below are the **load-bearing abuse classes** the
> design must hold against; the bodies are filled in as the corresponding surface is
> built, one section per phase (`docs/ROADMAP.md`). The credential/identity surface
> (**§1 and §4**) is **completed** as the Phase-0 exit criterion ("a written threat model
> for this surface"); §2, §3, §5, and §6 remain placeholders for their phases.

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

**Assets.** The per-user subscription OAuth tokens at rest; the KMS root / envelope keys
that protect them; the key broker's **distinct signing identity** (the root that signs
commits and artefacts); the SSO→per-session-NHI bindings; short-lived credential
references in flight; and the integrity of the lineage/evidence chain.

**Actors / entry points.** A compromised control-plane process; a platform operator with
control-plane access (insider); a caller reaching the key-broker API; lateral movement
from any other Tier-1 component. (Compromise via Console7's *own* build/dependencies is
abuse class #6 — supply chain — and is treated there, not here.)

**Attack paths.**

- *Operator or control-plane reads a stored subscription token.* Defeated by the
  separation of duties between artifacts: the **control plane holds no keys at rest**
  (`DESIGN.md` §8) and the `SecretsProvider` seam exposes **no plaintext read path** —
  `StoreSubscriptionToken` seals the token *inside* the broker (it does not accept
  caller-sealed ciphertext) and `InjectSubscriptionToken` returns the plaintext to no
  caller, only to the owning sandbox (`DESIGN.md` §2.2). There is structurally nothing for
  the control plane to read.
- *Control-plane compromise reaches the signing key.* Defeated by peeling the credential
  broker and signing service out into a **separately-hardened artifact with a distinct
  signing identity** (`ARCHITECTURE.md` §6.2, §6.4): a control-plane compromise does not
  hold the keys, so it cannot forge the lineage root.
- *Attacker mints a long-lived or over-scoped credential.* Defeated by §2.1 + the
  `MintEphemeral` contract: every minted credential carries an expiry capped to
  `min(now+TTL, SessionDeadline)` and a scope no wider than requested, and a zero/past
  deadline is refused rather than minted open-ended.
- *Attacker pools or cross-injects a token.* Defeated by **per-user keying** (a fresh
  per-subject DEK; no shared/multi-user key exists) and the **owner/session binding** on
  injection (a token is delivered only into a sandbox the registry confirms belongs to the
  owning subject's session).

**Controls of record.** The control-plane-holds-no-keys / broker-holds-keys separation
with a distinct signing identity (`DESIGN.md` §8; `ARCHITECTURE.md` §6.4); per-user
envelope encryption under the adopter's CMK and **no standing operator read path**
(`DESIGN.md` §2.1–§2.2); ephemeral, session-capped minting (`DESIGN.md` §2.1).

**Defence-in-depth.** Least-privilege scopes on every minted credential; ephemerality so a
leaked reference self-expires; the lineage/evidence chain so a key-handling anomaly is
attributable.

**Residual risk.** Phase 0 demonstrates these invariants against an **in-memory** broker:
the `SecretsProvider` "KMS" is an in-process key and the broker is not yet a separately-
deployed, network-isolated, separately-signed image. So the *cryptographic boundary* and
the *artifact-isolation* controls are **Phase-1+** — the in-memory bench proves the
behavioural shape (seal-inside, no-plaintext-return, per-user keying, expiry/scope caps,
owner-bound injection), not a real HSM/KMS trust boundary. The posture also relies on
adopter-owned controls (the CMK, image signing/provenance) listed under *External control
dependencies*.

**Evidence / conformance.** `conformance/`:
`SecretsProvider.{MintEphemeral, StoreSubscriptionToken, InjectSubscriptionToken,
RevokeSubject}` assert the interface-observable invariants (expiry caps; attended-only,
owner-bound injection refusals; no plaintext read path by construction). The at-rest
crypto invariants the interface cannot probe — sealed ciphertext never contains the
plaintext, distinct per-user keys, crypto-shred on revoke — are asserted white-box in
`sdk/devkit/secrets_mem_test.go`, and the lineage-signing root in
`keybroker/signing/signing_test.go`.

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

**Assets.** The user's own subscription OAuth token — already injected into their own
sandbox to back their interactive CLI, so treated as **agent-readable, exposed not
secret** (see *In-sandbox readable material* above); and the attended/single-beneficiary
invariant itself ("one human, one credential, one beneficiary", `GOAL.md` tenet 2).

**Actors / entry points.** An orchestrated, scheduled, webhook-triggered, or headless
caller trying to ride a subscription token; an attended **fan-out** (one human, many
beneficiaries) trying to reuse one seat across beneficiaries; a prompt-injected agent
*inside the user's own attended session* reading its own token; a caller presenting a
stale or mismatched sandbox handle.

**Attack paths.**

- *Unattended job requests subscription inference.* Refused at **two seams**:
  `InferenceBackend.Resolve` routes anything not `Attended && Beneficiaries == 1` to the
  org-API and refuses a subscription selection that fails the gate, and
  `SecretsProvider.InjectSubscriptionToken` refuses to inject unless `Attended == true`
  and `Beneficiaries == 1` (`DESIGN.md` §3, §2.2).
- *`ModeUnspecified` silently defaulting to subscription.* Refused — `Resolve` rejects the
  zero/unspecified mode (fail closed); a selection never defaults to a credential class.
- *Attended fan-out* (`Attended && Beneficiaries > 1`). Refused at both seams — the
  `Beneficiaries` field is carried explicitly (not folded into `Attended`) precisely so a
  human-present fan-out is caught.
- *Cross-user injection* into a non-owner sandbox. Refused by the owner/session binding on
  injection.
- *Prompt-injected agent reads its own token and tries to exfiltrate it.* This is **not**
  defeated by concealment — the token is unavoidably readable in its own session. The
  controls are **blast-radius** (it is the user's *own* token, per-user-isolated, never
  pooled) plus the **default-deny egress wall** (abuse class #2, `DESIGN.md` §5.2) and
  **pre-egress DLP** (`DESIGN.md` §6) denying the exfiltration path. Removing a leg of the
  trifecta is the control.

**Discriminator note (do not over-tighten).** The seam keys on the *(Attended,
Beneficiaries)* facts, **not** the invocation mode: a forked/headless `claude -p` inside
an attended single-user session carries `Attended=true, Beneficiaries=1` — the *same*
selection as the interactive case — and therefore **stays on the subscription**. Treating
"headless" as the discriminator would wrongly reroute it; the explicit facts prevent that.

**Controls of record.** The policy-enforced attended/unattended seam, realised at the
`Resolve` and `InjectSubscriptionToken` seams (`DESIGN.md` §3); per-user isolation / no
pooling (`DESIGN.md` §2.2); fail-closed on `ModeUnspecified`; "one human, one credential,
one beneficiary" (`GOAL.md` tenet 2). The seam trigger is a **configurable enterprise
policy** (flip policy, not architecture), so it can be tightened if upstream terms change.

**Defence-in-depth.** Minimise identifying metadata readable in-sandbox (the cross-cutting
note); the lineage/evidence chain so misuse is attributable to the human at the root.

**Residual risk.** The token *is* readable by its own attended session's agent — that is
acknowledged, not eliminated. The two controls that handle the **exfiltration path** of an
already-injected, agent-readable token — the default-deny egress wall and pre-egress DLP —
are **not present in Phase 0** (abuse classes #2 / §6, later phases). Phase 0 demonstrates
the *routing and injection refusals*; it asserts the exfil-path controls only as design
intent. Note also that **revocation reaches the at-rest copy only**: `RevokeSubject`
crypto-shreds the stored token, but a token already injected into a live session is killed
by **sandbox teardown** (the CloudProvider's job, Phase 1), not by revocation — consistent
with the token being agent-readable in its own session.

**Evidence / conformance.** `conformance/`:
`InferenceBackend.Resolve` and `SecretsProvider.InjectSubscriptionToken` assert refusal of
the unattended, multi-beneficiary, and unspecified-mode cases. The full seam matrix —
including that the forked `claude -p` selection stays on subscription, and that an
attended fan-out is refused — is in `sdk/devkit/inference_policy_test.go` and the
end-to-end walk in `keybroker/broker/broker_test.go` (`TestSpike_LoginToSignedAction`).

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
(MDM/EDR/egress), the network perimeter (e.g. cloud firewall / NAT; VPC Service
Controls guards the cloud's API surface only), the policy
system-of-record (adopter GRC), and SCM branch protection. **To be expanded with the
trust assumptions each abuse class above leans on.**
