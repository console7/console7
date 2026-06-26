# Console7 — Roadmap

Sequencing rationale, stated once because it drives everything below:

1. **Prove the riskiest novel surface first.** The hosted-subscription credential
   flow and the SSO→non-human-identity lineage are the parts with no precedent and
   the highest blast radius. They get an isolated spike before any orchestration.
2. **Boundary controls before features.** Because the platform is meant to be the
   *mandatory* paved road, prevention must be live before prohibition — so the
   default-deny egress wall and ephemeral-credential model land in the **first**
   working milestone, not a later hardening pass.
3. **One lane, one tier × stratum, one cloud, one SCM — then breadth.** Depth on a
   single end-to-end path proves the pattern; breadth (clouds, SCMs, tiers) follows.
4. **Open-source posture is built in from Phase 1, not bolted on.** The maintainer-
   hosts-nothing property and the self-assurance suite are product requirements with
   their own milestones.

Phases are capability gates, not calendar commitments. Each lists scope, the control
objectives that come online, and a concrete **exit criterion**.

---

## Phase 0 — Credential & identity spike

**Goal:** de-risk the novel core in isolation, wired to nothing.

- Subscription-token persistence: `claude /login` → per-user vault (adopter KMS) →
  injection into that user's sandbox only; operator cannot read it; not pooled.
- SSO → per-session non-human-identity propagation into model + SCM credentials.
- The attended-only subscription behaviour: a forked/headless `claude -p` inside an
  attended single-user session stays on the subscription; nothing orchestrated does.

**Exit:** the credential/identity/seam behaviour demonstrated end to end on a bench,
with a written threat model for this surface. No orchestration, no policy, no UI.

---

## Phase 1 — Single-lane PoC (author × T3, GCP, GitHub)

**Goal:** one governed task, end to end, once.

- Scope: **GCP**, **GitHub**, **gVisor + ephemeral sandboxes**, **author** persona,
  **S1 Engineered × T3 Standard** (highest-volume, lowest-consequence — proves the
  pattern without owing the T1 human gate or full attestation on day one).
- **Default-deny egress enforced at the sandbox boundary** (out-of-band proxy).
- Inference via **Vertex** (keeps inference in-account/in-region).
- Output **crypto-attested**; lineage intact **SSO → NHI → signed commit**;
  **evidence landed immutably** (WORM).
- Web-CLI UI sufficient to launch, watch, and review one session.

**Control objectives online:** CO-04 (source integrity), CO-08 (secrets / NHI),
CO-06 (pipeline integrity, partial), CO-14 (evidence, partial).

**Open-source milestones:** repository public; **Apache-2.0**; `SECURITY.md`;
`CONTRIBUTING.md`; first **signed release with SBOM and provenance** (the project
eats its own dog food from release one).

**Exit:** a single GitHub task runs in a policy-bound sandbox, default-deny egress
enforced at the boundary, output attested, lineage intact, evidence immutable —
deployable by an adopter in their own GCP project with their own Vertex backend and
their own subscription, **maintainer-uninvolved**.

---

## Phase 2 — Operate lane + evidence hardening

**Goal:** make production observability safe to switch on.

- **Observe vs actuate** planes: read-only operate identity; network perimeter
  scoped to observability APIs; **Observe Gateway** (redacting, query-audited) for
  high-tier telemetry; the **PreToolUse mutating-command tripwire** as
  defence-in-depth.
- **Propose-via-PR**: operate output is a proposed artefact through the pipeline,
  never a direct production mutation.
- Evidence: **WORM hash-chaining + signing**, **SIEM** stream, transcript access
  least-privilege and separated from operations.

**Control objectives online:** CO-10 (deployment safety, propose side), CO-12
(AI-assisted & agentic — scope enforcement, tripwire, sub-agent coverage), CO-14
(evidence, full).

**Exit:** an operate session diagnoses against read-only production telemetry and
opens a PR with a proposed fix, with **no path to actuation** and every read
evidenced.

---

## Phase 3 — Policy & scale

**Goal:** make scope-follows-the-artefact real and stop the side doors.

- **Central policy registry / GRC adapter** as the authoritative tier × stratum
  source; in-repo files declare intent only.
- **Tier × stratum → session profile** resolution as the enforcement point for the
  eligibility matrix; persona/precedence composition (enterprise > team > user).
- **Cross-repo take-the-max + step-up.**
- **Enterprise-curated MCP allowlist** with vetting; approved domains fold into the
  egress allowlist.
- **Pre-egress DLP** blocking for high tiers.

**Control objectives online:** CO-01 (governance & tiering), CO-13 (user-developed
apps — citizen/operate scoping), CO-05/CO-09 intake discipline (via MCP/dependency
chokepoint).

**Exit:** a cross-repo session inherits the **target's** policy and gates; an
unapproved MCP server is refused; a blocked secret egress is denied at the boundary.

---

## Phase 4 — Portability + self-governance

**Goal:** prove bring-your-own-cloud and that Console7 passes its own bar.

- **AWS and Azure** provider parity behind the existing interfaces; **BYO SCM**
  (GitLab / Bitbucket / Azure DevOps) behind `SCMProvider`.
- **HA topology + optional break-glass instance** as configuration (resilience is
  the adopter's posture, exposed, not fixed).
- Inference-routing policy hardened (subscription-vs-org-API enforcement, backend
  enable/disable).
- **Console7 passes its own Tier-1 control set** (2LoD challenge) and its build chain
  is fully signed/SBOM'd/provenanced.

**Exit:** stand Console7 up in a **second cloud with a second SCM**, maintainer-
uninvolved; Console7's own pipeline is demonstrably T1-conformant.

---

## Phase 5 — Open-source GA

**Goal:** an external enterprise runs it themselves and can prove the controls.

- **Extensibility SDK** for the provider interfaces (clean, documented, versioned).
- **Conformance / control-mapping test suite** so an adopter can **evidence each
  control objective** and **self-classify** the inference boundary against their own
  obligations.
- **Reference deployments** (GCP / AWS / Azure) and a documentation site.
- **Published threat model + abuse-case register**; a documented **governance
  model** (maintainership, release, security response).

**Exit:** an external enterprise deploys Console7 in its own tenancy with its own keys
and subscription, evidences the control objectives via the conformance suite, and
the maintainer can prove it received **zero** adopter data — all with **zero
maintainer involvement**.

---

## Cross-cutting workstreams (run continuously)

- **Security:** threat-model every phase; the abuse-case register (control-plane-as-
  target, lethal trifecta, cross-tier escalation, subscription misuse, sub-agent
  lineage, platform supply chain) is living, not a one-off.
- **Upstream tracking:** pin and canary Claude Code; watch the auth/credential terms
  and keep the subscription/org-API seam a *policy* flip, not an architecture change.
- **Docs & self-assurance:** the control mapping and data-flow documentation are
  shipped artefacts, kept current with the code.
- **Community:** contribution, review, and provider-interface stability guarantees
  appropriate to a product enterprises bet on.
- **Dogfood — local cloudless target:** Console7 is exercised *on itself* via the
  out-of-tree local single-host target (`docs/adr/0003-local-cloudless-target.md`) — as
  much, and as early, as each piece is genuinely possible. Its phased dogfood plan lives
  **in that repo, not duplicated here** (the link is access-gated — deliberate, to avoid
  over-disclosing on a public repo, not a broken reference):
  [console7-cloud-local `docs/ROADMAP.md`](https://github.com/console7/console7-cloud-local/blob/main/docs/ROADMAP.md).
  **Working this repo? Treat that as a live, gated workstream — consult it; don't take
  this public roadmap as the whole plan.** Cross-gates worth knowing:
  - The local **real-engine dev-loop** dogfood (run a genuine Claude Code session
    locally, → "Console7 builds Console7") unlocks with the **core sandbox base-image +
    `policyHelper`** — until that lands, the local target can only *model* the sandbox,
    so building the dev-loop would be scaffolding around an artifact that doesn't exist.
    **Posture (2026-06-20): stay the course on the Phase-1 provider track; landing the
    sandbox base-image is the trigger to pivot the local target to the real-engine
    dogfood.** Flag it then.
  - The local **CI/CD adoption-loop** dogfood unlocks with **signed release images
    (#11)** — landing #11 should trigger it.

### SAST carry-forward — VVAH scan 2026-06-25

An external agentic SAST (Visa VVAH) over the tree surfaced 32 verified findings. The
self-contained defence-in-depth fixes landed immediately (guard-bash interpreter/segment/
quoted-ref gaps, the tripwire parser bugs, the scm-github HTTPS parity, the git-bundle `--`
terminator, the evidence-gcs read/count bounds, the hook stdin caps, the managed-settings
Read-deny, the inference-credential revocation TOCTOU, the KMS-HSM production gate, the testkit
rig-skip, the DCO bot-exemption/log-injection). The remainder are **design-level** items whose
correct fix is owned by a later phase — tracked here so they are not silently dropped.

> Each deferred/accepted finding also carries an **inline marker at its code site** so a
> re-scan sees the acknowledgement in situ — grep `SAST-DEFERRED` / `SAST-ACCEPTED` (tagged
> `VVAH-2026-06-25 #N`). `SAST-DEFERRED` → this carry-forward; `SAST-ACCEPTED` → a `docs/RISKS.md`
> entry (#2 → R-14, #12 → R-15).

| Finding | Item | Closes in / by |
|---|---|---|
| #1 | SCM `MintWorkingCredential` does no subject→repo authorization (any SSO user can scope a token to any App-installed repo) | **Phase 3** — the tier×stratum→session-profile resolver is the authorization enforcement point; add a fail-closed `AuthorizationChecker` port consulted before any token mint. Today's `FixedPolicySoR` is the dev stand-in. |
| #9, #10 | `--user` / `--attended` are self-attested (circular dev-IdP authn; subscription routing self-declared) | **Phase 3 / real OIDC IdP** — the SSO→NHI binding is currently dev/fixed (banner-flagged). Derive subject + attendance from a verified OIDC token, not a CLI flag. Interim: stop the orchestrator hard-coding `Attended:true`, which makes the seam's attended-gate a no-op. |
| #16, #31 | Evidence chain is tamper-EVIDENT but not tamper-RESISTANT: chainHash has no secret, and `payloadTBS` omits the sequence/prior-hash so a workload-SA holder could fork the chain or replay a same-event record at another position | **Phase 2** — evidence hardening (full WORM hash-chaining + signing). Bind the record sequence into the signed `payloadTBS`; run a tail chain-integrity check in preflight; production retention-LOCK is the boundary control. (Partial mitigation already landed: `Count()` ignores stray non-record objects.) |
| #26 | Sandbox and control-plane GKE node pools share one GCP service account (future IAM grants silently widen the sandbox blast radius) | **Phase 2/3 deploy hardening** — split into a dedicated, minimal sandbox-node SA. |
| #13 | Reaper CronJob image pinned by mutable tag, not digest | **Deploy hardening** — pin `@sha256:…` and add an admission/digest check (bundle with the next deploy PR). |

## Roadmap decisions (log)

Dated, durable decisions so we don't re-litigate or trip over them later. Newest first.

### 2026-06-26 — Vertex × Anthropic-model testing is parked; test on org-API first, subscription ASAP

- **Vertex lane committed UNTESTED.** The Vertex path for Anthropic models (engine → per-session
  auth-proxy → bearer → Vertex → Anthropic model) is being merged and carried forward **without a
  validation pass**. Functional testing of *this specific feature* is **parked** to a later phase —
  it is a known-unverified surface, not a proven one. A green build is NOT evidence the Vertex lane
  works end-to-end; it has not been exercised against live models since the quota block.
- **Model-usage testing sequence (deliberate):** validation of the model-usage/inference path
  begins on **org API keys, Anthropic direct** (the simplest, most available lane), and **migrates
  to the subscription lane ASAP**. This also sits naturally with GOAL.md tenet 2 (one human, one
  credential, one beneficiary) — automated/headless test runs use org API keys, while the
  subscription lane backs only attended single-user sessions — so org-API-first is both the pragmatic
  and the policy-correct start, with the subscription lane as the
  priority follow-on (it is the novel, higher-blast-radius surface Phase 0 exists to de-risk).
- **Why parked:** the live Vertex exit was blocked on Google denying the Claude quota on the fresh
  project (see the live-deploy notes), not on a Console7 defect — so end-to-end Vertex validation is
  gated on quota/account work outside this codebase. Proceeding on org-API-direct unblocks the
  model-usage track without waiting on that.
- **Unpark trigger:** resume Vertex-lane validation once (a) the org-API-direct model path is green
  end-to-end, and (b) Vertex Claude quota is granted on a usable project. Until then, anything that
  depends on "Vertex works" must state that assumption explicitly.

## Control-objective onramp (summary)

| Phase | Newly online |
|------|---------------|
| 1 | CO-04, CO-08, CO-06 (partial), CO-14 (partial) |
| 2 | CO-10 (propose), CO-12, CO-14 (full) |
| 3 | CO-01, CO-05/CO-09 (intake), CO-13 |
| 4 | Self-governance (Console7 as T1); CO-16/CO-17 for Console7 itself |
| 5 | Conformance evidence for the full set; adopter self-classification |

> Objectives not listed (e.g. CO-07 security testing, CO-11 vulnerability response,
> CO-15 functional QA) are **inherited from the adopter's existing pipeline** rather
> than implemented by Console7; the conformance suite maps which Console7 owns, which it
> enforces, and which it inherits.
