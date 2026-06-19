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
