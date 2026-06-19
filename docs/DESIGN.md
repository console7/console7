# Console7 — Design Specification

This is the normative specification. Requirement language: **MUST / SHOULD / MAY**.
Each requirement carries a short rationale; where it derives from a decision in the
design record, the reference (e.g. *D7*) is given. It is written to be read by
engineers building Console7 and by assurance reviewing it.

> **Reading note.** The controls divide into three layers of descending assurance:
> **boundary** (authoritative, out-of-band), **in-sandbox enforcement**
> (non-overridable by the user, but in-band), and **guidance** (model-facing,
> lowest). When two layers disagree, the higher-assurance layer wins. Nothing in
> the in-sandbox or guidance layers is ever the control of record.

---

## 1. Conceptual model

### 1.1 The web-CLI

Console7 presents a Claude Code session through a web UI that **emulates a desktop or
container CLI**. The session is real Claude Code running in a sandbox; the browser
is a thin, governed window onto it. Sessions persist server-side and survive a
closed browser. This is *not* multiple people sharing one credential — it is one
user's own CLI, hosted (*D5*).

### 1.2 Personas

A session runs as exactly one **persona**, realised as a distinct non-human
identity with distinct scope and egress (*D21*):

- **Author** — develop. Reads and edits within the target repository, runs the
  repo's build/test tooling, commits to a working branch, opens pull requests.
  Holds **no** production credentials; production CLIs are denied.
- **Operate** — read-only production observability → propose. Reads logs, metrics,
  traces, topology, change history (via the Observe Gateway) and the repository,
  to diagnose. Emits any required change as a **proposed artefact** (PR / IaC /
  runbook step). Holds a **read-only** production identity; cannot mutate.

There is **deliberately no "actuate" persona**. Actuation against production is the
pipeline's responsibility, under human approval (*D20, D23*). The same model plays
different roles in different sessions; **no single session ever holds author +
approver + actuator** — the separation of duties that an all-AI-authored estate
otherwise collapses.

### 1.3 Scope follows the artefact (tier × stratum)

Console7 is the **enforcement point for the eligibility matrix**. At launch and at
every cross-resource boundary, it resolves the **target's** criticality tier (T1–T4)
and authoring stratum (S1–S5) and derives the session profile from them: egress
allowlist, autonomy ceiling, persona constraints, and whether a human gate is
required (*D10, D11*). A citizen-built and a professionally-built artefact at the
same tier × stratum owe the **same** controls; what differs (lower eligibility
ceiling, centrally-supplied controls) is policy on the profile, not a relaxation.

### 1.4 Engine

Console7 **MUST wrap the genuine Claude Code engine** (headless CLI / Agent SDK) and
**MUST NOT reimplement the agent**. Rationale: fidelity of agent behaviour, hooks,
permission semantics, and model behaviour; the platform's job is orchestration,
isolation, policy, identity, and evidence — not agency.

- Subscription-backed sessions use the CLI with the user's interactive OAuth.
- Org-API sessions use the Agent SDK / CLI with an org API key (OAuth is not
  accepted by the Agent SDK).
- The upstream version **MUST be pinned**, and upgrades **MUST be canaried** in a
  non-production environment before fleet rollout — an upstream change can alter
  permission or hook behaviour (*D16*).

---

## 2. Credential & identity

### 2.1 No long-lived secrets at rest

Console7 **MUST NOT** store long-lived cloud or SCM credentials in its datastore
(*D1*). It is a broker: at session start it **mints or fetches** short-lived
material from the adopter's secrets manager / identity platform, scoped to the
session, expiring with it.

- Ephemeral identity (workload-identity federation / OIDC) **SHOULD** be preferred
  over any stored secret (*D2*). Nothing long-lived to steal is the strongest
  control.
- SCM access **SHOULD** use a GitHub App (or equivalent) issuing short-lived,
  per-install, scoped installation tokens; push **MUST** be restricted to the
  working branch; the sandbox git client **MUST NOT** see a durable token.
- Any persisted material **MUST** be envelope-encrypted under the adopter's
  customer-managed KMS key, per user.

### 2.2 The one stored credential: subscription OAuth

Where a user binds their subscription, the OAuth token is the single unavoidable
stored credential (*D3*). It **MUST**:

- live in the adopter's secret store under a **per-user** key;
- be injected **only** into that user's sandbox, at session start;
- be **unreadable by platform operators** (no standing operator read path);
- **never be pooled** or used for any beneficiary but its owner.
- Revocation = secret delete + prompt to revoke at the provider; offboarding =
  automated purge on identity-provider deprovision (SCIM).

### 2.3 Identity continuity and lineage

The user's authenticated platform identity (SSO/OAuth subject) is the lineage
anchor and **SHOULD propagate into both the model credential and the SCM/cloud
credential by default** (*D14*) — identity continuity, not a loosely-mapped service
account. Override-by-exception is limited to two sanctioned cases: the org-API /
automation route (an org service subject, §3) and break-glass (§7).

- Console7 **MUST** stamp an unbroken chain — human subject → per-session non-human
  identity → every tool call, sub-agent action, and artefact — **at the
  orchestrator**, because the engine's sub-agent lineage is leaky and cannot be the
  sole source of attribution.
- Commits and produced artefacts **MUST** be cryptographically signed by the
  session identity (e.g. Sigstore keyless or an org CA).

---

## 3. Inference routing

Console7 **MUST** support both inference modes and make the available backends an
enterprise configuration (enable/disable per adopter policy) (*D18*):

- **Subscription** — attended, single-user, interactive only.
- **Org API** — via **Vertex**, **Bedrock**, or **direct Anthropic**. A unifying
  gateway abstraction (e.g. LiteLLM) **MAY** come later.

The **attended/unattended seam MUST be enforced in policy, not guidance** (*D5*):

- A subscription credential backs only human-present sessions and the session ends
  when the human's session ends.
- Orchestrated, scheduled, webhook-triggered, headless, or cross-repo fan-out work
  **MUST** use the org-API route and **MUST** be refused on a subscription token.
- The discriminator is **human presence and single beneficiary**, not invocation
  mode: a forked/headless `claude -p` inside an attended single-user session stays
  on the subscription credential.
- This posture is **provisional**; the routing trigger **MUST** be a configurable
  enterprise policy so it can be tightened when upstream terms change — flip policy,
  not architecture.

---

## 4. Policy

### 4.1 Authority and composition

- A repository's authoritative policy (tier × stratum, session profile, egress
  allowlist, autonomy ceiling, human-gate flag) **MUST** live in a **central
  registry / GRC system of record keyed by repo**, queried at each action boundary
  (*D10*). An **in-repo file MAY declare intent**, but the registry **decides** —
  an in-repo control is editable by the very agent it governs (the
  "prompt-edited-in-prod" / self-relaxation threat).
- Policy **composes** with fixed precedence: **enterprise-managed > team/project >
  user**. The enterprise-managed layer is non-overridable by lower layers.
- Console7 **integrates** a policy engine (e.g. OPA/Rego or Cedar) and **MUST NOT**
  *own* the system of record. It is an enforcement and integration point, not the
  policy authority.

### 4.2 Cross-tier reach

When a session touches more than one resource, Console7 **MUST** apply
**take-the-max + step-up** (*D11*): bind the session to the most restrictive
profile across all resources in scope; reaching into a higher tier triggers that
tier's gates; if the target demands stronger authentication than the session holds,
**force step-up re-auth or block**. A permissive origin **MUST NOT** confer access
to a stricter target — that is the privilege-escalation path.

### 4.3 MCP and tool extensibility

- Users **MUST NOT** add arbitrary MCP servers. Console7 **MUST** enforce an
  **enterprise-curated MCP allowlist** (*D9*).
- Each approved server **MUST** be vetted for tool reach and egress, and its
  required domains **MUST** fold into the sandbox egress allowlist — the same
  single-chokepoint discipline used for dependency intake. Unvetted MCP is the open
  side door that otherwise undoes the sandbox.

---

## 5. Sandbox & egress

### 5.1 Isolation

- Tool execution **MUST** run in an isolated sandbox per session — **gVisor or a
  microVM** — with **ephemeral** workspaces by default. Filesystem confinement
  **MUST** be enforced at the kernel/syscall boundary, not by request to the agent.
- The default data policy is **no production data, no real customer data, no real
  secrets in any sandbox — synthetic / test only** for the author lane (*D7*).
  Higher classes require an explicit, tier-aware, approved policy exception, with
  masking/tokenisation preferred.

### 5.2 Egress is the authoritative network control

- Egress **MUST** be **default-deny at the sandbox boundary**, via an **out-of-band
  proxy / network perimeter** (e.g. VPC Service Controls) — **not** the engine's own
  in-process proxy, which only constrains well-behaved clients (*D6*).
- The allowlist is composed from: the chosen inference endpoint, approved package
  registries / artefact chokepoint, approved internal services, and approved MCP
  domains. Anything else is denied and the attempt is visible.

### 5.3 The lethal-trifecta default

The combination of **private-data access + egress capability + exposure to
untrusted content** (e.g. a poisoned repo or dependency) is the central abuse case
(*D6*). The default posture **MUST remove a leg**: default-deny egress (§5.2), no
production data by default (§5.1), and an MCP allowlist (§4.3).

### 5.4 Observe vs actuate (operate lane)

For the operate lane (*D7, D22*):

- The session's cloud identity **MUST be read-only** (the authoritative mutation
  block; see the credential bundle for reference IAM-as-code). A leaked operate
  token is still only a read token.
- The session **MUST** sit inside a network perimeter scoped to observability APIs.
- High-tier targets' telemetry **MUST** be reached through the **Observe Gateway** —
  a redacting, query-audited, rate-limited façade — not raw log-store credentials;
  redaction depth and the right to attach scale with the target's tier. Lower-tier
  targets **MAY** use direct read-only CLI inside the perimeter.
- A **PreToolUse mutating-command tripwire MUST** run as defence-in-depth: detect a
  mutating command attempt, deny it in-sandbox, and emit it as an **incident** to
  the evidence sink. It is heuristic and fail-closed; it is never the primary
  control (IAM is).

---

## 6. Evidence, DLP & transcript handling

- Evidence **MUST** be written to an **append-only, WORM** store, **hash-chained
  and signed** for tamper-evidence, and **streamed to the adopter's SIEM** (*D12*).
  It is the system of record for verification and is **separate** from the
  operational database.
- **Pre-egress DLP** is a control of record at the boundary (*D8*): secret-scanning
  plus PII/classification detection on anything committed or sent. It **MUST block**
  for high tiers (T1/T2) and **MAY be advisory** below (proportionality). It runs at
  the boundary, never as a bypassable hook.
- Transcript access **MUST** be least-privilege and **separated from operations**
  (*D13*): readable by the initiating user and a tightly-scoped assurance/2LoD role
  with logged, justified access. The team operating Console7 **MUST NOT** have
  standing read access to everyone's sessions — operators operate; they do not
  surveil.

---

## 7. Change-management integration

- Operate-agent (and author-agent) output **MUST** enter the adopter's existing
  change pipeline as a **proposed artefact** (PR / IaC change / runbook step) and
  **MUST NOT** mutate production directly (*D20*). The pipeline, with the
  tier-appropriate **human gate**, actuates.
- The agent that diagnoses or authors **MUST** be a distinct identity from the
  approver/executor; **no session holds author + approve + actuate** (*D21*).
- **Break-glass** actuation **MUST** be human-approved and **executed by the
  platform/pipeline**, not by a standing agent credential (*D23*). Closed-loop
  auto-remediation, if an adopter enables it, **MUST** be pre-reviewed, deployed
  code with a **bounded, pre-approved action space and circuit breakers** — never
  open-ended runtime improvisation. The +1 ratchet for irreversible external action
  applies.

---

## 8. Self-governance & supply chain

- Console7 is a **Tier-1 system** and **MUST** be subject to its own control set, with
  2LoD challenge (*D4*). A control system that fails its own controls is the obvious
  own-goal.
- Console7 **MUST** be a credible software-supply-chain citizen (*D16*): pinned
  upstream, canaried upgrades, **signed builds, SBOM, provenance, isolated build
  runners**. It eats its own dog food.
- **Distinct artifacts by trust tier.** The control-plane artifact (pristine,
  Tier-1, never executes untrusted code) and the **sandbox base image** (which runs
  untrusted agent code) **MUST** be separate release artifacts with **distinct
  provenance and signing identities** — the thing that holds the keys must not share
  a build identity with the thing that runs untrusted code. The credential-broker /
  signing component **SHOULD** be a separately-hardened, narrowly-scoped artifact so
  a control-plane compromise does not reach the keys (the control-plane-as-target
  case, §10.1). See `ARCHITECTURE.md` §6 for the repository and artifact layout.

---

## 9. Open-source & bring-your-own requirements

These are first-class product requirements, not packaging afterthoughts.

- **Maintainer hosts nothing.** Console7 **MUST** run entirely in the adopter's
  tenancy. There **MUST** be no mandatory egress of adopter data, code, credentials,
  or session content to the maintainer or any maintainer-operated service. Optional
  telemetry, if ever added, **MUST** be opt-in and content-free.
- **Pluggable provider interfaces** (§ARCHITECTURE) for cloud, secrets, identity
  provider, SCM, inference backend, policy engine, policy system-of-record, and
  evidence sink. Each has **sensible-secure defaults** and is fully configurable.
- **Bring-your-own** cloud, subscription, and keys are the only supported
  consumption model (no maintainer-hosted SaaS tier is in scope).
- **Self-assurance.** Console7 **MUST** ship a **control-objective mapping** and a
  **conformance test suite** so an adopter can evidence the controls and
  self-classify the inference boundary against their own obligations (*D17*). The
  product documents its data flows precisely; it does not make the adopter's
  regulatory determinations.
- **Licence & governance.** Apache-2.0 (recommended), a published **security
  disclosure policy**, and a published **threat model / abuse-case register**.

---

## 10. Threat model spine

The full abuse-case register is a separate artefact; these are the load-bearing
classes the design must hold against.

1. **Control-plane-as-target.** Console7 holds the keys to many sandboxes and mints
   identities. Mitigation: §2 (no long-lived secrets; per-user isolation; operator
   cannot read tokens), §8 (self-governance), strict blast-radius limits.
2. **Lethal trifecta / indirect prompt injection.** Untrusted repo or dependency
   content steering an agent to exfiltrate over an *allowed* egress path.
   Mitigation: §5.2–5.3 (remove a leg), §6 (pre-egress DLP), §4.3 (MCP allowlist).
3. **Cross-tier escalation.** Launching from a permissive repo to reach a stricter
   one. Mitigation: §4.2 (take-the-max + step-up).
4. **Subscription-credential misuse / unattended drift.** A seat token used for
   service-like or multi-beneficiary work. Mitigation: §3 (policy-enforced seam),
   §2.2 (per-user isolation, no pooling).
5. **Sub-agent lineage break.** Attribution lost where the engine spawns sub-agents.
   Mitigation: §2.3 (orchestrator-stamped lineage; managed permission rules and
   hooks apply to sub-agent sessions).
6. **Platform supply-chain compromise.** Mitigation: §8.

## 11. External control dependencies (assumptions)

Console7's posture relies on controls it does not itself own; adopters **MUST**
provide them, and the docs **MUST** state them:

- **Endpoint control (MDM/EDR/egress).** If an adopter forbids local-CLI use to
  make Console7 the mandatory path, Console7 cannot enforce that — it is an endpoint
  control the value proposition depends on.
- **Network perimeter.** The default-deny egress wall is realised with the adopter's
  cloud networking (e.g. VPC Service Controls); Console7 configures, the cloud
  enforces.
- **Policy system-of-record.** The authoritative tier × stratum data lives in the
  adopter's GRC; Console7 reads it.
- **SCM branch protection.** Push restrictions are belt-and-suspenders with
  server-side branch protection the adopter configures.
