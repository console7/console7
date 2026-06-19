# Console7 — Goal & North Star

## Mission

Give every engineer and operator in a regulated enterprise a **governed place to
run agents** — for building software and for operating it — that is safe enough to
be the *mandatory* path, and good enough that nobody wants the ungoverned one. It
must run entirely inside the adopter's own cloud, on the adopter's own
credentials, and it must make a modernised SDLC faster rather than fighting it.

## The problem

Three assumptions the classic secure-development standard was built on are now
false, and they are why this can't wait:

- **Cadence.** Threat and change run on compute; controls that run on calendars
  are already a record of the past. Controls must be continuous and as-code.
- **Actors.** AI assistants, agents, and citizen developers now write and ship
  software at scale. Scope has to follow the *artefact*, not the *author*.
- **Evidence.** Plausible attestations are near-free to fabricate and sampling is
  meaningless at machine tempo. Move from attestation to verification.

There is, today, **no governed substrate for agentic work**. So enterprises face a
bad choice: ban agents (and lose the productivity, and drive shadow usage), or let
them run ungoverned on endpoints with broad credentials and unbounded egress. The
recent tightening of subscription-credential terms — OAuth is for attended,
single-beneficiary, first-party use only; the Agent SDK requires API keys —
removes the easy "just point it at a shared seat" shortcut and makes a deliberate
platform necessary.

## What we're building

A self-hosted **web-CLI**: it emulates a desktop or container Claude Code session
through a web UI, inside a deliberately permissioned sandbox, with enterprise
policy and user context composed together. It is the concrete substrate for the
**agentic authoring stratum** and a paved road for AI-assisted development — the
governed platform that "opinionates the production control plane" so agentic and
citizen work inherit it by construction.

## Design tenets

These are load-bearing. A change that violates one is a design regression, not a
trade-off to be made quietly.

1. **The adopter's tenancy is the trust boundary.** Console7 hosts nothing for the
   adopter. No data, code, credentials, or session content reaches the maintainer.
   No mandatory phone-home. This is the precondition for open-source trust.
2. **One human, one credential, one beneficiary.** Subscription credentials back
   only attended, single-user, first-party sessions. Anything orchestrated,
   scheduled, triggered, headless, or multi-beneficiary routes to org API keys.
3. **Boundary controls are authoritative; in-band guards are defence-in-depth.**
   Least-privilege identity and a default-deny egress perimeter are the controls of
   record. Agent permission rules, hooks, and `CLAUDE.md` are layers on top. Where
   they disagree, the boundary wins — by design.
4. **Scope follows the artefact, not the author.** Session reach is derived from
   the *target's* criticality tier × authoring stratum. A citizen-built and a
   pro-built artefact at the same tier × stratum owe the same controls.
5. **Least privilege, ephemeral by default.** No long-lived cloud or SCM secrets in
   Console7's datastore. Identities are minted short-lived at session start and die
   with the session. The agent never grants or widens its own scope.
6. **Observe is not actuate.** Agents observe, understand, and **propose**; the
   pipeline actuates, under human approval. No session holds author + approver +
   actuator. No standing production-write credential exists, even for emergencies.
7. **Evidence over attestation; lineage is unbroken.** Every tool call, sub-agent
   action, and commit carries an attributable chain from the human's identity
   through a per-session non-human identity, recorded immutably and signed.
8. **Proportionate by consequence.** Rigour scales to tier; the objective is never
   waived, only its mechanism and evidence. Tier-1 rigour on Tier-4 work is itself
   a finding — it spends control budget where there is no consequence and breeds the
   workarounds that erode real assurance.
9. **Pluggable everything.** Cloud, secrets manager, identity provider, SCM,
   inference backend, policy engine, policy system-of-record, and evidence sink are
   all provider interfaces the adopter implements or selects. Sensible-secure
   defaults; every boundary configurable.
10. **It governs itself, and proves it.** Console7 is a Tier-1 system subject to its
    own control set, and a credible software-supply-chain citizen: pinned upstream,
    canaried updates, signed releases, SBOM, provenance, a published threat model.

## Non-goals

Stating these prevents scope drift and over-trust.

- **Not a model and not an Anthropic-hosted service.** Console7 orchestrates the
  genuine Claude Code engine; it provides no inference of its own.
- **Does not broker or pool subscriptions.** It hosts a CLI for a user's own seat;
  it never routes one person's work through another's credential.
- **Does not own the SDLC pipeline or the GRC system of record.** It *integrates*
  with the adopter's change pipeline and policy authority; it does not replace them.
- **Not an autonomous production control system.** Agents propose; they do not
  self-actuate against production. Closed-loop remediation, if an adopter wants it,
  is separately engineered, pre-reviewed, bounded code — not runtime improvisation.
- **Not a substitute for human review** on high-consequence change. The human gate
  on the critical tier is a feature, not friction to be optimised away.
- **Not a compliance oracle.** Console7 documents its data flows and maps to control
  objectives so an adopter can self-assure and self-classify; it does not make the
  adopter's regulatory determinations for them.

## Success criteria

- A session runs **end to end** with default-deny egress enforced at the sandbox
  boundary, output crypto-attested, lineage intact from SSO subject → non-human
  identity → signed commit, and evidence landed in immutable storage — once,
  demonstrably, before any feature breadth is added.
- An enterprise can **stand Console7 up in its own cloud, with its own keys and
  subscription, with zero maintainer involvement**, and the maintainer can prove
  it never received any adopter data.
- An adopter can **evidence each control objective** through a shipped conformance
  test suite and control mapping, and can self-classify the inference boundary
  against their own regulatory obligations.
- Agentic development and operations **move off ungoverned endpoints onto the paved
  road**, and the new-non-compliant-asset-creation rate trends to zero while mean
  time to adapt improves.

## North-star prompt (reusable seed)

A compact statement of intent and constraints, suitable to prime an agent or a new
contributor. Keep it in sync with the tenets above.

```text
Build Console7: an open-source, self-hosted control plane that lets enterprise staff
run Claude Code agents inside the ADOPTER'S OWN cloud tenancy, under enterprise
policy, via a hosted web-CLI that emulates a desktop/container CLI.

Hard constraints (violating any is a regression, not a trade-off):
- The adopter's tenancy is the trust boundary. The maintainer hosts nothing and
  must never receive adopter data, code, credentials, or session content. No
  mandatory phone-home. Everything runs in the adopter's GCP/AWS/Azure account;
  only model inference crosses the boundary, to a backend the adopter chooses
  (Vertex, Bedrock, or direct Anthropic).
- Bring-your-own: cloud, subscription, and API keys. Subscription credentials back
  ONLY attended, single-user, first-party interactive sessions (one human, one
  credential, one beneficiary). Anything orchestrated, scheduled, triggered,
  headless, or multi-beneficiary uses org API keys via the chosen backend.
- Store NO long-lived cloud or SCM secrets. Mint short-lived identities at session
  start from the adopter's secrets manager via workload-identity federation/OIDC;
  they die with the session. The single stored credential — a user's subscription
  OAuth token — is per-user encrypted under the adopter's KMS, injected only into
  that user's sandbox, never operator-readable, never pooled.
- Boundary controls are authoritative and out-of-band: least-privilege IAM and a
  default-deny egress perimeter. Agent permission rules, PreToolUse hooks, and
  CLAUDE.md are defence-in-depth only. Where they disagree, the boundary wins.
- Scope follows the artefact: derive a session's reach (egress allowlist, autonomy
  ceiling, human-gate requirement, persona constraints) from the TARGET's
  criticality tier x authoring stratum, resolved from the adopter's policy
  system-of-record (authoritative), not from an in-repo file (intent only). On
  cross-repo reach, take the most restrictive profile and step up auth or block.
- Two personas as distinct non-human identities: AUTHOR (repo-scoped, opens PRs, no
  production reach) and OPERATE (read-only production telemetry via a redacting,
  audited gateway and a read-only cloud identity; proposes changes as PRs; cannot
  mutate production). No "actuate" session; actuation is the pipeline under a human.
- Evidence over attestation: stamp an unbroken lineage (human SSO subject ->
  per-session NHI -> every tool call/sub-agent action/commit) at the orchestrator
  (sub-agent lineage is otherwise leaky); sign commits; write tamper-evident,
  hash-chained, append-only evidence and stream it to the adopter's SIEM.
- Wrap the genuine Claude Code engine (headless CLI / Agent SDK); do not reimplement
  the agent. Pin the version; canary upgrades. Console7 is itself a Tier-1 system and
  a clean supply-chain citizen (signed builds, SBOM, provenance).
- Pluggable provider interfaces for cloud, secrets, IdP, SCM, inference backend,
  policy engine, policy system-of-record, and evidence sink. Secure defaults;
  everything configurable. Ship a control-objective mapping and conformance suite.

Definition of done for the first milestone: a single GitHub task runs in a
gVisor-isolated ephemeral sandbox with default-deny egress enforced at the
boundary, output crypto-attested, lineage intact SSO->NHI->signed commit, evidence
landed immutably — deployable by an adopter in their own GCP project with their own
Vertex backend and their own subscription, maintainer-uninvolved.
```
