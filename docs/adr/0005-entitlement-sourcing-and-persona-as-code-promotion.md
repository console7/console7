# 5. Entitlement sourcing and the persona-as-code promotion contract

- **Status:** Draft (proposed — under review)
- **Date:** 2026-06-27
- **Deciders:** Console7 maintainers
- **Supersedes / Superseded by:** —

> ADRs capture a single, significant, hard-to-reverse choice and the reasoning behind it
> (see `docs/adr/0001-language.md`). This one is a **DRAFT for review**; it is not yet Accepted.
> Pairs with [ADR-0006](0006-hi-nhi-identity-and-wielder-intersection.md) (the HI/NHI identity model
> the resolved entitlements are minted into).

## Context

An operate-lane (or any non-author) session runs an agent under a **persona**. The persona's
**entitlements** — what cloud/telemetry/SCM scope the agent's per-session identity may hold — must come
from somewhere. Adopters told us they want three sourcing models, **chosen per persona**, none a
prerequisite:

1. **App-expressed (persona-as-code).** The application's *own* repo declares its operational personas;
   the adopter's CD asserts them into deployment. The modern path.
2. **Operator-team-configured.** The cloud/SRE/governance team wires fine-grained permissions to the
   persona directly.
3. **Human-grounded (SSO).** The persona runs grounded in the wielding human's own identity/entitlements
   — as-is (dangerous) or downscoped.

The hard constraint is **tenet 3**: *"scope follows the artefact, resolved from the policy
system-of-record (AUTHORITATIVE), never from an in-repo file (intent only)."* And **tenet 1**: Console7
must not become the owner/authority of the adopter's policy. Today the `PolicySoR` seam is **read-only**
(`ResolveRepo`/`ResolveResource → TierStratum`); there is **no path to ingest a promoted persona /
entitlement set**, and no persona-resolution method. That gap is what this ADR fills.

The naive reading of source (1) — "Console7 reads `app/operations.yaml` at launch and grants it" —
**directly violates tenet 3** and is a privilege-escalation foot-gun (a malicious PR to the file
self-grants). So the central design question is: **how does Console7 consume app-declared personas
without ever trusting the file as authority?**

## Decision

**Hybrid. Engineer a minimal *intent* spec; adopt the *promotion* mechanics; let the adopter own the
authority.** Console7 is a **promotion conduit into the adopter's policy authority, never its owner.**

### 1. A minimal `OperatePersona` intent spec (engineered, Console7-native)

App devs commit a tiny declarative record (e.g. `.console7/personas/*.yaml`), shaped for IDP/Backstage
catalog pickup on the *binding* fields but Console7-native on the entitlement payload. It is an
entitlement **request**, NOT a policy language (we do not ask app devs to write Rego/Cedar). Four
properties make it **intent, not authority, by construction**:

- **Symbolic, not concrete.** It names *what* (`telemetry, read, service: payments-api`), **never** an
  IAM role, ARN, project, or scope. The concrete grant is *manufactured at promotion* against the
  PolicySoR resource registry. A forged file **cannot name a privileged role because the vocabulary has
  no role names** (the SPIRE "selectors, not self-asserted identity" lesson).
- **Closed, monotone `class` enum** (`observe` ⇒ structurally non-actuating; `propose`; never `actuate`).
  The schema rejects any mutate verb under a non-actuating class. The dev cannot define a stronger class.
- **Tighten-only constraints.** Constraints (TTL, data-class denies, regions) compose by **intersection**
  with platform/tier floors. A malicious edit can only *shrink* reach.
- **Never read at launch.** Console7 has **no code path that fetches the app-repo file when a session
  starts** — tenet 3 enforced architecturally, not by lint. Only the promoted artifact (below) reaches
  the runtime.

### 2. The promotion contract — how intent becomes authority (adopted from in-toto/SLSA + OPA-bundle GitOps)

- The adopter's **CD** validates the spec, resolves the symbolic request to a *candidate concrete grant*
  against the PolicySoR, runs the **structural non-actuation proof** (§4), and emits a *proposed*
  `PromotedEntitlement`.
- **Separation of duties (configurable, default-on):** approval is by the **target resource's owner**
  (resolved from PolicySoR ownership), and **MUST be distinct from the source-repo author**. Where the
  app team owns its own prod (you-build-it-you-run-it), a **second governance axis** is required for
  `class` boundaries and any cross-tier reach. Self-approval is a **hard seam failure**, not a warning.
  Reuse the adopter's JIT/approval engine (Teleport / ConductorOne / Entitle) or a CODEOWNERS-gated
  policy store.
- **Promotion = a signed, content-addressed attestation.** The **key broker** (distinct signing identity)
  signs an in-toto-style attestation whose predicate is the canonical `PromotedEntitlement` and whose
  subject digest is `entitlementVersion = sha256(canonical(...))`. It lands in the **PolicySoR** as the
  authoritative record. The source-repo commit is referenced for *provenance*, never as authority.

### 3. Consumption at session launch (small seam delta)

- New read method: **`PolicySoR.ResolvePersona(service, persona) → (PromotedEntitlement, version, error)`**,
  fail-closed (unknown persona ⇒ most-restrictive/deny, mirroring `ResolveRepo`).
- The resolved grant + persona class feed **`PolicyEngine.Evaluate`** as *facts* (engine stays
  data-only / fail-closed — unchanged contract).
- The **key broker / `IdentityProvider`** mints the per-session NHI scoped to the resolved grant
  (see [ADR-0006](0006-hi-nhi-identity-and-wielder-intersection.md)).
- The orchestrator **stamps `entitlementVersion` + the promotion signature ref into the WORM evidence**
  at session start, alongside human→NHI lineage — so an auditor resolves the hash back to the promoted
  object, its approver, and the source commit.

### 4. "observe = non-actuating", VERIFIED not assumed (three layers; the boundary is authoritative)

1. **Promotion-time structural proof** — the concrete grant set MUST be a subset of a statically-defined,
   conservative **read-only capability closure** per `CloudProvider` (deny-unknown-verb). Promotion
   **fails closed** if non-actuation is not provable.
2. **Runtime PolicyEngine obligation** — `class: observe` carries no actuate obligation; any mutate denies.
3. **The minted NHI simply LACKS write permissions** — the control of record (tenet 2). Even a buggy
   upper layer cannot actuate.

The guarantee is the **intersection of (1) and (3)**; (2) is in-band defence-in-depth.

### Source unification

`ResolvePersona` abstracts the source. **(1) app-expressed** = promoted via this contract; **(2)
operator-configured** = written directly into the PolicySoR (no app-repo step); **(3) human-grounded** =
resolved at launch from the wielder's identity, then downscoped (ADR-0006). One authoritative resolution,
three back-ends.

## Visualised flow

```mermaid
flowchart TD
    subgraph APP["Application repo (adopter)"]
        INTENT["OperatePersona intent<br/>.console7/personas/*.yaml<br/>symbolic · class-typed · tighten-only"]
    end

    subgraph CD["Adopter CD — assert step"]
        VALIDATE["schema-validate"]
        RESOLVE["resolve symbolic request<br/>to candidate concrete grant<br/>(via PolicySoR registry)"]
        STRUCT["structural non-actuation proof<br/>grant subset of read-only closure"]
        PROPOSE["emit PROPOSED<br/>PromotedEntitlement (unsigned)"]
    end

    subgraph GOV["Governance — separation of duties"]
        APPROVE{"approver = resource owner<br/>and NOT the author<br/>(2nd governance axis for<br/>class / cross-tier)"}
    end

    subgraph AUTH["Authority plane"]
        SIGN["key broker signs<br/>in-toto attestation<br/>version = sha256(canonical)"]
        SOR[("PolicySoR<br/>authoritative record")]
    end

    subgraph RUN["Session launch — the ONLY thing the runtime reads"]
        RP["PolicySoR.ResolvePersona<br/>verify signature · fail-closed"]
        PE["PolicyEngine.Evaluate<br/>facts: class + grant"]
        NHI["key broker mints per-session NHI<br/>scoped to grant (ADR-0006)"]
        EV[("WORM evidence<br/>stamps entitlementVersion<br/>+ human to NHI lineage")]
    end

    INTENT -->|"PR merged"| VALIDATE --> RESOLVE --> STRUCT --> PROPOSE --> APPROVE
    APPROVE -->|"approved by a distinct owner"| SIGN --> SOR
    APPROVE -->|"rejected / self-approval"| FAIL["fail closed"]
    SOR -.->|"resolved at launch"| RP --> PE --> NHI --> EV
    INTENT -. "provenance ref only, NEVER authority" .-> SOR
```

## Decision drivers

- **Tenet 3** — the file is intent; authority is the promoted, governance-gated record. Enforced by the
  runtime never reading the repo file.
- **Tenet 1** — Console7 is a conduit into the adopter's authority, not the policy owner.
- **Tenet 5 / least privilege** — the symbolic vocabulary caps blast radius; non-actuation is *proved*.
- **Don't reimplement** — adopt in-toto/SLSA signing + OPA-bundle promotion + existing JIT/SoD tooling;
  engineer only the small intent spec the industry has no exact donor for.

## Consequences

- **New `PolicySoR.ResolvePersona` read method** + **new write-side promotion port** (PolicySoR is
  read-only today; the asymmetry — resolvable but not owned-by-Console7 — is itself a stated principle).
- **New signed artifact type `PromotedEntitlement`** (content-addressed in-toto attestation, a new
  release-artifact class alongside the policy bundle).
- **The read-only capability closure is a dedicated, tracked risk** — cloud-specific, non-trivial ("read"
  APIs with side effects exist), needs a conservative deny-unknown-verb allowlist with its own security
  review. It is the piece that *earns* the observe≠actuate claim and the riskiest novel work.
- **Adoption friction (open):** two policy stores (app repo intent + SRE-owned promoted store). The
  GitOps-reconciler reference keeps it ergonomic; validate with a design partner.
- **SoD is configurable in *scope*, not in *existence*** (you-build-it-you-run-it orgs differ in *who*
  the second axis is, never in *whether* it applies — see Hardening H4): single-axis approval is
  permitted **only** for pure within-tier `observe`; `propose`, any cross-tier reach, and break-glass
  **require** the second governance axis. It is not an adopter on/off toggle.

## Hardening requirements (MUST hold in implementation — resolved before Accepted)

These close the privilege-escalation paths an adversarial review found in the draft. They are
**normative** for the build: each carries a conformance obligation so the gate exists before the
code does. (Paired with [ADR-0006](0006-hi-nhi-identity-and-wielder-intersection.md) Hardening, which
covers the *mint* side.)

**H1 — One canonical capability-set algebra, deny-biased and total.** Scope is a canonical,
provider-namespaced capability set. `Intersect`/`Subset` ship as **one shared library** used by *both*
the promotion-time structural proof (§4.1) and the launch-time mint (ADR-0006), so "what `observe`
means" cannot drift between where it is proved and where it is minted. Unknown on either side ⇒
excluded. Property-tested: `A∩B ⊆ A,B`; commutative; idempotent; `A∩∅ = ∅`.

**H2 — The read-only closure is a positive allowlist with NO wildcards.** Explicit verbs only — no
`*`/prefix matching — so a newly-shipped side-effecting `get*`/`list*` API is **denied by default**,
not auto-admitted. A maintained **denylist** of read-shaped-but-dangerous verbs (e.g. GCP
`iam…getAccessToken`, `signBlob`/`signJwt`, `cloudkms…useToDecrypt`, `*getIamPolicy`; AWS STS
exchanges) is asserted in CI: **`closure ∩ denylist = ∅`**. *Corollary (binds ADR-0006 H3): you
cannot grant what the provider cannot bound — a verb whose effect a provider's attenuation primitive
cannot constrain is removed from that provider's closure.*

**H3 — `propose` is proved too; it gets its own closure.** The structural non-actuation proof (§4)
covers `observe` only. `propose` is a real write capability and MUST carry a *separate*, proven
allowlist (e.g. SCM branch/PR creation only; never cloud-mutate, never CI-trigger verbs). No class
escapes a closure.

**H4 — SoD binds to authenticated identity, and is mandatory for any write/cross-tier/break-glass.**
`author` and `approver` are derived from the **authenticated promotion identities** at the broker
(who signed the request / the approval), **never** from git commit metadata (`--author`, co-author
trailers, and merge-bot committers are all spoofable). The approver MUST be a cryptographically
distinct principal from *every* author in the persona's provenance chain. Self-approval is a hard
seam failure (already stated). The second axis is non-optional for the classes named in Consequences.

**H5 — Ownership is a signed, SoD-gated PolicySoR record — never app-repo-editable.** "Resource owner"
(the H4 approver identity) resolves only from the authoritative ownership record in the PolicySoR,
itself promoted under this same ceremony. An app-repo PR can never change who owns a resource, closing
the "PR yourself into ownership, then self-approve" path.

**H6 — Promotion binds to a code revision.** A `PromotedEntitlement` records the code SHA it was
reviewed against. At launch the running revision MUST match (or be a policy-permitted fast-forward
descendant); for a standing persona on a sensitive target, a code change since promotion forces
step-up re-approval. A reviewed-capability must not silently wield un-reviewed code (TOCTOU).

**H7 — Revocation + monotonic supersession.** `ResolvePersona` returns only the *current, non-revoked*
version; promoting a tighter version revokes the broader; a **signed revocation list** is consulted
**fail-closed**. No caller can pin a stale, broader promoted version.

**H8 — The closure and the symbolic→concrete resolution registry are Tier-1 signed artifacts** with
their own SoD review (a security owner, *not* the persona authors) and a re-review SLA triggered on
cloud API-surface change. Compromise of the closure data ≈ forging entitlements, so it earns the same
ceremony as the entitlements it governs.

### Conformance obligations (land as stubs before implementation)

- `capset`: intersection property tests (H1).
- `closure_denylist_test`: `closure ∩ denylist = ∅`, per provider, no-wildcard lint (H2/H3).
- `promotion_sod_test`: identity-bound author≠approver; self-approval refused; second axis enforced for
  `propose`/cross-tier (H4); ownership not resolvable from app-repo input (H5).
- `entitlement_lifecycle_test`: revoked/superseded version refused; code-revision mismatch refused (H6/H7).

## Open questions (genuinely undecided — adopter-shaped, not security-load-bearing)

- The exact `OperatePersona` schema fields + the `class` enum closed set (the *closure* governance is
  now decided in H2/H8; the field list is ergonomic detail).
- The promotion port reference impl: GitOps reconciler into an SRE-owned store vs. API submission to an
  adopter GRC — ship both? which first? (Either satisfies H4/H5; this is sequencing, not safety.)

## Links

- Pairs with [ADR-0006 — HI/NHI identity model & wielder-intersection](0006-hi-nhi-identity-and-wielder-intersection.md).
- `GOAL.md` tenets 1, 3, 5; `docs/ARCHITECTURE.md` §5 (seams), §4.2 (cross-repo take-the-max).
- Prior art: in-toto/SLSA signed attestations; OPA bundle build/sign/promote (Styra DAS); SPIFFE/SPIRE
  registration (selectors vs self-assertion); Backstage `catalog-info` (binding/ownership only — its
  "file is authoritative" semantics are deliberately NOT inherited); AWS Cedar / OPA Rego as
  `PolicyEngine` backings; Teleport/ConductorOne/Entitle for the SoD/approval seam.
