# 6. Human & Non-Human Identity model, and the wielder-intersection

- **Status:** Draft (proposed — under review)
- **Date:** 2026-06-27
- **Deciders:** Console7 maintainers
- **Supersedes / Superseded by:** —

> ADRs capture a single, significant, hard-to-reverse choice (see `docs/adr/0001-language.md`). This one
> is a **DRAFT for review**; it is not yet Accepted. It is the foundational identity model that
> [ADR-0005](0005-entitlement-sourcing-and-persona-as-code-promotion.md) (entitlement sourcing) mints
> into. **Getting this wrong is a re-foundation, not a refactor** — hence the deliberate ADR before the
> operate-lane build.

## Context

Every Console7 session runs an agent under a **per-session Non-Human Identity (NHI)** bound to the
**Human Identity (HI)** that launched it, with lineage human → NHI → action signed by the key broker.
The product's guarantees (evidence, observe≠actuate, least-privilege) all rest on this binding.

Three things make the current model insufficient for Phase 2/3 and expensive to retrofit later:

1. **The NHI today is logical-only.** It is an *attestation* identity (`nhi/<session>/<persona>`,
   KMS-rooted, signs commits + evidence) — but it carries **no downscoped *access* credential**. The
   agent's actual cloud/SCM reach is not yet derived from, or bounded by, the NHI.
2. **The HI binding is stubbed.** Production authn is a dev assertion under a process-local key (SAST
   #9/#10, banner-flagged); there is no real OIDC IdP, and `PolicySoR` is `FixedPolicySoR`.
3. **The wielder principle is unimplemented.** We want: *an agent can never do something its launching
   human couldn't.* That requires the NHI's access to be the **intersection** of the persona ceiling, the
   target app's ownership, and **the human's own standing entitlements** — a real mechanism, not a
   docstring.

The conflation to avoid: **the NHI is two coherent-but-different things.** An *attestation identity*
(who signed this) and an *access identity* (what credential touched production). We have the first; this
ADR designs the second and welds them.

## Decision

### A. The four-stage trust chain, with the key broker as the single authz/mint chokepoint

1. **Authenticate the HI** via `IdentityProvider` (real OIDC/SSO) → verified subject + group claims +
   the human's standing entitlements (resolvable from the adopter's IdP/IAM).
2. **Check launch rights** — a **distinct authorization** from the persona's entitlements: *may this HI
   launch this persona, in this env, for this app?* Resolved from the PolicySoR (itself sourced as-code,
   per ADR-0005). Launch-rights ≠ entitlements: holding the right to launch a persona is separate from
   what that persona then grants.
3. **Resolve the entitlement set** (ADR-0005) and compute the **effective NHI scope =
   `persona ceiling ∩ target-app ownership ∩ wielder's standing entitlements`** (see §B).
4. **Mint the NHI** at the key broker (the *only* authz/mint point; it holds the signing identity) —
   ephemeral, TTL ≤ session deadline — and project it into each backend at the effective scope.

### B. The wielder-intersection mechanism — credential downscoping (the crux, hard to reverse)

`NHI access ⊆ the human's own standing access` is enforced **mechanically by per-provider credential
attenuation**, not by policy text:

- **GCP** — short-lived token via SA impersonation **with a downscoped credential / IAM Condition**
  bounding to the resolved grant (Credential Access Boundaries).
- **AWS** — STS `AssumeRole` with a **session policy** that is the intersection.
- **GitHub** — installation-token **permission narrowing** to the resolved repo/scope.

The `IdentityProvider` (and `CloudProvider`/`SCMProvider`) seams **must expose attenuation** so the minted
principal is the *intersection*, never a fixed role. **Recommended default: strict subset (attenuation)** —
the agent can never exceed the wielder. A **persona-defined / break-glass** mode (the agent runs broader
than the human's day-to-day, on the *right to launch* alone) is an **explicit, governance-gated, evidenced
exception**, never the default. *(This default vs. exception is the key call to ratify.)*

### C. Two welded NHI facets

| Facet | Purpose | State | Root |
|---|---|---|---|
| **Attestation identity** | signs commits + stamps evidence (who acted) | exists | KMS-rooted CA (key broker) |
| **Access identity** | the downscoped per-provider credential (what touched prod) | **new** | minted from §B at the effective scope |

Both bind to the **same NHI id and the same lineage record**, so every *access* is provably tied to the
*attested* human → NHI chain. Neither facet outlives the session.

### D. Standing vs. ephemeral boundary (tenet 4)

- **Standing** (durable, governed): persona definitions, launch rights, the CA root / signing identity,
  the IdP trust config.
- **Ephemeral** (per session, dies with the deadline): the NHI, both its facets, and every minted token.

No standing production-write credential exists anywhere (tenet 5). The key broker holds the only standing
signing identity; access credentials are always minted fresh and bounded.

### E. Evidence binding

Session-start evidence stamps **HI + the launch-rights decision + the resolved entitlementVersion
(ADR-0005) + persona + NHI id**, so an auditor reconstructs *which human, under which launch authority,
with which policy version, via which NHI, performed which action.*

## Visualised — the trust chain

```mermaid
sequenceDiagram
    actor Human as Human (wielder)
    participant IdP as IdentityProvider (SSO/OIDC)
    participant Orch as Orchestrator
    participant SoR as PolicySoR (authoritative)
    participant KB as Key broker (mint + sign)
    participant Prov as Cloud / SCM provider
    participant EV as WORM evidence

    Human->>IdP: authenticate (SSO)
    IdP-->>Orch: HI assertion (subject, groups, standing entitlements)
    Orch->>SoR: launch-rights? (HI x persona x env x app)
    SoR-->>Orch: allow / DENY (fail-closed)
    Orch->>SoR: ResolvePersona -> PromotedEntitlement (ADR-0005)
    SoR-->>Orch: grant + version (signed)
    Note over Orch: effective scope =<br/>persona ceiling INTERSECT app ownership INTERSECT wielder entitlements
    Orch->>KB: mint NHI (effective scope, TTL <= deadline)
    KB-->>Orch: NHI {attestation facet (KMS-signed)}
    KB->>Prov: attenuate credential (downscoped token / session policy / narrowed install token)
    Prov-->>KB: NHI {access facet (downscoped)}
    Orch->>EV: stamp HI + launch decision + entitlementVersion + persona + NHI
    Note over Prov,EV: agent acts within the access facet; every action attributed to the attested NHI
```

## Identity model at a glance

```mermaid
flowchart LR
    subgraph STANDING["Standing (governed)"]
        PD["persona defs"]
        LR["launch rights"]
        CA["CA root / signing identity"]
    end
    subgraph EPH["Ephemeral (dies with session deadline)"]
        NHI["per-session NHI"]
        ATT["attestation facet<br/>signs commits + evidence"]
        ACC["access facet<br/>downscoped per-provider token"]
    end
    HI["Human Identity<br/>SSO subject + standing entitlements"]
    HI -->|"binds (lineage)"| NHI
    LR -->|"gates launch"| NHI
    PD -->|"ceiling"| ACC
    HI -->|"wielder cap (intersection)"| ACC
    CA -->|"roots"| ATT
    NHI --> ATT
    NHI --> ACC
```

## Decision drivers

- **Tenet 6 (lineage unbroken) / evidence** — welding attestation + access to one NHI id keeps every
  action attributable.
- **Tenet 5 (observe≠actuate) / least privilege** — the wielder-intersection cap + per-session minting
  prevent an agent exceeding its human or holding standing write.
- **Tenet 4 (ephemeral)** — the standing/ephemeral line.
- **Hard-to-reverse** — the downscoping primitive and the keybroker-chokepoint are load-bearing across
  every provider; choosing them deliberately now avoids a re-foundation.

## Consequences

- **`IdentityProvider` (and `CloudProvider`/`SCMProvider`) seams must expose credential *attenuation*** —
  not just "mint a token for role X" but "mint a token for the *intersection* of a grant and the wielder's
  access." This shapes the seam signatures; getting it absent now is the expensive retrofit.
- **A new access-identity facet** on the NHI, minted per-provider; the keybroker grows from "signs" to
  "signs + mints downscoped access" (still the single chokepoint, still no standing write).
- **Real OIDC IdP** is on the critical path (closes SAST #9/#10) — the dev-assertion stub must go before
  this is real.
- **Break-glass mode** needs explicit guardrails (when run-as-broader-than-human is allowed, who approves,
  how it is evidenced) even though it ships as a non-default exception.

## Open questions (to resolve before Accepted)

- **The wielder default:** strict-subset (recommended) vs. persona-defined vs. configurable-per-persona.
- **The downscoping primitive per `CloudProvider`** — capability-boundary tokens vs. impersonation+condition
  vs. STS session policy; the seam abstraction that covers all of GCP/AWS/GitHub.
- **Launch-rights representation** — is it a distinct as-code artifact, or a facet of the persona
  promotion (ADR-0005)?
- **Cross-repo / multi-app sessions** — composing multiple entitlements under take-the-max-restrictive tier
  while keeping the single-NHI lineage.

## Links

- Pairs with [ADR-0005 — entitlement sourcing & persona-as-code promotion](0005-entitlement-sourcing-and-persona-as-code-promotion.md).
- `GOAL.md` tenets 4, 5, 6; `docs/ARCHITECTURE.md` §2 (lineage), §5 (seams); `docs/THREAT-MODEL.md`.
- Related: SAST #9/#10 (self-attested `--user`/`--attended`, the dev-IdP residual this closes); the key
  broker (`keybroker/`); the `IdentityProvider` seam (`sdk/interfaces/identity.go`).
- Prior art: OIDC Workload Identity Federation; GCP Credential Access Boundaries / downscoped tokens; AWS
  STS session policies; GitHub App installation-token scoping; SPIFFE/SPIRE (attestation vs. self-assertion).
