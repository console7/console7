# 2. Adoption & deployment model: consume-by-pin, GitOps refresh, no runtime phone-home

- **Status:** Accepted
- **Date:** 2026-06-20
- **Deciders:** Console7 maintainers
- **Supersedes / Superseded by:** —

ADRs capture a single, significant, hard-to-reverse choice and the reasoning behind
it (see `docs/adr/0001-language.md`). They are immutable once accepted: to change a
decision, add a new ADR that supersedes this one rather than editing it.

## Context

Console7 deploys into the **adopter's own tenancy**; the maintainer runs nothing
(`GOAL.md` tenet 1). *How* an adopter obtains Console7, stands it up, and — crucially —
**keeps it current** is a foundational choice: it scopes `deploy/`, the release process
(`ROADMAP.md` Phase 1 open-source milestones and Phase 4–5 supply-chain hardening), and
the developer story, and it is expensive to revisit once adopters have live deployments
wired to whatever update path we pick. It therefore warrants a recorded decision.

Constraints that bound the choice:

- **Drift is the enemy.** The naïve path — an adopter copies our Terraform/Helm into
  their repo and edits it — diverges permanently from upstream; every refresh becomes
  a manual merge-conflict slog, and security fixes arrive late or never. The model
  must make staying current cheap and make divergence structurally hard.
- **Maintainer-uninvolved, no phone-home (tenet 1).** Nothing we ship may require a
  maintainer-hosted control point, at deploy time *or* at runtime. The line between
  "pull a pinned, signed artifact at build time" (acceptable — it is a package
  dependency) and "the running system depends on us" (forbidden) must be explicit.
- **Least privilege, ephemeral (tenet 5).** The deploy pipeline must not hoard
  long-lived cloud credentials any more than a session does.
- **Target-agnostic mechanism, mission-bounded target set.** The consume/refresh
  *mechanism* must not privilege one deployment target. But the *supported* targets are
  bounded by the mission — Console7 "must run entirely inside the adopter's own cloud"
  (`GOAL.md` Mission), so the sanctioned targets today are the adopter's cloud: GCP
  (reference, `ARCHITECTURE.md` §4) with AWS/Azure parity (`ROADMAP.md` Phase 4).
  Whether to admit a non-cloud target is a separate, explicit decision (see Decision §3
  and Open Items); this ADR expresses the mechanism target-agnostically so that decision
  is unconstrained either way.

## Decision

Console7's adoption and deployment model is **consume-by-reference, pinned; refresh
by reviewed version bump; deploy-time dependency only.** Concretely:

1. **Consume by pinned reference — adopters never copy-and-edit our code.** An adopter
   holds a *thin config repository* of their own that **references** Console7's
   versioned `deploy` module and the separately-signed images (`ARCHITECTURE.md` §6.4)
   by **pinned version / digest**. They supply *inputs only* (project/host, region,
   policy bindings, SSO config, repo allowlist) — never a fork of Console7's
   deployment logic. Because they hold no copy of that logic, **drift is structurally
   impossible**: there is nothing to diverge.

2. **Refresh is a reviewed version bump.** A dependency bot (e.g. Renovate) in the
   adopter's config repo opens a PR raising the pin (`vX → vY`); their CI runs a
   `plan` and posts the **effect diff** (what infrastructure changes) as a comment; a
   human reviews and merges; CI applies under the adopter's own identity. Adopters
   review a *diff of effects*, never a diff of our source. *(The bot + signature
   verification automation lands with the signed-release work — `ROADMAP.md` Phase 1
   open-source milestones, hardened in Phase 4–5 — which it needs in order to have
   signed, provenance'd releases to bump toward. This ADR makes the model normative now
   so `deploy/` is built for it from line one.)*

3. **Target-agnostic in mechanism; the *supported* target set is governed by the
   mission.** The mechanism above makes no assumption about the deployment target — it
   governs a Helm release on GKE and a `docker compose` stack on a single host
   identically (each pins image digests; each refreshes by reviewed bump). The targets
   Console7 *supports*, however, are set by the normative docs: today the mission
   requires Console7 to run **"entirely inside the adopter's own cloud"** (`GOAL.md`
   Mission; north-star: *"Everything runs in the adopter's GCP/AWS/Azure account"*), so
   the sanctioned targets are the adopter's cloud — **GCP (reference, `ARCHITECTURE.md`
   §4)** with **AWS/Azure parity** (`ROADMAP.md` Phase 4). A **local single-host
   (cloudless) target** — desirable for low-cost development and an MVP that lets
   Console7 development run *on* Console7 — is **not sanctioned by the mission as
   written**, even though it satisfies the deeper trust principle (tenet 1: the
   adopter's *tenancy* is the boundary, and a self-hosted box is the adopter's tenancy).
   *How* to admit it is therefore a **scope decision for the forthcoming ADR-0003** —
   either an explicit normative amendment (the mission and `ARCHITECTURE.md` §4), or
   admitting it as an **out-of-tree community extension** under the existing ecosystem
   route (`ARCHITECTURE.md` §6.1, tenet 9 pluggability), which needs no mission change
   since core would still ship only cloud targets. This ADR deliberately neither adopts
   nor blocks a cloudless target, and does not prescribe which route ADR-0003 takes; it
   only guarantees the consume/refresh mechanism will not need rework either way.
   *(See Open Items.)*

4. **Keyless cloud CD (cloud path only).** Cloud deploy pipelines authenticate to the
   adopter's cloud via **Workload Identity Federation** — the pipeline's OIDC token is
   exchanged for short-lived deploy credentials; **no long-lived service-account key is
   stored in the adopter's git secrets** (tenet 5). This mechanism is scoped to the
   cloud-CD path; any future non-cloud target would not use federation and must not be
   made to require it.

5. **Deploy-time dependency only — no runtime phone-home (tenet 1).** Adopter
   pipelines pull pinned, signed artifacts at **build / deploy time** — a package
   dependency, no different in kind from `go get` or pulling a base image. The
   **running system never depends on a maintainer-hosted endpoint.** Pulled artifacts
   are signature- and provenance-verified (`cosign` / SLSA) before use; that
   verification automation attaches to the signed-release work (`ROADMAP.md` Phase 1
   open-source milestones / Phase 4–5).

6. **Project / billing is the human bootstrap act; one module serves both cloud
   adoption modes.** For the cloud target, the deploy module always operates *within a
   pre-existing `project_id`* — creating the project and linking billing is a
   human-authority bootstrap step (GUI or a thin bootstrap script), never something the
   module does. This caters to **both** adopters who want a **new dedicated project**
   and those deploying into an **existing project**, with one module: new-project mode
   simply adds a create-and-link step ahead of the same apply.

7. **`deploy/` is partitioned by target.** Cloud compositions live under `deploy/gcp/`
   (with AWS/Azure peers as parity lands), genuinely shared pieces factored out (e.g. a
   common Helm chart). Partitioning by target keeps targets — and the concurrent
   workstreams building them — from colliding in one subtree; a `deploy/local/` subtree
   materializes only if ADR-0003 adopts a cloudless target. The adopter config
   *template* is published as a **standalone repository** (`console7-deploy-template`),
   not carried in-tree, so adopters instantiate it without cloning core.

## Decision drivers

- **No-drift updates** are the headline adopter benefit and the reason to invert
  fork-and-edit into reference-and-pin.
- **Tenet 1** forbids any maintainer-hosted path; the deploy-time/runtime line makes
  "pull our signed release" compatible with "we host nothing for you."
- **Tenet 5** extends least-privilege/ephemeral all the way into the CD pipeline via
  keyless federation.
- **One model across targets** lets the same refresh discipline cover the GCP reference
  and AWS/Azure parity uniformly, and — should a cloudless target be admitted
  (ADR-0003) — extend to it without rework.

## Consequences

**Positive**

- Adopters take security and feature updates as small, reviewed, planned bumps;
  divergence is impossible by construction.
- One module covers new-project and existing-project cloud adoption.
- The mechanism is target-agnostic, so admitting a cloudless dev target later
  (ADR-0003) needs no change to how adopters consume or refresh.
- The maintainer stays entirely out of the adopter's tenancy (tenet 1) at deploy time
  and runtime.

**Negative / costs**

- Makes **signed, provenance'd releases load-bearing** (`ROADMAP.md` Phase 1 open-source
  milestones / Phase 4–5), not just hygiene — the refresh and verification story cannot
  complete until releases are cut and `cosign` verification is wired.
- The bot-driven refresh automation is follow-on work, not delivered by this ADR.
- A versioned deploy module is more upfront structure than throwaway config.

**Neutral**

- Out-of-tree community deployment targets follow the same consume-by-pin contract;
  they reference the SDK and published artifacts, not a fork of core.

## Alternatives considered

- **Fork the monorepo + merge upstream.** Drift-prone, carries all of core into the
  adopter's repo, and turns every update into a merge. Rejected.
- **Ship Terraform/Helm to copy and edit.** The drift trap this ADR exists to avoid.
  Rejected.
- **Maintainer-hosted deploy service / phone-home auto-updater.** Most convenient
  refresh UX, but a direct violation of tenet 1 (maintainer-hosted path, egress from
  the adopter's tenancy). Rejected outright.
- **Long-lived service-account keys in CI** instead of federation. Simpler to wire,
  but stores a standing high-privilege cloud credential in git secrets — contrary to
  tenet 5. Rejected.

## Open items to reconcile (non-blocking)

- **Concurrent cloudless deployment workstream → ADR-0003.** A separate workstream is
  designing a local single-host (cloudless) target so Console7 development can run on a
  Console7 MVP without cloud compute cost. Admitting that target is **out of scope for
  this ADR**; *how* to admit it is ADR-0003's to decide — either an explicit normative
  amendment (the mission's "entirely inside the adopter's own cloud" and
  `ARCHITECTURE.md` §4 sanction cloud targets only, though a self-hosted target honours
  tenet 1's *tenancy* boundary), or treating it as an **out-of-tree community
  extension** under the existing ecosystem route (`ARCHITECTURE.md` §6.1, tenet 9), in
  which case core still ships only cloud targets and no mission change is needed. Either
  way, the target's topology/provider-set/bootstrap belong to **ADR-0003** (the next
  free ADR number — two windows must not both author `0002` or edit the same `deploy/`
  subtree). This ADR's mechanism accommodates whichever route ADR-0003 picks, without
  rework; it does not presume one.
- **Refresh automation + signature verification** (Renovate bumps, `cosign verify`,
  SLSA provenance checks in the adopter pipeline) attach to the signed-release work
  (`ROADMAP.md` Phase 1 open-source milestones / Phase 4–5) once signed releases exist.
- **Template repository.** `console7-deploy-template` is created and populated with the
  scripts-and-template PR of this track, not by this ADR.

## Links

- `docs/ARCHITECTURE.md` §4 (deployment topology — Kubernetes in the adopter's cloud),
  §5 (provider seams), §6.4 (release artifacts), §6.1 (monorepo + standalone SDK +
  out-of-tree ecosystem).
- `docs/ROADMAP.md` — Phase 1 open-source milestones (first signed release with SBOM +
  provenance) and Phase 4–5 (fully signed/SBOM'd/provenanced build chain) make the
  refresh + verification automation load-bearing; Phase 5 reference deployments
  (GCP / AWS / Azure) and the Phase 1 exit (deployable in the adopter's own GCP project,
  maintainer-uninvolved).
- `GOAL.md` — Mission ("entirely inside the adopter's own cloud"); tenet 1 (adopter
  tenancy is the boundary; no phone-home), tenet 5 (least privilege / ephemeral),
  tenet 6 (observe is not actuate — the pipeline actuates under a human), tenet 7
  (evidence over attestation; unbroken lineage), tenet 8 (proportionate by
  consequence), tenet 10 (governs itself: signed releases, SBOM, provenance).
- `deploy/README.md` — reference-deployment responsibility statement.
- `docs/adr/0001-language.md` — the ADR that established this record format.
