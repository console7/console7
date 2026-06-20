# 2. Adoption & deployment model: consume-by-pin, GitOps refresh, no runtime phone-home

- **Status:** Proposed
- **Date:** 2026-06-20
- **Deciders:** Console7 maintainers
- **Supersedes / Superseded by:** —

ADRs capture a single, significant, hard-to-reverse choice and the reasoning behind
it (see `docs/adr/0001-language.md`). They are immutable once accepted: to change a
decision, add a new ADR that supersedes this one rather than editing it.

## Context

Console7 deploys into the **adopter's own tenancy**; the maintainer runs nothing
(`GOAL.md` tenet 1). *How* an adopter obtains Console7, stands it up, and — crucially —
**keeps it current** is a foundational choice: it scopes `deploy/`, the release
process (`ROADMAP.md` #11), and the developer/local-dev story, and it is expensive to
revisit once adopters have live deployments wired to whatever update path we pick.
It therefore warrants a recorded decision.

Constraints that bound the choice:

- **Drift is the enemy.** The naïve path — an adopter copies our Terraform/Helm into
  their repo and edits it — diverges permanently from upstream; every refresh becomes
  a manual merge-conflict slog, and security fixes arrive late or never. The model
  must make staying current cheap and make divergence structurally hard.
- **Maintainer-uninvolved, no phone-home (tenet 1).** Nothing we ship may require a
  maintainer-hosted control point, at deploy time *or* at runtime. The line between
  "pull a pinned, signed artifact at build time" (acceptable — it is a package
  dependency) and "the running system depends on us" (forbidden) must be explicit.
- **Least privilege, ephemeral (tenet 4).** The deploy pipeline must not hoard
  long-lived cloud credentials any more than a session does.
- **Multiple deployment targets, none privileged.** The reference target is GCP /
  Kubernetes (`ARCHITECTURE.md` §4); AWS and Azure are parity targets behind the
  provider seams (§5). A **local, single-host Docker (cloudless) target** is also
  in scope — for low-cost development, an MVP that lets Console7 development run *on*
  Console7, air-gapped, and demo use. The adoption model must be expressed
  target-agnostically so it does not privilege the cloud path or block the local one.

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
   verification automation lands with `ROADMAP.md` #11 — it requires real signed,
   provenance'd releases to bump toward. This ADR makes the model normative now so
   `deploy/` is built for it from line one.)*

3. **The model is target-agnostic; the deployment target is pluggable.** The target
   sits behind the provider seams (§5). The reference cloud target is GCP / Kubernetes
   (§4); a **local single-host Docker (cloudless) target is a first-class parallel
   target**, using local-target provider implementations — the production cousins of
   the `sdk/devkit` in-memory fakes (`MemSecrets`, `MemCloud`, …) — composed with
   `docker compose` rather than Helm-on-GKE. The same consume-by-pin + bump-to-refresh
   model applies to both: a compose file pinning image digests is governed exactly as
   a Helm release pinning the same digests is. The local target's topology and its
   provider set are **deferred to that workstream's own ADR**; this ADR only requires
   that the general model accommodate it.

4. **Keyless cloud CD (cloud path only).** Cloud deploy pipelines authenticate to the
   adopter's cloud via **Workload Identity Federation** — the pipeline's OIDC token is
   exchanged for short-lived deploy credentials; **no long-lived service-account key is
   stored in the adopter's git secrets** (tenet 4). This mechanism is scoped to the
   cloud-CD path; the local/dev target needs no federation and MUST NOT require it.

5. **Deploy-time dependency only — no runtime phone-home (tenet 1).** Adopter
   pipelines pull pinned, signed artifacts at **build / deploy time** — a package
   dependency, no different in kind from `go get` or pulling a base image. The
   **running system never depends on a maintainer-hosted endpoint.** Pulled artifacts
   are signature- and provenance-verified (`cosign` / SLSA) before use; that
   verification automation attaches to #11.

6. **Project / billing is the human bootstrap act; one module serves both cloud
   adoption modes.** For the cloud target, the deploy module always operates *within a
   pre-existing `project_id`* — creating the project and linking billing is a
   human-authority bootstrap step (GUI or a thin bootstrap script), never something the
   module does. This caters to **both** adopters who want a **new dedicated project**
   and those deploying into an **existing project**, with one module: new-project mode
   simply adds a create-and-link step ahead of the same apply. *(N/A to the local
   target.)*

7. **`deploy/` is partitioned by target.** Cloud and local compositions live in
   distinct subtrees (e.g. `deploy/gcp/`, `deploy/local/`) with genuinely shared
   pieces factored out (e.g. a common Helm chart). This keeps targets — and concurrent
   workstreams building them — from colliding in one subtree. The adopter config
   *template* is published as a **standalone repository** (`console7-deploy-template`),
   not carried in-tree, so adopters instantiate it without cloning core.

## Decision drivers

- **No-drift updates** are the headline adopter benefit and the reason to invert
  fork-and-edit into reference-and-pin.
- **Tenet 1** forbids any maintainer-hosted path; the deploy-time/runtime line makes
  "pull our signed release" compatible with "we host nothing for you."
- **Tenet 4** extends least-privilege/ephemeral all the way into the CD pipeline via
  keyless federation.
- **One model across targets** lets the same refresh discipline cover the GCP
  reference, AWS/Azure parity, and the local cloudless target — and lets Console7
  development eventually run on a local Console7 MVP without cloud cost.

## Consequences

**Positive**

- Adopters take security and feature updates as small, reviewed, planned bumps;
  divergence is impossible by construction.
- One module covers new-project and existing-project cloud adoption.
- The local Docker target reuses the same seams and the same refresh model — a clean
  path to dogfooding Console7 development on Console7.
- The maintainer stays entirely out of the adopter's tenancy (tenet 1) at deploy time
  and runtime.

**Negative / costs**

- Makes **signed, provenance'd releases (#11) load-bearing**, not just hygiene — the
  refresh and verification story cannot complete until releases are cut and `cosign`
  verification is wired.
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
  tenet 4. Rejected.

## Open items to reconcile (non-blocking)

- **Concurrent local-cloudless deployment workstream.** A separate workstream is
  designing the local single-host Docker (cloudless) target so Console7 development can
  run on a Console7 MVP without cloud compute cost. This ADR governs only the *general*
  adoption/refresh model and explicitly admits that target (Decision §3, §7); the
  target's **topology, provider set, and bootstrap** belong in its **own ADR, which
  should take the next free number (0003+)** — two windows must not both author
  `0002` or edit the same `deploy/` subtree.
- **Refresh automation + signature verification** (Renovate bumps, `cosign verify`,
  SLSA provenance checks in the adopter pipeline) attach to `ROADMAP.md` #11 once
  signed releases exist.
- **Template repository.** `console7-deploy-template` is created and populated with the
  scripts-and-template PR of this track, not by this ADR.

## Links

- `docs/ARCHITECTURE.md` §4 (deployment topology), §5 (provider seams), §6.4 (release
  artifacts), §6.1 (monorepo + standalone SDK + out-of-tree ecosystem).
- `docs/ROADMAP.md` — #11 (signed release, SBOM, SLSA, cosign), #12 (`deploy/`
  Terraform + live integration run).
- `GOAL.md` — tenet 1 (adopter tenancy is the boundary; no phone-home), tenet 4
  (least privilege / ephemeral), tenet 5 (human actuates), tenet 6 (evidence /
  supply chain).
- `deploy/README.md` — reference-deployment responsibility statement.
- `docs/adr/0001-language.md` — the ADR that established this record format.
