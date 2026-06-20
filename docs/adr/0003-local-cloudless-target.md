# 3. Local single-host (cloudless) target: an out-of-tree provider repository

- **Status:** Proposed
- **Date:** 2026-06-20
- **Deciders:** Console7 maintainers
- **Supersedes / Superseded by:** —

ADRs capture a single, significant, hard-to-reverse choice and the reasoning behind it
(see `docs/adr/0001-language.md`). They are immutable once accepted: to change a decision,
add a new ADR that supersedes this one rather than editing it.

## Context

`docs/adr/0002-adoption-deployment-model.md` (PR #22) establishes that the consume-by-pin /
reviewed-refresh **mechanism is target-agnostic**, while the **supported target set is
mission-bounded**: Console7's mission requires it to run *"entirely inside the adopter's own
cloud,"* so the sanctioned targets today are the adopter's cloud — GCP (reference) with
AWS/Azure parity. A **local single-host (cloudless) target** is desirable (low-cost
development; an MVP that lets Console7 development eventually run *on* Console7) but is **not
sanctioned by the mission as a current target**. ADR-0002 therefore leaves admitting it to
this ADR, via one of **two sanctioned routes**: a **mission amendment**, or an **out-of-tree
community extension** (`ARCHITECTURE.md` §6.1, the out-of-tree ecosystem; `GOAL.md` tenet 9,
*pluggable everything*). This is that decision.

The local target needs a real `CloudProvider` (the production cousin of `sdk/devkit`'s
`MemCloud`), durable evidence, and a way to run `control-plane/orchestrator` end to end with
**no GCP**. The open choice ADR-0002 left is *where that code lives* — in core (e.g. an
in-tree `deploy/local/` plus provider packages) or out-of-tree — and *how much it depends on
core*. That placement is foundational: it shapes whether core's `providers/` stays the
reference set, whether the community-provider path is real, and how the cloudless target
takes refreshes.

Constraints that bound the choice:

- **`providers/` is the reference set only.** `CLAUDE.md` and `ARCHITECTURE.md` §6.1 state
  that core carries a curated reference provider set (GCP/GitHub/Vertex/OPA/GCS) and that
  **community providers live out-of-tree against the published SDK** — long-tail provider
  implementations must not be buried in core.
- **The community-provider path is so far untested.** No out-of-tree provider exists yet, so
  we do not actually know whether `sdk/interfaces` (+ `sdk/testkit`) is a *sufficient* surface
  to build a real provider against, or what else a provider must reach into.
- **ADR-0002's contract.** Whatever we build must be **consume-by-pin, no runtime
  phone-home**, and — for an out-of-tree target — reference the SDK and published artifacts,
  not a fork of core (ADR-0002, Decision §3 and Open Items).
- **Boundary controls are authoritative (`GOAL.md` tenet 3); wrap — don't reimplement — the
  engine (`GOAL.md` north-star principle).** A local target may not weaken default-deny
  egress, and must wrap, never reimplement, the engine.

## Decision

**The local single-host (cloudless) target lives out-of-tree, in a separate, private
repository under the `console7` GitHub organisation** (working name `console7-cloud-local`),
built against the published SDK and pinned core artifacts. This takes the **out-of-tree
community-extension** route — one of the two options ADR-0002 sanctions for admitting a
cloudless target (its Decision §3 and Open Items). Because the target lives outside core as
a community extension, **core's mission stays cloud-only and this ADR requires no `GOAL.md`
amendment.** Concretely:

1. **Out-of-tree, private, org-owned.** The target's provider implementations, its
   `docker compose` composition, and its bootstrap live in their own repo — not in core's
   `providers/` (reference set only) and not in core's `deploy/local/`. It is private for now;
   it goes public on the same milestone cadence as core. **This deliberately makes the local
   target the first real exercise of the community-provider path** (ADR-0002's "out-of-tree
   community targets" route), validating that an external repo can compose Console7 from the
   SDK by pin.

2. **Production cousins of the `sdk/devkit` fakes** (ADR-0002 §3). The repo provides a Docker
   `CloudProvider` (cousin of `MemCloud`), a durable file-backed evidence store behind core's
   `control-plane/evidence.Sink` (cousin of `MemEvidence`), and composes the existing
   `keybroker/signing` dev CA + `sdk/devkit` secrets, driving `control-plane/orchestrator`
   unchanged. All by **pinned** dependency on core (`github.com/console7/console7@vX`); core
   is public, so no private-module auth is required.

3. **Spine-first; engine wrap deferred.** The first deliverable proves the **seams compose
   locally end to end** — provision a real container sandbox, land a verifiable hash-chained
   evidence file, sign an unbroken Subject→NHI lineage, enforce default-deny egress, destroy
   without residue — while keeping the orchestrator's current synthetic-work step. Wrapping
   the **genuine** Claude Code engine (the `GOAL.md` north-star: wrap, do not reimplement) inside the local sandbox, and hardening the
   boundary around live engine traffic, is a **later increment** (it pulls the boundary-first
   sandbox + engine-wrap work forward and is sized accordingly).

4. **Isolation: gVisor target, explicit dev-only fallback.** The target isolation is
   **gVisor (`runsc`)**, matching the cloud reference. A plain-container fallback is permitted
   **only** as an explicit, loudly-documented **dev-only** relaxation that lowers *syscall*
   isolation and **never** relaxes default-deny egress (which stays the authoritative
   boundary — `GOAL.md` tenet 3) and **never** becomes a production posture. On macOS, gVisor runs
   inside a Linux VM (Lima/Colima); that is platform logistics, not a relaxation.

5. **Consume-by-pin, no federation, no phone-home** (ADR-0002 §3/§4/§5). The local target's
   `docker compose` pins the SDK and image digests and is governed exactly as a Helm release
   is; it needs **no** Workload Identity Federation and **no** project/billing bootstrap
   (both cloud-only), and the running system depends on no maintainer-hosted endpoint.

6. **`deploy/local/` in core is not populated.** ADR-0002 contemplates a `deploy/local/`
   partition in core; by placing the target out-of-tree, this ADR resolves that deferred
   placement so core's `deploy/local/` carries no local-target logic — at most a thin pointer
   to the external repo later. *(This fills in ADR-0002's deferred item; it does not edit
   ADR-0002.)*

7. **The new repo is SDLC-governed.** It adopts the Console7 Repository SDLC standard from
   commit one — `.claude/` guards + skills, signed + DCO commits, branch protection, the CI
   gate set (build/vet/test/gofmt, govulncheck, CodeQL, gitleaks, DCO, provenance), and
   `SECURITY.md`/`SECURITY-INSIGHTS.yml` — so the community-provider path is exercised *with
   its governance*, not just its code.

## Decision drivers

- **Keep `providers/` the reference set** and prove the community path is real, rather than
  asserting it — the strongest reason to go out-of-tree for the very first non-reference
  provider.
- **ADR-0002 already sanctions this route**: admitting a cloudless target via an out-of-tree
  community extension is one of the two options it names (Decision §3 and Open Items); taking
  it needs no mission amendment and leaves `GOAL.md` untouched.
- **Isolation of churn**: the local target can iterate (Docker quirks, compose) without
  touching core or colliding with the concurrent GCP/adoption workstream.
- **Tenets preserved unchanged** — `GOAL.md` tenet 1 (no phone-home), tenet 3 (boundary
  authoritative), tenet 5 (ephemeral), tenet 9 (pluggable everything); the engine is wrapped,
  not reimplemented (north-star).

## Consequences

**Positive**
- First end-to-end validation that `sdk/interfaces` (+ testkit) is buildable-against by an
  external repo; findings feed back into the published SDK surface.
- Console7 development gains a no-GCP path toward running on a Console7 MVP.
- Core stays clean: reference providers only; no local-target churn in `providers/` or
  `deploy/`.

**Negative / costs**
- A second SDLC-governed repo to maintain (governance, CI, releases) — real overhead, accepted
  as the price of testing the community path properly.
- Cross-repo version coordination: the local repo pins core and must bump to follow it
  (the same consume-by-pin discipline adopters use — dogfooding it).

**Neutral**
- The engine-wrap increment remains future work, tracked separately; this ADR scopes only the
  cloudless target's placement and its spine-first first cut.

## Open items to reconcile (non-blocking)

- **Published-SDK surface (the key thing this test answers).** Reusing core's durable WORM
  chain and signing means the out-of-tree repo currently imports **core packages beyond the
  published SDK** — `control-plane/evidence` and `keybroker/signing` — not just
  `sdk/interfaces`/`sdk/testkit`. The spike must report whether import-core-by-pin is an
  acceptable contract for community providers, or whether the durable-evidence/signing helpers
  should be **promoted into the published SDK surface**. This finding is recorded back here (or
  in a superseding note) once the spike lands.
- **Coordination with the GCP/adoption workstream.** That workstream owns ADR-0002,
  `deploy/README.md`, and `deploy/gcp/`; this ADR owns 0003 and the out-of-tree repo. Neither
  edits the other's files.
- **Engine wrap + live-traffic boundary** is a later, larger increment (the north-star
  engine-wrap principle + boundary-first), not delivered by the spine-first cut.

## Links

- `docs/adr/0002-adoption-deployment-model.md` — the consume-by-pin adoption/refresh model
  this target follows; mission-bounds the supported targets to cloud and defers the decision
  to admit a cloudless target (mission amendment vs out-of-tree extension) to this ADR.
- `docs/adr/0001-language.md` — the ADR that established this record format.
- `docs/ARCHITECTURE.md` §4 (deployment topology), §5 (provider seams), §6.1 (monorepo +
  standalone SDK + out-of-tree ecosystem).
- `docs/ROADMAP.md` — #11 (signed release / SBOM / SLSA / cosign), #12 (`deploy/` + live run).
- `GOAL.md` — tenet 1 (adopter tenancy; no phone-home), tenet 3 (boundary controls
  authoritative), tenet 5 (least privilege / ephemeral), tenet 9 (pluggable everything — the
  out-of-tree provider route); wrap-the-engine is the `GOAL.md` north-star principle.
- `sdk/interfaces/cloud.go`, `control-plane/evidence/`, `keybroker/signing/`, `sdk/devkit/` —
  the seam contract and the in-tree cousins the local target builds production versions of.
