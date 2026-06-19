# Bootstrapping Console7

How to get this rolling without one-shotting a sprawling control plane. The
principle: **the docs are durable context; you drive with scoped tasks against the
roadmap, in reviewed PRs.**

## Step sequence

1. **Create the repo** (`console7/console7`) and seed it with this skeleton: `LICENSE`
   (Apache-2.0), `README.md`, `GOAL.md`, `CLAUDE.md`, `SECURITY.md`, `.gitignore`,
   and `docs/`.
2. **Lock the repo down *before* any agent work** — this is the dogfood step:
   - Protect `main`; require a reviewed PR to merge; require signed commits.
   - Confirm `.gitignore` covers secrets; never put a real credential in the repo.
   - Add the `SECURITY_CONTACT` and supported-versions placeholders in `SECURITY.md`.
3. **Pick the language now** (it scopes the SDK and all components). Go is the
   conventional fit for a cloud-native control plane and a clean SDK module; the
   engine you wrap is Node/Python, reached over its CLI/Agent SDK regardless. Make
   the call and record it in an ADR (`docs/adr/0001-language.md`).
4. **Start Claude Code in the repo.** It auto-loads `CLAUDE.md`. (Run `/init` if you
   want it to confirm/extend the context file.) Use whichever surface you prefer —
   local CLI, Cowork, or Claude Code on the web. (Building the in-tenant web-CLI
   *using* Anthropic's hosted sandbox is a fair way to feel the gaps you're closing.)
5. **Fire the scoped kickoff prompt below — not the goal prompt.** Let it open a PR.
   Review it like you'd review a contributor: does each change map to a doc section,
   does it touch credentials (it shouldn't), did it redesign anything (it shouldn't).
6. **Proceed down the prompt ladder**, one roadmap phase-gate per PR.

## The kickoff prompt (scaffolding — pre-Phase-0)

Paste this as your first task. It builds the contract surface and nothing behind it.

```text
Read GOAL.md, docs/DESIGN.md, docs/ARCHITECTURE.md, docs/ROADMAP.md and CLAUDE.md.
Do not redesign anything; implement to the spec. If you think a tenet or requirement
is wrong, raise it in the PR description rather than deviating.

Task — scaffolding only; implement NOTHING behind the interfaces yet:
1. Create the repository skeleton exactly as ARCHITECTURE.md §6.3 specifies
   (control-plane/, keybroker/, sandbox/, sdk/, providers/, deploy/, conformance/,
   docs/), with placeholder READMEs stating each directory's responsibility and
   trust tier.
2. In sdk/interfaces, define the provider contracts from ARCHITECTURE.md §5
   (CloudProvider, SecretsProvider, IdentityProvider, SCMProvider, InferenceBackend,
   PolicyEngine, PolicySoR, EvidenceSink, ObserveGateway) as typed interfaces with
   docstrings that state each method's SECURITY contract (what it must never do —
   e.g. SecretsProvider must never return long-lived material to the control plane).
   No implementations.
3. In sdk/testkit and conformance/, scaffold a conformance harness skeleton that will
   later assert each provider implementation upholds its contract: stub test cases
   keyed to the interface methods, no logic yet.
4. Add docs/THREAT-MODEL.md as a placeholder that cross-references DESIGN.md §10 and
   lists the load-bearing abuse classes as headings to be filled later.

Hard rules: touch no credentials; commit no secrets; control-plane code holds no
keys; the sandbox base image and control-plane are distinct artifacts. Open this as
a single PR against a feature branch with a description mapping each change to its
doc section. Do NOT start Phase 0.
```

## Prompt ladder (one phase-gate per PR)

Keep each task this scoped. Full detail and exit criteria are in `docs/ROADMAP.md`.

- **P0 · Scaffolding** *(above)* — skeleton + `sdk/interfaces` contracts + conformance
  skeleton + threat-model placeholder.
- **P1 · Phase 0 — credential & identity spike** — implement `SecretsProvider`
  (a dev/in-memory implementation first), the key-broker minting flow, the per-user
  subscription-token vault model, SSO→NHI binding + commit signing, and the
  attended-only subscription-routing logic — all against the interfaces, bench-tested.
  No orchestration, no UI. Exit: the credential/identity/seam behaviour demonstrated
  in isolation, with the threat-model section for this surface filled in.
- **P2 · Phase 1 — single vertical slice** — one author × T3 GitHub session end to
  end on GCP/Vertex: gVisor sandbox, default-deny egress at the boundary, signed
  commit, immutable evidence, lineage SSO→NHI→commit. Exit: one task, end to end,
  once, deployable in your own GCP project, maintainer-uninvolved.
- **P3 → onward** — operate lane, policy registry + tier × stratum resolution,
  cross-cloud portability, self-governance, GA. Drive each strictly from `ROADMAP.md`.

## Why not just fire GOAL.md's north-star prompt?

Because it's a *destination*, and its own definition of done is Phase 1 — already too
large for one task. Used as a single instruction it invites a plausible one-shot that
quietly breaks its own tenets (scope from an in-repo file, a standing prod
credential, the broker fused into the control plane) and costs more to unwind than to
scope. Keep `GOAL.md` as orientation in `CLAUDE.md`; build from the ladder.
