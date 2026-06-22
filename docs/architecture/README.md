# Console7 — Architecture Pack

A multi-viewpoint, **diagrams-as-code** architecture description of Console7, produced by
reading the four repositories (`console7/console7`, `console7-cloud-local`,
`console7-deploy`, `console7-deploy-template`) — not from guesswork. Every diagram is
**Mermaid** so it renders on GitHub and can be restyled later (each uses `classDef` for
theming). Diagrams use robust `flowchart`/`sequenceDiagram` syntax (not the experimental
Mermaid C4 dialect) for reliable GitHub rendering; the C4 *levels* are noted in titles.

> **Status of the system.** Console7 is pre-alpha. The credential/identity/evidence **core
> is implemented** (orchestrator, PDP, key broker + signing, evidence WORM, and the
> GCP/GitHub/Vertex/Anthropic/GCS reference providers), and the **authoritative sandbox
> boundary is now largely landed** — gVisor isolation, per-session default-deny egress
> (NetworkPolicy on Dataplane V2), Cloud NAT, and node-SA metadata concealment
> (`providers/cloud-gcp` #41, `modules/gke` #43), and the **engine-invocation seam** —
> `Cloud.RunTask`→`EngineResult` with real-commit-digest signing (#47), plus in-sandbox
> `git`/`ca-certificates` (#48). The **sandbox base image** now also has a real
> **signed-release pipeline** (build → SBOM → SLSA provenance → keyless cosign sign, distinct
> identity enforced). Still **target state**: the out-of-band FQDN-allowlist egress **proxy**
> (PR-3), **DLP**, the **Observe Gateway**, the **MCP allowlist**, the consumer-side image
> **digest pin** (B3), and the engine's **live in-pod integration** (Tier-2). The views
> mark this explicitly — **faded + dashed = target state**. See
> [Reviewer observations](#c-reviewer-observations).

## The views

| # | View | Purpose (one line) |
|---|---|---|
| [01](01-system-context.md) | **System context (C4 L1)** | Who/what Console7 talks to and the one boundary crossing (model inference). |
| [02](02-functional-logical.md) | **Functional / logical (C4 L2 containers)** | The deployable building blocks, responsibilities, trust tiers, sync vs async. |
| [03](03-component-view.md) | **Component view (C4 L3)** | Internals of the key broker, orchestrator, and evidence sink — where invariants live. |
| [04](04-runtime-behaviour.md) | **Runtime behaviour (sequences)** | Session lifecycle, authN/authZ, the data-egress crossing, and the operate lane. |
| [05](05-deployment.md) | **Technical / deployment** | GKE-on-GCP topology, networks, IAM, release artifacts, and the local target. |
| [06](06-data-flow-trust-boundaries.md) | **Data flow & trust boundaries (STRIDE-ready DFD)** | Data classes, stores, boundary crossings, and a per-boundary STRIDE table. |
| [07](07-technology-lifecycle-controls.md) | **Technology lifecycle & controls** | commit→run SDLC swimlanes with control gates and the evidence each produces. |
| [08](08-dependency-supply-chain.md) | **Dependency / supply chain** | First- vs third-party, notable OSS, runtime placement, and the wrapped engine. |

## Reading conventions (consistent across all views)
- **Status markers:** ✅ implemented (read in source) · ◻ scaffold/placeholder or tracked
  target · ⬡ pluggable seam · **(assumed)** inferred from the normative docs, not confirmed
  in code.
- **Target-state rendering (visual):** elements **not yet coded & landed** are drawn **faded
  with a dashed border** (flowcharts — a lighter `*Plan` class variant) or inside a **shaded
  `rect`** (sequence diagrams), in addition to the ◻/(planned) text marker. Solid = implemented
  & landed. *(Cross-view nuance: a box can be solid in one view and faded in another when the
  question differs — e.g. a component's code exists but its deployment infra isn't provisioned.)*
- **Trust tiers / colours:** Tier-1 control plane (blue), key broker (purple, *separate*
  artifact), data-plane sandbox (red, untrusted), SDK seams (green), reference providers /
  OSS (amber), stores (grey).
- **Canonical names** (used everywhere): personas **Author** / **Operate**; the nine seams
  `CloudProvider`, `SecretsProvider`, `IdentityProvider`, `SCMProvider`, `InferenceBackend`,
  `PolicyEngine`, `PolicySoR`, `EvidenceSink`, `ObserveGateway`; domain types `Subject`,
  `SessionID`, `Tier`(T1–T4), `Stratum`(S1–S5), `TierStratum`, `SessionProfile`,
  `CredentialRef`, `SessionIdentity` (NHI), `SandboxSpec`/`Handle`, `EgressPolicy`,
  `EvidenceRecord`/`RecordRef`, `Signature`/`SinkSignature`.

## Keeping this pack current
When a change touches an architecture-significant surface (`sdk/interfaces`,
`control-plane`, `keybroker`, `providers`, `sandbox`, `deploy`, `scripts`,
`.github/workflows`, or `go.mod`), refresh the affected view(s) with the
**`architecture-docs`** skill
(`.claude/skills/architecture-docs/`) — it maps each code area to its view, enforces the
conventions above, and ships an offline Mermaid validator. The `pre-pr-review` workflow
runs an *architecture-docs currency* lens and the pre-push Bash guard prints a
non-blocking nudge when an architecture-significant change lands without a
`docs/architecture/` update (defence-in-depth, tenet 2 — never a gate).

## Sources read
Normative docs (`GOAL.md`, `docs/DESIGN.md`, `docs/ARCHITECTURE.md`, `docs/ROADMAP.md`,
`docs/THREAT-MODEL.md`, `docs/RISKS.md`, `docs/adr/000{1..4}`, the SDLC standard); all Go in
`sdk/`, `control-plane/`, `keybroker/`, `providers/`; `deploy/gcp` Terraform + bootstrap; all
`.github/workflows`; `socket.yml`, `.golangci.yml`, `.gitleaks.toml`; and the
`console7-cloud-local`, `console7-deploy`, `console7-deploy-template` repos.

---

## (a) Assumptions made
Elements drawn from the normative spec/process but **not confirmed in code** (marked
**(assumed)** in the views):
1. **IdP and GitHub as federated SaaS** placement on the context diagram (both are pluggable
   seams; reference = Okta/Entra OIDC, GitHub App).
2. **Operate lane & Observe Gateway behaviour** (read-only IAM, redaction, query audit) —
   specified in `DESIGN.md` §5.4. The `policyHelper` render + the operate **mutating-command
   tripwire** binary exist (PR-3); the read-only IAM identity + Observe Gateway are not yet wired.
3. **Bedrock / AWS / Azure** backends and **cross-cloud** inference topologies — admitted by
   `ARCHITECTURE.md` §4 + ADR-0004; only GCP+Vertex+direct-Anthropic exist in code.
4. **Production signing root** (Sigstore-keyless or org CA) replacing the in-process
   `DevCA`; **release images** and their **distinct signing identities** (no Dockerfiles in
   tree).
5. **In-cluster topology** (GKE gVisor node pool, VPC/firewall/NAT, NetworkPolicy, egress
   proxy) — the `gke`/`networking` Terraform modules are stubs.
6. **SSE-streamed Web-CLI UI**, **MCP allowlist composition**, **SCIM offboarding**,
   **HA/break-glass** postures, **canary-upgrade automation**, and the **AI (Codex) external
   review gate** — all from prose/process, not code.
7. **Live engine egress + per-tool-call evidence emission** from the sandbox (the inner
   agentic loop of `ARCHITECTURE.md` §7).

## (b) Residual gaps the code did not let me determine
1. **Exact sandbox/network topology** — pod/namespace layout, NetworkPolicy rules, node-pool
   shape, and whether egress is forward-proxy + firewall or firewall-only (modules stubbed).
2. **The real `IdentityProvider` and `PolicySoR` adapters** — production OIDC/JWKS rotation
   and the GRC registry integration; today only `devkit.DevIdentity` and
   `devkit.FixedPolicySoR` (fixed T3/S1) exist.
3. **DLP engine** — scanner choice, rule set, and where exactly it sits relative to the
   commit/egress path (README-only).
4. **`inference-router` as a container** — routing logic lives in `broker.ResolveInference`
   + the backends; whether it becomes a distinct process is undetermined.
5. **Checkpoint durability + SIEM webhook** — signed checkpoints are in-memory in the Sink;
   the SIEM `Stream` is a ref-integrity check, not a wired, authenticated webhook.
6. **Image build/sign/SBOM/provenance pipeline** — landed for the **sandbox base image**: the
   Dockerfile (#45, now digest-pinned bases), the AR publish destination (`modules/artifact-
   registry`, `immutable_tags`), and the **release workflow** (`sandbox-image-release.yml`: SBOM +
   SLSA provenance + keyless cosign sign + an enforced identity pin). Still open: the **control-
   plane / key-broker** image pipelines, **SLSA-L3** + admission-time verification, and the
   consumer-side **digest pin** (`Config.SandboxImage` `@sha256`, B3).
7. **Break-glass actuation mechanism** and **closed-loop remediation bounds** — design-level
   only.

## (c) Reviewer observations
What a second-line (2LoD) reviewer should flag, roughly in priority order:

1. **The controls of record have now substantially landed.** Tenet 2 makes least-privilege
   IAM + **default-deny egress** the authoritative controls. As of #39/#41/#43 these are real:
   **gVisor syscall isolation**, **per-session default-deny egress** (NetworkPolicy on Dataplane
   V2), **Cloud NAT**, and **node-SA metadata concealment** (`providers/cloud-gcp`, `modules/gke`)
   — on top of the already-implemented cryptographic layers (signing, evidence chain, seam
   refusals) and — as of #47/#48 — the **engine-invocation seam** (`Cloud.RunTask`→`EngineResult`
   with real-commit-digest signing; in-sandbox `git`/`ca-certificates`). What **remains target
   state**: the **out-of-band FQDN-allowlist egress proxy** (PR-3), **DLP**, the **Observe
   Gateway**, the **MCP allowlist**, the **release/signing pipeline**, and the engine's **live
   in-pod integration** (Tier-2). The residual gap is now the *content-aware* egress
   controls (FQDN allowlist + DLP) and the operate lane — not the coarse boundary, which is in place.
2. **Evidence integrity vs the privileged provisioning identity (SoD gap).** The GCS evidence
   bucket is only **tamper-evident** until `is_locked=true` (off by default, `RISKS.md` R-2),
   and the **APPLY SA holds `roles/storage.admin`** — so the very identity that provisions
   can delete/rewrite evidence objects (and alter retention) **before** the lock is set.
   Recommend: enable bucket-lock in production *and* separate evidence-bucket administration
   from the general Terraform APPLY identity.
3. **Single-maintainer governance.** `CODEOWNERS` is one owner and `enforce_admins` is off
   (tracked target #1), so the **human-review leg of CO-4 SoD is unmet** and an admin can
   bypass branch protection / self-merge. Automated gates + AI review compensate, but this is
   the top governance risk until a second independent reviewer exists.
4. **`DevCA` is a dev-only trust root.** All lineage/commit/checkpoint signatures currently
   chain to an in-process Ed25519 root. "Evidence over attestation" (tenet 7) is bench-grade
   until Sigstore-keyless/org-CA lands; ensure `DevCA` can **never** reach a release build.
5. **First distinct-signing-identity artifact landed; others still aspirational.** The
   **sandbox base image** now has a real signed-release pipeline (`sandbox-image-release.yml`:
   SBOM + SLSA provenance + keyless cosign sign, with the distinct identity **enforced** by an
   always-on wrong-identity-rejection test) — so "distinct trust tiers ship as distinct signed
   artifacts" is realized for the one image that runs untrusted code. The **control-plane and
   key-broker** images have no pipeline yet, and **SLSA-L3** + **admission-time** signature
   verification (CO-5.3/5.4) remain tracked, so the guarantee is partial, not complete.
6. **Provider co-location discipline.** `scm-github` handles short-lived **token material**
   and belongs in the **key-broker** artifact; a deployment that folds it into the control
   plane would breach key isolation (TB2). The build/deploy split that enforces this is not
   yet codified.
7. **AuthZ is a single fixed lane.** Cross-tier **take-the-max + step-up** and
   `PolicyEngine.Evaluate` are unimplemented (P3); cross-repo reach is not yet gated, and
   `PolicySoR` is a fixed in-memory map — so the privilege-escalation mitigation and the
   "scope from the authoritative system-of-record" guarantee are design-only today.
8. **APPLY SA privilege + optional protected environment.** The deploy `APPLY SA` is
   broadly privileged (KMS/IAM/storage admin); `refs/heads/main`-only WIF binding is good,
   but the protected `console7-apply` environment is **optional/recommended** and unavailable
   on some GitHub plans — on those, `terraform apply` can run on push to `main` **without an
   independent reviewer**. Make the protected environment a hard prerequisite in adopter docs.
9. **Checkpoint tail-truncation residual.** With checkpoints held in memory, a crash can
   leave an unsealed tail; `Verify` detects an uncovered tail but the records' durable
   sealing depends on the (planned) checkpoint persistence.
10. **Inherent subscription-token exposure.** The one stored credential is unavoidably
    agent-readable **inside its own session**; the mitigations are blast-radius only
    (per-user isolation, no pooling, default-deny egress, planned DLP). Subscription mode
    should not be enabled in anger before those egress/DLP controls are live.
11. **Toolchain-pin maintenance burden.** `go 1.25.11` is pinned to dodge `.0` stdlib CVEs —
    correct, but it requires active bumping when `govulncheck` flags newer fixes; treat as an
    operational control, not a set-and-forget.
