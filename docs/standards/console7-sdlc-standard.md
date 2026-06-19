# Console7 Repository SDLC Standard

*Status: DRAFT for maintainer review · Owner: Console7 maintainers (1LoD) · Review cadence: quarterly or on material change*
*Derives from: a "Secure Software Development Lifecycle (SDLC) Standard" (19 control objectives, CO-1…CO-19) written for a fully-modernised G-SIB. This is Console7's **proportionate tailoring** of that standard for **the Console7 repository itself** — a controlled management-system artifact in its own right (parent CO-1.5). It is enforced by CI gates, branch protection, and the OpenSSF Scorecard — not by this prose.*

---

## 1. Scope — what this governs (and what it does not)

This standard governs **the engineering of the Console7 repository itself**: the
control plane, key broker, sandbox, SDK, providers, and docs that live here, and the
agentic configuration artifacts (`.claude/` skills, agents, commands, hooks) used to
build them. It is Console7's expression of its own tenet 8 — *"it governs itself"* —
and of the open-source posture the ROADMAP says is "built in from Phase 1, not bolted
on".

It must **not** be conflated with two adjacent things:

1. **The product's control objectives.** Console7-the-product brings the *same*
   19-CO framework online *as runtime capabilities* for adopters, sequenced in
   [`docs/ROADMAP.md`](../ROADMAP.md) (CO-04 source integrity, CO-08 secrets/NHI,
   CO-06 pipeline integrity, CO-14 evidence, …). That is product delivery. **This
   document is about how *we build Console7*, not what Console7 *does* for an
   adopter.** The two instances share a framework, deliberately; they are not the
   same control set.
2. **The adopter's own SDLC.** Console7 ships a conformance suite (Phase 5) so an
   adopter can evidence *their* obligations. This standard is the maintainers'
   posture, not the adopter's.

A reflexive note worth stating once: Console7 is **both** an S5-agentic system *and*
**built by** S5-agentic tooling (Claude Code). CO-12 therefore binds this repository
twice over — as the modality that authors the code, and as the class of artifact the
product is. §4/CO-12 treats both.

## 2. Proportionality basis — tier and stratum

The parent standard tiers by **criticality × authoring stratum** (parent §5–§6).
Console7 sits at the **top of the matrix**, and says so deliberately:

| Axis | Assignment | Basis |
|---|---|---|
| **Criticality tier** | **Tier-1 — Critical** | Runs untrusted agent code, holds the keys to many sandboxes, and is meant to be trusted inside other organisations' tenancies (`SECURITY.md`, `DESIGN.md` §10). A compromise here is a supply-chain compromise of every adopter. |
| **Authoring stratum** | **S1 Engineered + S5 Agentic** | Full professional toolchain (Go, VCS, CI) **and** agent-authored, with in-repo agentic configuration artifacts that are themselves software (CO-12.8). |

Console7 takes **no proportionate relief** on tier — it claims the heaviest column
(CO-4.4 segregation of duties, CO-6.4 independent production approval, CO-5.3 SLSA L3,
CO-7.4 independent testing, CO-12.6 human gate). The only thing that bounds "now" is
**timing**: the repository is pre-Phase-0 (docs + skeleton; no Go code, no build
artifacts, no deployment from this repo yet), so a control that needs an artifact that
does not exist is a **tracked target with a date** (§5), never a dropped objective.

> **Preventative-first rule (parent §7.1).** *A prohibition without prevention
> manufactures undiscovered debt.* Where a control cannot fully bind yet, its
> **preventative mechanism is wired now** (secret-scanning before any secret can land,
> SHA-pinning before the first action, least-privilege tokens before the first
> workflow, the skills/plugins provenance rule before the first `.claude/` asset).

## 3. Conformance target — OpenSSF, bound at the top

Because Console7 is **public** open source, its controls get an external, measurable
expression that a bank-internal standard lacks — and that is exactly the *"evidence
over attestation"* the parent standard (CO-1.2) and Console7 (tenet 6) demand. We bind
the **maximal** OpenSSF posture from commencement:

| Programme | Target (now) | Trajectory |
|---|---|---|
| **OpenSSF Scorecard** | Run **locally / on-demand**, kept **private for now** — *not* in public CI. (On a public repo, Actions logs and artifacts are world-readable, so a CI run cannot be private; the score is read locally instead.) The checks are the internal evidence of CO-4/5/6/7/8/11. | **Publish the score + badge, and move it into CI (runtime image digest-pinned), when there is something meaningful to share** (≈ first release / critical mass); then hold ≥ target and treat regressions as findings (CO-18). |
| **OpenSSF Security Baseline (OSPS)** | **Level 3** (the high-value/critical tier) is the binding bar. Criteria that need build artifacts are carried as dated accepted-gaps (§5). | All L3 criteria demonstrably met by GA. |
| **OpenSSF Best Practices Badge** | **Silver** is the target; "passing" criteria met as gates land. | Gold at/after GA, when two-person human review and full release provenance exist. |

OpenSSF Scorecard + the Best Practices Badge are also Console7's expression of the
parent's **maturity-assessment** requirement (CO-1.5's CMMI/BSIMM/SAMM tail): for a
public OSS project these *are* the maturity signal, so that tail is **mapped, not
dropped**.

## 4. Disposition of all 19 control objectives

Legend — **Adopt** (binds now; mechanism live or wired) · **Target** (kept as a
CO-1.3 accepted-gap with a date + interim slice; binds when the artifact it needs
exists) · **Drop** (reasoned N/A, recorded — not carried as debt).

| CO | Objective | Disposition | Console7-repo posture (and OpenSSF expression) |
|---|---|---|---|
| **CO-1** | Governance, ownership, tiering | **Adopt** | 1.1 owner = maintainers (1LoD); tier = T1 (§2). 1.2 evidence-based — Scorecard (private now) + signed history + dated reviews. 1.3 exception register = §5. 1.4 risk-committee reporting → the **public standard + threat model + quarterly review of this doc** is the transparency substitute now; the **public Scorecard badge joins when results are meaningful to publish** (§3). 1.5 controlled artifact = **this document**. *(OSPS: Governance.)* |
| **CO-2** | Secure-by-design & threat modelling | **Adopt** | Threat model = `DESIGN.md` §10 + `docs/THREAT-MODEL.md` (placeholder, filled in P0). Paved road = the provider-seam architecture (`ARCHITECTURE.md` §5). |
| **CO-3** | Developer enablement & competency | **Adopt** (relax 3.3) | 3.1/3.2 approved toolchain = Go + Claude Code (the only approved AI tool, CO-12.1); RBAC = GitHub org + WIF on any minted identity. 3.3 formal training: N/A for a small maintainer set — recorded as accepted. |
| **CO-4** | Source integrity & change provenance | **Adopt; human-review leg = Target** | 4.1 protected history ✓ (linear history, no force-push). 4.2 **signed commits required ✓ now** — public repo unlocks the ruleset Linden-class private repos cannot. 4.3/4.4 **technical SoD bound for contributors now** (required review + required status checks; no self-approve; **DCO sign-off** on every commit). Two single-maintainer reductions are dated accepted-gaps (§5 #1): the **independent-*human*-reviewer** leg, and **`enforce_admins`** (the lone maintainer retains admin bypass until a second maintainer / critical mass) — both compensated by automated gates + AI security review + the mandatory human merge gate. *(Scorecard: Branch-Protection, Code-Review, Signed-Releases-prep; OSPS: Access Control.)* |
| **CO-5** | Supply-chain integrity | **Adopt (preventative) + Target (artifacts)** | 5.1 approved registries — Go module proxy + checksum DB; actions **SHA-pinned from workflow #1**. 5.5 pinning ✓ now (Dependabot keeps pins fresh). 5.2 SBOM, 5.3 SLSA L3 provenance, 5.4 signed artifacts + admission = **Target** (no build artifact exists yet) — §5. *(Scorecard: Pinned-Dependencies, Dependency-Update-Tool; OSPS: Build & Release.)* |
| **CO-6** | Build / CI/CD integrity | **Adopt (preventative) + Target** | 6.1 pipelines-as-code ✓. 6.3 **least-privilege `GITHUB_TOKEN` (`permissions: contents: read`) from workflow #1**; no `pull_request_target` foot-guns. 6.5 tamper-evident logs ✓ (Actions). 6.2 ephemeral hardened builders, 6.4 independent prod-approval gate = **Target** (no build/deploy from this repo yet). *(Scorecard: Token-Permissions, Dangerous-Workflow.)* |
| **CO-7** | Continuous security testing | **Adopt (secrets now) + Target (rest)** | 7.1 **secrets scan live now** (gitleaks CI + GitHub native secret-scanning & push-protection — free on public). SAST (**CodeQL — free on public**), SCA (`govulncheck` + Dependabot), IaC scan, image scan each **switch on when the artifact they test lands** (Go code / `go.mod` / `deploy/` / images). 7.3 blocking thresholds ✓. 7.2 DAST, 7.4 pentest/red-team, **fuzzing** (Go native) = **Target** (§5). 7.5 no prod data in tests — N/A (no prod data). *(Scorecard: SAST, Fuzzing; OSPS: Quality.)* |
| **CO-8** | Secrets, keys, non-human identity | **Adopt (strength)** | No secret in the repo (`.gitignore` + gitleaks **block-on-detect** + GitHub **push protection**). No long-lived secret at rest (tenet 4). WIF/OIDC for any future minted identity. This is Console7's core competence; the repo holds itself to it. |
| **CO-9** | Infrastructure & config as code | **Target** | Binds when `deploy/` exists (Terraform/Helm); policy-as-code (trivy/checkov, fail-closed) lands with it. No infra code in-repo yet. |
| **CO-10** | Deployment safety & resilience | **Drop-for-now (N/A)** | Nothing is deployed *from* this repo today. The product's deployment-safety controls are ROADMAP work; re-evaluated if/when this repo gains a deploy path. |
| **CO-11** | Vulnerability response & post-release | **Adopt** | 11.1 SBOM vuln-eval (with the §5 SBOM). 11.2 lightweight remediation SLAs defined here (Critical ≤ 7d, High ≤ 30d on T1). 11.3 **coordinated disclosure ✓** (`SECURITY.md` + GitHub Security Advisories; `security.txt`/RFC 9116 as a cheap add). 11.4 decommissioning — N/A. *(Scorecard: Vulnerabilities; OSPS: Vulnerability Management.)* |
| **CO-12** | AI-assisted & agentic development | **Adopt (keystone — binds twice, §1)** | 12.1 approved AI tool = Claude Code ✓. 12.2 AI code = same gates ✓. 12.4 AI use logged — commit `Co-Authored-By` trailers + session evidence. 12.5 in-repo agents = least-privilege scope (binds when `.claude/` agents exist). 12.6 **no agent self-approve/-merge; human merge gate ✓**. 12.7 **skills/plugins are supply-chain inputs — first-party-curated or self-authored only; any third-party `SKILL.md`/plugin is a reviewed, version-pinned, in-repo dependency** (rule stated now, **preventatively**, before the first asset lands). 12.8 **agentic artifacts are code** — `.claude/` assets version-controlled + reviewed + rollback-capable. 12.9 scope-derived tiering = Console7 tenet 3. 12.10 behavioural eval suite = **Target** (when in-repo agents exist). |
| **CO-13** | Low-code / citizen development | **Drop (N/A)** | No low-code/no-code platform. Agentic artifacts are governed under CO-12 (S5), not here. Reasoned exclusion. |
| **CO-14** | Evidence, auditability & records | **Adopt** | git + signed commits + Actions logs + dated security reviews + Scorecard results + `SECURITY-INSIGHTS.yml`. 14.2 traceability — **every PR body maps each change to the doc section / CO it implements** (PR template; already a CLAUDE.md rule). |
| **CO-15** | Functional QA & test strategy | **Target** | Binds with the first Go code (P0): table tests + the SDK conformance suite as the release gate (`conformance/`). No code to test yet. |
| **CO-16** | Non-functional quality & resilience | **Target** | Observability-by-design is a product requirement (`DESIGN.md`); NFR/perf/chaos bind as services materialise. |
| **CO-17** | Code quality, maintainability, tech debt | **Target → Adopt at first code** | Lint (`gofmt`, `go vet`, `golangci-lint`) wired as a blocking gate the moment `go.mod` lands; tech debt tracked in a RISKS register. |
| **CO-18** | Defect, problem & continuous improvement | **Adopt** | Root-cause → update **this standard**, the paved roads, and the gates. Scorecard `Maintained` + Dependabot cadence are the live signals. |
| **CO-19** | Regulated workloads (RTS 6) | **Drop (N/A)** | No trading systems. Reasoned exclusion. |

## 5. Tracked targets (kept, not struck) — interim slice + trajectory

These are the OSPS-L3 / Tier-1 controls that **cannot fully bind until an artifact
that does not yet exist is created**. Each is a CO-1.3 accepted-gap: named, dated,
with a cheap interim slice and a full trajectory. This is the **complete** set of
exceptions Console7 carries at commencement — there are no silent gaps.

| # | Target (CO / OSPS) | Why it can't fully bind yet | Interim slice (now) | Full trajectory |
|---|---|---|---|---|
| 1 | **Independent human review + maintainer admin-bypass** (CO-4.3/4.4; Badge silver/gold) | Single maintainer: no second human reviewer, and flipping `enforce_admins` now would gate the lone maintainer out of their own merges | Branch protection binds all contributors; automated gates + AI security review on every PR + **mandatory human merge gate** | At **critical mass / a second maintainer** (targeted before GA): flip **`enforce_admins: true`** (maintainer PRs everything too) and require **independent human approval** |
| 2 | **SBOM** (CO-5.2; OSPS Build&Release) | No release artifact to describe | Document the CycloneDX/SPDX plan; wire it into the first build | SBOM generated at build, bound to artifact digest, vuln-evaluated continuously |
| 3 | **SLSA L3 provenance** (CO-5.3) | No build pipeline / artifact | Plan the hardened ephemeral builder (GH Actions OIDC + `slsa-github-generator`) | L3 provenance on every released artifact |
| 4 | **Signed releases + admission** (CO-5.4; Scorecard Signed-Releases) | No release exists | Decide signing identity now (cosign keyless / Sigstore); distinct identities per artifact tier (`ARCHITECTURE.md` §6.4) | Sign on release; verify-on-admission rejects unsigned/unattested |
| 5 | **DAST/IAST** (CO-7.2) | No running service | — | Authenticated dynamic scans pre-release per service |
| 6 | **Independent pentest / red-team** (CO-7.4) | Nothing deployable to test | Threat-model review (CO-2) | Independent engagement before GA / first adopter-facing release |
| 7 | **Fuzzing** (Scorecard Fuzzing) | No Go fuzzable surface yet | — | Go native fuzz targets on parsers/policy-eval when they exist; OSS-Fuzz at GA |
| 8 | **Behavioural eval suite for in-repo agents** (CO-12.10) | No in-repo `.claude/` agents yet | State the rule (CO-12.8) preventatively | Eval suite gates changes to any in-repo agent/prompt/tool |

## 6. Deliberate exclusions (reasoned N/A — do not carry as debt)

- **CO-13 low-code / no-code citizen development** — no such platform exists. Agentic
  artifacts are governed under CO-12 (S5), not as UDAs.
- **CO-19 RTS 6 algorithmic-trading obligations** — no trading systems.
- **CO-7.5 production-data-in-test controls** — Console7 holds no production data.
- **CO-1.5 CMMI/BSIMM/SAMM as a separate maturity programme** — **mapped, not run
  separately**: OpenSSF Scorecard + Best Practices Badge are the OSS-native maturity
  assessment (§3).

## 7. Implementation = the gates (this doc does not enforce itself)

The parent standard's thesis is that **the pipeline is the control plane and the
evidence store**. This document is the *posture*; the **gates are the enforcement**.
The bootstrapping gate set (separate, reviewable PRs that each cite the CO(s) and OSPS
control they satisfy):

1. **Repo-governance gates** — gitleaks secret-scan CI (full history, checksum-
   verified; + GitHub native secret-scanning & push-protection), SHA-pinned actions,
   least-privilege `GITHUB_TOKEN`, Dependabot (actions; Go modules when `go.mod`
   lands), the CO-12.7 governance gate, and CodeQL/`govulncheck` (dormant until Go).
   OpenSSF Scorecard is run **locally/on-demand** (not in public CI) until we publish
   (§3). *(CO-4, CO-5, CO-6, CO-7.1, CO-8.)*
2. **Branch-protection tightening** — required PR review; required status checks
   (once the gates above are green checks); DCO required check. **`enforce_admins`
   stays off** until critical mass / a second maintainer (tracked target §5 #1).
   *(CO-4.4, CO-6.4-prep.)*
3. **OSS-governance docs** — `CONTRIBUTING.md` (DCO), `CODE_OF_CONDUCT.md`
   (Contributor Covenant), `CODEOWNERS`, a thin `GOVERNANCE.md`/`MAINTAINERS.md`,
   `SECURITY-INSIGHTS.yml`, PR template; fill the `SECURITY.md` contact + ACK SLA.
   *(CO-1, CO-11.3, CO-14.)*

> **Pull-forward note.** ROADMAP sequenced `CONTRIBUTING.md` to Phase 1. Authoring it
> (and the OSS-governance set) now is a **deliberate, reasoned pull-forward** under
> the "create no debt / start as we mean to finish" direction and the OSPS-L3 binding
> in §3 — recorded here rather than silently deviating (CLAUDE.md rule).

## 8. How this stays true going forward

1. **This document** is the canonical posture (CO-1.5), reviewed quarterly / on
   material change.
2. **OpenSSF Scorecard** is run on-demand now; once published it runs continuously
   and the public score is the live evidence, with a regression a finding (CO-18).
3. **Every gate PR cites** the CO(s) and OSPS control it satisfies (CO-14.2).
4. **ADRs** (`docs/adr/`) record hard, durable decisions (the language ADR is the
   template).
5. **The product-vs-repo distinction (§1) is maintained** — product control
   objectives are tracked in `ROADMAP.md`; this standard governs only the repository.
6. **CO-18.4 loop** — recurring root causes update this standard, the paved roads,
   and the gates.
