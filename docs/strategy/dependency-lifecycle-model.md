# A strategic model for dependency lifecycle, maintainability & VM

> Status: working model (strategy note, not a normative spec). Companion tool:
> [`scripts/dep-lifecycle-model.py`](../../scripts/dep-lifecycle-model.py).
> Strategic companion paper:
> [`dependency-risk-energy-model.md`](./dependency-risk-energy-model.md) reframes these
> axes as a potential/kinetic energy model (PE · KE · hazard · drift‑cost · containment).
> Source framing: *"SDLC of the Future — L2 Working Discussion"*, **Part III — The
> Supply‑Chain Watershed** and **Part V — Measuring Distance from Modern**.
> Binds to the repo SDLC standard: **CO‑05** (supply‑chain integrity), **CO‑11**
> (vulnerability response), **CO‑17** (code quality & debt), **CO‑14** (evidence).

## 1. The question

A dependency is not a scan result; it is an **asset whose consequence sets its tier,
and whose tier sets its controls** — the same proportionality machinery as the rest of
the standard, pointed at third‑party code. The estate spent a decade tooling the
*consequences* of unconstrained adoption (SBOM, scanning, patching) and almost nothing
on the *decision to adopt and keep*. This model closes that gap.

It answers one strategic question per dependency: **adopt / keep / migrate / kill —
and how much hygiene toil is genuinely owed?** Three inputs the discussion pack
identifies are decisive, and they are exactly the ones in the brief:

- **Depth (substitutability).** An app that leverages OpenSSL *deeply* (TLS, X.509,
  PKCS) cannot substitute that capability; an app that uses it only for secure‑random
  could rewrite the call over a lunch break. Same package, opposite lock‑in. This is
  the pack's *"industry's unfilled gap"* — judgment, not yet a metric.
- **Breadth (fan‑out / concentration).** One app using OpenSSL is cheap to keep
  hygienic. OpenSSL as the *spine of every app* is concentration risk: fix‑once /
  benefit‑everywhere on a good day, blast‑radius‑everywhere on a bad one, and a
  cost of ownership that grows with the dependent count, not linearly.
- **Reachability.** Of the CVEs you inherit, only those on your **call path** are
  exploitable. Reachability is the leading indicator that decides whether the toil is
  *owed* at all (you inherit 100% of the blast radius but typically reach <10% of it).

## 2. The five axes

The pack's four‑axis watershed, plus the user's framing, collapses to five scored
dimensions. Each is scored `0–3` (higher ⇒ more carry cost / more attention owed):

| Axis | Question | Data source | Tooled today? |
|------|----------|-------------|---------------|
| **R — Reachability** | Is the dependency on a build/exec path? Of inherited CVEs, how many are reachable? | call‑graph / `go list -deps`; reachability‑aware SCA | ✅ established |
| **C — Concentration (fan‑out)** | How load‑bearing is it across the estate? How many things break if it does? | module in‑degree; dependent count; internal fan‑out | ✅ established |
| **H — Health / drift** | Maintenance posture and currency. | OpenSSF Scorecard + Criticality Score; **libyear** drift; abandonment / bus‑factor | ✅ established (SCA/OSSF) |
| **F — Function criticality** | Trivial utility or core capability? On a security‑critical path? | consuming trust **tier × stratum** (the standard's Axis 1) | ✅ via tiering |
| **S — Substitutability** | Inline it, swap the vendor, or are you wedded to it? | **the gap** — two levers: (A) opacity/IP × vendor‑count, (B) reachable‑KLoC × licence | ⚠️ judgment (A) + computed (B) |

**S is the axis the industry under‑measures**, and "effort to replace" is not one
number — it is **two orthogonal levers**, because the two ways a dependency traps you
have different exits:

- **Lever A — opacity / IP barrier (can we rebuild it at all?).** Some dependencies
  front a capability we *cannot reproduce*: a licensed/trade‑secret artifact, or an
  OSS client to a remote managed service (a cloud HSM, a secret store, an SCM API).
  The source we'd need isn't ours to write. The exit is **not a rebuild — it's a
  vendor swap**, and substitutability then turns on whether a *competitor exists*:
  `multi`‑vendor (KMS → AWS KMS / Vault; GitHub → GitLab) is swap‑able, `single`‑vendor
  (a sole‑source trade‑secret moat) is genuine lock‑in. Inputs: `fronts ∈
  {code, service, proprietary}`, `vendors ∈ {multi, single}` — judgment, reviewed as
  code in `CAPABILITY_REGISTRY`.
- **Lever B — reproduction cost (how many K‑lines to rebuild the slice we use?).** For
  transparent OSS logic we *could* rewrite, substitutability is governed by **KLoC of
  the reachable slice** — *computed* from reachable LoC, not guessed. This is the
  OpenSSL test made arithmetic: do I source OpenSSL for secure‑random (inherit ~500
  KLoC) or write ~30 lines over the OS CSPRNG? `secure‑rand` is `code` + tiny KLoC ⇒
  **inline**; a transport stack is `code` + spine‑scale KLoC ⇒ **fork‑readiness, not
  rewrite**. Modified by licence: **copyleft** raises the effort (legal encumbrance on
  vendoring/forking) even when the code is small; permissive ("not left") is a clean
  rebuild/fork.

The two levers resolve to a class and an effort score `S`:

| class | lever pattern | exit |
|---|---|---|
| `inline` | code · tiny KLoC | rewrite the slice in‑house |
| `rewrite` | code · small KLoC | abstract behind a port, migrate if it drifts |
| `fork` / `fork-hard` | code · large/spine KLoC | can't rewrite — **fund fork‑readiness / buy support** |
| `vendor-swap` | service · multi‑vendor | keep behind the seam; replacement is another impl |
| `lock-in` | service/proprietary · single‑vendor | **strategic** — support contract / escrow / multi‑source |

The decisive subtlety the two levers expose: **LoC alone misleads.** A 100‑KLoC
generated client (`go-github`) is *not* hard to substitute — Lever A routes it to
`vendor-swap` (you change provider, you don't rebuild it), so its effort is *low*.
Conversely a thin API over a deep engine (we call 523 lines of `grpc`, but lean on 79
KLoC of transport) is `fork-hard`. One number could never separate those; two levers
do. *(Caveat: KLoC still overstates rebuild cost for spec‑backed or generated `code`
— a standard like OAuth2, or protobuf stubs — where a generator or spec does the work;
treat the KLoC band as an upper bound there.)*

## 3. From axes to a decision

### 3.1 Substitutability‑weighted carry cost

The pack's novel metric — *carry cost* — made computable:

```
carry = Reachability × max(Concentration, 1) × (Substitutability_effort + Health_drift)
        ─────────────────────────────────────────────────────────────────────────────
                                      Benefit
```

- **Reachability gates the whole thing.** Not on a build path ⇒ `carry = 0`: no toil
  owed, VEX it as *"not affected"* and prune when you can (Part III, **RULE 1**).
- **Concentration multiplies.** A reachable bug in a 25‑dependent spine costs far more
  to remediate than the same bug in a leaf.
- **Substitutability sets remediation effort.** A `wedded` capability you must *fix in
  place*; a `swap` you can migrate away from; an `inline` you delete.
- **Health/drift** is the live‑data term (Scorecard + libyear). Offline it is held
  neutral (`H = 1`); wired to OSSF it becomes the canary that turns "important &
  substitutable" into "**drifting** ⇒ migrate now."
- **Benefit** is the denominator: a core capability *earns* its carry cost; a trivial
  utility carrying the same toil is a finding (over‑control is a finding too).

### 3.2 Disposition → tier → controls

Carry cost and the axis pattern resolve to one of the pack's dispositions, which then
pulls controls from the proportionality matrix — *the dependency is just another
asset whose tier sets its obligations*:

| Pattern | Disposition |
|---------|-------------|
| trivial · substitutable · unreachable | **Inline / vendor / VEX‑suppress** — shed the inheritance |
| important · substitutable · **drifting** | **Migrate** to a healthier alternative |
| critical · **non‑substitutable** · poorly‑maintained | **TCO scrutiny** — buy support or fund fork‑readiness |
| any · **high fan‑out** (> N dependents) | **Blast‑radius gate (RULE 2)** — clear a higher health/MTTR bar, *or be quarantined behind a paved‑road wrapper* |

The blast‑radius gate is the strategic heart of the *breadth* dimension: above a
dependent threshold, a component must earn a higher health bar **or** be hidden behind
a single internal seam so the estate depends on *your wrapper*, not on the raw
package. Console7 already does this by construction (§4).

## 4. Testing it on Console7

Run live against the module graph — regenerate any time with
`python3 scripts/dep-lifecycle-model.py [--json]`. Snapshot (this branch), with the
**H axis now wired to live data** (OpenSSF Scorecard + libyear, captured into
`dep-track-record.json` by `scripts/dep-capture.py`; H was held neutral `=1` before):

```
closure = 203 modules   build-reachable = 53   graph-only = 150   directly-imported = 10
Tier-1 core (keybroker / control-plane / sdk) direct external imports: 0   (tenet: must be 0)
H feed: live (Scorecard + libyear)
```

| carry | R | C | S | F | H | sub (2‑lever) | reachLoC | module | disposition |
|------:|:-:|:-:|:-:|:-:|:-:|-----|--------:|--------|-------------|
| 6.0 | 2 | 3 | 3 | 2 | 0 | `fork-hard` | 79 039 | `google.golang.org/grpc` | TCO + quarantine (spine); fork‑readiness |
| 4.0 | 3 | 2 | 2 | 2 | 0 | `fork` | 22 092 | `google.golang.org/api` | TCO + quarantine (spine); fork‑readiness |
| 4.0 | 2 | 3 | 2 | 2 | 0 | `fork` | 46 581 | `google.golang.org/protobuf` | TCO + quarantine (spine); fork‑readiness |
| 2.7 | 2 | 2 | 2 | 2 | 0 | `fork` | 5 131 | `golang.org/x/oauth2` | fork (KLoC overstates — OAuth2 is spec‑backed) |
| 2.0 | 2 | 1 | 1 | 2 | 0 | `vendor-swap` | 99 982 | `github.com/google/go-github/v88` | swap behind SCMProvider — not a rebuild |
| 1.3 | 2 | 2 | 1 | 2 | 0 | `vendor-swap` | 4 326 | `cloud.google.com/go/iam` | swap behind the seam (high fan‑out: MTTR bar) |
| 0.7 | 2 | 1 | 1 | 2 | 0 | `vendor-swap` | 30 114 | `cloud.google.com/go/kms` | swap behind SecretsProvider — not a rebuild |
| 0.7 | 2 | 1 | 1 | 2 | 0 | `vendor-swap` | 6 236 | `cloud.google.com/go/secretmanager` | swap behind SecretsProvider |
| 0.7 | 2 | 1 | 1 | 2 | 0 | `vendor-swap` | 32 466 | `cloud.google.com/go/storage` | swap behind EvidenceSink |
| 0.0 | 2 | 0 | 0 | 2 | 0 | `inline` | 432 | `…/ghinstallation/v2` | inline the slice — shed the inheritance |

The live H **lowers carry uniformly across a fresh, healthy, well‑pinned set** — every
direct scores **H = 0** at t0 (`grpc` falls 8.0 → 6.0, the GCP clients to 0.7), because
each is either well‑maintained (libyear within the 90‑day band; Scorecard 7.1–8.7 for
the GCP/`go‑github`/`grpc` base) **or** a low‑confidence Gerrit mirror that is excluded
from penalty. The capture detects mirrors by the **canonical VCS host** (`?go-get=1` →
`go.googlesource.com`), not a path prefix — which correctly catches not just
`golang.org/x/*` (`oauth2` 3.5, `crypto` 5.0) but also `google.golang.org/protobuf`
(developed on Gerrit, GitHub is a read‑only mirror), so its under‑read Scorecard never
inflates H. The one non‑mirror module whose Scorecard *is* notably low — `ghinstallation`
(5.9) — clears the H penalty cut (`< 5`) but is still flagged in the **track record**
(trust‑the‑quiet bar `≥ 6`, §5). H is the live regression hook the doc promised: when a
non‑mirror Scorecard drops below 5 or libyear grows past a quarter, carry rises and the
disposition tips toward *migrate*.

### What the readout says — strategically

1. **The OSS‑trap ratio is real and favourable.** 203 modules in the closure, but only
   **53 are build‑reachable** and only **10 are directly imported**, at shallow depth
   (1–3 sub‑packages each). You inherit a 203‑module blast radius and *use a sliver* —
   precisely the pack's "surface you use 3% / blast radius inherited 100%." Toil is
   owed on the 53, triaged by the ledger; the other **150 are VEX‑able** without
   call‑path scrutiny. That is the single biggest hygiene‑budget saving available.

2. **The concentration is a genuine spine — and it is correctly quarantined.** The
   high‑fan‑out modules (`protobuf` in‑degree 25, `grpc` 21, `x/sys` 31, `otel` 23)
   are the GCP/gRPC transport base: `fork`/`fork-hard` (transparent OSS, but spine‑scale
   KLoC — too large to rewrite), load‑bearing. The
   model flags them **TCO + quarantine**. Console7 already satisfies that disposition
   *by construction*: every one of the 10 directs lives in `providers/` (9) or
   `sandbox/` (1), behind the `sdk/interfaces` provider seam — the paved‑road wrapper
   the blast‑radius gate demands. The estate depends on the *interface*, not the SDK.

3. **The tenet holds, and the model proves it numerically.** The **Tier‑1 core**
   (`control-plane`, `keybroker`, `sdk`) imports **zero** external modules directly.
   The concentration risk is fenced entirely into the reference‑provider tier. This is
   GOAL.md tenet 1 (tenancy is the boundary) and the `go.mod` design note made
   *measurable* — and it gives the model a regression check: **if `core_direct_imports`
   ever exceeds 0, the spine has breached the seam.**

4. **The two‑lever substitutability splits look‑alikes that one number would merge.**
   `go-github` is **99 982 reachable LoC** — by raw size the heaviest dependency in the
   estate — yet it scores *low* effort (`vendor-swap`, S=1): Lever A sees it fronts the
   GitHub service behind `SCMProvider`, so the exit is *swap a provider impl*, not
   rebuild 100 KLoC. Meanwhile `grpc` is a **523‑line API we call** over a **79 KLoC**
   transport engine we can neither swap nor rewrite → `fork-hard`, S=3. A single
   "size" or "depth" number ranks those backwards; the levers — opacity (can we rebuild
   at all?) and reproduction KLoC (how much if we could?) — separate them correctly.
   The GCP service clients (`kms`/`secretmanager`/`storage`/`iam`) all land
   `vendor-swap` **because Console7 already abstracts them behind the provider seam** —
   the seam is what converts opaque‑service lock‑in into a swap. That is the depth axis
   the brief asks for, and exactly what no vuln‑count or Scorecard captures.

### What this would direct, as strategy

- **Don't spend hygiene budget uniformly.** The ledger says: deep‑scan the reachable
  53, VEX the 150, and concentrate *fork‑readiness / vendor‑support* spend on the four
  `wedded` spine modules — not on the substitutable leaves.
- **Protect the seam, not the package.** The strategic control for the GCP spine is
  *keeping it behind `sdk/interfaces`*, so the day a `protobuf`/`grpc` CVE or an EOL
  lands, the migration surface is one provider package, not the whole estate. The
  model makes "is it still quarantined?" a computed assertion.
- **(Part V tie‑in) the same data feeds Distance‑from‑Modern.** Dependency currency vs
  EOL is one of the Stack‑posture inputs to **Mean‑Time‑to‑Adapt**. A `wedded` +
  high‑fan‑out + drifting dependency is the low‑fitness/high‑tier *danger quadrant*;
  the disposition there is *migrate or fund fork‑readiness*, not *patch forever*.

## 5. Track records — the temporal axis: noise vs signal

A point-in-time score says *where a dependency stands*; a **track record** says *which
way it is moving* — and movement is what decides migrate-vs-keep. The pack names the
two series exactly: *"vuln rate is the lagging canary, where a low count can just mean
nobody is looking; reachability is the separate exposure signal that decides whether
the toil is owed."* So per dependency, per period, record two numbers:

- **Noise (the canary)** — NEW CVEs disclosed in the component this period. Lagging.
  A property of *the package*, independent of how you use it. Answers *"is this a CVE
  magnet?"* Source: OSV / GHSA / NVD.
- **Signal (the toil owed)** — of those, how many are **reachable on our call path**.
  Leading. A property of *our usage*. Answers *"does it actually cost us?"* Source:
  `govulncheck` / reachability‑aware SCA.

From the two series the model derives the measures that drive decisions:

| Measure | Definition | What it tells you |
|---|---|---|
| **ρ = Σsignal / Σnoise** | reachable ratio over the window | **empirical measurement of the depth/substitutability axis** — how much of what breaks upstream actually reaches you. Low ρ = well‑insulated (you use a sliver); high ρ = wedded. ρ *confirms or refutes* the registry's `inline/swap/wedded` guess with data. |
| **noise trend** | slope of noise[t] | the package's health trajectory; rising noise feeds the **H (drift)** axis |
| **signal trend** | slope of signal[t] | *your* exposure trajectory; rising + still‑elevated = the danger quadrant |
| **MTTR** | disclosure → fix shipped | feeds the blast‑radius **MTTR SLA** (RULE 2) above N dependents |
| **recurrence / open** | periods with signal>0; unremediated | a dep that throws reachable CVEs every quarter has a bad record regardless of any single score |

**Two faces, as the brief frames it.** *Noise without signal is VEX fodder*: the
canary chirps, nothing is on your path, and your **track record of correctly ignoring
it validates the seam**. *Signal is the real backlog*: reachable CVEs per period are
the actual VM workload, and its trend is whether the estate is getting safer or
decaying. Crucially, **noise = 0 is ambiguous** — *"a low count can just mean nobody is
looking"* — so a quiet series must be cross‑checked against Health (Scorecard activity,
libyear) before it is trusted, or it is a blind spot, not a clean bill.

### Worked archetypes

`python3 scripts/dep-lifecycle-model.py --track` over the illustrative ledger
([`dep-track-record.example.json`](dep-track-record.example.json) — hand‑authored, not
measured) shows the three records the model must tell apart:

```
cumN cumS   rho  noiseTr sigTr   MTTR  module                        verdict
  12    8  0.67  rising  rising   50d  example.com/legacy-xml-parser  DANGER
      reachable rate climbing AND you reach 67% of what breaks — pre-position migration / fork-readiness
   2    0  0.00  flat    flat       -  golang.org/x/oauth2            INSULATED
      canary chirped 2x, signal stayed flat — the seam is doing its job; VEX record validates it
  11    1  0.09  rising  rising    6d  google.golang.org/grpc         steady
      reachable CVEs handled within SLA, well insulated (rho=0.09); keep watching the trend
```

The discriminations that matter: `grpc` has a *noisier* canary than the legacy parser
(11 vs 12) yet a healthy record — **one** reachable CVE in a year, fixed in 6 days,
ρ=0.09 — because depth and the seam insulate it; the legacy parser, with comparable
noise, reaches 67% of it, is rising, and is behind on MTTR → **migrate**. Noise count
alone would have ranked them together; the signal track record splits them.

### Console7's record, measured

The series are no longer illustrative — they are **live‑captured** into
[`dep-track-record.json`](dep-track-record.json) by `scripts/dep-capture.py` (OSV for
noise, `govulncheck` for signal, deps.dev + `proxy.golang.org` for health) and read by
`--track`. The headline result confirms the prediction with real data:

```
cumN cumS   rho  noiseTr sigTr  module                    verdict
  19    0  0.00  rising  flat   golang.org/x/crypto       INSULATED
   2    0  0.00  flat    flat   google.golang.org/grpc    INSULATED
   1    0  0.00  falling flat   golang.org/x/oauth2       INSULATED
   1    0  0.00  falling flat   google.golang.org/protobuf INSULATED
   0    0     -  flat    flat   cloud.google.com/go/*     quiet (corroborated)
   0    0     -  flat    flat   github.com/bradleyfalzon/ghinstallation/v2  blind-spot?
```

**Signal = 0 across the whole build, measured, not assumed.** `govulncheck v1.1.4`
(built with `go1.25.11`) over `./...` returns **zero reachable** findings — Console7 is
`govulncheck`‑clean *by reach*, exactly as the `go.mod` header claims. The capture is
not vacuous: it found **13 advisories present at module‑required level** in
`golang.org/x/crypto` (the `ssh/*` audit batch disclosed 2026‑Q2, fixed in `v0.52.0`),
all **unreached** because Console7 imports no `ssh` package — so they are *noise, not
signal*. This is the INSULATED archetype made real and dramatic: `x/crypto`'s canary
**spiked to 13 in one quarter** (cumN 19, rising) while signal stayed flat at 0 — the
seam and shallow usage doing exactly their job. (Hygiene note: bump `x/crypto` to
`≥ v0.52.0` anyway as defence‑in‑depth, even though unreached.)

**The noise canary is real and per‑package.** `grpc` (HTTP/2 Rapid Reset, the
private‑token log leak, the 2026 `:path` authz bypass), `protobuf` (the 2023/2024
parser DoS pair), and `oauth2` (CVE‑2025‑22868) all chirped — and every one of those
advisories is **fixed at or below Console7's pinned version**, so none reaches the
current build. The `grpc` 2026‑Q1 advisory (`CVE‑2026‑33186`, alias `GO‑2026‑4762`,
fixed `1.79.3` — recorded in the ledger's `advisories` block) does not affect our
`v1.80.0` pin; `govulncheck` agrees by omitting it.

**`noise = 0` is now resolved by Health, not left ambiguous.** The quiet modules cross‑
check against the live Scorecard/libyear feed: the GCP set (8.2), `go‑github` (8.7) and
`api` (7.1) read **quiet (corroborated)** — trustworthy quiet, not a blind spot —
whereas `ghinstallation` (Scorecard 5.9) stays flagged **blind‑spot?**, the one place
the quiet is *not yet* trustworthy. That is the doc's own rule — "*a quiet series must
be cross‑checked against Health before it is trusted*" — now executed on real data.

The series is **evidence, versioned with the code**: `scripts/dep-capture.py` appends a
period each run (and is wired into `.github/workflows/dep-scan.yml`), so the ledger
self‑populates and the first real `signal > 0` will be a tracked event, not a surprise.

## 6. Where live data plugs in (the honest gaps)

The structural axes run against the toolchain; the two live‑data terms below are now
**captured**, by `scripts/dep-capture.py`, into `dep-track-record.json` (OSV, deps.dev,
`proxy.golang.org`) — closing the gaps the offline snapshot left open. `S` remains the
documented judgment axis.

- **H (health/drift) — ✅ wired.** Was held neutral (`H=1`); now computed from **OpenSSF
  Scorecard** (deps.dev) + **libyear** drift (`proxy.golang.org` version dates), CO‑05/
  CO‑11. libyear is the high‑confidence driver; Scorecard adds a penalty only for a
  genuinely low‑scoring **non‑mirror** repo (the `golang.org/x/*` Gerrit mirrors
  under‑read on Scorecard and are treated as low‑confidence). This is the term that
  turns "substitutable" into "substitutable **and drifting** ⇒ migrate now," and it is
  what now lets `--track` resolve an ambiguous `noise = 0` into *quiet (corroborated)*
  vs *blind‑spot?* (§5).
- **R (reachable‑CVE fraction) — live signal captured; structural R retained.** The
  ledger's `signal` series is now real `govulncheck` output (measured **0 reachable** at
  t0; 13 present‑but‑unreached in `x/crypto`). The `score()` ledger keeps *build*‑
  reachability as the **standing‑posture** R (binary, per module — "would a CVE here
  matter"), because per‑symbol reachable‑CVE fraction is `0/0` for every direct at t0
  and would erase the strategic ledger; the two are deliberately distinct (the standing
  posture vs the period's realised exposure). Upgrading `score()` R to a live
  call‑graph fraction is the natural next step once `signal > 0` exists to measure.
- **S (substitutability)** — capability class is human judgment in
  `CAPABILITY_REGISTRY`, reviewed as code. The API‑depth proxy is computed; richer
  signals (distinct symbols, not just packages; whether the surface is an interface we
  already abstract) would sharpen it. The pack is explicit that this axis is *not yet a
  metric* — the model's contribution is to make its inputs **explicit and auditable**
  rather than implicit.

## 7. Limits

- It scores the **module** graph, not per‑symbol call depth; `wedded`/`swap`/`inline`
  is a coarse human call, deliberately kept as reviewable code.
- Carry‑cost weights are illustrative, not calibrated against incident history; treat
  the *ordering and dispositions* as the signal, not the absolute number.
- It is **defence‑in‑depth and strategy** (tenet 2), not a CI gate. The authoritative
  supply‑chain controls remain `govulncheck`, Socket Firewall, pinning, and the
  SHA‑pinned‑action posture (CO‑05/CO‑12.7).
