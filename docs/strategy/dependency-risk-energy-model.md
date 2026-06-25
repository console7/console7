# Dependency risk as energy: a potential / kinetic model for Console7

> Status: strategy note (not a normative spec). Companion to the mechanical model in
> [`dependency-lifecycle-model.md`](./dependency-lifecycle-model.md) and the tools
> [`scripts/dep-lifecycle-model.py`](../../scripts/dep-lifecycle-model.py),
> [`scripts/dep-capture.py`](../../scripts/dep-capture.py) and
> [`scripts/dep-viz.py`](../../scripts/dep-viz.py).
> Binds to the repo SDLC standard: **CO‑05** (supply‑chain integrity), **CO‑11**
> (vulnerability response), **CO‑17** (code quality & debt), **CO‑14** (evidence).
> This is an **analysis lens / defence‑in‑depth** (GOAL.md tenet 2), **not a CI gate**.

---

## 0. Abstract

A dependency is not a scan result and risk is not a CVE count. This note develops a
small model in which dependency risk decomposes into **four typed quantities** — each
answering a different question, in a different tense, triggering a different action —
plus a fifth term, **containment**, contributed by Console7's deployment architecture.
The four are framed by a physical analogy that fell out of trying to draw the data
honestly:

- **Potential energy (PE)** — *how bad if it ignites?* Standing concentration (lock‑in ×
  blast‑radius), coupled to us by reachability. What you **pre‑position** against.
- **Kinetic energy (KE)** — *is it on fire now?* The current reachable‑CVE toll. What you
  **remediate today**.
- **Hazard** — *how likely, how soon?* A leading indicator built from the vulnerability
  disclosure trend — the "grey swan". What you **put on a watch‑list** and migrate ahead
  of.
- **Drift‑cost** — *what does staying safe cost?* The hygiene tax of rolling updates. The
  **price** against which the other three are the benefit.

The model's value is that it tells you these are *not co‑equal axes to be plotted against
each other* — they have different types, and the type dictates how each should be measured
and encoded. Applied to Console7's own `go.mod` closure at t0 (2026‑Q2), it says: **high
stored energy concentrated on a four‑module spine, nothing in motion (0 reachable),
pressure building only off‑chart where it cannot couple** — and it shows how the sandbox
architecture caps the consequence of whatever does eventually ignite.

---

## 1. The problem: a flat surface induces flat spending

The estate spent a decade tooling the *consequences* of unconstrained adoption — SBOMs,
scanners, patch treadmills — and almost nothing on the *decision to adopt and keep*. The
artefact of that era is the flat vulnerability surface: "203 dependencies, N CVEs", ranked
by severity or by count. A flat surface induces flat spending — hygiene effort applied
uniformly, proportional to CVE‑count or package size, which is precisely **uncorrelated
with where the risk actually is.**

The mechanical model ([`dependency-lifecycle-model.md`](./dependency-lifecycle-model.md))
already replaces the flat surface with five scored axes — Substitutability, Function,
Health, Reachability, Concentration — and a substitutability‑weighted **carry cost**. This
note is the strategic layer on top: it asks *what are the carry score's drivers, what do
they mean, and what is the smallest set of quantities a decision‑maker actually needs?*

---

## 2. The dimensionality trap

The first instinct is to visualise everything at once: a scatter of substitutability ×
concentration, bubble‑size for reachable LoC, colour for disposition — and then exile
reachability and the temporal trend to separate charts. That is **six dimensions smeared
across three pictures**, and no clean narrative survives it.

The resolution is not a cleverer projection. It is recognising that the dimensions are
**not co‑equal — they are different *types*, and the type tells you most of them should
not be an axis at all:**

| Dimension | Its true type | So encode it as |
|---|---|---|
| Reachability | a **filter** (membership) | not plotted — it *removes* candidates before you draw |
| Concentration: deep (substitutability) | **magnitude** | an axis |
| Concentration: broad (fan‑out) | magnitude, often collapsible | an axis *or* a flag |
| Temporal trend | a **derivative** | a glyph / leading indicator, not an axis |
| Health, disposition, size | **consequence** | colour / weight — already folded into the score |
| Drift effort | **cost** | a separate axis — the price, not the risk |

The governing principle: **the number of axes should equal the number of independent
things you can *act on*, not the number of things you can measure.** You make one decision
per module — *how much budget* — so the honest primary view is one‑dimensional (rank by
carry), with the drivers shown as decomposition rather than spatial position. Everything
else is a filter, a glyph, a colour, or the cost denominator.

The energy framing in §3 is what gives those types names that compose.

---

## 3. The model

### 3.1 Potential energy — what you pre‑position against

**PE ≈ concentration, coupled by reachability.** Borrowing `PE = m·g·h`:

- **height *h* = deep** = substitutability / lock‑in. How far it falls — you cannot catch
  it because you cannot exit. (Model axis `S`, the two‑lever index: Lever A *can we rebuild
  it at all?* — `code` vs `service`/`proprietary`; Lever B *how many KLoC of the slice we
  use would we rewrite?*)
- **mass *m* = broad** = fan‑out / blast‑radius. How much of the estate leans on it. (Model
  axis `C`, calibrated by in‑degree.)

PE is *standing, structural* risk — the harm capacity if a vulnerability is realised. It is
the carry score, and it is the thing the disposition map ranks. Crucially, **deep and broad
are independent and have opposite exits**: a transparent‑but‑spine‑scale module (high `S`
via Lever B) you cannot rewrite → **fund fork‑readiness**; a service client (high `S` via
Lever A) you cannot rebuild but *can swap* → **abstract behind a seam**. One number — size,
or CVE‑count — can never tell those apart, which is the whole reason the two‑lever index
exists.

### 3.2 The latch — reachability gates PE → KE

Reachability is not an axis; it is the **latch** that couples stored PE to you. A module at
high PE releases nothing until a vulnerability lands *on a call path you actually execute*.
This is why Console7 inherits a 203‑module closure but only **53** are build‑reachable and
only **10** are directly imported and scored — and why the **150 graph‑only** modules are
VEX‑able as "not affected" with no scan toil owed. The loudest canary in the estate can sit
in that decoupled set: **noise ≠ risk until the latch trips.**

### 3.3 Kinetic energy — what you remediate now

**KE = the current reachable‑CVE toll.** Present tense: *is this version vulnerable right
now, on a path we reach, and what do I do today?* This is what `govulncheck` measures, and
Console7's reading at t0 is **0 reachable findings** across the build, with **13
present‑but‑unreached** advisories (the `golang.org/x/crypto` `ssh/*` cluster, fixed in
v0.52.0, which we do not import). Every module is **at rest**. KE is the firefighting
quantity; today there is no fire.

### 3.4 Hazard — the grey swan, the leading indicator

KE and PE are not enough. A package with an **intensifying** vulnerability track record over
the last twelve months is sending a forward signal even while KE stays 0: *"I see lots of
vulns here; so far they don't affect me; but it's a matter of time — and then, suddenly, oh
no."* That is a **grey swan**: a foreseeable, high‑impact event whose *arrival* you can read
in the base rate but whose *timing* you cannot. It is neither PE (magnitude) nor KE (now) —
it is a **hazard rate**: the probability per unit time that the latch trips.

What does an intensifying disclosure trend actually say? Three readings, and the honest
answer holds all three in tension:

- **(a) The codebase.** Defects cluster and autocorrelate — a component that threw a vuln is
  likelier to throw the next. *But the opposite can be true:* a CVE spike often means
  someone finally pointed a fuzzer or an audit at it, so the code is getting **safer**, not
  rotting. The discriminator is **recurrence vs sweep** (a steady drip in one component =
  fragility; a one‑time cluster across many files = an audit).
- **(b) The attention.** Disclosure rate is a proxy for *total researcher eyeballs*. Crossing
  into the "interesting to look at" regime — high deployment, high criticality, recent fame —
  pulls in **both** defenders and adversaries on the same code, and every disclosed bug is a
  published *technique* that lowers the weaponisation cost of the next one.
- **(c) The abuse likelihood.** Per‑CVE exploitation is rare (~5% of all CVEs are ever
  exploited) but **clusters** on high‑deployment × dangerous‑bug‑class × prior‑exploitation ×
  reachable‑surface. An intensifying history in a load‑bearing, reachable package raises the
  **base rate** that the *next* disclosure lands somewhere you touch and is weaponisable.

The temporal factor therefore has **two layers**, easily conflated: a *lagging* edge (KE
trend — realised, currently 0) and a *leading* edge (the **canary** — disclosure
intensity × trend — predictive). The hazard quantity is the leading edge. The actionable
composite is **expected imminence ≈ PE × hazard**, and the danger quadrant is **high PE ×
rising hazard × KE‑still‑0**: the place you migrate *before* anything is wrong.

> **Measurement honesty.** A first‑order hazard is computable today from what we capture —
> trailing‑12‑month intensity, trend, and recurrence (disclosure dates + fix versions). A
> *proper* hazard wants adversary‑attention and exploitability signals — EPSS percentile,
> CISA KEV membership, CWE/bug‑class, deployment/criticality beyond in‑degree — which are
> fetchable feeds but not yet wired. A disclosure‑count trend is the **leading proxy** for
> exploitation, not exploitation itself; it must not be reported as a probability.

### 3.5 The model is not conservative — you cannot drain PE

A pendulum trades PE ↔ KE with the total fixed. Dependency risk does **not**: a vulnerability
firing on `grpc` converts stored concentration into incident toil, but `grpc` is exactly as
deep and broad the morning after. **The reservoir refills.** Consequences:

- You **cannot lower PE** — you cannot make `grpc` less deep or less broad; the height and
  mass are structural.
- Mitigation works on the **latch and the damping**, never the energy: fork‑readiness, the
  seam, and a tight MTTR don't drain the reservoir — they make the latch harder to trip and
  the discharge shorter. This is why the action is always *pre‑position*, never *remove*.

### 3.6 Drift‑cost — the price of staying safe

Every mitigation has a price, and that price is largely the **hygiene tax of rolling
updates**. The decision was never "rank by risk"; it is **cost‑benefit** — how much risk
does staying current buy down, per unit of effort. Drift‑cost is roughly a product:

```
drift-cost ≈ cadence(updates/qtr) × breakage-per-event(SemVer discipline)
             × surface-consumed(blast radius of a break) × fan-out(coordination)
           + debt-stock(libyear; super-linear payback if deferred)
```

Three properties make this the crux of the whole model:

1. **The cruel correlation.** Cost is highest exactly where risk is highest: deep + broad
   (high PE) means most API surface consumed *and* most call sites to coordinate. You
   **cannot economise by neglecting the expensive modules** — that is where the expected
   loss lives.
2. **Stock vs flow, and deferral as a time‑bomb.** Libyear is the debt *stock*;
   drift‑management is the *flow* to keep it low. Continuous small updates are **sub‑linear**;
   a deferred big‑bang catch‑up is **super‑linear** (breaking changes compound, context is
   lost). Worse, deferring on a high‑PE module **converts a steady opex into a catastrophic
   capex that comes due under fire** — you are forced to jump from far‑behind to current to
   ship a security patch, so MTTR explodes at the worst possible moment.
3. **Hygiene as a prepaid option.** Continuous drift management is an **insurance premium
   that buys the option to patch fast** when the grey swan lands. Neglect forfeits the
   option. This is the second half of why the seam and fork‑readiness pay off: they are
   **capex that lowers the per‑update opex** on the high‑PE spine, which is what makes
   continuous hygiene *affordable* where it is mandatory.

Drift‑cost is a **separate axis from risk** — it does **not** go into the carry score. (The
health axis `H`/libyear is the one input that plays two roles, kept distinct: stale → longer
MTTR → higher *hazard* in the risk score, **and** debt to pay down on the *cost* axis.) The
decision metric is **ROI = risk‑reduction ÷ drift‑cost**, which turns the risk ranking into a
**per‑module cadence policy** (§4.3).

---

## 4. Console7, measured (t0 = 2026‑Q2)

### 4.1 Coupling — how much energy is even pointed at us

```
in closure        203   inherited blast radius
build-reachable    53   the latch is open here
directly imported  10   scored on the ladder
Tier-1 core direct  0   tenet 3 invariant: core imports no provider SDK directly
```

`core direct imports == 0` is the load‑bearing number: it confirms every heavy client
(`grpc`, the GCP SDKs, `go-github`) is reached **only** through the `sdk/interfaces` seam,
never from the hardened control plane. The seam is the active ingredient that keeps the
swappable services at low PE; assert this in CI and a seam breach shows up as a regression.

### 4.2 The energy ladder — stored PE, ranked

| Module | carry (PE) | disposition | deep `S` | broad `C` (indeg) | reach LoC | canary (cumN / TTM) |
|---|---|---|---|---|---|---|
| `google.golang.org/grpc` | **6.0** | fork‑hard | 3 | 3 (21) | 79,039 | 2 / 1 |
| `google.golang.org/api` | 4.0 | fork | 2 | 2 (12) | 22,092 | 0 / 0 |
| `google.golang.org/protobuf` | 4.0 | fork | 2 | 3 (25) | 46,581 | 1 / 0 |
| `golang.org/x/oauth2` | 2.7 | fork | 2 | 2 (14) | 5,131 | 1 / 0 |
| `github.com/google/go-github/v88` | 2.0 | vendor‑swap | 1 | 1 (2) | 99,982 | 0 / 0 |
| `cloud.google.com/go/iam` | 1.3 | vendor‑swap | 1 | 2 (6) | 4,326 | 0 / 0 |
| `cloud.google.com/go/kms` | 0.7 | vendor‑swap | 1 | 1 (2) | 30,114 | 0 / 0 |
| `cloud.google.com/go/secretmanager` | 0.7 | vendor‑swap | 1 | 1 (2) | 6,236 | 0 / 0 |
| `cloud.google.com/go/storage` | 0.7 | vendor‑swap | 1 | 1 (2) | 32,466 | 0 / 0 |
| `github.com/bradleyfalzon/ghinstallation` | 0.0 | inline | 0 | 0 (1) | 432 | 0 / 0 |

Read it as energy: **the spine** (`grpc`, `protobuf`, `api`, `oauth2`) is high stored PE you
**cannot exit** — `grpc` maxes both height and mass. **The services** (`go-github`, the GCP
SDKs) are *large* (`go-github` is the biggest single surface at ~100K LoC) but **low PE**,
because the seam makes them swappable — `S=1` (Lever A: opaque, multi‑vendor). **The leaf**
(`ghinstallation`, ~432 LoC) is `inline`: rewrite the slice and shed the inheritance — and
it is the lowest‑confidence to keep (weakest non‑mirror Scorecard, verdict `blind‑spot?`).

### 4.3 What it directs — cadence policy by quadrant

| Quadrant | Members (today) | Cadence policy | Cost move |
|---|---|---|---|
| high PE × high hazard (grey swan) | *none* | tight/continuous — non‑negotiable | spend capex (seam, contract tests, fork‑readiness) to cut per‑update opex |
| high PE × low hazard (stable spine) | `grpc`, `protobuf`, `api`, `oauth2` | event‑driven + periodic catch‑up; never let libyear debt cross a threshold | hold the seam; don't chase every release |
| low PE | the GCP SDKs, `go-github`, `ghinstallation` | automate — Renovate auto‑merge, near‑zero human touch | none; plus inline‑and‑delete `ghinstallation` |

### 4.4 The grey‑swan check — and why it's reassuring, honestly

Apply the hazard lens to the trailing‑12‑month data and **nothing sits in the danger
quadrant today, for the right reasons:**

- `golang.org/x/crypto` — hazard genuinely rising (cumN 19, **16 in the last 12 months, 13
  last quarter**, clearly intensifying) **but PE‑to‑us ≈ 0**: unreached, not even in the
  scored 10. A loud seismograph under an *empty* building. Not our grey swan — *because
  coupling is zero.*
- The spine (`grpc`/`protobuf`/`oauth2`) — high PE, but hazard **low** (TTM 1/0/0, not
  intensifying). Stable, not igniting.

The value is the **trigger it would fire**: the day `grpc` starts showing several
reachable‑adjacent CVEs a quarter, it lights up as high‑PE × rising‑hazard and says
*accelerate fork‑readiness now* — before KE > 0. That is the entire point of a leading
indicator, and it is the "oh no, I should have moved earlier" the model exists to prevent.

> **Temporal honesty.** The **noise** (canary) series is real history — disclosure dates are
> facts, so OSV gives a true 10‑quarter back‑series. The **signal** (KE) series is **a single
> t0 measurement**, not ten: reachability is measured against a *build*, and the only build
> that has ever existed is today's. Pre‑adoption KE is 0 by construction, not by ten
> independent observations. The report draws it accordingly and does not imply otherwise.

---

## 5. Containment — how Console7's architecture reduces the toil

The model above scores the **Go module graph**. Console7's deployment architecture acts on a
*different* layer — the OS/runtime, the fleet, and the blast radius — and that is the point:
it deletes a class of toil the model does not even count, and it makes the §4.3 cadence
policy cheap to execute. Map the moves onto the drift‑cost function and see which terms they
zero:

- **Managed base images → fan‑out term ÷ N → 1.** Patch the base once; every consumer inherits
  on rebuild. The coordination term that made broad dependencies expensive collapses into a
  single maintained artefact.
- **Ephemeral, per‑session sandbox → debt‑stock → ~0.** No long‑lived host accrues drift, so
  the super‑linear "catch up under fire" trap is structurally impossible — every session is
  *born current* off the latest base. Rebuild‑to‑deploy is a forcing function that drags the
  whole tree forward.
- **Minimal base (distroless‑style) → surface shrinks.** Ship only what's needed → the inherited
  closure shrinks → fewer CVEs to triage, attacking the "203" at the OS layer.
- **MTTR → rebuild‑and‑redeploy.** The prepaid patch‑fast option (§3.6) is realised by
  amortisation: pull the new base, redeploy. The disclosure→deployed‑fix window — how long
  hazard has to bite — narrows sharply.
- **gVisor/microVM + default‑deny egress + ephemerality + no standing creds → consequence cap.**
  A reachable CVE in the agent runtime is boxed: it cannot pivot to the control plane or
  exfiltrate, because the **boundary controls are authoritative** (tenet 2). This bounds the
  *effective* PE/KE of anything sandbox‑side — which is what *lets* the contained tier run a
  looser, risk‑tuned cadence instead of panic‑patching.
- **Distinct, separately‑signed trust‑tier images** (sandbox base / control‑plane / key‑broker)
  → **scoped fix blast radius.** A dev‑tool CVE rebuilds only the sandbox base; you do not
  re‑certify the Tier‑1 control plane because a tool in the agent's sandbox had a finding.

**Honest limits.** Containment *moves and amortises* toil; it does not delete it. Someone still
maintains the base image (self‑managed = centralised cost you still own; vendor‑managed =
outsourced, but per tenet 1 it must run *in the adopter's tenancy* with no phone‑home — a
base‑image artefact, not a SaaS dependency). And containment caps *consequence*; it does **not**
lower a package's intrinsic *hazard*, nor does it patch the compiled Go deps (`grpc`/`protobuf`
ride the rebuild cadence, but their application‑layer ranking still governs how aggressively you
bump them).

In the model's language, this is a **containment discount**: a per‑tier factor that
down‑weights PE/hazard for deps that only ever run in the ephemeral, gVisor‑isolated,
egress‑denied sandbox — so the ranking distinguishes *"vulnerable in the hardened control
plane"* from *"vulnerable in a boxed, throwaway sandbox."* The two recurring moves —
**strengthen the latch, cap the damage** — are exactly what the deployment layer expresses.

---

## 6. How it binds to Console7's tenets and standard

- **Tenet 2 (boundary controls are authoritative; in‑band guards are defence‑in‑depth).** This
  model and its tools are an **analysis lens**, never a gate. Least‑privilege identity and
  default‑deny egress remain the controls of record; this informs *where to spend*, it does not
  *enforce*.
- **Tenet 3 (scope follows the artefact, not the author).** Risk derives from the target's
  reachability × concentration × consuming tier — computed from the build, never asserted by an
  in‑repo file. The `core direct imports == 0` invariant is the tenet‑3 check in miniature.
- **Tenet 4 (least privilege, ephemeral by default)** and **§5 containment** are the same idea
  at the deployment layer: ephemerality resets the drift debt; isolation caps the consequence.
- **SDLC standard:** CO‑05 (supply‑chain integrity — the disposition decision), CO‑11
  (vulnerability response — KE/hazard and the cadence policy), CO‑17 (code quality & debt —
  drift‑cost and libyear), CO‑14 (evidence — the `--json` ledger and the hash‑chained track
  record are the artefacts).

---

## 7. The tooling

| Artefact | Role |
|---|---|
| [`scripts/dep-lifecycle-model.py`](../../scripts/dep-lifecycle-model.py) | scores the live build closure → carry ledger + disposition (`--json` for evidence) |
| [`scripts/dep-capture.py`](../../scripts/dep-capture.py) | captures noise (OSV), signal (`govulncheck`), and health (Scorecard + libyear) into the track record |
| [`docs/strategy/dep-track-record.json`](./dep-track-record.json) | the temporal ledger — per‑quarter noise/signal + per‑advisory provenance + health |
| [`scripts/dep-viz.py`](../../scripts/dep-viz.py) | renders the self‑contained, zero‑egress PE/KE energy report (ladder → coupling → kinetic detail → PE‑structure drill‑down) |

```bash
python3 scripts/dep-lifecycle-model.py                 # human-readable ledger
python3 scripts/dep-lifecycle-model.py --json          # machine-readable (evidence)
python3 scripts/dep-lifecycle-model.py --track docs/strategy/dep-track-record.json
python3 scripts/dep-viz.py --out dep-report.html       # the energy report
```

Capture runs observe‑only on a schedule (the dependency‑scan workflow); the report is a
single portable HTML file with no third‑party JS/CSS and zero runtime egress, so it adds no
supply‑chain surface (CO‑05/CO‑12.7).

---

## 8. Limits & honest gaps

- **Substitutability is judgment, not yet a metric.** The two‑lever registry states that
  judgment explicitly and reviews it as code; it is the model's largest subjective input.
- **Signal (KE) is t0‑anchored.** Until a reachable CVE lands, the kinetic series is a single
  measured point honestly extended backward as 0. Its prospective value accrues quarter by
  quarter; today it is one quarter old on the axis that matters.
- **Hazard is first‑order.** Intensity × trend × recurrence from disclosure data; it is the
  leading *proxy* for exploitation and must be enriched with EPSS + CISA KEV + bug‑class before
  it is read as anything stronger.
- **Drift‑cost's hardest term is breakage‑per‑event.** True SemVer‑violation rate needs
  changelog / API‑diff analysis; today it is proxied by major‑version frequency.
- **Small‑n.** The estate is 10 scored modules with a thin track record. The model is built to
  *scale* (ledger rows carry an optional `repo` field for estate‑wide aggregation), but its
  confidence today is proportionate to the data behind it.

---

## 9. Summary — five quantities, five questions

| Quantity | Question | Tense | Measure | Action |
|---|---|---|---|---|
| **Kinetic** | on fire now? | present | reachable CVEs (`govulncheck`) | remediate today (none owed at t0) |
| **Potential** | how bad if it ignites? | standing | carry = concentration, coupled | pre‑position: fork‑readiness / seam |
| **Hazard** | how likely, how soon? | leading | canary intensity × trend (+ EPSS/KEV) | grey‑swan watch; migrate ahead |
| **Drift‑cost** | what does staying safe cost? | flow + stock | cadence × breakage × surface × fan‑out (+ libyear) | set cadence by ROI; capex to cut opex |
| **Containment** | how bounded is the blast? | architectural | tier isolation (gVisor / ephemeral / egress / signing) | discount PE/hazard for boxed tiers |

The one‑line spine: **risk is *stored* as potential energy (concentration, coupled by
reachability) and *released* as kinetic energy (the reachable‑CVE toll); the canary is the
pressure gauge, the latch is reachability, drift‑management is the prepaid option to patch
fast, and Console7's ephemeral, isolated sandbox caps how much energy any release can do.**
