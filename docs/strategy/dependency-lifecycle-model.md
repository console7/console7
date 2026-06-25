# A strategic model for dependency lifecycle, maintainability & VM

> Status: working model (strategy note, not a normative spec). Companion tool:
> [`scripts/dep-lifecycle-model.py`](../../scripts/dep-lifecycle-model.py).
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
| **S — Substitutability** | Inline it, swap it, or are you wedded to it? | **the gap** — capability class × API‑surface depth | ⚠️ judgment + proxy |

**S is the axis the industry under‑measures**, so the model makes its inputs explicit
rather than hand‑waving "it's complicated":

- *Capability class* (`inline` / `swap` / `wedded`) — human judgment, **reviewed as
  code** in the tool's `CAPABILITY_REGISTRY`. A cloud HSM (`kms`) is `wedded`: you
  cannot reimplement it. A UUID library is `inline`: `crypto/rand` replaces it. A
  GitHub REST client is `swap`: fungible, healthy alternatives exist.
- *API‑surface depth* (computed) — how many distinct sub‑packages of the dependency
  you actually bind. Reaching 1 package is a thin seam you could swap; reaching 30 is
  a marriage. This is the **proxy** that makes "depth" computable today, while the
  capability class supplies the judgment the proxy can't.

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
`python3 scripts/dep-lifecycle-model.py [--json]`. Snapshot (this branch):

```
closure = 203 modules   build-reachable = 53   graph-only = 150   directly-imported = 10
Tier-1 core (keybroker / control-plane / sdk) direct external imports: 0   (tenet: must be 0)
```

| carry | R | C | S | F | sub | module | area | disposition |
|------:|:-:|:-:|:-:|:-:|-----|--------|------|-------------|
| 8.0 | 3 | 2 | 3 | 2 | wedded | `google.golang.org/api` | providers | TCO + quarantine (spine) |
| 8.0 | 2 | 3 | 3 | 2 | wedded | `google.golang.org/grpc` | providers | TCO + quarantine (spine) |
| 8.0 | 2 | 3 | 3 | 2 | wedded | `google.golang.org/protobuf` | providers | TCO + quarantine (spine) |
| 5.3 | 2 | 2 | 3 | 2 | wedded | `cloud.google.com/go/iam` | providers | TCO + quarantine (spine) |
| 4.0 | 2 | 0 | 1 | 2 | swap | `…/ghinstallation/v2` | providers | tolerate / migrate‑if‑drifting |
| 4.0 | 2 | 1 | 1 | 2 | swap | `github.com/google/go-github/v88` | providers | tolerate / migrate‑if‑drifting |
| 2.7 | 2 | 1 | 3 | 2 | wedded | `cloud.google.com/go/kms` | providers | TCO scrutiny |
| 2.7 | 2 | 1 | 3 | 2 | wedded | `cloud.google.com/go/secretmanager` | providers | TCO scrutiny |
| 2.7 | 2 | 1 | 3 | 2 | wedded | `cloud.google.com/go/storage` | providers | TCO scrutiny |
| 2.7 | 2 | 2 | 1 | 2 | swap | `golang.org/x/oauth2` | sandbox | blast‑radius gate (RULE 2) |

### What the readout says — strategically

1. **The OSS‑trap ratio is real and favourable.** 203 modules in the closure, but only
   **53 are build‑reachable** and only **10 are directly imported**, at shallow depth
   (1–3 sub‑packages each). You inherit a 203‑module blast radius and *use a sliver* —
   precisely the pack's "surface you use 3% / blast radius inherited 100%." Toil is
   owed on the 53, triaged by the ledger; the other **150 are VEX‑able** without
   call‑path scrutiny. That is the single biggest hygiene‑budget saving available.

2. **The concentration is a genuine spine — and it is correctly quarantined.** The
   high‑fan‑out modules (`protobuf` in‑degree 25, `grpc` 21, `x/sys` 31, `otel` 23)
   are the GCP/gRPC transport base: `wedded`, non‑substitutable, load‑bearing. The
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

4. **Substitutability changes the verdict on identical health.** `go-github` and the
   GCP secret clients are both healthy, both reachable — but the model dispositions
   them oppositely. `go-github` is `swap` (regenerable from OpenAPI), so it is
   *tolerated*; `kms`/`secretmanager` are `wedded`, so they get *TCO scrutiny / fork‑
   readiness*. That divergence — invisible to a vuln‑count or a Scorecard alone — is
   exactly the depth axis the brief asks for, and exactly what no SCA score captures.

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

## 5. Where live data plugs in (the honest gaps)

This snapshot runs **offline** against the toolchain. Three terms are proxies until
wired to live data; none change the *shape* of the model, only sharpen scores:

- **H (health/drift)** — held neutral (`H=1`). Wire to **OpenSSF Scorecard +
  Criticality Score** and **libyear** drift (CO‑05/CO‑11). This is what turns
  "substitutable" into "substitutable **and drifting** ⇒ migrate now."
- **R (reachable‑CVE fraction)** — today it scores *build*‑reachability (binary, per
  module). A reachability‑aware SCA (call‑graph to the vulnerable symbol) upgrades it
  to the *fraction* of inherited CVEs on the call path, and emits the VEX directly.
- **S (substitutability)** — capability class is human judgment in
  `CAPABILITY_REGISTRY`, reviewed as code. The API‑depth proxy is computed; richer
  signals (distinct symbols, not just packages; whether the surface is an interface we
  already abstract) would sharpen it. The pack is explicit that this axis is *not yet a
  metric* — the model's contribution is to make its inputs **explicit and auditable**
  rather than implicit.

## 6. Limits

- It scores the **module** graph, not per‑symbol call depth; `wedded`/`swap`/`inline`
  is a coarse human call, deliberately kept as reviewable code.
- Carry‑cost weights are illustrative, not calibrated against incident history; treat
  the *ordering and dispositions* as the signal, not the absolute number.
- It is **defence‑in‑depth and strategy** (tenet 2), not a CI gate. The authoritative
  supply‑chain controls remain `govulncheck`, Socket Firewall, pinning, and the
  SHA‑pinned‑action posture (CO‑05/CO‑12.7).
