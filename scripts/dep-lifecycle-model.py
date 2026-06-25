#!/usr/bin/env python3
# Dependency Lifecycle Model — strategic dependency scorer for the Console7 repo.
#
# Implements docs/strategy/dependency-lifecycle-model.md: it turns each module in the
# build closure from a scan result into a *disposition* by scoring five axes —
# Substitutability, Function-criticality, Health/drift, Reachability, and
# Concentration (fan-out) — and computing a substitutability-weighted carry cost.
# This is the model from "SDLC of the Future" Part III (the four-axes supply-chain
# watershed), made computable and bound to Console7's own SDLC standard (CO-05
# supply-chain integrity, CO-11 vulnerability response, CO-17 code quality & debt).
#
# It is an ANALYSIS tool (defence-in-depth / strategy lens, GOAL.md tenet 2), not a
# CI gate. Pure stdlib; no third-party imports; reads the live `go` toolchain output
# so the ledger tracks the codebase. Run from the repo root:
#
#     python3 scripts/dep-lifecycle-model.py            # human-readable ledger
#     python3 scripts/dep-lifecycle-model.py --json     # machine-readable (evidence)
#
# The Substitutability and Function axes are the "industry's unfilled gap" (Part III):
# substitutability is *judgment, not yet a metric*. The CAPABILITY_REGISTRY below is
# that judgment, stated explicitly and reviewed as code, fused with computed proxies
# (API-surface depth, consuming trust tier). Everything else is computed from data.

import json
import os
import subprocess
import sys
import collections

CONSOLE = "github.com/console7/console7"

# Live health/drift feed: OpenSSF Scorecard (deps.dev) + libyear (proxy.golang.org),
# captured into the track-record ledger by scripts/dep-capture.py. Read here to wire
# the H axis to real data, replacing the offline H=1 neutral hold (doc §6).
HEALTH_LEDGER = "docs/strategy/dep-track-record.json"

# --- Substitutability: a TWO-LEVER index (the "unfilled gap", Part III). ---
# "Effort to replace" is not one number; it is two orthogonal barriers:
#
#  Lever A — OPACITY / IP barrier: can we rebuild it ourselves AT ALL?
#    'code'        pure in-process OSS logic — transparent; rebuild = write KLoC (Lever B)
#    'service'     a client fronting a remote/managed capability we cannot run ourselves
#                  (cloud HSM, secret store, SCM API). Rebuild is impossible — you SWAP
#                  vendors instead; substitutable iff a competitor exists ('vendors').
#    'proprietary' licensed / trade-secret artifact: opaque, often sole-source.
#  vendors: 'multi' (a competitor could replace it) | 'single' (trade-secret moat).
#
#  Lever B — REPRODUCTION cost (for 'code' only): how many KLoC of the slice we use
#    would we rewrite? COMPUTED from reachable LoC, modified by licence (permissive =
#    clean fork; copyleft = legal encumbrance; proprietary = cannot).
#
# The OpenSSL test, made precise: secure-rand is 'code' + tiny KLoC => inline; a cloud
# HSM is 'service' + multi-vendor => vendor-swap behind a seam, NOT a rewrite. The
# registry supplies the two LEVERS (judgment, reviewed as code); the tool computes the
# KLoC and licence that turn them into a score.
CAPABILITY_REGISTRY = [
    # prefix-matched, first match wins; order most-specific first
    ("cloud.google.com/go/kms",            dict(fronts="service", vendors="multi",  cap="core",    note="cloud HSM — swap to AWS KMS/Vault behind SecretsProvider, not rebuild")),
    ("cloud.google.com/go/secretmanager",  dict(fronts="service", vendors="multi",  cap="core",    note="managed secret store — multi-cloud; abstracted by SecretsProvider")),
    ("cloud.google.com/go/iam",            dict(fronts="service", vendors="multi",  cap="core",    note="workload-identity minting — every cloud has one; behind the seam")),
    ("cloud.google.com/go/storage",        dict(fronts="service", vendors="multi",  cap="core",    note="WORM object store — multi-cloud; abstracted by EvidenceSink")),
    ("github.com/google/go-github",        dict(fronts="service", vendors="multi",  cap="utility", note="GitHub API client — behind SCMProvider; swap to a GitLab/Gitea impl")),
    ("github.com/bradleyfalzon/ghinstallation", dict(fronts="code", vendors="multi", cap="utility", note="GitHub App JWT minting; ~400 LoC if inlined")),
    ("google.golang.org/grpc",             dict(fronts="code",    vendors="single", cap="core",    note="in-process transport; OSS but spine-scale — fork-readiness, not rewrite")),
    ("google.golang.org/protobuf",         dict(fronts="code",    vendors="single", cap="core",    note="wire codec; OSS but spine-scale — fork, not rewrite")),
    ("google.golang.org/api",              dict(fronts="code",    vendors="single", cap="core",    note="GCP client base; large transparent surface")),
    ("golang.org/x/oauth2",                dict(fronts="code",    vendors="multi",  cap="core",    note="OAuth2 is a standard; small + standardisable")),
    ("github.com/google/uuid",             dict(fronts="code",    vendors="multi",  cap="utility", note="RFC-4122 UUID; stdlib crypto/rand replaces it")),
    ("github.com/google/go-querystring",   dict(fronts="code",    vendors="multi",  cap="utility", note="struct->querystring; trivial reflection")),
    ("github.com/golang-jwt/jwt",          dict(fronts="code",    vendors="multi",  cap="utility", note="JWT codec; healthy alternatives exist")),
    ("go.opentelemetry.io",                dict(fronts="code",    vendors="multi",  cap="utility", note="telemetry; pluggable behind an interface")),
]
SUB_DEFAULT = dict(fronts="code", vendors="multi", cap="utility", note="(unclassified — defaults to code/multi/utility; classify in registry)")

# Lever-B KLoC bands -> effort score (reachable LoC of the slice we'd rebuild).
KLOC_BANDS = [(500, 0), (5000, 1), (50000, 2)]  # else 3


def load_health(path=HEALTH_LEDGER):
    """Live H feed: {module: {scorecard, libyear_days, mirror, ...}} from the
    captured track-record ledger. Empty if the file is absent (offline fallback)."""
    try:
        return json.load(open(path)).get("health", {})
    except (OSError, ValueError):
        return {}


def health_H(h):
    """H axis (0..3 health-drift; higher ⇒ more carry). Wired to live data (doc §6):
    the canary that turns 'substitutable' into 'substitutable AND drifting ⇒ migrate'.
    Driven by libyear (high-confidence, real version dates); OpenSSF Scorecard adds a
    penalty ONLY for a genuinely low-scoring, non-mirror repo. golang.org/x repos
    develop on Gerrit and their GitHub mirror under-reads on Scorecard — treated as
    low-confidence (mirror=true), never inflating H. No data ⇒ 1 (neutral, offline)."""
    ly, sc = (h or {}).get("libyear_days"), (h or {}).get("scorecard")
    if not h or (ly is None and sc is None):
        return 1  # no data (or a present-but-empty row from a failed capture) ⇒ neutral
    ly_band = 0 if ly is None else (0 if ly < 90 else 1 if ly < 365 else 2 if ly < 730 else 3)
    # Scorecard penalty fires only for a genuinely low (<5), non-mirror repo. NB this
    # 5.0 cut is DELIBERATELY below track_verdict's 6.0 "trust-the-quiet" bar: a [5,6)
    # repo is good enough not to add carry, not good enough to declare its silence safe.
    sc_pen = 1 if (sc is not None and not h.get("mirror") and sc < 5) else 0
    return min(ly_band + sc_pen, 3)


def _loc(path):
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            return sum(1 for _ in f)
    except OSError:
        return 0


def _licence(modcache, mod):
    import glob
    for d in sorted(glob.glob(os.path.join(modcache, mod) + "@*")):
        for name in ("LICENSE", "LICENSE.txt", "LICENSE.md", "COPYING", "LICENCE"):
            p = os.path.join(d, name)
            if os.path.exists(p):
                t = open(p, encoding="utf-8", errors="ignore").read()[:4000].lower()
                if "gnu general public" in t or "gnu affero" in t:
                    return "COPYLEFT"
                if "mozilla public" in t:
                    return "weak-copyleft"
                return "permissive"
    return None


def derive_sub(info, reach_loc, licence):
    """Resolve the two levers to a substitutability class + effort score S (0..3)."""
    if info["fronts"] in ("service", "proprietary"):
        # Lever A dominates: we cannot rebuild it; substitution = vendor swap.
        if info["vendors"] == "multi":
            return dict(sub="vendor-swap", S=1, leverA="opaque, multi-vendor",
                        leverB="n/a (swap, not rebuild)")
        return dict(sub="lock-in", S=3, leverA="opaque, single-vendor moat",
                    leverB="n/a")
    # fronts == 'code': Lever B governs — KLoC of the slice we'd rewrite.
    b = next((sc for lim, sc in KLOC_BANDS if reach_loc < lim), 3)
    if licence == "COPYLEFT":
        b = max(b, 2)  # legal encumbrance raises effort even when code is small
    cls = {0: "inline", 1: "rewrite", 2: "fork", 3: "fork-hard"}[b]
    return dict(sub=cls, S=b, leverA="transparent",
                leverB=f"{reach_loc} LoC{' (copyleft)' if licence=='COPYLEFT' else ''}")

# Trust tier of each top-level code area (Function-criticality input). Higher = more
# load-bearing consequence if the dependency fails or is compromised (ARCHITECTURE.md).
AREA_TIER = {
    "keybroker": 1, "control-plane": 1, "sdk": 1,   # Tier-1 core (must stay import-free)
    "providers": 2, "sandbox": 2,                    # reference / data-plane
    "conformance": 3, "scripts": 3, "deploy": 3,
}


def sh(*args):
    return subprocess.run(args, capture_output=True, text=True, check=True).stdout


def load():
    # module graph -> reverse in-degree (concentration / spine-ness)
    rev = collections.defaultdict(set)
    for ln in sh("go", "mod", "graph").splitlines():
        a, b = ln.split()
        am, bm = a.split("@")[0], b.split("@")[0]
        if am != bm:
            rev[bm].add(am)
    indeg = {m: len(rs) for m, rs in rev.items()}

    # packages reachable from buildable code, with their owning module
    pkgs = []
    dec = json.JSONDecoder()
    s = sh("go", "list", "-deps", "-json", "./...")
    i = 0
    while i < len(s):
        while i < len(s) and s[i] in " \n\r\t":
            i += 1
        if i >= len(s):
            break
        o, j = dec.raw_decode(s, i)
        pkgs.append(o)
        i = j
    pkgmod = {p["ImportPath"]: (p.get("Module") or {}).get("Path") for p in pkgs}

    reachable = {m for m in (pkgmod.values()) if m and m != CONSOLE}

    # reachable LoC per module (Lever B input): LoC of every package of the module
    # that lands in our build closure = "how much of its code we'd have to reproduce".
    reach_loc = collections.Counter()
    for p in pkgs:
        m = pkgmod.get(p["ImportPath"])
        if not m or m == CONSOLE or p.get("Standard"):
            continue
        d_ = p.get("Dir")
        if d_:
            reach_loc[m] += sum(_loc(os.path.join(d_, f))
                                for f in (p.get("GoFiles", []) or []))

    # direct imports by console7 code: module -> {areas}, module -> {sub-packages}
    areas = collections.defaultdict(set)
    depth = collections.defaultdict(set)
    for p in pkgs:
        if pkgmod.get(p["ImportPath"]) != CONSOLE:
            continue
        top = p["ImportPath"].replace(CONSOLE + "/", "").split("/")[0]
        for imp in p.get("Imports", []):
            em = pkgmod.get(imp)
            if em and em != CONSOLE:
                areas[em].add(top)
                depth[em].add(imp)

    # licence per scored (directly-imported) module — Lever B modifier, read offline.
    modcache = sh("go", "env", "GOMODCACHE").strip()
    licence = {m: _licence(modcache, m) for m in areas}

    closure = set(indeg) | reachable
    return dict(indeg=indeg, reachable=reachable, areas=areas, depth=depth,
                closure=closure, reach_loc=reach_loc, licence=licence)


def classify(mod):
    for prefix, info in CAPABILITY_REGISTRY:
        if mod == prefix or mod.startswith(prefix + "/") or mod.startswith(prefix):
            return info
    return SUB_DEFAULT


def score(mod, d, health=None):
    info = classify(mod)
    areas = sorted(d["areas"].get(mod, []))
    reachable = mod in d["reachable"]
    indeg = d["indeg"].get(mod, 0)
    api_depth = len(d["depth"].get(mod, []))
    function_tier = min([AREA_TIER.get(a, 3) for a in areas], default=4)

    # --- axis scores, 0..3 (higher = more carry cost / more attention owed) ---
    # R Reachability: not build-reachable => no toil owed (Part III RULE 1).
    R = 0 if not reachable else (1 if not areas else 2 if api_depth <= 2 else 3)
    # C Concentration / fan-out: module in-degree across the closure (spine-ness).
    C = 0 if indeg <= 1 else 1 if indeg <= 5 else 2 if indeg <= 15 else 3
    # S Substitutability -> remediation effort, from the two-lever index (computed).
    sub = derive_sub(info, d["reach_loc"].get(mod, 0), d["licence"].get(mod))
    S = sub["S"]
    # F Function-criticality from consuming trust tier (T1 core == highest).
    F = {1: 3, 2: 2, 3: 1, 4: 0}[function_tier]
    # Benefit denominator: core capability earns its carry; utility earns less slack.
    benefit = 3 if info["cap"] == "core" else 1

    # Substitutability-weighted carry cost (Part III: reachable-vuln × blast × effort / benefit).
    # H (health/drift) is now wired to LIVE data (Scorecard + libyear); 1 (neutral) only
    # when no health row exists (offline fallback). See doc §6 + dep-track-record.json.
    H = health_H((health or {}).get(mod))
    carry = round((R * max(C, 1) * (S + H)) / benefit, 1) if reachable else 0.0

    disposition = decide(reachable, sub, C)
    return dict(module=mod, areas=areas, reachable=reachable, indeg=indeg,
                api_depth=api_depth, reach_loc=d["reach_loc"].get(mod, 0),
                R=R, C=C, S=S, F=F, H=H, benefit=benefit, carry=carry,
                sub=sub["sub"], leverA=sub["leverA"], leverB=sub["leverB"],
                cap=info["cap"], disposition=disposition, note=info["note"])


def decide(reachable, sub, C):
    if not reachable:
        return "VEX/prune — not on any build path (inherited blast radius, zero reach)"
    cls = sub["sub"]
    if cls == "inline":
        return "Inline / vendor — rewrite the slice in-house; shed the inheritance"
    if cls == "rewrite":
        return "Substitutable by rewrite — abstract behind a port; migrate if it drifts"
    if cls == "vendor-swap":
        base = ("Vendor-swap-able — keep behind the provider seam; replacement is "
                "another impl, not a rebuild")
        return base + (" (high fan-out: hold the MTTR bar — RULE 2)" if C >= 2 else "")
    if cls == "lock-in":
        return "Strategic lock-in — sole-source moat: support contract / escrow / multi-source plan"
    # fork / fork-hard
    base = "Non-substitutable by rewrite — fund fork-readiness / buy support"
    if C >= 2:
        return "TCO scrutiny + quarantine — spine: keep behind the seam; " + base
    return base


# --------------------------------------------------------------------------
# Track records: two time series per dependency (SDLC-of-the-Future Part III —
# "vuln rate is the lagging canary; reachability is the leading indicator").
#   noise[t]  = NEW CVEs disclosed in the component per period   (the canary)
#   signal[t] = of those, how many are REACHABLE on our call path (the toil)
# Sources: noise <- OSV/GHSA/NVD ; signal <- govulncheck/reachability SCA.
# Both are egress-gated (vuln.go.dev / api.osv.dev); this tool INGESTS a
# committed observations ledger so the series is evidence, not a live fetch.
# --------------------------------------------------------------------------

# MTTR SLA (days) above which a high-fan-out dependency breaches the
# blast-radius gate (Part III RULE 2). Illustrative; calibrate to policy.
MTTR_SLA_DAYS = 30


def load_track(path):
    doc = json.load(open(path))
    by_mod = collections.defaultdict(list)
    for o in doc.get("observations", []):
        by_mod[o["module"]].append(o)
    for m in by_mod:
        by_mod[m].sort(key=lambda x: x["period"])
    return by_mod


def _trend(xs):
    if len(xs) < 2:
        return "flat"
    h = len(xs) // 2
    a = sum(xs[:h]) / max(h, 1)
    b = sum(xs[h:]) / max(len(xs) - h, 1)
    return "rising" if b > a * 1.15 else "falling" if b < a * 0.85 else "flat"


def track_measures(series):
    noise = [s.get("noise", 0) for s in series]
    signal = [s.get("signal", 0) for s in series]
    cn, cs = sum(noise), sum(signal)
    rem = [s["remediated_days"] for s in series
           if s.get("signal", 0) > 0 and "remediated_days" in s]
    return dict(
        periods=len(series), cum_noise=cn, cum_signal=cs,
        # reachable ratio = empirical measurement of the depth/substitutability axis:
        # how much of what breaks upstream actually reaches us. Low = well-insulated.
        rho=(round(cs / cn, 2) if cn else None),
        noise_trend=_trend(noise), signal_trend=_trend(signal),
        mttr_days=(round(sum(rem) / len(rem), 1) if rem else None),
        open_signals=sum(1 for s in series
                         if s.get("signal", 0) > 0 and "remediated_days" not in s),
        recurrence=sum(1 for s in signal if s > 0),
        latest_signal=(signal[-1] if signal else 0),
    )


def track_verdict(m, t, indeg, health=None):
    high_fanout = indeg > 5
    n, s = t["cum_noise"], t["cum_signal"]
    if n == 0 and s == 0:
        # noise=0 is AMBIGUOUS (Part III) — cross-check the live Health feed before
        # trusting the quiet. With Scorecard/libyear wired, we can now resolve it.
        h = (health or {}).get(m)
        sc, ly = (h or {}).get("scorecard"), (h or {}).get("libyear_days")
        lyd = "?" if ly is None else f"{ly}d"
        # Corroborating quiet needs at least one real health signal; an all-None row
        # (capture failed) is still a blind spot, not a clean bill. The trust bar is
        # Scorecard ≥ 6 (stricter than health_H's <5 carry cut — see health_H).
        if h and (sc is not None or ly is not None):
            healthy = ((sc is None or h.get("mirror") or sc >= 6)
                       and (ly is None or ly < 365))
            if healthy:
                return ("quiet (corroborated)", f"noise=0 AND health checks out "
                        f"(Scorecard {sc}, libyear {lyd}) — trustworthy quiet, not a blind spot")
            return ("blind-spot?", f"noise=0 but health is weak (Scorecard {sc}, "
                    f"libyear {lyd}) — quiet may be unscanned; verify before trusting")
        return ("blind-spot?", "zero noise may mean nobody is looking — cross-check "
                "Scorecard activity / libyear before trusting the quiet")
    if s == 0:
        return ("INSULATED", f"canary chirped {n}x, signal stayed flat — "
                "the seam/usage is doing its job; VEX record validates it")
    # there is reachable history; is it CURRENTLY elevated, or a handled blip?
    rising = t["signal_trend"] == "rising" and t["latest_signal"] > 0
    wedded = t["rho"] is not None and t["rho"] > 0.5
    if t["open_signals"] > 0 and high_fanout:
        return ("MTTR-breach", f"{t['open_signals']} reachable CVE(s) unremediated on a "
                f"fan-out-{indeg} spine — blast-radius gate (RULE 2)")
    if rising and wedded:
        return ("DANGER", f"reachable rate climbing AND you reach {int(t['rho']*100)}% of "
                "what breaks — pre-position the seam migration / fund fork-readiness")
    if rising:
        return ("watch", "reachable rate ticking up — confirm it is a trend, not a blip")
    if wedded:
        return ("depth-underestimated", f"reach {int(t['rho']*100)}% of what breaks — "
                "more wedded than the registry assumes; reclassify")
    if t["mttr_days"] is not None and t["mttr_days"] > MTTR_SLA_DAYS and high_fanout:
        return ("MTTR-breach", f"MTTR {t['mttr_days']}d > {MTTR_SLA_DAYS}d SLA on a "
                f"fan-out-{indeg} spine — raise the bar or wrap (RULE 2)")
    rho = "-" if t["rho"] is None else f"{t['rho']:.2f}"
    return ("steady", f"reachable CVEs handled within SLA, well insulated (rho={rho}); "
            "keep watching the trend")


def report_track(path, d, as_json):
    track = load_track(path)
    health = load_health(path)
    rows = []
    for m, series in sorted(track.items()):
        t = track_measures(series)
        indeg = d["indeg"].get(m, 0)
        tag, why = track_verdict(m, t, indeg, health)
        rows.append(dict(module=m, indeg=indeg, **t, verdict=tag, why=why))
    if as_json:
        print(json.dumps({"track_record": rows}, indent=2))
        return
    print()
    print("TRACK RECORDS — noise (canary) vs signal (toil owed)")
    print("=" * 78)
    print(f"{'cumN':>4}{'cumS':>5}{'rho':>6}  {'noiseTr':<8}{'sigTr':<8}{'MTTR':>5} "
          f" {'module':<34} verdict")
    for r in rows:
        rho = "-" if r["rho"] is None else f"{r['rho']:.2f}"
        mttr = "-" if r["mttr_days"] is None else f"{r['mttr_days']:.0f}d"
        print(f"{r['cum_noise']:>4}{r['cum_signal']:>5}{rho:>6}  "
              f"{r['noise_trend']:<8}{r['signal_trend']:<8}{mttr:>5}  "
              f"{r['module'][:34]:<34} {r['verdict']}")
        print(f"      -> {r['why']}")
    print("-" * 78)
    print("rho = cum_signal / cum_noise (reachable ratio = empirical depth/insulation).")
    print("noise=0 is AMBIGUOUS (Part III): quiet can mean unscanned — cross H/Scorecard.")


def main():
    argv = sys.argv[1:]
    as_json = "--json" in argv
    if "--track" in argv:
        i = argv.index("--track")
        path = argv[i + 1] if i + 1 < len(argv) and not argv[i + 1].startswith("-") \
            else "docs/strategy/dep-track-record.example.json"
        report_track(path, load(), as_json)
        return
    d = load()
    health = load_health()
    directs = sorted(d["areas"], key=lambda m: (-score(m, d, health)["carry"], m))
    rows = [score(m, d, health) for m in directs]

    summary = dict(
        modules_in_closure=len(d["closure"]),
        build_reachable=len(d["reachable"]),
        graph_only=len(d["closure"]) - len(d["reachable"]),
        directly_imported=len(directs),
        core_direct_imports=sum(1 for r in rows if any(
            a in ("keybroker", "control-plane", "sdk") for a in r["areas"])),
    )
    if as_json:
        print(json.dumps(dict(summary=summary, ledger=rows), indent=2))
        return
    print("CONSOLE7 DEPENDENCY LIFECYCLE LEDGER")
    print("=" * 78)
    print(f"closure={summary['modules_in_closure']} modules  "
          f"build-reachable={summary['build_reachable']}  "
          f"graph-only={summary['graph_only']}  "
          f"directly-imported={summary['directly_imported']}")
    print(f"Tier-1 core (keybroker/control-plane/sdk) direct external imports: "
          f"{summary['core_direct_imports']}  (tenet: must be 0)")
    print("-" * 78)
    h_live = "live (Scorecard+libyear)" if health else "offline (H=1 neutral)"
    print(f"{'carry':>5} {'R':>1}{'C':>2}{'S':>2}{'F':>2}{'H':>2}  {'sub':<11}{'reachLoC':>9}  module")
    for r in rows:
        print(f"{r['carry']:>5} {r['R']:>1}{r['C']:>2}{r['S']:>2}{r['F']:>2}{r['H']:>2}  "
              f"{r['sub']:<11}{r['reach_loc']:>9}  {r['module']}  [{','.join(r['areas'])}]")
        print(f"       -> {r['disposition']}")
    print("-" * 78)
    print("R=reachability C=concentration/fan-out S=substitutability-effort F=function-tier H=health/drift")
    print("sub via two levers: A=opacity (code/service/proprietary x vendors) B=reachLoC (rebuild cost)")
    print(f"carry = R x max(C,1) x (S + H) / benefit ; H feed: {h_live}")


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:  # tolerate `| head`, `| less` closing the pipe early
        sys.exit(0)
