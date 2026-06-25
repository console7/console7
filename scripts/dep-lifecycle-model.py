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
import subprocess
import sys
import collections

CONSOLE = "github.com/console7/console7"

# --- The judgment axis (Part III "THE GAP"): capability class per module prefix. ---
# substitutability ∈ {inline, swap, wedded}
#   inline  — trivial logic we could rewrite in-house cheaply (utilities, encoders)
#   swap    — a real capability, but fungible: healthy alternatives exist, low lock-in
#   wedded  — non-substitutable capability (a cloud HSM, an SCM's own API): you cannot
#             reimplement it; the most you can do is fund fork-readiness / buy support
# capability — what it does, for the Benefit term ('core' load-bearing vs 'utility')
CAPABILITY_REGISTRY = [
    # prefix-matched, first match wins; order most-specific first
    ("cloud.google.com/go/kms",            dict(sub="wedded", cap="core",    note="cloud HSM / envelope crypto — irreplaceable capability")),
    ("cloud.google.com/go/secretmanager",  dict(sub="wedded", cap="core",    note="managed secret store — provider-native, not reimplementable")),
    ("cloud.google.com/go/iam",            dict(sub="wedded", cap="core",    note="workload-identity token minting — provider-native")),
    ("cloud.google.com/go/storage",        dict(sub="wedded", cap="core",    note="WORM evidence object store — provider-native")),
    ("google.golang.org/grpc",             dict(sub="wedded", cap="core",    note="transport for every GCP client; spine, not optional")),
    ("google.golang.org/protobuf",         dict(sub="wedded", cap="core",    note="wire format for every GCP client; spine")),
    ("google.golang.org/api",              dict(sub="wedded", cap="core",    note="GCP client option/iterator base")),
    ("golang.org/x/oauth2",                dict(sub="swap",   cap="core",    note="OAuth2/Google ADC token source; standardisable")),
    ("github.com/google/go-github",        dict(sub="swap",   cap="utility", note="GitHub REST client; thin, regenerable from OpenAPI")),
    ("github.com/bradleyfalzon/ghinstallation", dict(sub="swap", cap="utility", note="GitHub App JWT minting; ~200 LoC if inlined")),
    ("github.com/google/uuid",             dict(sub="inline", cap="utility", note="RFC-4122 UUID; stdlib crypto/rand can replace")),
    ("github.com/google/go-querystring",   dict(sub="inline", cap="utility", note="struct->querystring; trivial reflection")),
    ("github.com/golang-jwt/jwt",          dict(sub="swap",   cap="utility", note="JWT encode/verify; several healthy alternatives")),
    ("go.opentelemetry.io",                dict(sub="swap",   cap="utility", note="telemetry; pluggable behind an interface")),
]
SUB_DEFAULT = dict(sub="swap", cap="utility", note="(unclassified — defaults to swap/utility; classify in registry)")

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
    closure = set(indeg) | reachable
    return dict(indeg=indeg, reachable=reachable, areas=areas, depth=depth,
                closure=closure)


def classify(mod):
    for prefix, info in CAPABILITY_REGISTRY:
        if mod == prefix or mod.startswith(prefix + "/") or mod.startswith(prefix):
            return info
    return SUB_DEFAULT


def score(mod, d):
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
    # S Substitutability -> remediation effort if it goes bad.
    S = {"inline": 0, "swap": 1, "wedded": 3}[info["sub"]]
    # F Function-criticality from consuming trust tier (T1 core == highest).
    F = {1: 3, 2: 2, 3: 1, 4: 0}[function_tier]
    # Benefit denominator: core capability earns its carry; utility earns less slack.
    benefit = 3 if info["cap"] == "core" else 1

    # Substitutability-weighted carry cost (Part III: reachable-vuln × blast × effort / benefit).
    # H (health/drift) is the live-data slot — set to 1 (neutral) offline; see doc.
    H = 1
    carry = round((R * max(C, 1) * (S + H)) / benefit, 1) if reachable else 0.0

    disposition = decide(reachable, info, S, C, F)
    return dict(module=mod, areas=areas, reachable=reachable, indeg=indeg,
                api_depth=api_depth, R=R, C=C, S=S, F=F, H=H, benefit=benefit,
                carry=carry, sub=info["sub"], cap=info["cap"],
                disposition=disposition, note=info["note"])


def decide(reachable, info, S, C, F):
    if not reachable:
        return "VEX/prune — not on any build path (inherited blast radius, zero reach)"
    if info["sub"] == "inline":
        return "Inline / vendor — trivial + substitutable; shed the inheritance"
    if info["sub"] == "wedded":
        if C >= 2:
            return "TCO scrutiny + quarantine — non-substitutable spine: keep behind the paved-road seam, buy support / fund fork-readiness"
        return "TCO scrutiny — non-substitutable: buy support / fund fork-readiness"
    # swap
    if C >= 2:
        return "Blast-radius gate (RULE 2) — high fan-out: hold to a higher health/MTTR bar or wrap"
    return "Tolerate / migrate-if-drifting — substitutable; watch health"


def main():
    as_json = "--json" in sys.argv
    d = load()
    directs = sorted(d["areas"], key=lambda m: (-score(m, d)["carry"], m))
    rows = [score(m, d) for m in directs]

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
    print(f"{'carry':>5} {'R':>1}{'C':>2}{'S':>2}{'F':>2}  {'sub':<7} {'module':<42} areas")
    for r in rows:
        print(f"{r['carry']:>5} {r['R']:>1}{r['C']:>2}{r['S']:>2}{r['F']:>2}  "
              f"{r['sub']:<7} {r['module'][:42]:<42} {','.join(r['areas'])}")
        print(f"       -> {r['disposition']}")
    print("-" * 78)
    print("R=reachability C=concentration/fan-out S=substitutability-effort F=function-tier")
    print("carry = R x max(C,1) x (S + H) / benefit ; H is the live health/drift slot (=1 offline)")


if __name__ == "__main__":
    main()
