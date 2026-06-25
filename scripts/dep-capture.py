#!/usr/bin/env python3
# Dependency track-record capture — populates docs/strategy/dep-track-record.json with
# the live noise/signal/health data the lifecycle model (scripts/dep-lifecycle-model.py)
# turns into dispositions. This is the *evidence collector*; the model is the *scorer*.
#
# It captures, per the model's three live feeds (dependency-lifecycle-model.md §§5-6):
#   NOISE  (the canary)  — NEW CVEs disclosed per module per quarter.  Source: api.osv.dev
#   SIGNAL (the toil)    — of those, how many are REACHABLE on our call path. Source:
#                          govulncheck (build it with the module's go toolchain).
#   HEALTH (the H axis)  — OpenSSF Scorecard (api.deps.dev) + libyear drift
#                          (proxy.golang.org version dates).
#
# These are exactly the destinations an adopter's default-deny egress allowlists for the
# supply-chain lane: all public, read-only, and the only data leaving is the package
# names+versions of a public OSS repo (CO-05/CO-11). Pure stdlib + the `go` toolchain +
# `govulncheck` on PATH; honours HTTPS_PROXY via urllib.
#
#   python3 scripts/dep-capture.py                 # refresh health + append current quarter
#   python3 scripts/dep-capture.py --period 2026-Q2  # force the period bucket
#   python3 scripts/dep-capture.py --print         # capture to stdout, do not write
#   python3 scripts/dep-capture.py --no-signal     # skip govulncheck (noise+health only)
#
# Idempotent: re-running for the same period replaces that period's rows and refreshes
# `health`, preserving prior history. Designed to run as a scheduled CI job
# (.github/workflows/dep-scan.yml) so the ledger self-populates each period.

import collections
import datetime
import json
import os
import ssl
import subprocess
import sys
import urllib.request

LEDGER = "docs/strategy/dep-track-record.json"
CONSOLE = "github.com/console7/console7"
OSV = "https://api.osv.dev/v1/query"
DEPS_DEV = "https://api.deps.dev/v3"
PROXY = "https://proxy.golang.org"

# Honour the agent/CI proxy CA bundle when present; fall back to system trust.
_CA = "/root/.ccr/ca-bundle.crt"
_CTX = ssl.create_default_context(cafile=_CA) if os.path.exists(_CA) \
    else ssl.create_default_context()


def _get(url):
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=60, context=_CTX) as r:
        return json.loads(r.read().decode())


def _post(url, payload):
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60, context=_CTX) as r:
        return json.loads(r.read().decode())


def _enc(s):
    import urllib.parse
    return urllib.parse.quote(s, safe="")


def quarter_of(iso):
    d = datetime.date.fromisoformat(iso[:10])
    return f"{d.year}-Q{(d.month - 1) // 3 + 1}"


def go(*args):
    return subprocess.run(("go",) + args, capture_output=True, text=True,
                          check=True).stdout


def direct_modules():
    """The directly-required modules with their pinned versions (excludes std + self)."""
    out = {}
    fmt = "{{if not .Indirect}}{{.Path}} {{.Version}}{{end}}"
    for ln in go("list", "-m", "-f", fmt, "all").splitlines():
        ln = ln.strip()
        if not ln or ln.startswith(CONSOLE):
            continue
        path, ver = ln.split()
        out[path] = ver
    return out


# --- NOISE: OSV advisories, deduped by alias cluster, bucketed by published quarter ---
def _fixed_version(vs, mod):
    """Lowest 'fixed' version across the cluster's affected ranges for this module."""
    fixes = []
    for v in vs:
        for a in v.get("affected", []):
            if (a.get("package") or {}).get("name") != mod:
                continue
            for r in a.get("ranges", []):
                for e in r.get("events", []):
                    if e.get("fixed"):
                        fixes.append(e["fixed"])
    return sorted(fixes)[0] if fixes else None


def osv_noise(mod):
    """Returns ({quarter: count}, [advisory]) for DISTINCT advisories (GHSA<->GO<->CVE
    collapsed to one). Each advisory: {id (CVE/GO preferred), published, quarter, fixed}
    — recorded so a noise count is traceable to the specific CVEs behind it."""
    try:
        vulns = _post(OSV, {"package": {"ecosystem": "Go", "name": mod}}).get("vulns", [])
    except Exception as e:  # network/policy — record nothing rather than crash the run
        print(f"  ! OSV {mod}: {e}", file=sys.stderr)
        return {}, []
    parent = {}

    def find(x):
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for v in vulns:
        keys = [v["id"]] + v.get("aliases", [])
        for k in keys:
            find(k)
        for k in keys[1:]:
            parent[find(keys[0])] = find(k)
    clusters = collections.defaultdict(list)
    for v in vulns:
        clusters[find(v["id"])].append(v)
    q = collections.Counter()
    advisories = []
    for vs in clusters.values():
        pub = min(x.get("published", "9999") for x in vs)
        per = quarter_of(pub)
        q[per] += 1
        all_ids = {x["id"] for x in vs} | {a for x in vs for a in x.get("aliases", [])}
        canon = sorted([i for i in all_ids if i.startswith("CVE")]
                       or [i for i in all_ids if i.startswith("GO-")]
                       or sorted(all_ids))[:1]
        advisories.append({"id": canon[0] if canon else sorted(all_ids)[0],
                           "published": pub[:10], "quarter": per,
                           "fixed": _fixed_version(vs, mod)})
    advisories.sort(key=lambda a: (a["published"], a["id"]))
    return dict(q), advisories


# --- SIGNAL: govulncheck reachable findings per module (symbol-level call traces) ---
def govulncheck_signal():
    """{module: reachable_count}. A finding is REACHABLE iff its trace reaches a
    called symbol ('function' frame); module/package-only findings are present-but-
    unreached (noise, not signal). Returns ({}, note) on any tooling error."""
    try:
        proc = subprocess.run(["govulncheck", "-json", "./..."],
                              capture_output=True, text=True)
    except FileNotFoundError:
        return {}, set(), "govulncheck not on PATH — signal skipped"
    raw = proc.stdout
    dec = json.JSONDecoder()
    i, osv, findings = 0, {}, []
    while i < len(raw):
        while i < len(raw) and raw[i] in " \n\r\t":
            i += 1
        if i >= len(raw):
            break
        o, i = dec.raw_decode(raw, i)
        if "osv" in o:
            osv[o["osv"]["id"]] = o["osv"]
        if "finding" in o:
            findings.append(o["finding"])
    reach = collections.Counter()
    flagged = set()  # every module govulncheck reports on (reached OR present-only)
    present = 0
    for f in findings:
        trace = f.get("trace", [])
        called = any("function" in fr for fr in trace)
        # map the finding's OSV to its affected Go module(s)
        mods = set()
        for a in osv.get(f["osv"], {}).get("affected", []):
            p = (a.get("package") or {}).get("name")
            if p:
                mods.add(p)
        flagged |= mods
        if called:
            for m in mods:
                reach[m] += 1
        else:
            present += 1
    # govulncheck -json exits 0 even when vulns are found; a non-zero code with no
    # parsed advisories means it failed to ANALYZE (build break, bad flags) — that is a
    # false-clean, not a clean build, so flag it rather than recording 0 silently.
    if not osv and proc.returncode != 0:
        err = (proc.stderr or "").strip().splitlines()
        return {}, set(), f"govulncheck FAILED (rc={proc.returncode}): " \
            f"{err[-1] if err else 'no output'} — signal NOT captured"
    note = f"{sum(reach.values())} reachable, {present} present-but-unreached findings"
    return dict(reach), flagged, note


# --- HEALTH: OpenSSF Scorecard (deps.dev) + libyear (proxy.golang.org) ---
def _vcs_repo(mod):
    """The module's canonical source repo, via the Go vanity go-import meta tag
    (?go-get=1). Returns (host, 'host/owner/repo') or (None, None). General — no
    hardcoded module→repo map."""
    import re
    try:
        html = urllib.request.urlopen(
            urllib.request.Request(f"https://{mod}?go-get=1"),
            timeout=30, context=_CTX).read().decode("utf-8", "ignore")
    except Exception:
        return None, None
    m = re.search(r'go-import["\']\s+content=["\']([^"\']+)', html)
    if not m:
        return None, None
    parts = m.group(1).split()  # "<prefix> <vcs> <repo-url>"
    url = parts[-1]
    norm = re.sub(r'^https?://', '', url).rstrip('/')
    norm = re.sub(r'\.git$', '', norm)
    return norm.split('/')[0], norm


def _scorecard(mod, ver):
    """Resolve the source repo's OpenSSF Scorecard (deps.dev). A module developed on
    Gerrit (go.googlesource.com) — x/* AND e.g. google.golang.org/protobuf — has only a
    read-only GitHub *mirror*, which under-reads on Scorecard (no PR-review/branch-
    protection signal); we mark mirror=True so its score never inflates H. The mirror
    flag comes from the canonical VCS host, not a path-prefix guess."""
    host, repo = _vcs_repo(mod)
    mirror = host == "go.googlesource.com"
    candidates = []
    try:
        vinfo = _get(f"{DEPS_DEV}/systems/go/packages/{_enc(mod)}/versions/{_enc(ver)}")
        candidates = [r["projectKey"]["id"] for r in vinfo.get("relatedProjects", [])
                      if r.get("relationType") == "SOURCE_REPO"]
    except Exception:
        pass
    if host and host != "go.googlesource.com" and repo not in candidates:
        candidates.append(repo)  # deps.dev keys projects by the GitHub-style host/owner/repo
    if mirror and not candidates:  # Gerrit module → try the conventional GitHub mirror
        candidates.append("github.com/golang/" + mod.split("/")[-1])
    for pid in candidates:
        try:
            proj = _get(f"{DEPS_DEV}/projects/{_enc(pid)}")
            sc = (proj.get("scorecard") or {}).get("overallScore")
            if sc is not None:
                return sc, pid + (" (Gerrit mirror)" if mirror else ""), mirror
        except Exception:
            continue
    return None, (candidates[0] + (" (Gerrit mirror)" if mirror else "")
                  if candidates else None), mirror


def _libyear(mod, ver):
    try:
        latest = _get(f"{PROXY}/{mod}/@latest")
        pinned = _get(f"{PROXY}/{mod}/@v/{ver}.info")
    except Exception:
        return None
    lt, pt = latest.get("Time", "")[:10], pinned.get("Time", "")[:10]
    days = ((datetime.date.fromisoformat(lt) - datetime.date.fromisoformat(pt)).days
            if lt and pt else None)
    return dict(scorecard=None, pinned=ver, pinned_date=pt,
                latest=latest.get("Version"), latest_date=lt, libyear_days=days)


def health(directs):
    out = {}
    for mod, ver in directs.items():
        h = _libyear(mod, ver) or dict(pinned=ver)
        sc, src, mirror = _scorecard(mod, ver)
        h.update(scorecard=sc, sc_src=src, mirror=mirror)
        out[mod] = h
    return out


# --- merge a period's capture into the existing ledger, preserving history ----------
def merge(doc, period, tracked, noise_by_mod, signal_by_mod, health_by_mod,
          advisories_by_mod):
    # Drop this period's rows ONLY for modules we re-captured (`tracked`); leave every
    # other module's history — including its current period — untouched.
    obs = [o for o in doc.get("observations", [])
           if not (o.get("period") == period and o.get("module") in tracked)]
    for mod in sorted(tracked):
        obs.append({"module": mod, "period": period,
                    "noise": noise_by_mod.get(mod, {}).get(period, 0),
                    "signal": signal_by_mod.get(mod, 0)})
    obs.sort(key=lambda o: (o["module"], o["period"]))
    doc["observations"] = obs
    # Refresh health for tracked modules; keep any pre-existing rows for the rest.
    doc.setdefault("health", {}).update(health_by_mod)
    # Advisory detail (CVE/GO id, published, fix version) makes each noise count
    # traceable to the specific CVEs behind it. Refresh for tracked modules only.
    doc.setdefault("advisories", {}).update(
        {m: a for m, a in advisories_by_mod.items() if a})
    cap = doc.setdefault("_capture", {})
    cap["last_period"] = period
    return doc


def main():
    argv = sys.argv[1:]
    period = (argv[argv.index("--period") + 1] if "--period" in argv
              else quarter_of(datetime.date.today().isoformat()))
    do_signal = "--no-signal" not in argv
    write = "--print" not in argv

    directs = direct_modules()
    # SIGNAL first: it also tells us which *indirect* modules carry advisories in our
    # build (e.g. golang.org/x/crypto present-but-unreached) — those belong in the
    # track record too, so we fold them into the captured set.
    signal, flagged, sig_note = ({}, set(), "signal skipped")
    if do_signal:
        signal, flagged, sig_note = govulncheck_signal()
    print(f"  signal: {sig_note}", file=sys.stderr)

    tracked = dict(directs)
    for mod in sorted(flagged - set(directs)):
        try:
            tracked[mod] = go("list", "-m", "-f", "{{.Version}}", mod).strip()
        except subprocess.CalledProcessError:
            continue  # not in our build graph (transitive of a tool); skip
    print(f"capturing {len(directs)} direct + {len(tracked) - len(directs)} "
          f"flagged-indirect modules for {period} …", file=sys.stderr)

    noise, advisories = {}, {}
    for m in tracked:
        noise[m], advisories[m] = osv_noise(m)
    hp = health(tracked)

    try:
        doc = json.load(open(LEDGER))
    except (OSError, ValueError):
        doc = {"_status": "MEASURED — populated by scripts/dep-capture.py.",
               "observations": [], "health": {}}
    doc = merge(doc, period, set(tracked), noise, signal, hp, advisories)

    if write:
        with open(LEDGER, "w") as f:
            json.dump(doc, f, indent=2, ensure_ascii=False)
            f.write("\n")
        print(f"wrote {LEDGER}: {len(doc['observations'])} observations", file=sys.stderr)
    else:
        print(json.dumps(doc, indent=2))


if __name__ == "__main__":
    main()
