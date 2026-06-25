#!/usr/bin/env python3
# Dependency Lifecycle Model — strategic report visualiser.
#
# Renders the model (scripts/dep-lifecycle-model.py) as a SELF-CONTAINED static HTML
# report of three stacked panels, each answering a different strategic question:
#   1. Disposition map  — scatter of Substitutability (S, depth/lock-in) × Concentration
#      (C, fan-out/blast-radius), bubble = reachable LoC, colour = disposition. Top-right
#      is the danger quadrant (RULE 2: non-substitutable × high-fan-out => TCO / fork-
#      readiness); bottom-left is inline/VEX.  ("where to spend the hygiene budget")
#   2. Reachability funnel — closure ⊃ build-reachable ⊃ directly-imported, with the
#      graph-only remainder flagged VEX-able (RULE 1).  ("inherited blast radius vs reach")
#   3. Track-record sparklines — per module, noise canary (grey bars) vs reachable signal
#      (red), sorted by carry, tagged with the verdict.  ("is exposure trending?")
#
# Deliberately ZERO runtime egress and NO third-party JS/CSS: every chart is hand-emitted
# SVG with native <title> hover tooltips, so the artifact is one portable file that drops
# into control-plane/ui or ships as a CI artifact and adds no supply-chain surface
# (GOAL.md tenet 1; CO-05/CO-12.7). Pure stdlib.
#
#   python3 scripts/dep-viz.py                       # score live, write dep-lifecycle.html
#   python3 scripts/dep-viz.py --out /tmp/dep.html   # choose the output path
#   python3 scripts/dep-viz.py --track docs/strategy/dep-track-record.json   # track source
#   python3 scripts/dep-viz.py --in ledger.json      # render a pre-captured --json file
#   python3 scripts/dep-lifecycle-model.py --json | python3 scripts/dep-viz.py --in -
#
# Panels 1-2 need only the score ledger (`--json`: summary + ledger[]); panel 3 also reads
# the track ledger (`--track`) and renders only when it is present. Each ledger row may
# carry an optional "repo" field; when present it is shown in the tooltip and used to
# split same-module points — the seam for estate-scale aggregation (run the model per
# repo, concat the ledgers, render the estate in one view) with no renderer change.

import collections
import html
import json
import math
import subprocess
import sys

# Disposition class (from the row's two-lever `sub`) -> colour. Ordered low->high effort.
SUB_COLOUR = {
    "inline":      "#2e7d32",  # green   — rewrite the slice, shed the inheritance
    "rewrite":     "#1565c0",  # blue    — abstract behind a port
    "vendor-swap": "#0097a7",  # teal    — swap behind the seam, not a rebuild
    "fork":        "#ef6c00",  # orange  — fund fork-readiness
    "fork-hard":   "#c62828",  # red     — spine; cannot rewrite
    "lock-in":     "#6a1b9a",  # purple  — sole-source moat
    "VEX":         "#9e9e9e",  # grey    — not on a build path
}
SUB_ORDER = ["inline", "rewrite", "vendor-swap", "fork", "fork-hard", "lock-in", "VEX"]

W, H = 960, 660            # canvas
M = dict(l=78, r=250, t=78, b=70)   # margins (right margin holds the legend)
DMIN, DMAX = -0.5, 3.5     # axis data domain (S and C are 0..3; pad so dots clear edges)


def _model(*extra):
    out = subprocess.run([sys.executable, "scripts/dep-lifecycle-model.py", *extra, "--json"],
                         capture_output=True, text=True, check=True).stdout
    return json.loads(out)


def load(src, track_file):
    """Bundle the three data shapes the report needs: the score ledger + summary (point-
    in-time), the track aggregates (rho/trend/verdict per module), and the raw per-period
    noise/signal observations (for the sparklines). `src` overrides the ledger source
    (file or '-' for stdin); the track halves are read from `track_file` if it exists."""
    if src == "-":
        bundle = json.load(sys.stdin)
    elif src:
        bundle = json.load(open(src))
    else:
        bundle = _model()
    bundle.setdefault("track_record", [])
    obs = collections.defaultdict(list)
    try:
        bundle["track_record"] = _model("--track", track_file).get("track_record", [])
        raw = json.load(open(track_file))
        for o in raw.get("observations", []):
            obs[o["module"]].append(o)
        for m in obs:
            obs[m].sort(key=lambda x: x["period"])
    except (OSError, ValueError, subprocess.CalledProcessError):
        pass  # ledger-only render (scatter + funnel) when no track file is present
    bundle["obs_by_mod"] = {m: v for m, v in obs.items()}
    return bundle


def _x(v):
    return M["l"] + (v - DMIN) / (DMAX - DMIN) * (W - M["l"] - M["r"])


def _y(v):  # inverted: high concentration at the top
    return M["t"] + (DMAX - v) / (DMAX - DMIN) * (H - M["t"] - M["b"])


def _radius(loc):
    return 6 + 3.0 * math.log10(max(loc, 1))   # 432 LoC -> ~14px, 100k -> ~21px


def _short(mod):
    """Last path segment, skipping a trailing major-version element (…/v88 -> the name)."""
    parts = mod.split("/")
    last = parts[-1]
    if len(parts) > 1 and len(last) > 1 and last[0] == "v" and last[1:].isdigit():
        last = parts[-2]
    return last


def _jitter(rows):
    """Spread rows sharing an integer (S,C) cell around the cell centre, deterministic."""
    cells = {}
    for r in rows:
        cells.setdefault((r["S"], r["C"]), []).append(r)
    placed = []
    for (s, c), group in cells.items():
        n = len(group)
        for i, r in enumerate(sorted(group, key=lambda x: x["module"])):
            if n == 1:
                dx = dy = 0.0
            else:
                ang = 2 * math.pi * i / n
                rad = 0.20 if n <= 4 else 0.28
                dx, dy = rad * math.cos(ang), rad * math.sin(ang)
            placed.append((r, s + dx, c + dy))
    return placed


def svg(data):
    rows = data.get("ledger", [])
    summ = data.get("summary", {})
    px = []

    # quadrant shading + label
    def rect(x0, y0, x1, y1, fill, op):
        return (f'<rect x="{_x(x0):.1f}" y="{_y(y1):.1f}" width="{_x(x1)-_x(x0):.1f}" '
                f'height="{_y(y0)-_y(y1):.1f}" fill="{fill}" opacity="{op}"/>')
    px.append(rect(1.5, 1.5, 3.5, 3.5, "#c62828", 0.06))   # danger (top-right)
    px.append(rect(-0.5, -0.5, 1.5, 1.5, "#2e7d32", 0.05))  # inline/VEX (bottom-left)
    px.append(f'<text x="{_x(3.4):.1f}" y="{_y(3.42):.1f}" text-anchor="end" '
              f'font-size="12" fill="#c62828" font-weight="600">danger quadrant — '
              f'TCO / fork-readiness (RULE 2)</text>')
    px.append(f'<text x="{_x(-0.4):.1f}" y="{_y(-0.34):.1f}" font-size="12" '
              f'fill="#2e7d32" font-weight="600">inline / VEX — shed the inheritance</text>')

    # axes + integer gridlines/ticks
    for v in (0, 1, 2, 3):
        px.append(f'<line x1="{_x(v):.1f}" y1="{_y(DMIN):.1f}" x2="{_x(v):.1f}" '
                  f'y2="{_y(DMAX):.1f}" stroke="#eee"/>')
        px.append(f'<line x1="{_x(DMIN):.1f}" y1="{_y(v):.1f}" x2="{_x(DMAX):.1f}" '
                  f'y2="{_y(v):.1f}" stroke="#eee"/>')
        px.append(f'<text x="{_x(v):.1f}" y="{_y(DMIN)+20:.1f}" text-anchor="middle" '
                  f'font-size="12" fill="#555">{v}</text>')
        px.append(f'<text x="{_x(DMIN)-12:.1f}" y="{_y(v)+4:.1f}" text-anchor="end" '
                  f'font-size="12" fill="#555">{v}</text>')
    # axis titles
    px.append(f'<text x="{(_x(DMIN)+_x(DMAX))/2:.1f}" y="{H-22}" text-anchor="middle" '
              f'font-size="13" fill="#222" font-weight="600">S — substitutability '
              f'effort (depth / lock-in) →</text>')
    px.append(f'<text transform="translate(22,{(_y(DMIN)+_y(DMAX))/2:.1f}) rotate(-90)" '
              f'text-anchor="middle" font-size="13" fill="#222" font-weight="600">'
              f'C — concentration / fan-out (blast radius) →</text>')

    # bubbles
    for r, sx, cy in _jitter(rows):
        colour = SUB_COLOUR.get(r.get("sub"), "#607d8b")
        rad = _radius(r.get("reach_loc", 0))
        repo = r.get("repo")
        areas = ",".join(r.get("areas", []))
        tip = (f'{r["module"]}'
               + (f'  [{repo}]' if repo else '')
               + f'\ncarry {r["carry"]}   disposition: {r.get("sub")}'
               f'\nR{r["R"]} C{r["C"]} S{r["S"]} F{r["F"]} H{r["H"]}'
               f'   reachLoC {r.get("reach_loc", 0):,}'
               + (f'\narea: {areas}' if areas else '')
               + f'\n{r.get("disposition", "")}')
        px.append(f'<g><title>{html.escape(tip)}</title>'
                  f'<circle cx="{_x(sx):.1f}" cy="{_y(cy):.1f}" r="{rad:.1f}" '
                  f'fill="{colour}" fill-opacity="0.72" stroke="#fff" stroke-width="1.3"/>'
                  f'<text x="{_x(sx):.1f}" y="{_y(cy)-rad-3:.1f}" text-anchor="middle" '
                  f'font-size="10.5" fill="#333">{html.escape(_short(r["module"]))}'
                  f' · {r["carry"]}</text></g>')

    # legend (right gutter): disposition colours present in the data
    present = [s for s in SUB_ORDER if any(r.get("sub") == s for r in rows)]
    lx, ly = W - M["r"] + 22, M["t"] + 4
    px.append(f'<text x="{lx}" y="{ly}" font-size="12" font-weight="600" '
              f'fill="#222">disposition</text>')
    for i, s in enumerate(present):
        y = ly + 20 + i * 20
        px.append(f'<circle cx="{lx+7}" cy="{y-4}" r="7" fill="{SUB_COLOUR[s]}" '
                  f'fill-opacity="0.72" stroke="#fff"/>')
        px.append(f'<text x="{lx+22}" y="{y}" font-size="12" fill="#444">{s}</text>')
    # size legend
    sy = ly + 20 + len(present) * 20 + 24
    px.append(f'<text x="{lx}" y="{sy}" font-size="12" font-weight="600" '
              f'fill="#222">bubble = reachable LoC</text>')
    for i, loc in enumerate((500, 5000, 50000)):
        rr = _radius(loc)
        cy = sy + 26 + i * (rr + 18)
        px.append(f'<circle cx="{lx+18}" cy="{cy}" r="{rr:.1f}" fill="none" '
                  f'stroke="#888"/>')
        px.append(f'<text x="{lx+40}" y="{cy+4:.1f}" font-size="11" '
                  f'fill="#666">{loc:,}</text>')

    return "\n".join(px), summ


# ---- panel 2: reachability funnel (inherit 100% blast radius, reach a sliver) --------
FW = 960
def svg_funnel(summ):
    closure = summ.get("modules_in_closure", 0)
    reach = summ.get("build_reachable", 0)
    direct = summ.get("directly_imported", 0)
    graph_only = summ.get("graph_only", closure - reach)
    h, bar, gap, x0 = 232, 38, 14, 30
    full = FW - x0 - 360
    px = ['<text x="0" y="20" font-size="15" font-weight="600" fill="#222">'
          'Reachability funnel — you inherit the closure, you reach a sliver</text>']
    tiers = [("in closure (inherited blast radius)", closure, "#b0bec5"),
             ("build-reachable (toil triaged here)", reach, "#5c9ce6"),
             ("directly imported (scored on the scatter)", direct, "#1565c0")]
    for i, (label, n, colour) in enumerate(tiers):
        w = full * (n / closure) if closure else 0
        y = 44 + i * (bar + gap)
        px.append(f'<rect x="{x0}" y="{y}" width="{max(w,2):.1f}" height="{bar}" '
                  f'fill="{colour}" rx="3"/>')
        px.append(f'<text x="{x0+10}" y="{y+bar/2+5:.0f}" font-size="13" '
                  f'fill="#fff" font-weight="600">{n}</text>')
        px.append(f'<text x="{x0+max(w,2)+12:.1f}" y="{y+bar/2+5:.0f}" font-size="12.5" '
                  f'fill="#444">{html.escape(label)}</text>')
    yv = 44 + bar / 2
    px.append(f'<text x="{x0}" y="{44+3*(bar+gap)+6:.0f}" font-size="12.5" fill="#2e7d32" '
              f'font-weight="600">→ {graph_only} graph-only modules never reach a call '
              f'path: VEX as "not affected" and prune — no scan toil owed (RULE 1).</text>')
    return f'<svg width="{FW}" height="{h}" viewBox="0 0 {FW} {h}" font-family="inherit">' \
           + "\n".join(px) + '</svg>', yv


# ---- panel 3: track-record sparklines (noise canary vs signal toil, per module) ------
def _verdict_colour(tag):
    t = tag.lower()
    if any(k in t for k in ("danger", "breach")):
        return "#c62828"
    if any(k in t for k in ("blind", "watch", "underestim")):
        return "#ef6c00"
    return "#2e7d32"   # insulated / corroborated / steady


def svg_sparklines(bundle):
    track = bundle.get("track_record", [])
    obs = bundle.get("obs_by_mod", {})
    if not track:
        return ""
    carry = {r["module"]: r.get("carry", 0) for r in bundle.get("ledger", [])}
    track = sorted(track, key=lambda r: (-carry.get(r["module"], 0), r["module"]))
    gmax = max((o.get("noise", 0) for series in obs.values() for o in series), default=1) or 1
    cols, cw, ch = 3, 312, 116
    rows_n = (len(track) + cols - 1) // cols
    Hs = 44 + rows_n * ch
    px = ['<text x="0" y="20" font-size="15" font-weight="600" fill="#222">'
          'Track records — noise canary (grey) vs reachable signal (red), by carry'
          f' · bars scaled to global max {gmax}</text>']
    for idx, r in enumerate(track):
        mod = r["module"]
        cx, cy = (idx % cols) * cw + 4, 40 + (idx // cols) * ch
        series = obs.get(mod, [])
        pw, ph, bx, by = cw - 28, 46, cx + 8, None
        by = cy + 26 + ph        # baseline
        px.append(f'<text x="{cx+8}" y="{cy+14}" font-size="12.5" font-weight="600" '
                  f'fill="#222">{html.escape(_short(mod))} · carry {carry.get(mod,0)}</text>')
        n = len(series)
        if n:
            step = pw / max(n, 1)
            bw = step * 0.6
            sig_pts = []
            for j, o in enumerate(series):
                noise, sig = o.get("noise", 0), o.get("signal", 0)
                xb = bx + j * step + (step - bw) / 2
                nh = (noise / gmax) * ph
                if noise:
                    px.append(f'<rect x="{xb:.1f}" y="{by-nh:.1f}" width="{bw:.1f}" '
                              f'height="{nh:.1f}" fill="#cfd8dc"><title>'
                              f'{html.escape(o["period"])}: noise {noise}, signal {sig}'
                              f'</title></rect>')
                sig_pts.append(f'{bx + j*step + step/2:.1f},{by-(sig/gmax)*ph:.1f}')
            px.append(f'<line x1="{bx}" y1="{by}" x2="{bx+pw:.1f}" y2="{by}" stroke="#ddd"/>')
            px.append(f'<polyline points="{" ".join(sig_pts)}" fill="none" '
                      f'stroke="#c62828" stroke-width="1.6"/>')
            for p in sig_pts:
                px.append(f'<circle cx="{p.split(",")[0]}" cy="{p.split(",")[1]}" r="2.2" '
                          f'fill="#c62828"/>')
        rho = "-" if r.get("rho") is None else f'{r["rho"]:.2f}'
        vc = _verdict_colour(r.get("verdict", ""))
        px.append(f'<text x="{cx+8}" y="{by+18:.0f}" font-size="11.5" fill="#666">'
                  f'cumN {r.get("cum_noise",0)} · ρ {rho} · </text>')
        px.append(f'<text x="{cx+8}" y="{by+33:.0f}" font-size="11.5" font-weight="600" '
                  f'fill="{vc}">{html.escape(r.get("verdict",""))}</text>')
    return f'<svg width="{FW}" height="{Hs}" viewBox="0 0 {FW} {Hs}" ' \
           f'font-family="inherit">' + "\n".join(px) + '</svg>'


def render(data):
    body, summ = svg(data)
    funnel, _ = svg_funnel(summ)
    sparks = svg_sparklines(data)
    sub = (f'closure {summ.get("modules_in_closure","?")} · '
           f'build-reachable {summ.get("build_reachable","?")} · '
           f'direct {summ.get("directly_imported","?")} · '
           f'Tier-1 core direct imports {summ.get("core_direct_imports","?")} '
           f'(tenet: must be 0)')
    spark_section = (f'<h2>Track records — is exposure trending?</h2>\n'
                     f'<svg width="{FW}" height="0"></svg>\n{sparks}\n'
                     f'<p class="note">Per module: grey bars = NEW CVEs disclosed that '
                     f'quarter (the canary, a property of the package); red = how many '
                     f'were REACHABLE on our call path (the toil, a property of our usage). '
                     f'At t0 signal is flat at 0 everywhere — the spike in <code>x/crypto</code> '
                     f'noise with no signal is the INSULATED archetype, measured.</p>'
                     ) if sparks else ''
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Console7 — dependency lifecycle report</title>
<style>
 body{{font:14px -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#222;
   margin:24px;background:#fff;max-width:1040px}}
 h1{{font-size:19px;margin:0 0 2px}} h2{{font-size:15px;margin:30px 0 4px}}
 .sub{{color:#666;font-size:12.5px;margin:0 0 10px}}
 .note{{color:#777;font-size:12px;margin-top:6px;max-width:900px}}
 rect,circle,polyline{{cursor:default}} g:hover circle{{fill-opacity:0.95}}
</style></head><body>
<h1>Dependency lifecycle — strategic report</h1>
<p class="sub">{html.escape(sub)}</p>
<h2>Disposition map — where to spend the hygiene budget</h2>
<svg width="{W}" height="{H}" viewBox="0 0 {W} {H}" font-family="inherit"
  role="img" aria-label="Substitutability by concentration scatter of dependencies">
{body}
</svg>
<p class="note">Substitutability (depth/lock-in) × concentration (fan-out). Bubble size =
reachable LoC; colour = disposition. Top-right = non-substitutable × high-fan-out =
the spine to keep behind the <code>sdk/interfaces</code> seam and fund fork-readiness
for; bottom-left = inline / VEX. Hover a bubble for its axis breakdown.</p>
<h2>Reachability — inherited blast radius vs what you actually reach</h2>
{funnel}
{spark_section}
<p class="note">Generated by <code>scripts/dep-viz.py</code> from
<code>dep-lifecycle-model.py --json</code> (+ <code>--track</code>) — self-contained,
zero egress. Strategy / defence-in-depth (tenet 2), not a gate.</p>
</body></html>
"""


def main():
    argv = sys.argv[1:]
    src = argv[argv.index("--in") + 1] if "--in" in argv else None
    track_file = (argv[argv.index("--track") + 1] if "--track" in argv
                  else "docs/strategy/dep-track-record.json")
    out = argv[argv.index("--out") + 1] if "--out" in argv else "dep-lifecycle.html"
    doc = render(load(src, track_file))
    if out == "-":
        sys.stdout.write(doc)
    else:
        with open(out, "w") as f:
            f.write(doc)
        print(f"wrote {out} ({len(doc):,} bytes, self-contained, zero egress)",
              file=sys.stderr)


if __name__ == "__main__":
    main()
