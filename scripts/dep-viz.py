#!/usr/bin/env python3
# Dependency Lifecycle Model — danger-quadrant visualiser.
#
# Renders the score ledger (scripts/dep-lifecycle-model.py --json) as a SELF-CONTAINED
# static HTML file: an inline-SVG scatter of Substitutability (S, depth/lock-in) ×
# Concentration (C, fan-out/blast-radius), bubble size = reachable LoC, colour =
# disposition class. The top-right is the danger quadrant (RULE 2: non-substitutable ×
# high-fan-out => TCO scrutiny / fund fork-readiness); the bottom-left is inline/VEX.
#
# Deliberately ZERO runtime egress and NO third-party JS/CSS: the chart is hand-emitted
# SVG with native <title> hover tooltips, so the artifact is one portable file that
# drops into control-plane/ui or ships as a CI artifact, and adds no supply-chain
# surface (GOAL.md tenet 1; CO-05/CO-12.7). Pure stdlib.
#
#   python3 scripts/dep-viz.py                       # score live, write dep-lifecycle.html
#   python3 scripts/dep-viz.py --out /tmp/dep.html   # choose the output path
#   python3 scripts/dep-viz.py --in ledger.json      # render a pre-captured --json file
#   python3 scripts/dep-lifecycle-model.py --json | python3 scripts/dep-viz.py --in -
#
# The input schema is the model's `--json` (summary + ledger[]). Each ledger row may
# carry an optional "repo" field; when present it is shown in the tooltip and used to
# split same-module points — the seam for estate-scale aggregation (run the model per
# repo, concat the ledgers, render the estate in one view) with no renderer change.

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


def load(src):
    if src == "-":
        return json.load(sys.stdin)
    if src:
        return json.load(open(src))
    out = subprocess.run([sys.executable, "scripts/dep-lifecycle-model.py", "--json"],
                         capture_output=True, text=True, check=True).stdout
    return json.loads(out)


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


def render(data):
    body, summ = svg(data)
    sub = (f'closure {summ.get("modules_in_closure","?")} · '
           f'build-reachable {summ.get("build_reachable","?")} · '
           f'direct {summ.get("directly_imported","?")} · '
           f'Tier-1 core direct imports {summ.get("core_direct_imports","?")} '
           f'(tenet: must be 0)')
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Console7 — dependency danger quadrant</title>
<style>
 body{{font:14px -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#222;
   margin:24px;background:#fff}}
 h1{{font-size:18px;margin:0 0 2px}} .sub{{color:#666;font-size:12.5px;margin:0 0 10px}}
 .note{{color:#777;font-size:12px;margin-top:8px;max-width:900px}}
 circle{{cursor:default}} g:hover circle{{fill-opacity:0.95}}
</style></head><body>
<h1>Dependency lifecycle — danger quadrant</h1>
<p class="sub">{html.escape(sub)}</p>
<svg width="{W}" height="{H}" viewBox="0 0 {W} {H}" font-family="inherit"
  role="img" aria-label="Substitutability by concentration scatter of dependencies">
{body}
</svg>
<p class="note">Substitutability (depth/lock-in) × concentration (fan-out). Bubble size =
reachable LoC; colour = disposition. Top-right = non-substitutable × high-fan-out =
the spine to keep behind the <code>sdk/interfaces</code> seam and fund fork-readiness
for; bottom-left = inline / VEX. Hover a bubble for its axis breakdown. Generated by
<code>scripts/dep-viz.py</code> from <code>dep-lifecycle-model.py --json</code> — strategy
/ defence-in-depth (tenet 2), not a gate.</p>
</body></html>
"""


def main():
    argv = sys.argv[1:]
    src = argv[argv.index("--in") + 1] if "--in" in argv else None
    out = argv[argv.index("--out") + 1] if "--out" in argv else "dep-lifecycle.html"
    doc = render(load(src))
    if out == "-":
        sys.stdout.write(doc)
    else:
        with open(out, "w") as f:
            f.write(doc)
        print(f"wrote {out} ({len(doc):,} bytes, self-contained, zero egress)",
              file=sys.stderr)


if __name__ == "__main__":
    main()
