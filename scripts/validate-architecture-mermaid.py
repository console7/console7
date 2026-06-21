#!/usr/bin/env python3
"""Validate the docs/architecture/ Mermaid pack (offline, stdlib only).

The deterministic subset of the architecture-docs skill's review that can be a CI
control of record (Console7 SDLC Standard CO-14 evidence/auditability, CO-17 code
quality). For every Markdown file in the pack it checks that:

  * the file's ``` code fences are balanced;
  * each ```mermaid block declares a known diagram type (flowchart/graph/sequenceDiagram);
  * block openers (subgraph / alt / opt / loop / par / critical / rect / break / box)
    match their `end` closers;
  * sequence diagrams do not use the flowchart-only `==>` arrow (use ->> / -->>);
  * no `fa:fa-*` FontAwesome tokens (GitHub's Mermaid renders them as literal text).

Exit 0 if clean, 1 if any problem is found. Under GitHub Actions (GITHUB_ACTIONS set)
problems are emitted as `::error file=...::` annotations; otherwise as plain lines.

Usage: validate-architecture-mermaid.py [DIR]   (DIR defaults to docs/architecture)
No network, no third-party dependencies — the same check the architecture-docs CI
workflow runs as a blocking gate.
"""
import glob
import os
import re
import sys

FLOW_OPEN = ("subgraph",)
SEQ_OPEN = ("alt", "opt", "loop", "par", "critical", "rect", "break", "box")


def diagram_type(lines):
    """Return 'flow', 'seq', or '?' from the first meaningful line of a block."""
    for ln in lines:
        s = ln.strip()
        if not s or s.startswith("%%"):  # skip blanks and %%{init}%% directives
            continue
        if s.startswith(("flowchart", "graph")):
            return "flow"
        if s.startswith("sequenceDiagram"):
            return "seq"
        return "?"
    return "?"


def check_file(path):
    problems = []
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    if text.count("```") % 2:
        problems.append("odd number of ``` code fences")
    blocks = re.findall(r"```mermaid\n(.*?)```", text, re.S)
    # A fence the author *intends* as mermaid but that GitHub will not render as a
    # diagram (wrong case, trailing chars, indentation) is not captured above and would
    # silently skip validation — count intended openers and flag any that did not parse.
    intended = len(re.findall(r"(?im)^[ \t]*`{3}[ \t]*mermaid\b", text))
    if intended != len(blocks):
        problems.append(
            f"{intended} '```mermaid' fence(s) but {len(blocks)} parsed — a fence is malformed "
            "(casing / trailing chars / indentation); GitHub renders only an exact "
            "'```mermaid' opener followed by a newline"
        )
    for i, block in enumerate(blocks, 1):
        lines = block.splitlines()
        dt = diagram_type(lines)
        openers = FLOW_OPEN if dt == "flow" else SEQ_OPEN if dt == "seq" else ()
        n_open = sum(1 for x in lines if x.strip().split(" ", 1)[0] in openers)
        n_end = sum(1 for x in lines if x.strip() == "end")
        if dt == "?":
            problems.append(f"block {i}: unknown diagram type (expect flowchart/graph/sequenceDiagram)")
        if n_open != n_end:
            problems.append(f"block {i}: opener/`end` mismatch ({n_open} opens vs {n_end} ends)")
        if dt == "seq" and any("==>" in x for x in lines):
            problems.append(f"block {i}: `==>` is invalid in a sequenceDiagram (use ->> / -->>)")
        if "fa:fa-" in block:
            problems.append(f"block {i}: `fa:fa-` renders as literal text on GitHub (use emoji/plain text)")
    return problems


def main():
    explicit = len(sys.argv) > 1
    root = sys.argv[1] if explicit else "docs/architecture"
    in_actions = bool(os.environ.get("GITHUB_ACTIONS"))

    def err(msg):
        print(f"::error::{msg}" if in_actions else msg)

    if not os.path.isdir(root):
        # An explicit DIR argument may legitimately be absent (ad-hoc local use); the
        # default pack, however, MUST exist — its disappearance is a fail-closed condition
        # for this control-of-record gate, not a silent pass.
        if explicit:
            print(f"validate-architecture-mermaid: no {root}/ directory — nothing to validate")
            return 0
        err(f"expected architecture pack at {root}/ is missing — refusing to pass (fail-closed)")
        return 1
    files = sorted(glob.glob(os.path.join(root, "*.md")))
    if not files:
        if explicit:
            print(f"validate-architecture-mermaid: no markdown under {root}/ — nothing to validate")
            return 0
        err(f"no markdown under {root}/ — the architecture pack must exist (fail-closed)")
        return 1
    bad = 0
    for f in files:
        for p in check_file(f):
            print(f"::error file={f}::{p}" if in_actions else f"{f}: {p}")
            bad += 1
    if bad:
        print(f"VALIDATION FAILED — {bad} problem(s) across {len(files)} file(s)")
        return 1
    print(f"VALIDATION OK — {len(files)} file(s) checked")
    return 0


if __name__ == "__main__":
    sys.exit(main())
