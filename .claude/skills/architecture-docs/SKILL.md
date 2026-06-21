---
name: architecture-docs
description: Keep the docs/architecture/ pack (the multi-viewpoint Mermaid architecture views 01–08 + README) current. Use when a change touches an architecture-significant surface — sdk/interfaces, control-plane, keybroker, providers, sandbox, deploy, scripts, CI/build config, or go.mod — or when the user asks to update/regenerate an architecture view. Maps each code area to the view(s) it affects, enforces the diagram conventions, and validates the Mermaid before push. Defence-in-depth (tenet 2), not a gate.
---

# Keep the architecture pack current (Console7)

`docs/architecture/` is a code-grounded, multi-viewpoint architecture description
rendered as **Mermaid** (GitHub-native, restylable). When a PR changes the system's
shape, the affected view must move with it — stale architecture docs are worse than
none, because reviewers and adopters trust them. This skill is the **how**: which view
each change touches, the conventions to preserve, and how to validate before pushing.

It is **defence-in-depth, not a gate** (`GOAL.md` tenet 2). It never blocks a push; it
keeps the pack honest. Proportionality (tenet 8): skip it for architecturally inert
changes (a refactor with no new component/flow/boundary/dependency).

## The pack
| File | View | Refresh when… |
|---|---|---|
| `01-system-context.md` | C4 L1 — actors, externals, the one inference crossing | a new external actor/system or a new boundary crossing appears |
| `02-functional-logical.md` | C4 L2 containers — trust tiers, the 9 seams, sync/async | a container or seam is added/removed, or a call becomes async |
| `03-component-view.md` | C4 L3 — key broker, orchestrator, evidence sink | internals/invariants of those three change |
| `04-runtime-behaviour.md` | Sequences — lifecycle, authN/authZ, egress, operate | the call order, a fail-closed check, or the egress flow changes |
| `05-deployment.md` | GKE/GCP topology, networks, IAM, artifacts, local target | `deploy/**` or `sandbox/**` topology/IAM changes |
| `06-data-flow-trust-boundaries.md` | STRIDE-ready DFD + per-boundary table | a data flow, store, classification, or trust boundary changes |
| `07-technology-lifecycle-controls.md` | SDLC swimlanes — gates + evidence | a CI gate / control / evidence artifact is added or changes |
| `08-dependency-supply-chain.md` | first/third-party, OSS, runtime placement | `go.mod`/`go.sum` or a provider's external dependency changes |
| `README.md` | index + assumptions / gaps / reviewer observations | any of the above, or status of a marked item flips |

## Code area → affected view(s)
Run `git diff --name-only <base>...HEAD` and map the changed paths:

- `sdk/interfaces/**`, `sdk/types*` → **02, 03, 06** (and **08** if a dep is added)
- `control-plane/**`, `keybroker/**` → **02, 03, 04, 06**
- `providers/**` → **02, 06, 08** (and **05** if it changes deploy IAM)
- `sandbox/**`, `deploy/**` → **05** (and **06** if a boundary moves)
- `.github/workflows/**`, `scripts/**`, `.golangci.yml`, `socket.yml` → **07**
- `go.mod`, `go.sum` → **08**
- cross-repo (`console7-cloud-local`, `console7-deploy*`) → **05, 08**

A flip of an implementation **status** (a ◻ scaffold becomes ✅ implemented, or an
**(assumed)** item is confirmed/removed) always touches the relevant view **and** the
README's status markers / reviewer-observations list.

## How to update
1. **Read the changed code — do not guess** (the pack's founding rule). Open the actual
   diff and the source it touches; the diagrams must reflect what the code does, not the
   spec's intent alone.
2. **Edit the mapped view(s):** update the Mermaid diagram, the prose walkthrough, and
   the **status markers**.
3. **Preserve the conventions** (see `README.md` → "Reading conventions"):
   - Status: **✅** implemented (read in source) · **◻** scaffold / tracked target ·
     **⬡** pluggable seam · **(assumed)** inferred from docs, not confirmed in code.
   - Trust-tier colours via `classDef`: control plane (blue), key broker (purple,
     *separate* artifact), data-plane sandbox (red), seams (green), providers/OSS
     (amber), stores (grey). Keep the legend consistent across views.
   - **Canonical names** must match across views and the code: personas Author/Operate;
     the nine seams (`CloudProvider`, `SecretsProvider`, `IdentityProvider`,
     `SCMProvider`, `InferenceBackend`, `PolicyEngine`, `PolicySoR`, `EvidenceSink`,
     `ObserveGateway`); domain types (`Subject`, `SessionID`, `Tier`, `Stratum`,
     `TierStratum`, `SessionProfile`, `CredentialRef`, `SessionIdentity`/NHI,
     `EvidenceRecord`/`RecordRef`, `Signature`/`SinkSignature`).
4. **Keep GitHub-rendering constraints:** use `flowchart` / `sequenceDiagram` only
   (not the experimental Mermaid C4 dialect); **no FontAwesome** (`fa:fa-*` renders as
   literal text — use plain text or emoji); sequence diagrams use `->>`/`-->>` arrows
   (the `==>` thick arrow is flowchart-only); quote any node label containing `(`, `)`,
   `&`, or `<br/>`.
5. **Update `README.md`** if the index, an assumption, a residual gap, or a reviewer
   observation changed.

## Validate before pushing (offline, dependency-free)
Run from the repo root — checks diagram-type, block balance, sequence-arrow misuse,
stray FontAwesome, and code-fence parity. No network, stdlib `python3` only:

```bash
python3 - <<'PY'
import re, glob, sys
flow_open=('subgraph',); seq_open=('alt','opt','loop','par','critical','rect','break','box')
bad=0
for f in sorted(glob.glob('docs/architecture/*.md')):
    t=open(f).read()
    if t.count('```')%2: print(f'{f}: ODD code fences'); bad=1
    for i,b in enumerate(re.findall(r'```mermaid\n(.*?)```', t, re.S),1):
        L=b.splitlines(); first=next((x.strip() for x in L if x.strip()),'')
        dt='flow' if first.startswith(('flowchart','graph')) else ('seq' if first.startswith('sequenceDiagram') else '?')
        op=sum(1 for x in L if x.strip().split(' ',1)[0] in (flow_open if dt=='flow' else seq_open))
        en=sum(1 for x in L if x.strip()=='end')
        if dt=='?': print(f'{f} block{i}: unknown diagram type'); bad=1
        if op!=en: print(f'{f} block{i}: subgraph/end mismatch {op}!={en}'); bad=1
        if dt=='seq' and any('==>' in x for x in L): print(f'{f} block{i}: ==> invalid in sequenceDiagram'); bad=1
        if 'fa:fa-' in b: print(f'{f} block{i}: fa:fa- icon will render as literal text on GitHub'); bad=1
print('VALIDATION', 'FAILED' if bad else 'OK'); sys.exit(1 if bad else 0)
PY
```

Structural validation is necessary but not sufficient — also eyeball the rendered
diagram (GitHub preview, or `mmdc` if the adopter has it pinned/vetted) for layout.

## Scope & honesty
- The pack lives in **`console7/console7`**; cross-repo changes (`console7-cloud-local`,
  `console7-deploy*`) are reflected in views **05** and **08** by extension.
- Mark anything you infer but cannot confirm in code as **(assumed)** — never quietly
  upgrade a scaffold to "implemented".
- This is descriptive documentation: it changes no behaviour, so the **pure-docs**
  proportionality applies — the heavyweight `pre-pr-review` adversarial fan-out is not
  required for a docs-only refresh, but the validation snippet above always is.

## Relationship to the other guards
- The **pre-pr-review** skill/workflow runs an *architecture-docs currency* lens that
  flags when an architecture-significant surface changed without a `docs/architecture/`
  update, and points back here.
- The **Bash guard** (`.claude/hooks/guard-bash.sh`) prints a **non-blocking** pre-push
  reminder in the same situation. Both are nudges, never gates (tenet 2); the
  authoritative review remains CI + Socket/Codex + the maintainer's admin-merge.
