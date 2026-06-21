// Console7 pre-PR adversarial review fan-out (defence-in-depth; tenet 2).
//
// Runs four INDEPENDENT review lenses over the current branch's diff vs main —
// correctness, security/threat, spec-alignment, and architecture-docs currency —
// then synthesizes a single prioritized, deduplicated report. It does NOT gate
// anything: CI + Socket/Codex + the human admin-merge stay authoritative. See
// .claude/skills/pre-pr-review (and .claude/skills/architecture-docs for the
// currency lens).
//
// Opt-in: running this requires the user to opt into the Workflow tool. The
// no-opt-in default is the Agent-tool fan-out documented in the skill.
//
// Usage: Workflow({ name: 'pre-pr-review' })  or  Workflow({ name: 'pre-pr-review',
// args: { base: 'origin/main' } }) to diff against a different base ref.

export const meta = {
  name: 'pre-pr-review',
  description: 'Adversarial pre-push review fan-out: correctness + security + spec-alignment + architecture-docs currency over the branch diff, reconciled into one prioritized report.',
  phases: [
    { title: 'Review', detail: 'four independent lenses over the diff' },
    { title: 'Synthesize', detail: 'dedup + prioritize findings' },
  ],
}

// `args` is injected by the Workflow runtime; `typeof` keeps this safe even if a
// runtime ever omits the binding.
const base = (typeof args !== 'undefined' && args && args.base) || 'main'
const diffCmd = `git --no-pager diff ${base}...HEAD`

const FINDINGS = {
  type: 'object',
  properties: {
    findings: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          severity: { type: 'string', enum: ['P1', 'P2', 'P3'] },
          file: { type: 'string' },
          title: { type: 'string' },
          detail: { type: 'string' },
          fix: { type: 'string' },
        },
        required: ['severity', 'file', 'title', 'detail'],
      },
    },
  },
  required: ['findings'],
}

const LENSES = [
  {
    key: 'correctness',
    prompt: `You are an ADVERSARIAL correctness reviewer. Run \`${diffCmd}\` to see the change. Assume it is wrong and prove where: logic bugs, fail-open defaults, zero-value/empty-input traps, boundary/ordering errors, error handling. Report only real issues, each with a concrete fix. Return findings (empty array if none).`,
  },
  {
    key: 'security',
    prompt: `You are an ADVERSARIAL security/threat reviewer for Console7. Read GOAL.md (tenets) and docs/DESIGN.md section 10 (abuse classes), then run \`${diffCmd}\`. Which abuse class could this weaken (control-plane-as-target, lethal trifecta, cross-tier escalation, subscription misuse, sub-agent lineage, supply chain)? Flag anything that returns or persists long-lived credentials, widens scope, fails open, or adds maintainer egress. Return findings (empty array if none).`,
  },
  {
    key: 'spec-alignment',
    prompt: `You are an ADVERSARIAL spec-alignment reviewer for Console7. Read GOAL.md, docs/DESIGN.md, docs/ARCHITECTURE.md, and docs/standards/console7-sdlc-standard.md, then run \`${diffCmd}\`. Does the change deviate from a tenet or doc section? In particular: does any SECURITY docstring or comment claim a guarantee the signature/type cannot actually enforce? Return findings (empty array if none).`,
  },
  {
    key: 'architecture-docs',
    prompt: `You are an ADVERSARIAL architecture-documentation-currency reviewer for Console7. Run \`git --no-pager diff --name-only ${base}...HEAD\`. The repo keeps a multi-viewpoint architecture pack in docs/architecture/ (Mermaid views 01–08 + README). If the diff changes an architecture-significant surface but does NOT update the corresponding docs/architecture/ view(s), emit ONE finding per stale view (severity P3) whose fix is "run the architecture-docs skill to refresh the affected view and re-validate the Mermaid". Map changed paths to views: sdk/interfaces or sdk/types→02,03,06; control-plane/ or keybroker/→02,03,04,06; providers/→02,06,08; sandbox/ or deploy/→05; .github/workflows/ or scripts/ or .golangci.yml or socket.yml→07; go.mod or go.sum→08 (this map is a coarse subset — the architecture-docs skill's code-area→view map is canonical). If docs/architecture/ was updated appropriately for the change, or the change is architecturally inert (refactor with no new component/flow/boundary/dependency/control), return an empty findings array. Do NOT invent unrelated findings — currency only.`,
  },
]

phase('Review')
const reviews = await parallel(
  LENSES.map((l) => () =>
    agent(l.prompt, { label: `review:${l.key}`, phase: 'Review', schema: FINDINGS }),
  ),
)

const all = reviews
  .filter(Boolean)
  .flatMap((r) => (r && Array.isArray(r.findings) ? r.findings : []))

let summary
if (all.length === 0) {
  log('Pre-PR review: no findings from any lens.')
  summary = 'clean — no findings'
} else {
  phase('Synthesize')
  summary = await agent(
    `Four independent reviewers produced these findings on the same diff:\n${JSON.stringify(all, null, 2)}\n\nDeduplicate, drop false positives, order by severity (P1 first), and for each surviving finding give file, severity, a one-line title, and the concrete fix. Be concise; this is a pre-push checklist to reconcile before \`git push\`.`,
    { label: 'synthesize', phase: 'Synthesize' },
  )
}

return { findings: all, summary }
