// Console7 pre-PR adversarial review fan-out (defence-in-depth; tenet 2).
//
// Runs three INDEPENDENT review lenses over the current branch's diff vs main —
// correctness, security/threat, spec-alignment — then synthesizes a single
// prioritized, deduplicated report. It does NOT gate anything: CI + Socket/Codex +
// the human admin-merge stay authoritative. See .claude/skills/pre-pr-review.
//
// Opt-in: running this requires the user to opt into the Workflow tool. The
// no-opt-in default is the Agent-tool fan-out documented in the skill.
//
// Usage: Workflow({ name: 'pre-pr-review' })  or  Workflow({ name: 'pre-pr-review',
// args: { base: 'origin/main' } }) to diff against a different base ref.

export const meta = {
  name: 'pre-pr-review',
  description: 'Adversarial pre-push review fan-out: correctness + security + spec-alignment over the branch diff, reconciled into one prioritized report.',
  phases: [
    { title: 'Review', detail: 'three independent lenses over the diff' },
    { title: 'Synthesize', detail: 'dedup + prioritize findings' },
  ],
}

const base = (args && args.base) || 'main'
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
    `Three independent reviewers produced these findings on the same diff:\n${JSON.stringify(all, null, 2)}\n\nDeduplicate, drop false positives, order by severity (P1 first), and for each surviving finding give file, severity, a one-line title, and the concrete fix. Be concise; this is a pre-push checklist to reconcile before \`git push\`.`,
    { label: 'synthesize', phase: 'Synthesize' },
  )
}

return { findings: all, summary }
