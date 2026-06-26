# Phase 2 kickoff plan — Operate lane + evidence hardening

**Goal (`docs/ROADMAP.md` §Phase 2).** Make production observability safe to switch on.

**Exit gate.** An **operate** session diagnoses against **read-only** production telemetry and opens a
**PR with a proposed fix**, with **no path to actuation** and **every read evidenced**. Brings
**CO-10 (propose side), CO-12, CO-14 (full)** online.

**Sequencing principle (ROADMAP tenet).** *Boundary controls before features* — the read-only operate
identity + observability-scoped egress (the controls of record) land before the Observe Gateway feature.

**Already in place (do NOT re-build).** Operate persona rendering (read-only, denies Edit/Write); the
PreToolUse mutating-command tripwire (defence-in-depth, hardened in the SAST sprint). The
`ObserveGateway` seam is *defined* (`sdk/interfaces/observe.go`) but *unimplemented* (scaffold README).

> **Open decision — not blocking Phase 2 start.** The **in-cluster control-plane** (which carries the
> Web-CLI UI, the API gateway, and the Option-B identity end-state) has no phase home yet. Candidates:
> (a) its own "in-cluster platform" milestone, (b) folded into Phase 2, (c) Phase 3. Recommendation: (a).
> Deferred Phase-1 exit clauses (Vertex run, B13 walkthrough, subscription lifecycle, Web UI) are tracked
> separately and run *alongside*, never blocking this phase.

---

## Workstreams → PRs

### WS-1 — Evidence: tamper-EVIDENT → tamper-RESISTANT (CO-14 toward full)
WORM hash-chaining + checkpoint signing already exist. These close the SAST gaps already marked in code
(`SAST-DEFERRED #16/#31/#15/#30`); each PR also **removes the corresponding in-code marker**.

| PR | Scope | Exit criterion |
|---|---|---|
| **E1** — sequence-bind the lineage signature (#31) | Bind the record **sequence** into `payloadTBS`; thread the committed sequence from `Evidence.Append` → `appendSigned`; `VerifyRecordPayload` recomputes with the sequence. | A record replayed at another position **fails** `VerifyRecordPayload`; the existing chain still verifies. Remove `SAST-DEFERRED #31`. |
| **E3** — forensic completeness (#15 + #30) | `abort()` emits a distinct `sandbox-destroy-failed` WORM event; `proposalBody` escapes engine-sourced `FilesChanged`/`HeadSHA`. | A destroy-failure leaves a WORM record; a malicious filename cannot render as a live PR-body link. Remove `SAST-DEFERRED #15/#30`. |
| **E2** — preflight tail chain-integrity (#16) | Export a `ChainHash`/`VerifyTail` helper from `control-plane/evidence`; `evidence-gcs.preflight` recomputes the tail hash from its predecessor. | A crafted next-slot record whose hash doesn't chain is rejected **at startup**. Remove `SAST-DEFERRED #16`. |
| **E1b** *(small follow-up to E1)* | Wire per-record lineage verification into the production verifier: a `VerifyLineage(caRoot)` that walks the chain and calls `VerifyRecordPayload(caRoot, ref.Sequence, rec)` per record, surfaced alongside `VerifyChain` in the CLI/verify path. | Today only `VerifyChain` (hash) runs in production; the E1 sequence-binding (and attribution/persona binding) is exercised only in tests until this lands. |
| **E4** *(larger; may slip)* | SIEM stream + transcript-read least-privilege, separated from operations. | Every evidence append is mirrorable to an adopter SIEM sink; transcript access is a distinct least-priv role. |

### WS-2 — Operate lane: observe ≠ actuate (boundary-first, CO-12)
| PR | Scope | Exit criterion |
|---|---|---|
| **O1** *(BOUNDARY — control of record)* | Operate-lane **read-only cloud identity** (no mutating verbs) + session egress allowlist **scoped to observability APIs only**. | Operate identity reads telemetry, nothing mutating; egress reaches only observability endpoints; default-deny holds. |
| **O2** *(ATOMIC: interface + impl + conformance)* | Implement `ObserveGateway` (redacting, query-audited) — reference impl + wire the testkit conformance contract (currently skipped). | The `ObserveGateway` conformance contract runs green; queries are redacted and audited into evidence. |

### WS-3 — Propose-via-PR for operate (CO-10 propose side)
| PR | Scope | Exit criterion |
|---|---|---|
| **P1** | Operate session's diagnosis → a **proposed-PR** through the pipeline; **no** actuation path from operate. | An operate session opens a proposed-fix PR holding no credential/path to actuate. |

### WS-4 — Sub-agent lineage + scope (CO-12 sub-agent coverage)
| PR | Scope | Exit criterion |
|---|---|---|
| **S1** *(small; may fold into O1/orchestrator)* | Forked `claude -p` sub-agents inherit the human→NHI lineage + the session scope ceiling. | A sub-agent action is evidenced under the same lineage; scope cannot exceed the session ceiling. |

---

## Execution sequence (boundary-first)

1. **E1** — sequence-bind (foundational, already marked in code) ← first PR
2. **E3** — forensic small fixes (quick, parallelizable)
3. **E2** — preflight chain-integrity (pairs with E1 → evidence authenticity complete)
4. **O1** — operate read-only identity + observability-scoped egress (the boundary)
5. **O2** — ObserveGateway seam (the feature on the boundary)
6. **P1** — propose-via-PR → then **S1** + **E4** as the CO-14-full / CO-12-full completion
7. **Exit validation** — operate session diagnoses read-only telemetry → proposed-fix PR → no actuation → every read evidenced

Each PR: implement + tests → static gates (`go build/vet/test`, `gofmt`, `golangci-lint`, coverage, `terraform fmt`/`shellcheck` where relevant) → `pre-pr-review` (3-lens) for substantive changes → signed PR mapping to its CO → merge.
