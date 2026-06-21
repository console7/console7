# RISKS register — tracked technical debt & calibrated exceptions

This register satisfies **CO-17** of the
[Console7 Repository SDLC Standard](standards/console7-sdlc-standard.md): *"tech debt
tracked in a RISKS register."* It records every **conscious** deviation from a
quality gate — a relaxed threshold, an excluded lint rule, a `//nolint`, an accepted
gap — so debt is **tracked, never silently absorbed** (the project's stance on
itself: a deviation is a regression to be justified, not a free trade-off).

Scope: this register is about the **engineering of this repo**. Product-level accepted
gaps live in the SDLC standard §5 (Tracked targets); session/product risks live in
`docs/THREAT-MODEL.md`. Keep entries terse; link the code and the gate each touches.

| ID | Date | Area | The exception | Why it is acceptable | Revisit when |
|----|------|------|---------------|----------------------|--------------|
| R-1 | 2026-06-21 | Lint / gosec (CO-17, CO-7.1) | `gosec` rule **G115** (integer-overflow on conversion) is excluded in [`.golangci.yml`](../.golangci.yml). | Every G115 site in the tree is a safe-by-construction conversion in a length-prefix codec (`appendField`/`takeField` in `keybroker/signing/ca_dev.go`, `providers/secrets-gcp/ports.go`) or a record count (`control-plane/evidence` `Sink.Len`). The lengths are KB-scale and bounded well under 2³², never attacker-sized to overflow. (The same idiom recurs in the matching `_test.go` files — e.g. `control-plane/evidence/evidence_test.go` — and is covered by the same tree-wide exclusion.) G115 is high-noise on exactly this idiom. **CodeQL remains the SAST of record** for genuine overflow-driven vulnerabilities; all other `gosec` rules stay on. | A conversion of an *externally-sized* quantity (a network/file length read into a narrower type without a bound) is introduced — then re-enable G115 and guard the specific site instead. |
| R-2 | 2026-06-21 | Trivy / terraform config (CO-17, CO-7.1) | `trivy` rule **GCP-0077** (bucket access logging) is ignored inline on the evidence bucket (`#trivy:ignore:AVD-GCP-0077` in [`deploy/gcp/modules/evidence/main.tf`](../deploy/gcp/modules/evidence/main.tf)). | GCP-0077 wants the **legacy** Cloud Storage bucket access/usage logs delivered to a target log bucket. The right control for auditing access to the evidence bucket is **Cloud Audit Logs (Data Access)** — a project/org-level configuration, not a bucket resource attribute — which records reads/writes with identity and is GCP-recommended over the older best-effort access logs. Wiring legacy logs would also require a second log bucket that itself re-triggers GCP-0077 (recursion). The bucket is otherwise hardened (uniform access, public-access-prevention, retention policy); the ignore is scoped to this one bucket with an inline reason. | The module gains a dedicated log-sink bucket for another reason, or an adopter requires legacy access logs specifically — then add a `logging{}` block (and ignore GCP-0077 on the log bucket only). |

## How to add an entry

1. Give it the next `R-N` id and today's date.
2. Name the gate it relaxes and link the exact code/config.
3. State *why it is safe* and the concrete *revisit* trigger — never "we'll get to it".
4. If the exception is a `//nolint`, the inline comment MUST cite this register id.
