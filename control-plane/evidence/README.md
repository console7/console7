# `control-plane/evidence/` — WORM writer + SIEM stream

**Trust tier:** Tier-1 (control plane). Holds no keys at rest.

Writes evidence to an **append-only, WORM** store, **hash-chained and signed** for
tamper-evidence, and **streams it to the adopter's SIEM** (`DESIGN.md` §6). It is the
**system of record for verification** and is **separate from the operational
database**. Transcript access is least-privilege and separated from operations —
operators operate; they do not surveil. Drives the `EvidenceSink` seam.

## What's implemented

The real `Sink` (`evidence.go`) implements `interfaces.EvidenceSink`:

- **Append-only / WORM** through a narrow `Store` seam (`store.go`) that has no update or
  delete method by construction; the in-memory `memStore` accepts the next sequence only
  (no gaps, no rewrite). A durable backing (GCS bucket-lock) slots in behind `Store` in a
  later PR without reopening the fail-closed append path.
- **Hash-chained** (SHA-256, length-prefixed, sink-stamped `AppendedAt` — never the
  caller's `ObservedAt`), identical to the `devkit.MemEvidence` chain so the real sink and
  the bench double are interchangeable behind the seam.
- **Sink-level signed** — the sink periodically (and on `Seal`) signs a **checkpoint** over
  its chain head, distinct from the per-record lineage signature the orchestrator embeds in
  payloads. Checkpoints form their own hash chain. The sink **holds no key**: it signs
  through a `CheckpointSigner` backed by the keybroker (`keybroker/signing.SinkSigner`).
- **Fail-closed** — a record is committed-or-errored atomically; a checkpoint-seal failure
  never un-commits or drops a committed record.
- **`Stream`** — fail-closed ref check; no off-box egress on the bench (the real SIEM
  webhook lands with `providers/evidence-gcs`).

`Verify` / `VerifyChain` / `VerifyCheckpoints` give an auditor full integrity checks. See
the package doc (`doc.go`) for the bench-mitigated-vs-real residual table.
