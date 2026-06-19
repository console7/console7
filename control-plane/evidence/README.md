# `control-plane/evidence/` — WORM writer + SIEM stream

**Trust tier:** Tier-1 (control plane). Holds no keys at rest.

Writes evidence to an **append-only, WORM** store, **hash-chained and signed** for
tamper-evidence, and **streams it to the adopter's SIEM** (`DESIGN.md` §6). It is the
**system of record for verification** and is **separate from the operational
database**. Transcript access is least-privilege and separated from operations —
operators operate; they do not surveil. Drives the `EvidenceSink` seam.

> P0: placeholder — no implementation.
