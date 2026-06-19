# `providers/evidence-gcs/` — reference `EvidenceSink`

**Trust tier:** reference provider implementation.

Reference implementation of [`EvidenceSink`](../../sdk/interfaces/evidence.go) on
**GCS bucket-lock + a SIEM webhook** (`ARCHITECTURE.md` §5). Must uphold the SECURITY
contracts — append-only/WORM with no update/delete path for written records,
hash-chained and signed, fail-closed (never drop silently), separate from the
operational DB, and stream only to the adopter's SIEM.

> P0: placeholder — no implementation.
