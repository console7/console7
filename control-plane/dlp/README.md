# `control-plane/dlp/` — pre-egress DLP scanner

**Trust tier:** Tier-1 (control plane). Holds no keys at rest.

Secret-scanning plus PII/classification detection on anything committed or sent — a
**control of record at the boundary** (`DESIGN.md` §6, §8). It **MUST block** for
high tiers (T1/T2) and **MAY be advisory** below (proportionality), and it runs at
the boundary, **never as a bypassable in-sandbox hook**.

> P0: placeholder — no implementation.
