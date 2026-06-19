# `control-plane/inference-router/` — inference routing

**Trust tier:** Tier-1 (control plane). Holds no keys at rest.

Selects subscription vs org-API and the backend (Vertex / Bedrock / direct) per
enterprise policy, and **enforces the attended/unattended seam in policy, not
guidance** (`DESIGN.md` §3): a subscription credential backs only attended,
single-user sessions; anything orchestrated/scheduled/triggered/headless or
multi-beneficiary routes to the org-API key. The routing trigger is a configurable
enterprise policy — flip policy, not architecture. Drives the `InferenceBackend`
seam.

> P0: placeholder — no implementation.
