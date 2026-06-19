# `control-plane/inference-router/` — inference routing

**Trust tier:** Tier-1 (control plane). Holds no keys at rest.

Selects subscription vs org-API and the backend (Vertex / Bedrock / direct) per
enterprise policy, and **enforces the attended/unattended seam in policy, not
guidance** (`DESIGN.md` §3): a subscription credential backs only attended,
single-user sessions; any session without a present human or with more than one
beneficiary (orchestrated/scheduled/triggered/headless-unattended or cross-repo
fan-out) routes to the org-API key. The discriminator is human presence and single
beneficiary, **not** invocation mode — a forked/headless `claude -p` inside an
attended single-user session stays subscription-backed. The routing trigger is a
configurable enterprise policy — flip policy, not architecture. Drives the
`InferenceBackend` seam.

> P0: placeholder — no implementation.
