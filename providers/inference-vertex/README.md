# `providers/inference-vertex/` — reference `InferenceBackend`

**Trust tier:** reference provider implementation.

Reference implementation of [`InferenceBackend`](../../sdk/interfaces/inference.go) on
**Vertex** (`ARCHITECTURE.md` §5), which keeps inference **in the adopter's own cloud
account/region** (`ARCHITECTURE.md` §3). Must uphold the SECURITY contract — enforce
the attended/unattended seam: refuse a subscription credential for any unattended or
multi-beneficiary session; never pool a subscription across beneficiaries.

> P0: placeholder — no implementation.
