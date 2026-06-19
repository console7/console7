# `conformance/` — control-objective mapping + CI-gated suite

**Trust tier:** assurance (the self-classification surface — `GOAL.md` tenet 10).

The **CI-gated conformance suite** plus the **control-objective mapping**, so an
adopter can **evidence each control objective** and **self-classify** the inference
boundary against their own obligations (`DESIGN.md` §9; `ARCHITECTURE.md` §6.3). It
asserts that each provider implementation upholds the SECURITY contracts in
[`../sdk/interfaces/`](../sdk/interfaces/), driving the harness in
[`../sdk/testkit/`](../sdk/testkit/).

**Active suite** (`go test ./conformance/...`):

- `harness_test.go` — wires the suite to the `testkit` harness; `TestHarnessWiring` is
  the aggregate gate over every supplied provider.
- `contracts_test.go` — one case per provider-interface method, keyed to the must-never
  SECURITY clause it asserts. **Seven of nine seams are asserted for real** against the
  dev/in-memory providers — Cloud, Secrets, Identity, SCM, Inference, PolicySoR, Evidence
  (16 method-contracts); the remaining two (PolicyEngine, ObserveGateway) still **skip**
  until their providers land in Phases 2–3.

The full suite (and the control-objective mapping) is a **Phase-5** deliverable
(`docs/ROADMAP.md`). An interface change, its reference implementation, and its
conformance test land in **one atomic PR** (`ARCHITECTURE.md` §6.1).
