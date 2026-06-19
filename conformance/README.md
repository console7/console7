# `conformance/` — control-objective mapping + CI-gated suite

**Trust tier:** assurance (the self-classification surface — `GOAL.md` tenet 10).

The **CI-gated conformance suite** plus the **control-objective mapping**, so an
adopter can **evidence each control objective** and **self-classify** the inference
boundary against their own obligations (`DESIGN.md` §9; `ARCHITECTURE.md` §6.3). It
asserts that each provider implementation upholds the SECURITY contracts in
[`../sdk/interfaces/`](../sdk/interfaces/), driving the harness in
[`../sdk/testkit/`](../sdk/testkit/).

**Skeleton at P0** (`go test ./conformance/...`):

- `harness_test.go` — wires the suite to the `testkit` harness; the one non-stub test
  asserts the scaffolding composes.
- `contracts_test.go` — one **stub case per provider-interface method**, keyed to the
  must-never SECURITY clause it will assert. Every case **skips** — no logic yet.

The full suite (and the control-objective mapping) is a **Phase-5** deliverable
(`docs/ROADMAP.md`). An interface change, its reference implementation, and its
conformance test land in **one atomic PR** (`ARCHITECTURE.md` §6.1).
