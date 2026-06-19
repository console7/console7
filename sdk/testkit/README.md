# `sdk/testkit/` — conformance harness

**Trust tier:** public contract (ships with the SDK). The harness adopters and
out-of-tree provider authors run to prove an implementation upholds the SECURITY
contracts in [`../interfaces/`](../interfaces/) (`ARCHITECTURE.md` §6.1).

**Skeleton at P0:** it enumerates the provider-interface methods and the must-never
clause each check will assert (`Contract`, `ProviderUnderTest`, `Run`), but holds
**no assertion logic**. The stub cases keyed to these contracts live under
[`../../conformance/`](../../conformance/). The full suite is a Phase-5 deliverable
(`docs/ROADMAP.md`).
