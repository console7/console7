# `sdk/` — the published contract surface

**Trust tier:** public contract (the promise to adopters and connector authors).
**Artifact:** SDK packages — semver'd, signed, published to registries
(`ARCHITECTURE.md` §6.4). The canonical, system-of-record SDK is this **Go module**
(`docs/adr/0001-language.md`); any npm/PyPI/crate packages are generated bindings,
not reimplementations.

This is the **independently versioned** seam that makes "bring your own everything"
real (`ARCHITECTURE.md` §6.1). It is *developed* in the monorepo but is the stable
interface out-of-tree providers and connectors depend on — **nobody should fork the
repo to write a provider.**

- [`interfaces/`](interfaces/) — the nine provider contracts from `ARCHITECTURE.md`
  §5, as typed Go interfaces with load-bearing SECURITY docstrings. Contracts only;
  no implementations (the reference set lives in [`../providers/`](../providers/),
  community providers out-of-tree).
- [`testkit/`](testkit/) — the conformance harness adopters and provider authors run
  to prove an implementation upholds those contracts. Skeleton at P0.

> P0 scaffolding: the interfaces are defined and the harness is stubbed; **nothing is
> implemented behind them yet.**
