// Console7 — the canonical SDK and core are one Go module (docs/adr/0001-language.md).
// The module is intentionally dependency-free at P0 scaffolding: the provider
// contracts in sdk/interfaces are pure type declarations with no implementations
// behind them, so there is nothing to depend on yet. Keeping the dependency
// surface empty is the strongest supply-chain posture for a Tier-1 codebase
// (GOAL.md tenet 10); dependencies arrive with the reference providers, vetted
// through the chokepoint (docs/standards/console7-sdlc-standard.md, CO-5/CO-12.7).
module github.com/console7/console7

go 1.23
