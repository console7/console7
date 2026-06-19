# 1. Implementation language: Go

- **Status:** Accepted
- **Date:** 2026-06-19
- **Deciders:** Console7 maintainers
- **Supersedes / Superseded by:** —

This is the first Architecture Decision Record. ADRs capture a single, significant,
hard-to-reverse choice and the reasoning behind it. They are immutable once accepted:
to change a decision, add a new ADR that supersedes this one rather than editing it.

## Context

`docs/BOOTSTRAP.md` step 3 requires the implementation language to be picked **now**,
because it scopes the SDK and every in-tree component. The choice is foundational and
expensive to revisit once `sdk/interfaces`, `control-plane/`, `keybroker/`, and
`sandbox/` exist (`ARCHITECTURE.md` §6.3), so it warrants a recorded decision.

Constraints that bound the choice:

- **Cloud-native control plane.** The runtime is a modular-monolith control plane
  deployed to Kubernetes in the adopter's cloud (`ARCHITECTURE.md` §4, §6.2), with a
  separately-hardened key broker and a sandbox data plane — each a distinct,
  separately-signed artifact (§6.4).
- **A published SDK is the contract surface.** `sdk/interfaces` and `sdk/testkit` are
  versioned independently and consumed out-of-tree by provider and connector authors
  (§6.1). The language must produce a clean, stable, easily-vendored module.
- **We wrap the engine; we do not reimplement it** (Tenet 8). The genuine Claude Code
  engine is Node/Python and is reached **over its CLI / Agent SDK** from the sandbox
  base image (§6.3 `sandbox/base-image/`). The control-plane language therefore does
  **not** need to match the engine's language — that boundary is a process/CLI seam,
  not an in-process one.
- **Least privilege, ephemeral, supply-chain-tight** (Tenets 4, 6). Small, statically
  analysable, easily-reproducible binaries with a tight dependency surface reduce the
  attack surface of a Tier-1 artifact that holds the keys to many sandboxes.

## Decision

**Console7's implementation language is Go.**

It applies to:

- `sdk/interfaces` and `sdk/testkit` — the published, independently versioned contract
  surface and conformance harness (canonical SDK = a **Go module**).
- `control-plane/` (orchestrator, pdp, inference-router, dlp, evidence, UI/API gateway).
- `keybroker/` (broker, signing) — the separately-hardened artifact.
- `sandbox/` control-side helpers (egress-proxy, observe-gateway) and the in-tree
  reference providers under `providers/`.

It explicitly does **not** apply to:

- The **wrapped engine.** Claude Code (Node/Python) runs as-is inside the sandbox base
  image and is invoked over its CLI / Agent SDK. We do not port or reimplement it.
- Agent-authored workloads, fixtures, or scripts that are naturally another language.

## Decision drivers

- Conventional, well-trodden fit for cloud-native control planes and Kubernetes
  operators (the ecosystem we deploy into — `ARCHITECTURE.md` §4).
- Single static binary per artifact with a small runtime footprint — eases the
  distinct-artifact, distinct-signing-identity requirement (§6.4) and reproducible
  builds (Tenet 6).
- Strong standard library for servers, TLS, and concurrency; mature gRPC/OPA/cloud
  SDKs for the reference providers (`policy-opa`, `cloud-gcp`, …).
- Go modules give a clean, semver'd, vendorable SDK that out-of-tree authors can
  depend on without forking the repo (§6.1).
- First-class static analysis and a narrow dependency culture suit a Tier-1,
  public, security-sensitive codebase.

## Consequences

**Positive**

- One language across control plane, key broker, and SDK lowers cognitive load and
  lets the conformance suite test the *composed* system in one toolchain (§6.1).
- Small attack surface and reproducible, statically-linked artifacts.
- The control-plane / engine boundary stays an explicit, audited CLI/process seam —
  which is exactly where lineage is stamped — rather than blurring into in-process
  calls.

**Negative / costs**

- The engine integration crosses a language boundary (Go ↔ Node/Python CLI). This is
  deliberate and aligned with Tenet 8, but means engine I/O is marshalled over the
  CLI/Agent-SDK protocol, not shared in-process.
- Consumers who want the SDK in another language need bindings. See the open item
  below.

**Neutral**

- Provider authors write Go against `sdk/interfaces`; non-Go ecosystems integrate at
  the process/HTTP/gRPC boundary, not via the in-tree SDK.

## Alternatives considered

- **Rust** — strongest memory-safety and a compelling story for the key broker, but a
  steeper contributor on-ramp and a heavier build for a broad multi-service monorepo.
  Rejected as the default; may be revisited for a specific hardened component via a
  future ADR if a concrete need arises.
- **TypeScript / Node** — matches the engine's language and the web-CLI front end, but
  a weaker fit for small statically-linked control-plane/key-broker artifacts and a
  larger, faster-moving dependency surface for a Tier-1 system. Not chosen for the
  core; the `control-plane/ui` front end may still use web tooling within its own
  build.
- **Python** — fast to prototype and native to parts of the engine, but packaging and
  runtime footprint are a poor fit for the distinct-artifact, least-dependency
  posture. Rejected for the core.

## Open items to reconcile (non-blocking)

- `ARCHITECTURE.md` §6.1 lists the SDK being published as "npm / PyPI / Go module /
  crate". This ADR makes the **Go module the canonical, system-of-record SDK**; any
  npm/PyPI/crate packages would be **generated or hand-maintained bindings**, not
  independent reimplementations. This is a clarification, not a contradiction, but
  §6.1 should be reworded to say so. Flagged here rather than silently editing the
  normative doc; track as a follow-up doc PR.

## Links

- `docs/BOOTSTRAP.md` §3 — the directive to pick the language and record it here.
- `docs/ARCHITECTURE.md` §4 (topology), §6.1–§6.4 (repo layout, runtime, artifacts).
- `GOAL.md` — Tenet 4 (least privilege/ephemeral), Tenet 6 (evidence/supply chain),
  Tenet 8 (wrap the engine; do not reimplement).
