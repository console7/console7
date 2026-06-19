# `providers/policy-opa/` — reference `PolicyEngine`

**Trust tier:** reference provider implementation.

Reference implementation of [`PolicyEngine`](../../sdk/interfaces/policy.go) on **OPA**
(Rego) (`ARCHITECTURE.md` §5). Must uphold the SECURITY contract — deterministic and
**fail-closed**: any error, timeout, or ambiguity yields a deny, never a
default-allow; decide only from the supplied facts. It evaluates rules; it is **not**
the system of record (that is `PolicySoR`).

> P0: placeholder — no implementation.
