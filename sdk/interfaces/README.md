# `sdk/interfaces/` — provider contracts

**Trust tier:** public contract. **No implementations live here, ever** — this
package is type declarations and SECURITY docstrings only.

The nine "bring your own" seams from `ARCHITECTURE.md` §5. Each method carries a
**SECURITY contract** stating what an implementation MUST NEVER do; those clauses
encode the `GOAL.md` tenets and `DESIGN.md` MUST-requirements at the one place every
adopter's code passes through, and are what [`../testkit/`](../testkit/) asserts.

| Interface | Abstracts (`ARCHITECTURE.md` §5) | File |
|---|---|---|
| `CloudProvider` | sandbox isolation, networking, perimeter | `cloud.go` |
| `SecretsProvider` | secret storage, envelope encryption, KMS | `secrets.go` |
| `IdentityProvider` | user SSO/OIDC, group/role mapping | `identity.go` |
| `SCMProvider` | clone, branch, PR, short-lived tokens | `scm.go` |
| `InferenceBackend` | subscription / Vertex / Bedrock / direct | `inference.go` |
| `PolicyEngine` | rule evaluation | `policy.go` |
| `PolicySoR` | authoritative tier × stratum lookup | `policy.go` |
| `EvidenceSink` | WORM store + SIEM stream | `evidence.go` |
| `ObserveGateway` | redacting, audited telemetry reads | `observe.go` |

Shared value types are in `types.go`; the package overview is in `doc.go`.
