# `providers/` — IN-TREE reference implementations ONLY

**Trust tier:** reference implementations of the provider seams. Each composes
against [`../sdk/interfaces/`](../sdk/interfaces/) and must uphold that interface's
SECURITY contracts (asserted by [`../conformance/`](../conformance/)).

**Reference set only** (`ARCHITECTURE.md` §6.1, §6.3; `CLAUDE.md`). Core ships a
secure-default implementation per seam and **no more** — the long tail of connectors
must **not** be buried in core's release cadence and blast radius. **Community and
third-party providers live out-of-tree**, in their own repos, against the published
SDK (the Terraform-core-plus-providers / out-of-tree-CSI pattern). The boundary is
structural: **core + a stable SDK + an ecosystem.**

An interface change, its reference implementation here, and its conformance test land
in **one atomic PR** — this is why core is a monorepo (`ARCHITECTURE.md` §6.1).

Reference defaults (`ARCHITECTURE.md` §5):

| Dir | Seam | Default |
|---|---|---|
| [`cloud-gcp/`](cloud-gcp/) | `CloudProvider` | gVisor + VPC Service Controls |
| [`secrets-gcp/`](secrets-gcp/) | `SecretsProvider` | Secret Manager + Cloud KMS |
| [`scm-github/`](scm-github/) | `SCMProvider` | GitHub App |
| [`inference-vertex/`](inference-vertex/) | `InferenceBackend` | Vertex |
| [`policy-opa/`](policy-opa/) | `PolicyEngine` | OPA |
| [`evidence-gcs/`](evidence-gcs/) | `EvidenceSink` | GCS bucket-lock + SIEM webhook |

> Community providers (e.g. `cloud-aws`, `secrets-vault`, `scm-gitlab`) live in their
> own repositories — **not** here.
>
> P0 scaffolding: directory tree and responsibilities only — **no implementation.**
