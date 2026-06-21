# `modules/inference-vertex` — in-tenancy inference IAM (GCP Vertex AI)

The Vertex AI API enablement and the least-privilege predict grant the
[`inference-vertex`](../../../../providers/inference-vertex) reference `InferenceBackend`
relies on so a session can reach Claude (publisher) models **inside the adopter's own GCP
project and region**. The provider itself is a **pure routing seam** — it resolves the
in-tenancy endpoint but holds no credential and makes no call ([ADR-0004](../../../../docs/adr/0004-inference-backend-is-pure-routing.md)).

Provisions:

- the **Vertex AI API** (`aiplatform.googleapis.com`, `disable_on_destroy = false`);
- **one custom least-privilege role** (`aiplatform.endpoints.predict` only — online prediction
  via `predict` / `rawPredict` / `streamRawPredict`) bound to the **existing** workload SA
  passed in. There is deliberately **no `*.get`/`*.list`** (no enumeration), **no
  deploy/undeploy**, and **no `setIamPolicy`** (no self-grant); `roles/aiplatform.user` would be
  far too broad.

This module **adds exactly one verb to the one workload identity** (e.g. `modules/secrets`'
`workload_service_account_email`) rather than minting a second SA — least privilege composes.

> **Boundary note.** Granting predict does **not** make Vertex reachable from a session. The
> resolved endpoint host (`endpoint_host` output) MUST also be on the session's **default-deny
> egress allowlist**, which is the authoritative control (GOAL.md tenet 3). The allowlist wiring
> lands with the boundary-first sandbox PR.

Deliberately **not** here: project/billing (human bootstrap), GCP credential acquisition / the
workload-SA token mint (a `SecretsProvider` / key-broker concern), the engine-invocation env
emitted to the sandbox (`ANTHROPIC_VERTEX_PROJECT_ID` / `CLOUD_ML_REGION`), and the egress
allowlist itself.

## Inputs

| Variable | Description |
|---|---|
| `project_id` | Existing GCP project to deploy into |
| `region` | Vertex location (e.g. `us-east5`); validated, derives the endpoint host |
| `name_prefix` | Custom-role id prefix (consistent with the other deploy modules) |
| `workload_service_account_email` | The **existing** workload SA to grant predict to |

## Outputs

| Output | Description |
|---|---|
| `vertex_predict_role_id` | The least-privilege Vertex predict custom role |
| `endpoint_host` | The regional endpoint host — add it to the egress allowlist |
