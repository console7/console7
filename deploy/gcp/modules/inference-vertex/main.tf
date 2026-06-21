# Console7 in-tenancy inference substrate: the Vertex AI API plus the least-privilege
# predict grant the control-plane/sandbox workload identity needs to reach Claude
# (publisher) models on Vertex — and NOTHING else.
#
# This module backs the providers/inference-vertex reference InferenceBackend, which is a
# PURE ROUTING seam: it resolves a session to the in-tenancy Vertex endpoint
# (https://{region}-aiplatform.googleapis.com) but holds no credential and makes no call
# (docs/adr/0004). The actual inference call is made by the wrapped engine inside the
# sandbox, authenticating with a short-lived token for the workload SA granted here.
#
# Scope: enable aiplatform.googleapis.com and bind ONE custom role granting ONLY the Vertex
# online-prediction verb to the EXISTING workload SA (passed in — this module does not mint a
# second identity; least privilege composes by adding exactly one verb to the one workload
# identity). roles/aiplatform.user is deliberately NOT used: it carries a broad read/list/
# deploy surface this seam never exercises.
#
# Prerequisite (human bootstrap, not this module): the project and billing exist, and the
# workload SA (e.g. modules/secrets' "<prefix>-cp-secrets") is created.
#
# Boundary note: enabling predict here does NOT make Vertex reachable from a session — the
# resolved endpoint host (see outputs.tf) MUST also be on the session's default-deny egress
# allowlist, which is the authoritative control (GOAL.md tenet 3; wired in the sandbox PR).

resource "google_project_service" "aiplatform" {
  project = var.project_id
  service = "aiplatform.googleapis.com"

  # Don't disable the API on `terraform destroy` — other resources/users in the project may
  # depend on it, and re-enabling is slow.
  disable_on_destroy = false
}

# A single custom role granting ONLY online prediction. aiplatform.endpoints.predict is the
# verb evaluated for predict / rawPredict / streamRawPredict against Vertex endpoints and
# publisher models (the call path for Claude on Vertex). No *.get/*.list (no enumeration of
# models/endpoints), no deploy/undeploy, no setIamPolicy (no self-grant). Predefined
# roles/aiplatform.user bundles far more; a custom role is the least-privilege fit.
resource "google_project_iam_custom_role" "vertex_predict" {
  project     = var.project_id
  role_id     = "${replace(var.name_prefix, "-", "_")}_vertex_predict"
  title       = "Console7 inference workload — Vertex predict"
  description = "aiplatform.endpoints.predict only (online prediction against Vertex endpoints / publisher models). No enumeration, deploy, or self-grant."
  stage       = "GA"
  permissions = ["aiplatform.endpoints.predict"]
}

# Bind the predict role to the EXISTING workload SA. project-scoped: the predict verb is
# evaluated against the endpoint / publisher-model resource, and Console7 reaches first-party
# publisher models (projects/<project>/locations/<region>/publishers/anthropic/models/*) that
# are not adopter-created resources to name-condition on. The blast radius is bounded by the
# verb itself (predict only) and by the egress allowlist gating which host the session can reach.
resource "google_project_iam_member" "workload_vertex_predict" {
  project = var.project_id
  role    = google_project_iam_custom_role.vertex_predict.id
  member  = "serviceAccount:${var.workload_service_account_email}"
}
