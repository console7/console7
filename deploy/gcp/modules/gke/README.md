# `modules/gke` — gVisor node pool + Workload Identity (stub)

Stub. Filled by the `cloud-gcp` PR: a gVisor (sandboxed) node pool for ephemeral
sandboxes, and the Workload Identity binding that lets the control-plane Kubernetes
service account impersonate the `modules/secrets` workload SA. No resources yet — the
secrets module only *outputs* the SA email today, so there is no dangling reference to
a not-yet-existing cluster.
