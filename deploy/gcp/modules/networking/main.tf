# Console7 sandbox network perimeter: the STATIC, always-on default-deny egress floor the
# ephemeral sandboxes run inside. This is the AUTHORITATIVE network control of record
# (DESIGN.md §5.2; GOAL.md tenet 3) — the boundary the cloud enforces, not an in-process
# proxy a hostile workload could ignore. It lands boundary-first (ROADMAP.md sequencing #2):
# the wall exists before any sandbox node pool (modules/gke, PR-2) or per-session egress
# proxy, so a sandbox is default-deny from the moment it can run.
#
# WHAT THIS MODULE OWNS (the static DENY floor):
#   - enabling the Compute Engine API (the resources below need it on a fresh project);
#   - a custom-mode VPC + a sandbox subnet (primary + pod/service secondary ranges, flow logs);
#   - a single, effective EGRESS default-DENY firewall rule (IPv4) scoped to the sandbox node tag;
#   - one narrow EGRESS ALLOW rule: sandbox-tag -> proxy pod range on the proxy port (B7), the only
#     sanctioned escape from the floor (priority 900, above the deny).
#
# WHAT IT DELIBERATELY DOES NOT OWN (deferred to modules/gke + providers/cloud-gcp, PR-2 —
# every item here is an ALLOW/escape path, needs the cluster, or cannot be enforced at the VPC
# layer at all, so it lands with the thing that can actually enforce it):
#   - the SANCTIONED egress path's NAT (Cloud Router + Cloud NAT) and the narrow ALLOW to Google APIs
#     for node image pulls — both land in modules/gke (NAT is SNAT for *permitted* flows; landing it
#     here, where the only routable range is the sandbox's own (denied) range, would point
#     translation at the ranges the floor denies and rest the guarantee on tag fidelity). NOTE: the
#     one ALLOW rule that DOES live here is the narrow sandbox->forward-proxy escape (B7, below) —
#     it is a destination INSIDE the cluster (the proxy pod range), not an SNAT/external path.
#   - the per-session egress ALLOWLIST (dynamic; programmed at the out-of-band proxy by the
#     orchestrator's ApplyEgressPolicy narrow step — orchestrator.go narrow-egress);
#   - the per-pod NetworkPolicy routing sandbox pods to the proxy only;
#   - THE METADATA / IMDS BLOCK. Crucially this is NOT a VPC firewall control: GCP documents
#     VM-to-metadata-server traffic (169.254.169.254 and the link-local GKE metadata server) as
#     ALWAYS allowed and NOT subject to VPC firewall rules, so a firewall "deny" to those ranges
#     neither blocks the traffic nor produces a deny log — it is null at this layer. The
#     authoritative sandbox metadata block is therefore a NODE-config control: the GKE metadata
#     server in GKE_METADATA mode on the sandbox node pool, which CONCEALS the node service account
#     (modules/gke) — NOT "disable Workload Identity", which would leave GCE_METADATA and EXPOSE the
#     node SA token. Plus the legacy 127.0.0.1:988/987 path and the metadata DNS names
#     (metadata.google.internal / metadata.goog), which a VPC firewall cannot match either. All of
#     it lands in modules/gke (see its README); PR-1 does not pretend to enforce it at the VPC.
#   - IPv6 egress denial. This subnet is single-stack IPv4 and a VPC firewall rule cannot mix IP
#     families, so there is no IPv6 egress path to deny. modules/gke keeps the cluster single-stack
#     IPv4 (no dual-stack node pool), so this is MOOT today, not deferred — if a future change makes
#     the subnet/pool dual-stack, an IPv6 `::/0` deny rule MUST be added here at the same time.
#   - in-sandbox DNS denial ("no arbitrary resolver" — sandbox/egress-proxy/README.md): the base
#     image ships the sandbox no general resolver (PR-3).
#
# The firewall rule TARGETS var.sandbox_node_tag, which no instance carries until modules/gke
# creates the sandbox node pool with that tag. That is intentional: this is the reserved floor,
# applied the instant the tagged nodes appear. Nothing here grants egress, so there is no path
# for a future sandbox to inherit reach it was not given.

# --- Compute Engine API ---

# The google_compute_* resources below require compute.googleapis.com. Enable it in-module (the
# pattern modules/secrets + modules/evidence use for their own APIs) so a fresh-project adopter
# does not hit a "first VPC call fails" apply. The custom-mode network depends_on this so the
# enable lands first.
resource "google_project_service" "compute" {
  project = var.project_id
  service = "compute.googleapis.com"

  # Don't disable the API on `terraform destroy` — other resources/users in the project may
  # depend on it, and re-enabling is slow.
  disable_on_destroy = false
}

# --- VPC + sandbox subnet ---

# Custom-mode (auto_create_subnetworks=false): no auto subnets in every region, so the only
# routable surface is the one sandbox subnet we define and govern. Regional routing keeps the
# dataplane within the deploy region (the inference/evidence backends are regional too).
resource "google_compute_network" "sandbox" {
  project                 = var.project_id
  name                    = "${var.name_prefix}-sandbox-net"
  auto_create_subnetworks = false
  routing_mode            = "REGIONAL"

  depends_on = [google_project_service.compute]
}

# The sandbox subnet. private_ip_google_access lets in-tenancy nodes reach Google APIs over
# private routing WITHOUT external IPs — a ROUTING capability, not an authorization: the egress
# firewall still governs which tagged workloads may use it. For SANDBOX-tagged nodes it is inert
# by design (the default-deny floor drops the private-access path too); it is here for the
# non-sandbox node pool's operational pulls (modules/gke, PR-2), where a narrow ALLOW to the
# Google API range opens it. VPC flow logs are on so denied/allowed flows are auditable (the
# perimeter's "the attempt is visible" requirement — DESIGN.md §5.2 — and trivy AVD-GCP-0029).
resource "google_compute_subnetwork" "sandbox" {
  project                  = var.project_id
  name                     = "${var.name_prefix}-sandbox-subnet"
  region                   = var.region
  network                  = google_compute_network.sandbox.id
  ip_cidr_range            = var.subnet_cidr_range
  private_ip_google_access = true

  secondary_ip_range {
    range_name    = "${var.name_prefix}-sandbox-pods"
    ip_cidr_range = var.pod_cidr_range
  }
  secondary_ip_range {
    range_name    = "${var.name_prefix}-sandbox-services"
    ip_cidr_range = var.service_cidr_range
  }

  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

# --- Firewall: the default-deny egress floor (scoped to the sandbox node tag) ---

# The single effective floor rule: drop ALL IPv4 egress from a sandbox-tagged workload (priority
# 1000, overriding GCP's implied allow-egress at 65535). The per-session ALLOW paths (the resolved
# inference endpoint, approved registries/MCP) are NARROWER, higher-priority rules the orchestrator
# programs at the out-of-band proxy per session (never a static wide grant here), so "forgot to
# deny" can never silently permit (cloud.go EgressPolicy is allowlist-only by construction).
# Logged, so every denied attempt is visible.
#
# Scope note (deliberately NOT here, see the header): this rule does not — and at the VPC layer
# cannot — block the metadata server (GCP exempts metadata traffic from firewall rules) or IPv6
# (single-stack IPv4 subnet; a rule cannot mix families). Those are node-layer / dual-stack
# concerns deferred to PR-2. The floor's job is general IPv4 egress, and for that it is authoritative.
resource "google_compute_firewall" "deny_egress_all" {
  project     = var.project_id
  name        = "${var.name_prefix}-sandbox-deny-egress"
  network     = google_compute_network.sandbox.id
  description = "Default-deny egress floor: drop ALL IPv4 egress from sandbox-tagged workloads. Per-session allowlisted destinations are programmed narrower at the out-of-band proxy (providers/cloud-gcp), never widened here. Metadata block + IPv6 are node-layer/dual-stack concerns (modules/gke), not enforceable at this layer."
  direction   = "EGRESS"
  priority    = 1000

  target_tags        = [var.sandbox_node_tag]
  destination_ranges = ["0.0.0.0/0"]

  deny {
    protocol = "all"
  }

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

# --- Firewall: the narrow ALLOW to the egress proxy (the one sanctioned escape from the floor) ---

# Permit a sandbox-tagged node to reach the in-cluster forward proxy on the proxy port, and NOTHING
# else. Priority 900 (< the 1000 deny floor) so this one flow is allowed while every other
# destination still hits the floor. The destination is the POD range — the proxy runs as a pod — so
# at the VPC layer this is necessarily coarse (it permits :3128 to any pod). It is therefore the
# NODE-layer HALF of the path; the AUTHORITATIVE per-pod restriction is the per-session NetworkPolicy
# (providers/cloud-gcp renderNamespaceAndEgress), which pins sandbox egress to the
# console7.dev/egress-proxy namespace ONLY, and only the proxy listens on this port. The proxy itself
# (on the non-sandbox control pool, NAT egress) enforces the per-session FQDN allowlist
# (modules/egress-proxy + the orchestrator, B8). Keep var.egress_proxy_port in sync with the
# providers/cloud-gcp proxyPort (3128). Logged.
resource "google_compute_firewall" "allow_egress_proxy" {
  project     = var.project_id
  name        = "${var.name_prefix}-sandbox-allow-egress-proxy"
  network     = google_compute_network.sandbox.id
  description = "Narrow ALLOW: sandbox-tagged workloads may egress to the in-cluster forward proxy (pod range) on the proxy port ONLY (priority 900, above the deny floor). The per-pod NetworkPolicy restricts this to the egress-proxy namespace; the proxy enforces the per-session FQDN allowlist. Every other destination stays denied."
  direction   = "EGRESS"
  priority    = 900

  target_tags        = [var.sandbox_node_tag]
  destination_ranges = [var.pod_cidr_range]

  allow {
    protocol = "tcp"
    ports    = [tostring(var.egress_proxy_port)]
  }

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}
