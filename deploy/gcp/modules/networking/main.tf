# Console7 sandbox network perimeter: the STATIC, always-on default-deny egress floor the
# ephemeral sandboxes run inside. This is the AUTHORITATIVE network control of record
# (DESIGN.md §5.2; GOAL.md tenet 3) — the boundary the cloud enforces, not an in-process
# proxy a hostile workload could ignore. It lands boundary-first (ROADMAP.md sequencing #2):
# the wall exists before any sandbox node pool (modules/gke, PR-2) or per-session egress
# proxy, so a sandbox is default-deny from the moment it can run.
#
# WHAT THIS MODULE OWNS (the static DENY floor):
#   - a custom-mode VPC + a sandbox subnet (primary + pod/service secondary ranges, flow logs);
#   - an EGRESS default-DENY firewall rule scoped to the sandbox node tag — the deny floor;
#   - an explicit metadata/IMDS deny for the routed IP endpoints (defence-in-depth + a distinct,
#     logged signal).
#
# WHAT IT DELIBERATELY DOES NOT OWN (deferred to modules/gke + providers/cloud-gcp, PR-2 —
# every item here is an ALLOW/escape path or needs the cluster, so it lands with the thing it
# serves, never as a static grant ahead of it):
#   - the SANCTIONED egress path (Cloud Router + NAT, and the narrow ALLOW rules to the egress
#     proxy / Google APIs for node image pulls). NAT is SNAT for *permitted* flows; landing it
#     here — where the only routable range is the sandbox's own, which is denied — would point
#     translation at the very ranges the floor denies and rest the whole guarantee on tag
#     fidelity. It lands in PR-2 alongside the non-sandbox subnet/proxy that legitimately needs it.
#   - the per-session egress ALLOWLIST (dynamic; programmed at the out-of-band proxy by the
#     orchestrator's ApplyEgressPolicy narrow step — orchestrator.go narrow-egress);
#   - the per-pod NetworkPolicy routing sandbox pods to the proxy only, and the AUTHORITATIVE
#     node-level metadata block: on GKE the node-local metadata server is intercepted ON the VM
#     (incl. the legacy 127.0.0.1:988/987 Workload-Identity path, which a VPC firewall structurally
#     cannot match) and never reaches the VPC, so the real sandbox metadata block is "no Workload
#     Identity on the sandbox node pool" (modules/gke). The IP-deny below is the VPC-dataplane
#     LAYER of that defence-in-depth, not the whole of it;
#   - in-sandbox DNS denial ("no arbitrary resolver" — sandbox/egress-proxy/README.md) and the
#     metadata DNS NAMES metadata.google.internal / metadata.goog: a VPC firewall is IP-based and
#     cannot match names. Here those names are covered only transitively (they resolve to the
#     IPs the deny below drops); shipping the sandbox no general resolver is the base-image leg (PR-3).
#
# The firewall rules TARGET var.sandbox_node_tag, which no instance carries until modules/gke
# creates the sandbox node pool with that tag. That is intentional: this is the reserved floor,
# applied the instant the tagged nodes appear. Nothing here grants egress, so there is no path
# for a future sandbox to inherit reach it was not given.

# --- VPC + sandbox subnet ---

# Custom-mode (auto_create_subnetworks=false): no auto subnets in every region, so the only
# routable surface is the one sandbox subnet we define and govern. Regional routing keeps the
# dataplane within the deploy region (the inference/evidence backends are regional too).
resource "google_compute_network" "sandbox" {
  project                 = var.project_id
  name                    = "${var.name_prefix}-sandbox-net"
  auto_create_subnetworks = false
  routing_mode            = "REGIONAL"
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

# Explicit metadata/IMDS deny FIRST (priority 900, ahead of the catch-all deny) so a credential-
# theft / SSRF attempt against the ROUTED metadata surface is dropped AND surfaces as its own
# logged signal. Covers the IP endpoints a VPC firewall can match: IPv4 169.254.169.254, the GKE
# node-local metadata server 169.254.169.252 (ports 988/987 are included via protocol "all"), and
# the IPv6 metadata ULA fd20:ce::254. It does NOT — and a VPC firewall structurally cannot — cover
# the legacy 127.0.0.1:988/987 loopback path or the metadata DNS names; those are the node-level
# leg (no Workload Identity on the sandbox node pool) + base-image leg (no resolver), deferred to
# PR-2/PR-3 (see the header). This rule is one LAYER of that defence-in-depth (sandbox/egress-proxy/
# README.md; docs/THREAT-MODEL.md prior-art), not the whole metadata block. Denying the sandbox the
# routed metadata surface is part of what stops it minting a standing cloud credential of its own
# (cloud.go SECURITY: "MUST NOT grant the sandbox any standing credential of its own").
#
# NOTE: fd20:ce::254/128 and the ::/0 entry in the catch-all are inert on this IPv4-only subnet
# (no IPv6 egress path exists to match); they are accepted by the firewall API regardless and
# future-proof the floor for a dual-stack sandbox node pool — they are not active coverage today.
resource "google_compute_firewall" "deny_metadata" {
  project     = var.project_id
  name        = "${var.name_prefix}-sandbox-deny-metadata"
  network     = google_compute_network.sandbox.id
  description = "Default-deny floor (1/2): drop all egress from sandbox-tagged workloads to the ROUTED GCE/GKE metadata IP endpoints (credential-theft / SSRF surface). One layer of defence-in-depth with the no-Workload-Identity sandbox node pool (modules/gke); does not cover the loopback/DNS-name paths a VPC firewall cannot match."
  direction   = "EGRESS"
  priority    = 900

  target_tags        = [var.sandbox_node_tag]
  destination_ranges = ["169.254.169.254/32", "169.254.169.252/32", "fd20:ce::254/128"]

  deny {
    protocol = "all"
  }

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

# The catch-all egress deny (priority 1000): everything from a sandbox-tagged workload to
# anywhere — IPv4 0.0.0.0/0 (and IPv6 ::/0, inert on this IPv4-only subnet, see above) — is
# dropped. This overrides GCP's implied allow-egress (priority 65535) and is the default-deny
# baseline. The per-session ALLOW paths (the resolved inference endpoint, approved registries/MCP)
# are NARROWER, higher-priority rules the orchestrator programs at the out-of-band proxy per
# session (never a static wide grant here), so "forgot to deny" can never silently permit
# (cloud.go EgressPolicy is allowlist-only by construction). Logged, so every denied attempt is
# visible.
resource "google_compute_firewall" "deny_egress_all" {
  project     = var.project_id
  name        = "${var.name_prefix}-sandbox-deny-egress"
  network     = google_compute_network.sandbox.id
  description = "Default-deny floor (2/2): drop ALL egress from sandbox-tagged workloads. Per-session allowlisted destinations are programmed narrower at the out-of-band proxy (providers/cloud-gcp), never widened here."
  direction   = "EGRESS"
  priority    = 1000

  target_tags        = [var.sandbox_node_tag]
  destination_ranges = ["0.0.0.0/0", "::/0"]

  deny {
    protocol = "all"
  }

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}
