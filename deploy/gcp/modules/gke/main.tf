# Console7 sandbox compute substrate: a hardened regional GKE cluster, a gVisor (sandboxed)
# node pool for the ephemeral per-session sandboxes, a separate control-plane node pool, the
# Workload-Identity binding the control plane impersonates the secrets SA through, and the Cloud
# Router + NAT that gives the SANCTIONED (non-sandbox-tagged) egress path its outbound route.
#
# This is the compute half of the boundary the networking module (the default-deny egress wall,
# PR-1) already established. Two security properties here are LOAD-BEARING and are preflighted by
# providers/cloud-gcp's New() — a misconfigured cluster fails closed at provider construction:
#
#   1. GKE_METADATA mode (Workload Identity) on EVERY node pool. The GKE metadata server intercepts
#      the node-local metadata endpoint and CONCEALS the node service account, serving only WI
#      tokens for a pod's bound KSA. The sandbox pods are bound to NO KSA (and run with
#      automountServiceAccountToken=false), so they get no token at all. This — NOT "disable
#      Workload Identity" — is the authoritative metadata block: disabling WI would leave
#      GCE_METADATA, which EXPOSES the node SA token to any pod, exactly the standing credential a
#      prompt-injected sandbox could mint (cloud.go: "MUST NOT grant the sandbox any standing
#      credential of its own"). A VPC firewall cannot block that node-local path (see
#      modules/networking), which is why it is a node-config control.
#   2. Dataplane V2 (ADVANCED_DATAPATH) so the sandbox's per-session egress NetworkPolicy is
#      actually ENFORCED. Without an enforcing CNI a NetworkPolicy applies but does nothing, and the
#      perimeter would be silently inert.
#
# The sandbox node pool carries var.sandbox_node_tag so the networking module's default-deny egress
# firewall applies to it; the control-plane pool does NOT, so it keeps its sanctioned NAT egress.
#
# Prerequisite (human bootstrap): the APPLY identity holds roles/container.admin (cluster + node
# pools), roles/iam.serviceAccountUser (to create node pools that run AS the node SA), and — from
# earlier modules — iam.serviceAccountAdmin + resourcemanager.projectIamAdmin (create + bind the
# node SA) and compute.networkAdmin (the Router/NAT). bootstrap.sh.

resource "google_project_service" "container" {
  project = var.project_id
  service = "container.googleapis.com"

  # Don't disable on `terraform destroy` — other resources/users may depend on it.
  disable_on_destroy = false
}

# --- Least-privilege node service account ---

# A dedicated node SA instead of the over-privileged default Compute Engine SA. It holds only the
# verbs nodes need (write logs/metrics; image-pull is granted repo-scoped in modules/artifact-
# registry, not here); pod-level authorization comes from Workload Identity, not this SA, so
# concealing it (GKE_METADATA) costs the sandbox nothing legitimate.
resource "google_service_account" "nodes" {
  project      = var.project_id
  account_id   = "${var.name_prefix}-gke-nodes"
  display_name = "Console7 GKE node SA (least-privilege; pod auth is via Workload Identity)"
}

resource "google_project_iam_member" "nodes" {
  # The minimal GKE node SA set: write logs/metrics + node resource metadata. NO monitoring.viewer
  # (project-wide metric READ is not a node verb) — least privilege (tenet 5), so even if
  # GKE_METADATA were ever bypassed the node token reads nothing it should not write. Image-pull
  # (roles/artifactregistry.reader) is deliberately NOT granted here: modules/artifact-registry
  # grants it REPO-SCOPED on the one sandbox-image repository, so the node can pull that image and no
  # other repo's — a project-wide reader would point at every repo (and, before that module, at no
  # repo at all).
  for_each = toset([
    "roles/logging.logWriter",
    "roles/monitoring.metricWriter",
    "roles/stackdriver.resourceMetadata.writer",
  ])
  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.nodes.email}"
}

# --- The cluster ---

# Regional, VPC-native, private-nodes, Dataplane V2, Workload-Identity, shielded-nodes,
# release-channel-managed. The default node pool is removed immediately; the two pools below are
# managed explicitly so their node config (gVisor, GKE_METADATA, tags) is governed here.
resource "google_container_cluster" "sandbox" {
  project  = var.project_id
  name     = "${var.name_prefix}-sandbox"
  location = var.region

  network    = var.network_self_link
  subnetwork = var.subnetwork_self_link

  remove_default_node_pool = true
  initial_node_count       = 1
  deletion_protection      = var.deletion_protection

  networking_mode = "VPC_NATIVE"
  ip_allocation_policy {
    cluster_secondary_range_name  = var.pods_range_name
    services_secondary_range_name = var.services_range_name
  }

  # Dataplane V2 — the enforcing CNI for the per-session egress NetworkPolicy (cloud-gcp preflights
  # this). With ADVANCED_DATAPATH the legacy network_policy addon is omitted (they are mutually
  # exclusive); Dataplane V2 provides NetworkPolicy enforcement natively.
  datapath_provider = "ADVANCED_DATAPATH"

  # Workload Identity — the cluster-level pool that makes GKE_METADATA mode (node-SA concealment)
  # possible on the node pools, and lets the control-plane KSA impersonate the secrets SA.
  workload_identity_config {
    workload_pool = "${var.project_id}.svc.id.goog"
  }

  # Private nodes (no public IPs — egress is via Cloud NAT below for the sanctioned path; the
  # sandbox pool is firewall-denied regardless). The control-plane endpoint stays reachable for the
  # keyless CD/operator, scoped by master authorized networks.
  private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = false
    master_ipv4_cidr_block  = var.master_ipv4_cidr
  }

  master_authorized_networks_config {
    gcp_public_cidrs_access_enabled = false
    dynamic "cidr_blocks" {
      for_each = var.master_authorized_cidrs
      content {
        cidr_block   = cidr_blocks.value.cidr_block
        display_name = cidr_blocks.value.display_name
      }
    }
  }

  release_channel {
    channel = var.release_channel
  }

  # Shielded nodes (secure boot + integrity monitoring) cluster-wide.
  enable_shielded_nodes = true

  # Defence-in-depth: legacy ABAC off (RBAC only), intranode visibility on (pod-to-pod flows are
  # visible to VPC flow logs / firewall), and client-cert auth off (default in v6, asserted here).
  enable_intranode_visibility = true
  master_auth {
    client_certificate_config {
      issue_client_certificate = false
    }
  }

  depends_on = [google_project_service.container]
}

# --- Node pools ---

# Control-plane / system pool: runs the Console7 control-plane components (orchestrator, the egress
# proxy, the reaper). GKE_METADATA conceals the node SA here too; it is NOT sandbox-tagged, so it
# keeps NAT egress for image pulls and the proxy's allowlisted reach.
resource "google_container_node_pool" "control" {
  project  = var.project_id
  name     = "${var.name_prefix}-control"
  location = var.region
  cluster  = google_container_cluster.sandbox.name

  autoscaling {
    min_node_count = 1
    max_node_count = 3
  }

  management {
    auto_repair  = true
    auto_upgrade = true
  }

  node_config {
    machine_type    = var.control_node_machine_type
    image_type      = "COS_CONTAINERD"
    service_account = google_service_account.nodes.email
    oauth_scopes    = ["https://www.googleapis.com/auth/cloud-platform"]

    workload_metadata_config {
      mode = "GKE_METADATA"
    }
    shielded_instance_config {
      enable_secure_boot          = true
      enable_integrity_monitoring = true
    }
    metadata = {
      disable-legacy-endpoints = "true"
    }
  }
}

# gVisor SANDBOX pool: runs the untrusted per-session sandbox pods under the gVisor runtime
# sandbox (kernel/syscall isolation). It carries var.sandbox_node_tag so the networking module's
# default-deny egress firewall applies; GKE_METADATA conceals the node SA so a sandbox cannot mint
# the node credential. gVisor requires COS_CONTAINERD.
resource "google_container_node_pool" "sandbox" {
  # google-beta: sandbox_config (GKE Sandbox / gVisor) is a beta-only field.
  provider = google-beta
  project  = var.project_id
  name     = "${var.name_prefix}-sandbox"
  location = var.region
  cluster  = google_container_cluster.sandbox.name

  autoscaling {
    min_node_count = 1
    max_node_count = 5
  }

  management {
    auto_repair  = true
    auto_upgrade = true
  }

  node_config {
    machine_type    = var.sandbox_node_machine_type
    image_type      = "COS_CONTAINERD"
    service_account = google_service_account.nodes.email
    oauth_scopes    = ["https://www.googleapis.com/auth/cloud-platform"]

    # The load-bearing tag: ties these nodes to the default-deny egress firewall (modules/networking).
    tags = [var.sandbox_node_tag]

    # gVisor runtime sandbox — the kernel/syscall isolation boundary for untrusted agent code.
    sandbox_config {
      sandbox_type = "gvisor"
    }

    # STRUCTURAL gVisor enforcement (cloud.go: isolation MUST be at the kernel/syscall boundary,
    # never by asking the agent to behave; GOAL.md tenet 3). The taint repels any pod that does NOT
    # tolerate it, so a pod WITHOUT runtimeClassName=gvisor cannot land on the sandbox nodes and run
    # un-sandboxed (a co-tenancy break) — GKE auto-injects the matching toleration only for gvisor
    # RuntimeClass pods, so the cloud-gcp pod (which sets runtimeClassName: gvisor) schedules and
    # ordinary pods are excluded. Declared explicitly (matching GKE Sandbox's own taint) so the
    # guarantee lives in the IaC, not implicit runtime behaviour.
    taint {
      key    = "sandbox.gke.io/runtime"
      value  = "gvisor"
      effect = "NO_SCHEDULE"
    }

    # Conceal the node SA from pods (the authoritative metadata block; cloud-gcp preflights this).
    workload_metadata_config {
      mode = "GKE_METADATA"
    }
    shielded_instance_config {
      enable_secure_boot          = true
      enable_integrity_monitoring = true
    }
    metadata = {
      disable-legacy-endpoints = "true"
    }
  }
}

# --- Workload Identity: control-plane KSA -> secrets workload SA ---

# Let the control-plane Kubernetes service account impersonate the secrets workload SA (minted by
# modules/secrets with NO human impersonation binding). This is the only impersonation grant on
# that SA, so there is still no operator read path to secrets — only the in-cluster control plane,
# running as the bound KSA, can assume it. No key file is ever issued.
resource "google_service_account_iam_member" "control_plane_wi" {
  service_account_id = "projects/${var.project_id}/serviceAccounts/${var.secrets_workload_service_account_email}"
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:${var.project_id}.svc.id.goog[${var.control_plane_ksa}]"
}

# --- Cloud Router + NAT: the sanctioned egress path (deferred from modules/networking, PR-1) ---

# NAT provides source translation ONLY for traffic the firewall already permits. The sandbox pool
# is default-deny (networking module), so sandbox pods never use this NAT; it serves the
# control-plane pool's node image pulls and the egress proxy's allowlisted outbound reach. NAT does
# not widen egress — the firewall is the gate. Logging on for auditability.
resource "google_compute_router" "sandbox" {
  project = var.project_id
  name    = "${var.name_prefix}-sandbox-router"
  region  = var.region
  network = var.network_self_link
}

resource "google_compute_router_nat" "sandbox" {
  project                            = var.project_id
  name                               = "${var.name_prefix}-sandbox-nat"
  router                             = google_compute_router.sandbox.name
  region                             = var.region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "LIST_OF_SUBNETWORKS"

  subnetwork {
    name                    = var.subnetwork_self_link
    source_ip_ranges_to_nat = ["ALL_IP_RANGES"]
  }

  log_config {
    enable = true
    filter = "ALL"
  }
}
