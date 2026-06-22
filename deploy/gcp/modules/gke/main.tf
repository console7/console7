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
    # never by asking the agent to behave; GOAL.md tenet 3). Enabling sandbox_config above makes GKE
    # AUTO-APPLY the `sandbox.gke.io/runtime=gvisor:NoSchedule` taint to these nodes (and auto-inject
    # the matching toleration ONLY for gvisor-RuntimeClass pods) — so a pod WITHOUT
    # runtimeClassName=gvisor cannot land here and run un-sandboxed (a co-tenancy break). The taint is
    # GKE-MANAGED and MUST NOT be declared here: the API rejects a manual copy ("Node taints with key
    # sandbox.gke.io/runtime are managed by GKE and must not be manually specified" — caught by the
    # live-PoC dogfood). The isolation guarantee therefore comes from GKE's own automatic taint.

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

  # The member references the cluster's Workload-Identity pool (<project>.svc.id.goog) as a STRING,
  # so Terraform cannot infer the dependency. Without this, on a first apply the binding races ahead
  # of the (slow) cluster create and fails with "Identity Pool does not exist". The pool is created
  # WITH the cluster (workload_identity_config above), so order this binding after it explicitly.
  depends_on = [google_container_cluster.sandbox]
}

# --- Cloud Router + NAT: the sanctioned egress path (deferred from modules/networking, PR-1) ---

# NAT provides source translation ONLY for traffic the firewall already permits. It serves the
# control-plane pool's node image pulls and the egress proxy's allowlisted outbound reach. NAT does
# not widen egress — the firewall is the gate. Logging on for auditability.
#
# NB (finding #8, live PoC 2026-06-22): the sandbox NODES do NOT use this NAT — their two sanctioned
# paths (control-plane + Google APIs, below) are internal/PGA, not SNAT. Earlier this comment claimed
# "sandbox pods never use this NAT" as if the sandbox pool needed NO egress at all; that conflated the
# untrusted POD (default-deny, NetworkPolicy-confined to the proxy) with the NODE (which MUST reach
# the apiserver to register and Artifact Registry to pull, or it never becomes Ready). See below.
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

# --- Sandbox NODE egress: the minimal SANCTIONED paths a gVisor node needs to EXIST (finding #8) ---
#
# The default-deny egress floor (modules/networking) is scoped to the sandbox NODE TAG. A Kubernetes
# node, however, cannot REGISTER (kubelet -> apiserver CSR/lease) or PULL its images (Artifact
# Registry / GCR) under all-egress-deny — it never reaches Ready, so NO sandbox pod can ever schedule
# (live PoC 2026-06-22: nodes sat unregistered, serial log "dial tcp 172.16.0.2:443: i/o timeout").
#
# The control of record for the UNTRUSTED workload is the per-session NetworkPolicy on Dataplane V2
# (providers/cloud-gcp), which drops the POD's non-proxy egress at the veth BEFORE SNAT. So only the
# node-system traffic (kubelet/containerd) can reach the two narrow rules below; the agent's pod still
# egresses only through its per-session proxy. These rules give the NODE exactly what it needs and
# nothing more — both higher-priority (900) than the deny floor (1000) and tightly destination-scoped,
# never 0.0.0.0/0. This is Google's documented private-cluster Private-Google-Access egress pattern:
#
#   (1) node -> control-plane: tcp:443 to the private master CIDR (kubelet registration).
#   (2) node -> Google APIs: tcp:443 to the private.googleapis.com VIP (199.36.153.8/30) ONLY, paired
#       with a VPC-scoped private DNS that pins *.googleapis.com / pkg.dev / gcr.io to that VIP and a
#       route to it — so image pulls + node API calls take the in-tenancy private path and the firewall
#       surface stays a /30. The deny floor remains the backstop for every other destination.
#
# Why private.googleapis.com (.8/30), NOT restricted.googleapis.com (.4/30): the restricted VIP serves
# only VPC-SC-supported APIs and does NOT route Artifact Registry (*.pkg.dev) or Container Registry
# (*.gcr.io) — the node's image pull would blackhole on it. private.googleapis.com serves the full
# Google API set incl. AR/GCR AND everything the control-plane pool needs over the same VPC-wide DNS
# (KMS, Secret Manager, GCS evidence sink). We do not run a VPC-SC perimeter, so restricted buys nothing.

resource "google_project_service" "dns" {
  project            = var.project_id
  service            = "dns.googleapis.com"
  disable_on_destroy = false
}

# (1) node -> private control-plane endpoint, so the kubelet can register the node.
resource "google_compute_firewall" "allow_sandbox_to_master" {
  project     = var.project_id
  name        = "${var.name_prefix}-sandbox-allow-master"
  network     = var.network_self_link
  description = "Narrow ALLOW (finding #8): sandbox-tagged NODES may egress tcp:443 to the private control-plane CIDR so the kubelet can register/lease. Priority 900 (above the deny floor). The untrusted POD cannot use it — NetworkPolicy confines pod egress to the per-session proxy."
  direction   = "EGRESS"
  priority    = 900

  target_tags        = [var.sandbox_node_tag]
  destination_ranges = [var.master_ipv4_cidr]

  allow {
    protocol = "tcp"
    ports    = ["443"]
  }

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

# (2) node -> Google APIs (Artifact Registry image pulls, node API calls) via the private VIP ONLY.
resource "google_compute_firewall" "allow_sandbox_google_apis" {
  project     = var.project_id
  name        = "${var.name_prefix}-sandbox-allow-google-apis"
  network     = var.network_self_link
  description = "Narrow ALLOW (finding #8): sandbox-tagged NODES may egress tcp:443 to the private.googleapis.com VIP (199.36.153.8/30) ONLY — image pulls (Artifact Registry/GCR) + node API calls over the in-tenancy private path. Priority 900. The untrusted POD cannot use it (NetworkPolicy). Paired with the private DNS + route below that pin Google/registry domains to this /30."
  direction   = "EGRESS"
  priority    = 900

  target_tags        = [var.sandbox_node_tag]
  destination_ranges = ["199.36.153.8/30"]

  allow {
    protocol = "tcp"
    ports    = ["443"]
  }

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

# Route the private VIP via the default internet gateway; Private Google Access carries it over
# Google's internal fabric (no external hop, no NAT). Without this route the /30 has nowhere to go.
# (priority is immaterial here: a /30 always wins longest-prefix-match over 0.0.0.0/0 regardless.)
resource "google_compute_route" "google_apis_private_vip" {
  project          = var.project_id
  name             = "${var.name_prefix}-gapis-private-vip"
  network          = var.network_self_link
  dest_range       = "199.36.153.8/30"
  next_hop_gateway = "default-internet-gateway"
  priority         = 900
}

# VPC-scoped private DNS: pin the Google API + registry domains to the private.googleapis.com VIP so
# the node's resolver returns the in-tenancy path the firewall allows (a /30), never a public Google IP.
# One managed zone per apex domain (googleapis.com, pkg.dev, gcr.io); apex A (all four VIP IPs, per
# Google's guidance) + a wildcard CNAME to the apex, each.
locals {
  # private.googleapis.com occupies 199.36.153.8/30 = .8 .9 .10 .11; list all four on the apex A record.
  private_google_vips = ["199.36.153.8", "199.36.153.9", "199.36.153.10", "199.36.153.11"]
  private_dns_apex = {
    googleapis = "googleapis.com."
    pkgdev     = "pkg.dev."
    gcrio      = "gcr.io."
  }
}

resource "google_dns_managed_zone" "private_apis" {
  for_each    = local.private_dns_apex
  project     = var.project_id
  name        = "${var.name_prefix}-${each.key}"
  dns_name    = each.value
  description = "Private-Google-Access egress (finding #8): resolve ${each.value} to the private.googleapis.com VIP for the sandbox VPC."
  visibility  = "private"

  private_visibility_config {
    networks {
      network_url = var.network_self_link
    }
  }

  depends_on = [google_project_service.dns]
}

resource "google_dns_record_set" "private_apis_apex" {
  for_each     = local.private_dns_apex
  project      = var.project_id
  managed_zone = google_dns_managed_zone.private_apis[each.key].name
  name         = each.value
  type         = "A"
  ttl          = 300
  rrdatas      = local.private_google_vips
}

resource "google_dns_record_set" "private_apis_wildcard" {
  for_each     = local.private_dns_apex
  project      = var.project_id
  managed_zone = google_dns_managed_zone.private_apis[each.key].name
  name         = "*.${each.value}"
  type         = "CNAME"
  ttl          = 300
  rrdatas      = [each.value] # CNAME -> the apex (which A-resolves to the VIP)
}
