provider "google" {
  project = var.project_id
  region  = var.region
}

# google-beta, configured identically — used ONLY by the gVisor sandbox node pool (modules/gke)
# for its beta-only sandbox_config. Default config is inherited by the module.
provider "google-beta" {
  project = var.project_id
  region  = var.region
}

module "secrets" {
  source = "./modules/secrets"

  project_id          = var.project_id
  region              = var.region
  name_prefix         = var.name_prefix
  kms_rotation_period = var.kms_rotation_period
}

# In-tenancy inference (Vertex AI): enables the API and grants the control-plane workload SA
# a predict-only role. Reuses the secrets module's workload SA — least privilege composes by
# adding one verb to the one identity, rather than minting a second SA. The APPLY identity
# already holds serviceUsageAdmin / iam.roleAdmin / projectIamAdmin (bootstrap), which is all
# this module's API-enable + custom-role + IAM-binding need.
module "inference_vertex" {
  source = "./modules/inference-vertex"

  project_id                     = var.project_id
  region                         = var.region
  name_prefix                    = var.name_prefix
  workload_service_account_email = module.secrets.workload_service_account_email
}

# Sandbox network perimeter: the static, always-on default-deny egress floor the ephemeral
# sandboxes run inside — the AUTHORITATIVE network control of record (DESIGN.md §5.2; tenet 3),
# landed boundary-first (ROADMAP.md sequencing #2) ahead of the sandbox node pool (modules/gke)
# and the per-session egress proxy. Owns ONLY the DENY floor: enables the Compute API, and creates
# the VPC + sandbox subnet + a single IPv4 default-deny egress firewall rule scoped to the sandbox
# node tag. The sanctioned egress path (Cloud Router + NAT, narrow ALLOW rules), the per-session
# allowlist, and the node-layer metadata/IPv6 controls are deferred to PR-2 — they land with the
# proxy/cluster that can enforce them, never as a static grant ahead of it. The APPLY identity
# needs roles/compute.networkAdmin (network/subnet) AND roles/compute.securityAdmin (firewall
# rules — networkAdmin excludes them); this PR adds both to bootstrap.sh atomically (per-module
# deploy-identity convention).
module "networking" {
  source = "./modules/networking"

  project_id         = var.project_id
  region             = var.region
  name_prefix        = var.name_prefix
  sandbox_node_tag   = var.sandbox_node_tag
  subnet_cidr_range  = var.sandbox_subnet_cidr
  pod_cidr_range     = var.sandbox_pod_cidr
  service_cidr_range = var.sandbox_service_cidr
}

# Sandbox compute substrate (GKE): the hardened cluster + gVisor sandbox node pool the ephemeral
# sandboxes run on, the Workload-Identity binding the control plane impersonates the secrets SA
# through, and the Cloud Router + NAT for the sanctioned egress path (deferred from modules/networking).
# Consumes the networking module's VPC/subnet/range/tag outputs and the secrets module's workload SA.
# The APPLY identity needs roles/container.admin (cluster + node pools) and iam.serviceAccountUser on
# the node SA (bootstrap.sh). Two properties here are preflighted by providers/cloud-gcp: GKE_METADATA
# node-SA concealment and Dataplane V2 NetworkPolicy enforcement.
module "gke" {
  source = "./modules/gke"

  project_id                             = var.project_id
  region                                 = var.region
  name_prefix                            = var.name_prefix
  network_self_link                      = module.networking.network_self_link
  subnetwork_self_link                   = module.networking.subnetwork_self_link
  pods_range_name                        = module.networking.pods_range_name
  services_range_name                    = module.networking.services_range_name
  sandbox_node_tag                       = module.networking.sandbox_node_tag
  secrets_workload_service_account_email = module.secrets.workload_service_account_email
  control_plane_ksa                      = var.gke_control_plane_ksa
  master_authorized_cidrs                = var.gke_master_authorized_cidrs
  deletion_protection                    = var.gke_deletion_protection
  node_locations                         = var.gke_node_locations
}

# Sandbox-image registry (Artifact Registry): the one Docker repository the signed sandbox
# base-image (untrusted-agent runtime, distinct signing identity) is published to, plus a
# repo-SCOPED pull grant to the gke module's node SA. Consumes module.gke.node_service_account_email
# and narrows the node's image read to this repo — replacing the project-wide artifactregistry.reader
# the gke module used to grant against no repository (least privilege; GOAL.md tenet 5). The APPLY
# identity needs roles/artifactregistry.admin (repo create + repo IAM; bootstrap.sh).
module "artifact_registry" {
  source = "./modules/artifact-registry"

  project_id                 = var.project_id
  region                     = var.region
  name_prefix                = var.name_prefix
  node_service_account_email = module.gke.node_service_account_email
}

# Durable WORM evidence backing (GCS): the bucket the EvidenceSink commits records through, plus
# an append-only (create/get/list, no delete) grant to the same workload SA via an AUTHORITATIVE
# bucket policy — omitting delete blocks both delete AND overwrite on the append identity (GCS
# overwrite needs objects.delete), and the authoritative policy strips the default project-viewer
# object-read convenience grant. The retention LOCK is the authoritative WORM control against a
# privileged actor; it is plumbed through from the root var.evidence_retention_locked (default off),
# so the dogfood posture is tamper-EVIDENT (the Sink's hash-chain detects mutation) but a production
# deploy enables it WITHOUT editing module source by setting evidence_retention_locked = true
# (irreversible). The APPLY identity needs storage bucket-admin for create + retention (bootstrap.sh).
module "evidence" {
  source = "./modules/evidence"

  project_id                     = var.project_id
  region                         = var.region
  name_prefix                    = var.name_prefix
  workload_service_account_email = module.secrets.workload_service_account_email
  retention_seconds              = var.evidence_retention_seconds
  is_locked                      = var.evidence_retention_locked
}

# Keybroker signing identity (ARCHITECTURE.md §6.4): the Cloud KMS asymmetric-sign key (EC P-256)
# that is the cryptographic root of the lineage chain, in a key ring + service account DISTINCT from
# the secrets substrate — so one identity cannot both read secrets and forge lineage. Unlike the
# inference-vertex grant (which adds a verb to the one control-plane SA), signing gets its own SA:
# §6.4 mandates a distinct signing identity. providers/keybroker-gcp consumes signing_key_version.
# The APPLY identity already holds the KMS-admin / SA-admin / project-IAM perms (bootstrap.sh) the
# secrets module's key ring + SA + key IAM use.
module "keybroker_signing" {
  source = "./modules/keybroker-signing"

  project_id           = var.project_id
  region               = var.region
  name_prefix          = var.name_prefix
  kms_protection_level = var.keybroker_kms_protection_level
  require_hsm          = var.keybroker_require_hsm
}
