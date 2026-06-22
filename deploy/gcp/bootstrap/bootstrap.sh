#!/usr/bin/env bash
#
# Console7 GCP bootstrap — the one-time, human-actuated setup the deploy module (../)
# and the keyless CD pipeline depend on. Run it with YOUR OWN gcloud auth: per ADR-0002,
# creating the project, linking billing, and establishing the CD identities is the
# human-authority bootstrap act, never something the module does.
#
# Idempotent. Provisions ONLY the substrate the current deploy module needs:
#   - enables the required Google APIs
#   - creates a versioned, private GCS bucket for Terraform state (hardening enforced on
#     re-run too, even if the bucket pre-exists)
#   - creates a Workload Identity Federation pool + GitHub OIDC provider, restricted at
#     the PROVIDER level to a single owner/repo AND to the deploy workflow (tenet 5)
#   - creates TWO least-privilege identities, mirroring tenet 6 (observe != actuate):
#       * PLAN  — read-only (project viewer + IAM read + state read), impersonable from
#         ANY branch, for the PR `terraform plan` (run with -lock=false, so it needs no
#         state-write — see deploy.yml in console7-deploy-template);
#       * APPLY — admin-grade for the resources the modules provision, impersonable
#         ONLY from the default branch (refs/heads/<branch>), so a human merge is the
#         precondition for any actuation. Apply roles are only what the CURRENT module
#         provisions; later module PRs extend them — never ahead.
#
# Stores no secret and prints no credential. See ./README.md.

set -euo pipefail

# --- defaults (override via flags/env) ------------------------------------------------
REGION="${REGION:-us-east4}"
NAME_PREFIX="${NAME_PREFIX:-console7}"
PROVIDER_ID="${PROVIDER_ID:-github}"
WORKFLOW_FILE="${WORKFLOW_FILE:-deploy.yml}"
DEFAULT_BRANCH="${DEFAULT_BRANCH:-main}"
POOL_ID="${POOL_ID:-}"       # derived from NAME_PREFIX after parsing unless set
PLAN_SA_ID="${PLAN_SA_ID:-}" # "
APPLY_SA_ID="${APPLY_SA_ID:-}" # "
PROJECT_ID="${PROJECT_ID:-}"
GITHUB_REPO="${GITHUB_REPO:-}"
STATE_BUCKET="${STATE_BUCKET:-}"
BILLING_ACCOUNT="${BILLING_ACCOUNT:-}"
CREATE_PROJECT="false"

usage() {
  cat <<'USAGE'
Usage: bootstrap.sh --project <ID> --github-repo <owner/repo> [options]

Required:
  --project        <ID>          target GCP project (must already exist unless --create-project)
  --github-repo    <owner/repo>  the GitHub repo allowed to impersonate the CD identities (WIF)

Options:
  --region          <region>     default: us-east4
  --state-bucket    <name>       default: <project>-tfstate
  --name-prefix     <prefix>     isolates pool + identity names; default: console7
  --workflow-file   <name>       deploy workflow filename the WIF provider trusts; default: deploy.yml
  --default-branch  <branch>     branch the APPLY identity is locked to; default: main
  --create-project               create the project first (requires --billing-account)
  --billing-account <ID>         billing account to link when creating the project
  -h, --help                     show this help

All actions are idempotent. Run with your own gcloud auth (gcloud auth login).
USAGE
}

# --- arg parsing ----------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --project)         PROJECT_ID="$2"; shift 2 ;;
    --github-repo)     GITHUB_REPO="$2"; shift 2 ;;
    --region)          REGION="$2"; shift 2 ;;
    --state-bucket)    STATE_BUCKET="$2"; shift 2 ;;
    --name-prefix)     NAME_PREFIX="$2"; shift 2 ;;
    --workflow-file)   WORKFLOW_FILE="$2"; shift 2 ;;
    --default-branch)  DEFAULT_BRANCH="$2"; shift 2 ;;
    --create-project)  CREATE_PROJECT="true"; shift ;;
    --billing-account) BILLING_ACCOUNT="$2"; shift 2 ;;
    -h|--help)         usage; exit 0 ;;
    *) echo "error: unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

[[ -n "$PROJECT_ID"  ]] || { echo "error: --project is required" >&2; usage; exit 2; }
[[ -n "$GITHUB_REPO" ]] || { echo "error: --github-repo is required" >&2; usage; exit 2; }
# Validate inputs against their naming charsets — also closes any interpolation into
# the gcloud command strings (GitHub/GCP names can't contain quotes, but assert it).
[[ "$GITHUB_REPO" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] \
  || { echo "error: --github-repo must be owner/repo (alphanumerics, '.', '_', '-')" >&2; exit 2; }
[[ "$PROJECT_ID" =~ ^[a-z][a-z0-9-]{4,28}[a-z0-9]$ ]] \
  || { echo "error: --project must be a valid GCP project ID" >&2; exit 2; }
[[ "$DEFAULT_BRANCH" =~ ^[A-Za-z0-9_./-]+$ ]] \
  || { echo "error: --default-branch has invalid characters" >&2; exit 2; }
[[ "$NAME_PREFIX" =~ ^[a-z]([a-z0-9-]{0,17}[a-z0-9])?$ ]] \
  || { echo "error: --name-prefix must be 1-19 chars (lowercase letter first, no trailing hyphen)" >&2; exit 2; }
[[ "$WORKFLOW_FILE" =~ ^[A-Za-z0-9_.-]+\.ya?ml$ ]] \
  || { echo "error: --workflow-file must be a .yml/.yaml filename" >&2; exit 2; }
STATE_BUCKET="${STATE_BUCKET:-${PROJECT_ID}-tfstate}"
[[ "$STATE_BUCKET" =~ ^[a-z0-9][a-z0-9_.-]{1,61}[a-z0-9]$ ]] \
  || { echo "error: --state-bucket is not a valid GCS bucket name" >&2; exit 2; }

# Names derive from NAME_PREFIX so a second prefixed bootstrap is isolated (own pool +
# identities), not a collision with the first.
POOL_ID="${POOL_ID:-${NAME_PREFIX}-pool}"
PLAN_SA_ID="${PLAN_SA_ID:-${NAME_PREFIX}-plan}"
APPLY_SA_ID="${APPLY_SA_ID:-${NAME_PREFIX}-apply}"
PLAN_SA_EMAIL="${PLAN_SA_ID}@${PROJECT_ID}.iam.gserviceaccount.com"
APPLY_SA_EMAIL="${APPLY_SA_ID}@${PROJECT_ID}.iam.gserviceaccount.com"

command -v gcloud >/dev/null || { echo "error: gcloud not found on PATH" >&2; exit 1; }
gcloud auth list --filter=status:ACTIVE --format='value(account)' | grep -q . \
  || { echo "error: no active gcloud account — run 'gcloud auth login'" >&2; exit 1; }

log() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

grant_project_role() {
  gcloud projects add-iam-policy-binding "$PROJECT_ID" \
    --member="serviceAccount:$1" --role="$2" --condition=None >/dev/null
}
grant_impersonation() {
  gcloud iam service-accounts add-iam-policy-binding "$1" \
    --project="$PROJECT_ID" --role="roles/iam.workloadIdentityUser" \
    --member="$2" --condition=None >/dev/null
}

# --- 1. project (optional) ------------------------------------------------------------
if [[ "$CREATE_PROJECT" == "true" ]]; then
  [[ -n "$BILLING_ACCOUNT" ]] || { echo "error: --create-project requires --billing-account" >&2; exit 2; }
  if gcloud projects describe "$PROJECT_ID" >/dev/null 2>&1; then
    log "project $PROJECT_ID already exists — skipping create"
  else
    log "creating project $PROJECT_ID"
    gcloud projects create "$PROJECT_ID"
  fi
  if [[ "$(gcloud billing projects describe "$PROJECT_ID" --format='value(billingEnabled)' 2>/dev/null)" == "True" ]]; then
    log "billing already enabled — skipping link"
  else
    log "linking billing account $BILLING_ACCOUNT"
    gcloud billing projects link "$PROJECT_ID" --billing-account="$BILLING_ACCOUNT"
  fi
else
  gcloud projects describe "$PROJECT_ID" >/dev/null 2>&1 \
    || { echo "error: project $PROJECT_ID not found (use --create-project to create it)" >&2; exit 1; }
fi

PROJECT_NUMBER="$(gcloud projects describe "$PROJECT_ID" --format='value(projectNumber)')"
POOL_PRINCIPAL="principalSet://iam.googleapis.com/projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/${POOL_ID}"

# --- 2. APIs --------------------------------------------------------------------------
log "enabling required APIs"
gcloud services enable \
  cloudkms.googleapis.com \
  iam.googleapis.com \
  iamcredentials.googleapis.com \
  sts.googleapis.com \
  cloudresourcemanager.googleapis.com \
  storage.googleapis.com \
  --project="$PROJECT_ID"
# secretmanager.googleapis.com is enabled by the deploy module itself
# (google_project_service in deploy/gcp/modules/secrets); the APPLY identity is granted
# serviceUsageAdmin below so `terraform apply` can manage that enablement.

# --- 3. Terraform state bucket --------------------------------------------------------
if gcloud storage buckets describe "gs://${STATE_BUCKET}" >/dev/null 2>&1; then
  log "state bucket gs://${STATE_BUCKET} already exists — re-applying hardening"
else
  log "creating state bucket gs://${STATE_BUCKET}"
  gcloud storage buckets create "gs://${STATE_BUCKET}" \
    --project="$PROJECT_ID" --location="$REGION"
fi
# Enforce hardening on BOTH new and pre-existing buckets (don't trust a found bucket).
gcloud storage buckets update "gs://${STATE_BUCKET}" \
  --versioning --uniform-bucket-level-access --public-access-prevention

# --- 4. Workload Identity Federation (keyless CD) -------------------------------------
if gcloud iam workload-identity-pools describe "$POOL_ID" \
     --project="$PROJECT_ID" --location=global >/dev/null 2>&1; then
  log "WIF pool $POOL_ID already exists — skipping create"
else
  log "creating WIF pool $POOL_ID"
  gcloud iam workload-identity-pools create "$POOL_ID" \
    --project="$PROJECT_ID" --location=global \
    --display-name="Console7 CD"
fi

if gcloud iam workload-identity-pools providers describe "$PROVIDER_ID" \
     --project="$PROJECT_ID" --location=global \
     --workload-identity-pool="$POOL_ID" >/dev/null 2>&1; then
  log "WIF provider $PROVIDER_ID already exists — updating its restriction"
  PROVIDER_VERB="update-oidc"
else
  log "creating WIF GitHub OIDC provider $PROVIDER_ID (restricted to $GITHUB_REPO / $WORKFLOW_FILE)"
  PROVIDER_VERB="create-oidc"
fi
# Provider trusts ONLY tokens from $GITHUB_REPO's $WORKFLOW_FILE workflow — so an
# unrelated workflow added in the repo cannot mint a token into the pool at all.
#   attribute.repository      -> the any-branch PLAN binding
#   attribute.repository_ref  -> the default-branch-only APPLY binding
gcloud iam workload-identity-pools providers "$PROVIDER_VERB" "$PROVIDER_ID" \
  --project="$PROJECT_ID" --location=global \
  --workload-identity-pool="$POOL_ID" \
  --display-name="GitHub Actions" \
  --issuer-uri="https://token.actions.githubusercontent.com" \
  --attribute-mapping="google.subject=assertion.sub,attribute.repository=assertion.repository,attribute.repository_ref=assertion.repository + '@' + assertion.ref" \
  --attribute-condition="assertion.repository == '${GITHUB_REPO}' && assertion.workflow_ref.startsWith('${GITHUB_REPO}/.github/workflows/${WORKFLOW_FILE}@')"

# --- 5. CD identities -----------------------------------------------------------------
for sa in "$PLAN_SA_ID:Console7 keyless CD plan identity (read-only)" \
          "$APPLY_SA_ID:Console7 keyless CD apply identity (default-branch only)"; do
  sa_id="${sa%%:*}"; sa_desc="${sa#*:}"
  sa_email="${sa_id}@${PROJECT_ID}.iam.gserviceaccount.com"
  if gcloud iam service-accounts describe "$sa_email" --project="$PROJECT_ID" >/dev/null 2>&1; then
    log "SA $sa_email already exists — skipping create"
  else
    log "creating SA $sa_email"
    gcloud iam service-accounts create "$sa_id" --project="$PROJECT_ID" --display-name="$sa_desc"
  fi
done

# --- 6. impersonation: PLAN = any branch; APPLY = default branch only -----------------
log "binding PLAN identity to ${GITHUB_REPO} (any branch, read-only)"
grant_impersonation "$PLAN_SA_EMAIL" \
  "${POOL_PRINCIPAL}/attribute.repository/${GITHUB_REPO}"

# Re-runs that change --default-branch must not leave an old branch able to impersonate
# APPLY — strip any workloadIdentityUser member that isn't the current default-branch one.
APPLY_PRINCIPAL="${POOL_PRINCIPAL}/attribute.repository_ref/${GITHUB_REPO}@refs/heads/${DEFAULT_BRANCH}"
existing_apply_members="$(gcloud iam service-accounts get-iam-policy "$APPLY_SA_EMAIL" \
  --project="$PROJECT_ID" --flatten='bindings[].members' \
  --filter='bindings.role:roles/iam.workloadIdentityUser' \
  --format='value(bindings.members)' 2>/dev/null || true)"
while IFS= read -r m; do
  [[ -n "$m" && "$m" != "$APPLY_PRINCIPAL" ]] || continue
  log "removing stale APPLY impersonator: $m"
  gcloud iam service-accounts remove-iam-policy-binding "$APPLY_SA_EMAIL" \
    --project="$PROJECT_ID" --role="roles/iam.workloadIdentityUser" \
    --member="$m" --condition=None >/dev/null || true
done <<< "$existing_apply_members"

log "binding APPLY identity to ${GITHUB_REPO}@refs/heads/${DEFAULT_BRANCH} only"
grant_impersonation "$APPLY_SA_EMAIL" "$APPLY_PRINCIPAL"

# --- 7. least-privilege roles ---------------------------------------------------------
# PLAN is read-only by design — the pipeline runs `terraform plan -lock=false`, so it
# needs no state-write (objectViewer, not objectAdmin). This keeps a compromised plan
# job unable to mutate or delete state.
log "granting PLAN identity read-only roles"
grant_project_role "$PLAN_SA_EMAIL" "roles/viewer"
grant_project_role "$PLAN_SA_EMAIL" "roles/iam.securityReviewer" # read IAM policies (plan refresh)
gcloud storage buckets add-iam-policy-binding "gs://${STATE_BUCKET}" \
  --member="serviceAccount:${PLAN_SA_EMAIL}" --role="roles/storage.objectViewer"

log "granting APPLY identity least-privilege roles for the current modules"
grant_project_role "$APPLY_SA_EMAIL" "roles/cloudkms.admin"
grant_project_role "$APPLY_SA_EMAIL" "roles/iam.serviceAccountAdmin"
# providers/secrets-gcp's deploy delta (deploy/gcp/modules/secrets) adds three resource kinds
# the APPLY identity must be able to manage:
#   - enabling secretmanager.googleapis.com via google_project_service -> serviceUsageAdmin
#   - creating the custom least-privilege Secret Manager roles -> iam.roleAdmin
#   - the project-level IAM bindings for the workload SA -> resourcemanager.projectIamAdmin
grant_project_role "$APPLY_SA_EMAIL" "roles/serviceusage.serviceUsageAdmin"
grant_project_role "$APPLY_SA_EMAIL" "roles/iam.roleAdmin"
grant_project_role "$APPLY_SA_EMAIL" "roles/resourcemanager.projectIamAdmin"
# State read/write is scoped to the state bucket only, not project-wide storage admin.
gcloud storage buckets add-iam-policy-binding "gs://${STATE_BUCKET}" \
  --member="serviceAccount:${APPLY_SA_EMAIL}" --role="roles/storage.objectAdmin"
# providers/evidence-gcs' deploy delta (deploy/gcp/modules/evidence) adds a resource kind the
# state-bucket-scoped grant above cannot cover: CREATING a new bucket and setting its retention
# policy/lock. roles/storage.admin is the project-level grant for buckets.create + .update +
# .setRetentionPolicy/.lockRetentionPolicy (and the bucket-level setIamPolicy for the workload
# binding). NOTE: storage.admin also confers objects.delete on every bucket — but the APPLY
# identity ALREADY holds resourcemanager.projectIamAdmin (secrets module), i.e. it can self-grant
# any role, so this does NOT raise its effective ceiling. A least-privilege custom role
# (buckets.create/get/update/setRetentionPolicy/lockRetentionPolicy + bucket setIamPolicy,
# excluding objects.*) is a tracked future tightening (GOAL.md tenet 5).
grant_project_role "$APPLY_SA_EMAIL" "roles/storage.admin"
# deploy/gcp/modules/networking's delta (the boundary-first egress wall) adds compute resources
# the APPLY identity must manage: the sandbox VPC + subnet (compute.networkAdmin) and the
# default-deny egress firewall rule. NOTE: compute.networkAdmin deliberately EXCLUDES firewall
# rules — Google scopes firewalls.create/update/delete to roles/compute.securityAdmin — so BOTH
# are required, or `terraform apply` gets through the VPC/subnet and then fails on
# compute.firewalls.create, leaving the egress wall undeployed. Neither role confers instance
# create/start (that is compute.instanceAdmin, added with modules/gke when the sandbox node pool
# lands), so the deploy identity can shape the perimeter but not run workloads inside it.
grant_project_role "$APPLY_SA_EMAIL" "roles/compute.networkAdmin"
grant_project_role "$APPLY_SA_EMAIL" "roles/compute.securityAdmin"
# (Note: the GKE node pools are managed by GKE itself under roles/container.admin below — the deploy
# identity needs NO roles/compute.instanceAdmin, contrary to an earlier prediction here.)
# deploy/gcp/modules/gke's delta adds the GKE cluster + node pools (roles/container.admin), the
# Cloud Router + NAT (covered by compute.networkAdmin above), and a dedicated node service account
# the node pools run as. Creating a node pool that runs AS that SA requires the APPLY identity to
# hold iam.serviceAccounts.actAs on it (roles/iam.serviceAccountUser), in addition to
# iam.serviceAccountAdmin (granted above) to create it and projectIamAdmin (secrets module) to bind
# its project roles. This grant is PROJECT-scoped (not narrowed to the node SA) — which means the
# APPLY identity can actAs other SAs too. That does NOT raise its effective ceiling: it ALREADY
# holds resourcemanager.projectIamAdmin (secrets module), i.e. it can self-grant any role on any SA,
# so a project-wide serviceAccountUser is within the bootstrap-trusted CD identity's existing reach
# (the same reasoning the evidence module's project storage.admin uses). Narrowing it to a binding
# on the node SA alone (created in the gke module) is a tracked future tightening; it does NOT touch
# the secrets SA's "no HUMAN/operator impersonation binding" invariant, which is about people/
# groups, not this CD identity. container.admin confers no instance-level compute beyond GKE's own
# node pools, so the deploy identity still cannot run arbitrary VMs.
grant_project_role "$APPLY_SA_EMAIL" "roles/container.admin"
grant_project_role "$APPLY_SA_EMAIL" "roles/iam.serviceAccountUser"

# deploy/gcp/modules/artifact-registry's delta: create the one sandbox-image Docker repository and
# set its repo-scoped IAM (pull grant to the node SA). repository CREATE needs the project-level
# artifactregistry.repositories.create verb and setting repo IAM needs setIamPolicy; no narrower
# predefined role covers BOTH (repoAdmin grants repo-IAM but not project-level create), so
# artifactregistry.admin is the least over-grant that lets this one-shot CD identity stand the
# module up. Within-project it also implies artifact push/delete — i.e. the deploy identity is a
# write path to the sandbox image — but that is strictly less than the container.admin granted
# above (which can already deploy arbitrary cluster workloads), and it confers nothing in OTHER
# projects and no compute. The image's integrity rests on the registry's immutable_tags and the
# forthcoming consumer-side digest pin, not on withholding push from the deploy identity.
grant_project_role "$APPLY_SA_EMAIL" "roles/artifactregistry.admin"

# deploy/gcp/modules/gke's finding-#8 delta: the sandbox NODE's sanctioned egress to Google APIs over
# Private Google Access is pinned to the private.googleapis.com VIP by VPC-scoped private Cloud DNS
# zones (googleapis.com / pkg.dev / gcr.io), so the node can register + pull its image while the
# default-deny floor still walls everything else. Creating those managed zones + record sets needs
# dns.managedZones.create + dns.changes.create — no narrower predefined role covers both, so dns.admin
# is the least over-grant. It confers no compute and nothing outside this project's Cloud DNS. (Finding
# #9: the role set drifts as modules land — this grant was missing when modules/gke gained the DNS
# zones, and the first apply 403'd on ManagedZone create until it was added. Re-run bootstrap.sh before
# the first apply of any new module.)
grant_project_role "$APPLY_SA_EMAIL" "roles/dns.admin"

# --- outputs --------------------------------------------------------------------------
WIF_PROVIDER="projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/${POOL_ID}/providers/${PROVIDER_ID}"
cat <<EOF

==> bootstrap complete. Wire these into the adopter config repo (no secrets):

  project_id              : ${PROJECT_ID}
  region                  : ${REGION}
  terraform state bucket  : ${STATE_BUCKET}
  WIF provider (GH OIDC)  : ${WIF_PROVIDER}
  PLAN  identity (PRs)    : ${PLAN_SA_EMAIL}    [read-only, any branch]
  APPLY identity (merge)  : ${APPLY_SA_EMAIL}   [admin, refs/heads/${DEFAULT_BRANCH} only]

  The WIF provider trusts only ${GITHUB_REPO}'s ${WORKFLOW_FILE} workflow.

  GitHub Actions (google-github-actions/auth, keyless):
    - PR plan job  -> service_account: ${PLAN_SA_EMAIL}
    - apply job (on ${DEFAULT_BRANCH}, protected environment):
                      service_account: ${APPLY_SA_EMAIL}
    workload_identity_provider (both): ${WIF_PROVIDER}

  Terraform backend init:
    terraform -chdir=deploy/gcp init -backend-config="bucket=${STATE_BUCKET}"

Later module PRs (gke, networking, secrets-gcp) extend the APPLY identity's roles as
their resources require — re-run this script after pulling those changes.
EOF
