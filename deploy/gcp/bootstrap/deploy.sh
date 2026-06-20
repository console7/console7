#!/usr/bin/env bash
#
# Console7 adopter scaffolding — create the adopter's thin config repo from the
# standalone console7-deploy-template (ADR-0002 §7: the template is published as its
# own repo, NOT carried in core) and wire the bootstrap.sh outputs into it as GitHub
# Actions *variables* (never secrets — keyless WIF means there is no secret to set).
#
# Run with your own gh + gcloud auth. Idempotent where the underlying tools allow.
# Stores and prints no credential.

set -euo pipefail

TEMPLATE_REPO="${TEMPLATE_REPO:-console7/console7-deploy-template}"
REGION="${REGION:-us-east4}"
VISIBILITY="${VISIBILITY:-private}"
ADOPTER_REPO="" PROJECT_ID="" STATE_BUCKET="" WIF_PROVIDER="" PLAN_SA="" APPLY_SA=""

usage() {
  cat <<'USAGE'
Usage: deploy.sh --adopter-repo <owner/repo> --project <ID> --state-bucket <name> \
                 --wif-provider <resource> --plan-sa <email> --apply-sa <email> [options]

Required (all from bootstrap.sh output):
  --adopter-repo  <owner/repo>  the config repo to create from the template
  --project       <ID>          GCP project to deploy into
  --state-bucket  <name>        Terraform state bucket
  --wif-provider  <resource>    full WIF provider resource name
  --plan-sa       <email>       read-only PLAN service account (PR plan jobs)
  --apply-sa      <email>       APPLY service account (default-branch apply jobs)

Options:
  --region        <region>      default: us-east4
  --template-repo <owner/repo>  default: console7/console7-deploy-template
  --visibility    <private|internal|public>  default: private
  -h, --help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --adopter-repo) ADOPTER_REPO="$2"; shift 2 ;;
    --project)      PROJECT_ID="$2"; shift 2 ;;
    --state-bucket) STATE_BUCKET="$2"; shift 2 ;;
    --wif-provider) WIF_PROVIDER="$2"; shift 2 ;;
    --plan-sa)      PLAN_SA="$2"; shift 2 ;;
    --apply-sa)     APPLY_SA="$2"; shift 2 ;;
    --region)       REGION="$2"; shift 2 ;;
    --template-repo) TEMPLATE_REPO="$2"; shift 2 ;;
    --visibility)   VISIBILITY="$2"; shift 2 ;;
    -h|--help)      usage; exit 0 ;;
    *) echo "error: unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

# Explicit checks (no bash-4 ${var,,}/assoc-arrays — keep this runnable on the stock
# macOS /bin/bash 3.2) so the hint names the real flag.
die() { echo "error: $*" >&2; usage; exit 2; }
[[ -n "$ADOPTER_REPO" ]] || die "--adopter-repo is required"
[[ -n "$PROJECT_ID"   ]] || die "--project is required"
[[ -n "$STATE_BUCKET" ]] || die "--state-bucket is required"
[[ -n "$WIF_PROVIDER" ]] || die "--wif-provider is required"
[[ -n "$PLAN_SA"      ]] || die "--plan-sa is required"
[[ -n "$APPLY_SA"     ]] || die "--apply-sa is required"
case "$VISIBILITY" in
  private|internal|public) ;;
  *) die "--visibility must be private, internal, or public" ;;
esac
command -v gh >/dev/null || { echo "error: gh not found on PATH" >&2; exit 1; }
gh auth status >/dev/null 2>&1 || { echo "error: run 'gh auth login'" >&2; exit 1; }

log() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

# --- create the adopter repo from the template ---------------------------------------
if gh repo view "$ADOPTER_REPO" >/dev/null 2>&1; then
  log "adopter repo $ADOPTER_REPO already exists — verifying it was made from the template"
  if ! gh api "repos/${ADOPTER_REPO}/contents/.github/workflows/deploy.yml" >/dev/null 2>&1; then
    echo "error: $ADOPTER_REPO exists but has no .github/workflows/deploy.yml — it was not" >&2
    echo "       created from $TEMPLATE_REPO, so the keyless pipeline would not exist." >&2
    echo "       Create it from the template (gh repo create <repo> --template $TEMPLATE_REPO)" >&2
    echo "       or delete it, then re-run." >&2
    exit 1
  fi
else
  log "creating $ADOPTER_REPO from template $TEMPLATE_REPO ($VISIBILITY)"
  gh repo create "$ADOPTER_REPO" --template "$TEMPLATE_REPO" --"$VISIBILITY"
fi

# --- wire bootstrap outputs as Actions VARIABLES (not secrets — keyless WIF) ----------
log "setting GitHub Actions variables on $ADOPTER_REPO"
gh variable set GCP_PROJECT_ID         --repo "$ADOPTER_REPO" --body "$PROJECT_ID"
gh variable set GCP_REGION             --repo "$ADOPTER_REPO" --body "$REGION"
gh variable set TF_STATE_BUCKET        --repo "$ADOPTER_REPO" --body "$STATE_BUCKET"
gh variable set GCP_WIF_PROVIDER       --repo "$ADOPTER_REPO" --body "$WIF_PROVIDER"
gh variable set GCP_PLAN_SA            --repo "$ADOPTER_REPO" --body "$PLAN_SA"
gh variable set GCP_APPLY_SA           --repo "$ADOPTER_REPO" --body "$APPLY_SA"

cat <<EOF

==> $ADOPTER_REPO scaffolded. Next:
  1. Gate the apply. Branch protection (required PR review) and environment protection
     (required reviewers) are available on PUBLIC repos (all plans) or PRIVATE repos on a
     plan that includes them — a GitHub FREE PRIVATE repo has NEITHER, so its only gate
     is who can push to main (the APPLY identity trusts any workflow on main: restrict
     write/admin access, or use a public repo / capable plan for an enforced review gate).
  2. Before the FIRST deploy, REVIEW .github/workflows/deploy.yml (esp. CONSOLE7_REF) and
     the Actions variables, then run it deliberately: Actions -> 'console7 deploy' -> Run
     workflow (instantiation does not auto-apply).
  3. Refresh later by bumping CONSOLE7_REF via a PR — plan runs on the PR, merge applies.
     An ENFORCED review on that merge needs branch protection (public repo / capable plan).
EOF
