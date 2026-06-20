# `deploy/gcp/bootstrap/` — one-time human bootstrap + adopter scaffolding

Per [ADR-0002](../../../docs/adr/0002-adoption-deployment-model.md), standing Console7
up has two halves: a **one-time human-authority bootstrap** (this directory) and the
**keyless, version-bumped deploy pipeline** the bootstrap enables. The maintainer runs
nothing — the adopter runs these with their own credentials, in their own tenancy
(`GOAL.md` tenet 1).

## 1. Human prerequisites (GUI or CLI — your authority)

These are the human-authority acts; do them once, signed in as yourself:

1. **A GCP project.** Create a new one (or pick an existing one — Console7 supports
   both). `bootstrap.sh --create-project` can create it for you, or use the console.
2. **Billing linked** to that project (needs a Billing Account Admin — easiest in the
   console, or `gcloud billing projects link`).
3. **`gcloud auth login`** as a principal with Owner (or equivalent) on the project —
   the bootstrap creates IAM, WIF, and KMS substrate, so it needs admin rights *once*.

> Project creation + billing are deliberately **not** automated away: they are the
> human root of trust for everything the pipeline later does keylessly.

## 2. Run the bootstrap

```bash
# existing project:
./bootstrap.sh --project my-console7 --github-repo my-org/my-console7-deploy

# or create the project too:
./bootstrap.sh --project my-console7 --github-repo my-org/my-console7-deploy \
  --create-project --billing-account 0X0X0X-0X0X0X-0X0X0X
```

Idempotent (re-linking billing is a no-op). It provisions only the substrate the
**current** deploy module needs and prints the values to wire into the adopter config
repo: it enables the required APIs, creates a **versioned, private** Terraform state
bucket, and sets up **Workload Identity Federation** (a pool + GitHub OIDC provider
whose **provider-level condition restricts it to the one `owner/repo` you pass**) —
**no service-account key is ever created or stored** (tenet 5).

It then creates **two CD identities, mirroring tenet 6 (observe ≠ actuate)** so that a
human merge is the precondition for any change:

- a **PLAN** identity — **read-only** (project viewer + IAM read + state read),
  impersonable from **any branch**, for the PR `terraform plan` that posts the effect
  diff;
- an **APPLY** identity — **admin-grade** for the resources the modules provision,
  impersonable **only from the default branch** (`refs/heads/main`). It is bound via a
  `repository_ref` attribute, so a PR or feature branch **cannot** assume it.

> The apply identity is admin-grade by necessity (it creates KMS keys, service
> accounts, IAM). Its safety rests on three layers: the provider is locked to your one
> repo, impersonation is locked to the default branch, and a human merges before that
> branch moves. **Strongly recommended:** also run the apply job under a **protected
> GitHub environment** (required reviewers, branch policy) for defence in depth.

The APPLY identity is granted only the roles the current module provisions (KMS admin,
SA admin, `objectAdmin` on the state bucket). Later module PRs (`gke`, `networking`,
`secrets-gcp`) extend it as their resources require — re-run `bootstrap.sh` after
pulling them. Nothing is granted ahead of need.

## 3. Scaffold the adopter config repo

`deploy.sh` creates the adopter's thin config repo from the standalone
`console7-deploy-template` (ADR-0002 §7 — the template is **not** carried in core), and
wires the bootstrap outputs into it as GitHub Actions **variables** (not secrets):

```bash
./deploy.sh \
  --adopter-repo my-org/my-console7-deploy \
  --project my-console7 \
  --region us-east4 \
  --state-bucket my-console7-tfstate \
  --wif-provider projects/NNN/locations/global/workloadIdentityPools/console7-pool/providers/github \
  --plan-sa console7-plan@my-console7.iam.gserviceaccount.com \
  --apply-sa console7-apply@my-console7.iam.gserviceaccount.com
```

From there, refreshing Console7 is a **reviewed version bump** in that repo (ADR-0002):
a bot raises the pinned module `?ref=`, the PR runs `terraform plan` as the **plan**
identity and posts the effect diff, a human merges, and the merge-to-`main` job applies
as the **apply** identity. The maintainer is never in the loop.

## Security posture (at a glance)

- **No long-lived cloud secret anywhere** — keyless WIF (tenet 5); no SA key minted.
- **Provider locked to one repo** (provider-level attribute-condition) — no other
  GitHub repo can mint a token into the pool.
- **Observe ≠ actuate (tenet 6):** a read-only **plan** identity (any branch) and an
  admin **apply** identity (default branch only) — a PR cannot actuate.
- **State bucket** is private (public-access-prevention) + uniform IAM + versioned.
- **Least privilege, grown per module** — the apply identity gets only what the current
  module provisions; the plan identity is read-only.
- The scripts **print no secret** and store nothing.
