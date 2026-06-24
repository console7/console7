# Console7 adopter runbook — Phase-1 deploy & a governed session, end to end

This runbook takes you from a bare GCP project to **one governed Claude Code session**
running in your own tenancy, on your own Vertex backend, and shows you how to **verify
the controls** afterwards. It is written so an operator who is *not* a Console7
maintainer can complete the whole loop **using only this document** — that
"maintainer-uninvolved" property is itself the Phase-1 exit criterion
(`docs/ROADMAP.md` §Phase 1):

> **Exit:** a single GitHub task runs in a policy-bound sandbox, default-deny egress
> enforced at the boundary, output attested, lineage intact, evidence immutable —
> deployable by an adopter in their own GCP project with their own Vertex backend and
> their own subscription, **maintainer-uninvolved**.

Everything runs in **your** cloud tenancy. The only boundary crossing is model
inference to **your** Vertex backend (`GOAL.md` tenet 1: the adopter's tenancy is the
trust boundary; there is no maintainer-hosted path and no phone-home).

> **Scope boundary (be honest about what Phase-1 proves).** This run authenticates
> with a **dev SSO assertion** under a process-local key and resolves policy from a
> **fixed dev PolicySoR** — there is no OIDC IdP provider or central policy registry
> yet (later phases). The `c7 -tags c7_live` binary prints a banner saying so. What
> Phase-1 *does* prove end-to-end: policy-bound sandbox · default-deny egress at the
> boundary · metadata denied · genuine engine → real commit · **KMS-rooted** signed
> commit + unbroken lineage · immutable WORM evidence that verifies — all deployed by
> you, in your project, maintainer-uninvolved.

---

## 0. What you will stand up

A single `terraform apply` (driven through a thin GitOps repo) creates, in your project:

| Module | What it is |
|---|---|
| `modules/secrets` | KMS key ring + KEK + least-privilege **workload SA** (envelope-encrypts per-user DEKs; no human holds a credential read path) |
| `modules/keybroker-signing` | Cloud KMS **asymmetric signing key (EC P-256)** + a **distinct** signing SA — the lineage trust root (separate identity from the secrets KEK; never fused) |
| `modules/networking` | **default-deny egress floor** + the sandbox→proxy ALLOW rule (the authoritative perimeter) |
| `modules/gke` | hardened GKE cluster + **gVisor** node pool + Workload Identity binding + namespace-TTL reaper |
| `modules/inference-vertex` | Vertex AI API enablement + **predict-only** grant to the workload SA |
| `modules/artifact-registry` | Docker repo for the signed sandbox base-image |
| `modules/evidence` | GCS **bucket-lock WORM** backing for the evidence chain |

You then run one session through the `c7` CLI (the production `-tags c7_live` build),
which drives the orchestrator across the real provider seams.

---

## 1. Prerequisites (the human bootstrap act)

These steps are deliberately manual — project creation and billing are the human's
job; everything after is keyless and automated (ADR-0002).

1. A **GCP project** (existing, or let bootstrap create one) with **billing linked**.
2. `gcloud` CLI on PATH, authenticated as an Owner-equivalent on that project:
   ```
   ! gcloud auth login
   ```
3. A **GitHub repo** you control to hold the thin deploy config (it will be created
   from `console7-deploy-template`).
4. A **GitHub App** installed on the target code repo. The control plane (not the
   sandbox) does all git I/O — it fetches the base, pushes the session's working
   branch, and opens the PR — so the App needs **Repository permissions: Contents =
   Read & write, Pull requests = Read & write, Metadata = Read-only**. From its
   settings you need the **App ID**, the **installation ID** (in the install URL,
   `.../installations/<id>`), and a generated **private-key `.pem`** (store the path;
   never commit it). The sandbox holds no SCM credential and has no SCM egress.
5. `terraform`, `kubectl`, `gke-gcloud-auth-plugin`, `git`, and `cosign >= 3.0` on
   PATH for the deploy + operator-side verification steps.

> ⚠️ **Cost.** A GKE cluster bills continuously. Plan to **apply, prove, and destroy
> the same day** unless you intend to keep the deployment.

---

## 2. Bootstrap: keyless CD identities (one-time)

`deploy/gcp/bootstrap/bootstrap.sh` creates the Workload Identity Federation pool, two
least-privilege CD identities (a read-only **PLAN** SA and a branch-locked **APPLY**
SA), the Terraform state bucket, and enables the required APIs. **It creates no
secrets.**

```
! ./deploy/gcp/bootstrap/bootstrap.sh \
    --project <PROJECT_ID> \
    --github-repo <owner/deploy-repo> \
    [--region us-east4] [--name-prefix console7] \
    [--create-project --billing-account <BILLING_ID>]
```

Record the printed outputs — you need them next: **project_id**, **region**, **state
bucket**, **WIF provider resource**, **PLAN SA email**, **APPLY SA email**.

It is idempotent: re-running re-asserts the state-bucket hardening and prunes stale
impersonators.

---

## 3. Scaffold the thin GitOps repo

Console7 is consumed **by pinned reference**, never copy-and-edited (ADR-0002). The
adopter holds a thin config repo (from `console7-deploy-template`) that references a
pinned `CONSOLE7_REF`. `deploy/gcp/bootstrap/deploy.sh` instantiates it and wires the
bootstrap outputs as **GitHub Actions variables** (not secrets — the pipeline is
keyless WIF):

```
! ./deploy/gcp/bootstrap/deploy.sh \
    --adopter-repo <owner/deploy-repo> \
    --project <PROJECT_ID> \
    --state-bucket <STATE_BUCKET> \
    --wif-provider <WIF_PROVIDER_RESOURCE> \
    --plan-sa <PLAN_SA_EMAIL> \
    --apply-sa <APPLY_SA_EMAIL> \
    [--region us-east4]
```

This sets the repo variables `GCP_PROJECT_ID`, `GCP_REGION`, `TF_STATE_BUCKET`,
`GCP_WIF_PROVIDER`, `GCP_PLAN_SA`, `GCP_APPLY_SA`, and pins `CONSOLE7_REF` to a Console7
release ref in the workflow.

The deploy repo's `deploy.yml` has a **`plan`** job (on PR, as the read-only PLAN SA)
and an **`apply`** job (on merge to `main`, as the APPLY SA — impersonable only from
`refs/heads/main`). **First apply is deliberate**: instantiation does **not**
auto-apply. Review the variables and `.github/workflows/deploy.yml`, then trigger it
once from the Actions tab.

### Production hardening (set before a real deployment)

These root Terraform variables default to dev-safe values; for production set them via
the deploy repo:

| Variable | Default | Production |
|---|---|---|
| `keybroker_kms_protection_level` | `SOFTWARE` | **`HSM`** (the signing-root CA key) |
| `evidence_retention_locked` | `false` | **`true`** (irreversibly locks WORM retention) |
| `gke_deletion_protection` | `false` | **`true`** |
| `gke_master_authorized_cidrs` | `[]` (fail-closed) | add the CD egress range + any admin bastion |

---

## 4. First apply + mirror the signed sandbox image

1. Trigger the deploy repo's workflow (Actions → run). It applies the modules above
   and emits the root outputs (workload SA, keybroker signing key version, evidence
   bucket, cluster name, Vertex grant). Capture them.
2. **Mirror the signed sandbox base-image** from ghcr.io into your Artifact Registry,
   then **verify the signature** and capture the immutable digest — the kubelet must
   run the exact bytes you verified, so always pin `@sha256:...`, never a tag:
   ```
   ! ./scripts/verify-sandbox-image.sh <region>-docker.pkg.dev/<PROJECT>/console7/sandbox@sha256:<digest>
   ```
   (Defaults verify the keyless Sigstore signature from the Console7 release workflow
   identity; override `COSIGN_IDENTITY_REGEXP` / `COSIGN_OIDC_ISSUER` for a self-rebuilt
   image.)
3. Apply the namespace-TTL reaper (cleans up aborted sessions):
   ```
   ! kubectl apply -f deploy/gcp/modules/gke/reaper.yaml
   ```

---

## 5. Run a governed session (the exit run)

The production CLI is the default `c7` binary built with `-tags c7_live`. It reads its
whole configuration from the environment and **fails closed** with one aggregated error
if anything required is missing.

> **Vertex model id must be in `@` form** (e.g. `claude-haiku-4-5@20251001`); the
> Anthropic-API `-` form does **not** route through Vertex. Preflight that the model is
> actually served in your project/region (read-only, nothing billed):
> ```
> ! ./scripts/verify-vertex-model.sh <PROJECT> <REGION> claude-haiku-4-5@20251001
> ```

### Required environment (the Vertex lane)

```bash
# --- cluster / sandbox ---
export C7_GKE_PROJECT=<PROJECT>
export C7_GKE_LOCATION=<cluster location/region>
export C7_GKE_CLUSTER=<cluster name>
export C7_SANDBOX_IMAGE=<region>-docker.pkg.dev/<PROJECT>/console7/sandbox@sha256:<digest>

# --- secrets / KMS ---
export C7_KEK_RESOURCE=<full KMS CryptoKey resource of the secrets KEK>
export C7_REGION=<region>
export C7_WORKLOAD_SA_EMAIL=<workload SA email, from module.secrets>
export C7_KMS_KEY_VERSION=<full KMS CryptoKeyVersion of the keybroker signing key>

# --- evidence ---
export C7_EVIDENCE_BUCKET=<evidence bucket, from module.evidence>

# --- inference: Vertex ---
export C7_INFERENCE=vertex
export C7_VERTEX_MODEL=claude-haiku-4-5@20251001       # @-form, preflighted above
# C7_VERTEX_PROJECT / C7_VERTEX_REGION default to C7_GKE_PROJECT / C7_REGION

# --- SCM: the GitHub App that opens the PR (the only sanctioned exit) ---
export C7_GH_APP_ID=<app id>
export C7_GH_INSTALLATION_ID=<installation id>
export C7_GH_APP_KEY_FILE=<path to the App private key PEM>
```

Optional: `C7_ANTHROPIC_BASE_URL`, `C7_SECRET_PREFIX` (default `console7`),
`C7_EVIDENCE_PREFIX` (default `records`), `C7_GH_BASE_URL`, and — for the org-API lane
instead of Vertex — `C7_INFERENCE=anthropic` + `C7_ANTHROPIC_MODEL` (+ optional
`C7_ORG_API_KEY`).

#### Per-seam SA impersonation (restore the keybroker's distinct identity)

By default every GCP-SDK seam runs under one ambient ADC identity — which fuses the
keybroker's lineage-signing identity with the secrets/evidence workload identity. To
un-fuse them (`GOAL.md` tenet 2, least-privilege boundary), set these optional knobs so
each seam mints short-lived **impersonated** credentials for its own service account:

```bash
export C7_KEYBROKER_SA_EMAIL=<keybroker/CA SA email>   # the load-bearing one
export C7_SECRETS_SA_EMAIL=<secrets SA email>          # optional
export C7_EVIDENCE_SA_EMAIL=<evidence SA email>        # optional
```

Empty (the default) ⇒ ambient ADC, unchanged. With `C7_KEYBROKER_SA_EMAIL` set, the
lineage CA signs as the **keybroker** SA, distinct from the workload SA used by
secrets/evidence. The operator's ADC must hold `roles/iam.serviceAccountTokenCreator`
on each impersonated SA.

> **HONEST residual — this is not "clean".** Per-seam impersonation removes the static
> CA key file and un-fuses the SAs, but the operator (or any principal) holding
> `tokenCreator` on the keybroker SA can still mint a token for it and **sign as the
> lineage CA**. Impersonation does not close that path; only moving the keybroker into
> the in-cluster control plane (Option B), where no human holds `tokenCreator` on that
> SA, closes it.

> **cloud-gcp is excluded — it shells out to `kubectl`/`gcloud`** and has no Go GCP
> client, so the knobs above do not apply to it. Its calls run under the operator's
> ambient `gcloud` ADC. To run cloud-gcp **as** a specific SA, set gcloud's own
> impersonation out of band, e.g.
> `export CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT=<sandbox-ops SA>`.

The egress allowlist is **derived from the inference backend itself** — you do not set
an endpoint string; the orchestrator narrows egress to exactly the Vertex host the
backend resolves to, and re-checks the resolved URL at session time (the boundary is
authoritative, `GOAL.md` tenet 2).

### Launch

```
! c7 launch --repo <owner/name> --branch c7/exit-run \
     --prompt "fix the typo in README" --persona author
```

The CLI prints the PRODUCTION banner (and its Phase-1 residuals), then drives one
session: mint per-session NHI (binding cert signed by the **KMS** root) → provision a
gVisor sandbox → narrow egress to the Vertex host → **control plane fetches the base
branch** (as a git bundle, via the GitHub App) and seeds it into the sandbox → mint a
short-lived GCP token, delivered into the sandbox by file (never via metadata) →
genuine `claude -p` against Vertex on the real checkout → real commit → orchestrator
signs the commit + stamps lineage (KMS) → **control plane pushes the working branch**
to the remote (branch-scoped App token — the sandbox never holds it) → opens the GitHub
PR → seals WORM evidence to GCS. On success it reports the proposed commit, the PR URL,
and **`evidence chain VERIFIED`**. (All GitHub I/O is control-plane-side; the sandbox
stays SCM-free.)

---

## 6. Verify the controls

This is the audit. Each control maps to a clause of the exit criterion.

| Control | How to verify |
|---|---|
| **Output attested / lineage intact** | The CLI renders `PROPOSED commit <SHA> … signed by NHI <…>` and `evidence chain VERIFIED`. The commit signature is NHI-signed, **rooted in the KMS CA** (EC P-256). |
| **Evidence immutable (WORM)** | The sink's `Verify()` recomputes the hash chain from genesis, validates **every checkpoint signature** under the CA root, and confirms the head is sealed. The CLI's `EvidenceVerifier.VerifyChain()` gates the verdict; a tampered chain reports the first break (`hash mismatch at record N`). The GCS objects exist under `C7_EVIDENCE_PREFIX` and, with `evidence_retention_locked=true`, cannot be deleted or overwritten until retention expires. |
| **The only sanctioned exit is a PR** | A GitHub PR is opened by the App; no session holds author+approve+actuate (`GOAL.md` tenet 5). |
| **Default-deny egress + metadata denied** | From inside the sandbox, the proxy is reachable but everything else is denied. The live integration test (`providers/cloud-gcp/integration_test.go`, `TestIntegration_LiveEngineRun`, tag `cloud_gcp_integration`) probes this: the per-session proxy connects; `169.254.169.254:80` (metadata IP), `metadata.google.internal:80` (no in-sandbox resolver), and `1.1.1.1:443` (non-allowlisted) all **fail**. |

To run the boundary/engine assertions as a standalone live check against the deployed
cluster:

```
! C7_GKE_PROJECT=<PROJECT> C7_GKE_LOCATION=<loc> C7_GKE_CLUSTER=<cluster> \
  C7_SANDBOX_IMAGE=<image@sha256:...> C7_RUN_ENGINE=1 C7_ANTHROPIC_API_KEY=<key> \
  go test -tags cloud_gcp_integration -run TestIntegration_LiveEngineRun ./providers/cloud-gcp/...
```

---

## 7. Update-in-place, teardown, redeploy

- **Update:** bump `CONSOLE7_REF` in the deploy repo (a bot PR or by hand) → the PR
  runs `plan` → merge → `main` applies. Reviewed version bump, never copy-edit.
- **Teardown (same day, to stop billing):**
  ```
  ! terraform -chdir=deploy/gcp destroy -var="project_id=<PROJECT>"
  ```
  or run the deploy repo's destroy path. With `gke_deletion_protection=true` or
  `evidence_retention_locked=true`, those resources are intentionally protected — flip
  the variable first if you really mean to remove them.
- **Redeploy:** re-trigger the apply; bootstrap need not be re-run unless the WIF/CD
  identities changed.

---

## 8. Troubleshooting

- **`missing required env: …`** — the `c7_live` binary lists every missing/malformed
  `C7_*` variable at once (§5). Set them all and retry.
- **`inference backend (vertex) resolved no endpoints to allow`** — `C7_INFERENCE` /
  Vertex project/region/model are inconsistent; re-check §5 and the model preflight.
- **Cluster control plane unreachable** — `gke_master_authorized_cidrs` is empty
  (fail-closed); add the CD egress range and your admin source range.
- **Sandbox image rejected** — the reference is tag-only; re-pin to `@sha256:` and
  re-verify with `scripts/verify-sandbox-image.sh`.
- **Vertex 404 / model not served** — wrong model form (`-` vs `@`) or not served in
  your region; re-run `scripts/verify-vertex-model.sh`.
- **Aborted sessions leaving namespaces** — confirm the reaper is applied
  (`deploy/gcp/modules/gke/reaper.yaml`).
- **Bootstrap re-run drift / WIF scoping** — bootstrap is idempotent; the APPLY SA is
  locked to the default branch and the WIF provider to one repo + one workflow file. If
  CD impersonation fails, re-check `--github-repo`, `--default-branch`, and
  `--workflow-file`.

---

*This runbook is the maintainer-uninvolved walkthrough for the Phase-1 exit. If any
step required improvisation during your run, that is a runbook bug — please open an
issue against Console7 with the gap.*
