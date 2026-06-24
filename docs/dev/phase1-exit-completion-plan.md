# Phase-1 EXIT completion plan — the 7 live-run findings → the full (Vertex) exit

**Status (2026-06-25).** The Phase-1 EXIT was proven **live, end-to-end, through the orchestrator** on
the **org-API (Anthropic) lane**: one `c7 -tags c7_live` pass on `console7-poc1` produced a genuine
engine commit → **KMS-rooted NHI signature** → control-plane push → **real PR**
([console7/exit-poc#1](https://github.com/console7/exit-poc/pull/1)) → **WORM chain VERIFIED (12
records)**. The push→PR bridge (E1–E4, PRs #82–#85) is merged. The live cluster is torn down (billing
off; the WORM bucket is a ~$0 orphan, intentionally preserved).

**What "full Phase-1 EXIT" still needs.** The literal criterion (`docs/ROADMAP.md` §Phase 1) says *"their
own **Vertex** backend."* Tonight ran on the org-API lane and used **local-operator identity shortcuts**
that an adopter must not need. So two things gate the *full, defensible* exit:

1. **The Vertex lane actually works** (finding #4 — the engine↔Vertex auth).
2. **A clean identity model** (finding #2 — no human holding the lineage-CA key, no fused SAs).

…plus landing the in-flight fixes (#3/#5/#6) and the small ones (#1/#7) and a true non-author walkthrough.

This doc turns the 7 findings into a sequenced, PR-by-PR plan, and records the durable lessons. Read the
`console7-phase1-exit-execution` memory resume point alongside it.

---

## The 7 findings → work items

| # | Finding | Root cause | Fix | State |
|---|---|---|---|---|
| 1 | wire_production rejects `C7_VERTEX_REGION=global` | passed as `Config.Region`; inference-vertex's host-injection guard rejects "global" | map `global` → `inferencevertex.Config{Global:true}` | open |
| 2 | **Local single-identity can't honour the production identity split** (headline) | one `c7` process = one ADC, but prod splits workload-SA / keybroker-SA / evidence-writer; the run granted a human the CA key + fused SAs | per-seam SA impersonation in c7_live (or in-cluster control-plane) | open |
| 3 | Credential delivery races the not-yet-Ready pod (cold gVisor) → "sandbox no longer belongs" | only `RunTask` gated readiness; inject ran first, 30s-bounded | `kubeRuntime.Provision` waits Ready before returning | **fixed on branch `fix/e4-live-run-findings`** |
| 4 | **Vertex 401 — engine can't use a pre-minted bearer (R-V1)** | engine 1.0.44 Vertex auth = google-auth-library ADC (needs a token *fetch*) or `SKIP_VERTEX_AUTH=1` (empty headers); `CLOUDSDK_AUTH_ACCESS_TOKEN` is ignored | **auth-proxy sidecar** in the sandbox pod | open |
| 5 | PR-create 422 "not all refs are readable" | PR token was `pull_requests:write` only; GitHub must read head+base refs | add `contents:read` to `pullRequestPermissions` | **fixed on branch** |
| 6 | (defence) post-push ref race could 422 | GitHub eventual-consistency after a push | bounded retry on the transient in `CreatePullRequest` | **fixed on branch** |
| 7 | Proposed diff includes `.claude.json`/`.claude.json.backup` | `engineDotfileExcludes` covers `.claude/` (dir) not root `.claude.json*` | broaden the exclude; this is also the pre-egress DLP point | open |

---

## Sequenced plan (each phase = one reviewable PR unless noted)

### Phase F0 — land the in-flight fixes (branch `fix/e4-live-run-findings`)
The branch already carries #3, #5, #6 + a reusable build-tagged App preflight (`providers/scm-github/preflight_test.go`). **Before merge:**
- **Reconcile `providers/scm-github/doc.go`** — it still says the PR token is "pull_requests:write only, NOT contents"; that's now false (it's `+contents:read`). Update the prose + the `pullRequestPermissions` comment.
- **Tests:** (a) cloud-gcp — assert `Provision` invokes the readiness wait (white-box over the fake runner / a shape test); (b) scm-github — `pullRequestPermissions` includes `contents:read` and intersects correctly; (c) scm-github — `CreatePullRequest` retries `isTransientRefRace` and gives up after the bound (fake `PullRequestOpener` that fails N times then succeeds — note the real adapter is `ghApp`, so test the retry helper or refactor the loop to be unit-testable).
- **Gates:** `go build` (both tags) · `go vet` · `go test ./...` · `golangci-lint` (both tags) · coverage floors · `gofmt`. Run `./scripts/coverage-gate.sh` AFTER any reconciliation edit (a skipped local gate has sunk CI before).
- **F0 residual to note in the PR:** the `Provision` readiness wait holds `p.mu` for the cold-scale duration (single-session OK; a lock-free wait — record handle, unlock, wait, destroy-on-failure — is the production-grade form). File as a follow-up, don't block.
- pre-pr-review (3-lens) + ledger entry. CO-04, CO-06.

### Phase F1 — small wins + hygiene
- **Finding #1:** `control-plane/ui/cmd/c7/wire_production.go` `buildInference`: when `C7_VERTEX_REGION == "global"`, build `inferencevertex.Config{ProjectID, Global: true}` (no `Region`); else `Config{ProjectID, Region}`. Add a wire-level test. (Confirm `inference-vertex.Resolve` with `Global:true` returns `https://aiplatform.googleapis.com` + the derived egress allowlist matches.)
- **Finding #7:** `providers/cloud-gcp/kube_exec.go` `engineDotfileExcludes` → add `.claude.json`, `.claude.json.backup` (and audit what else 1.0.44 drops at the workspace root — `.claude.json*` glob if the seed's `.git/info/exclude` supports it, else enumerate). Add a `seed_test.go` assertion. Tie to the DLP note (the proposed diff is the pre-egress DLP surface).
- **Hygiene (ops, not a PR):** revoke the lingering local-run IAM grants on `console7-poc1` (classifier-gated, user-authorized): `davosparent` `tokenCreator` on `console7-cp-secrets`; `davosparent` + `console7-cp-secrets` `signerVerifier` on `console7-nhi-ca`. They let a human sign as the lineage CA post-teardown.

### Phase F2 — the Vertex lane (finding #4): auth-proxy sidecar
This is the substantive Vertex build. The engine (1.0.44) will **not** consume a pre-minted bearer via env, so inject it at the wire.
- **Design:** add a small **auth-proxy sidecar** container to the sandbox pod (`renderSandboxPod`). It listens on `localhost:<port>`, reads the bearer from the in-pod token file (`/run/console7/credential`, the same file the Vertex InjectInferenceCredential delivers), adds `Authorization: Bearer <token>`, and forwards to the real regional Vertex host over TLS **via the per-session Squid proxy** (`HTTPS_PROXY` = the same proxy; the Vertex host stays on the egress allowlist). The engine is configured with `CLAUDE_CODE_USE_VERTEX=1`, `CLAUDE_CODE_SKIP_VERTEX_AUTH=1`, `ANTHROPIC_VERTEX_BASE_URL=http://localhost:<port>`, `ANTHROPIC_VERTEX_PROJECT_ID`, `CLOUD_ML_REGION`.
- **cloud-gcp changes:** `engineRunScript` (Vertex lane) — DROP `CLOUDSDK_AUTH_ACCESS_TOKEN` (ignored) and `claude` envs above; `renderSandboxPod` — add the sidecar + a shared loopback. Keep the token delivered to the file (the sidecar reads it; the engine never sees it directly).
- **The sidecar artifact:** a tiny static binary (Go, ~50 LOC reverse proxy) baked into the sandbox base image as a second process, OR a minimal second container image. Prefer baking into the base image (one signed artifact) with a distinct entrypoint the pod invokes for the sidecar container. Token refresh: for a single short session one ~1h token suffices; a re-read-on-each-request keeps it simple (the control plane can re-deliver on refresh later).
- **Rejected alternatives (record why):** google-auth-library has no static-access-token credential type; `external_account`/`authorized_user` still require an STS/oauth fetch (egress the sandbox forbids); giving the sandbox metadata/WI or an SA key violates the untrusted-sandbox tenet. The sidecar is the only design that keeps the bearer pre-minted + the sandbox SCM/IAM-egress-free.
- **Tests:** render test (sidecar present, engine env points at localhost + skip-auth, no `CLOUDSDK_AUTH_ACCESS_TOKEN`); a hermetic sidecar unit test (injects the header, forwards). Live proof is the exit run (F4).
- **Deploy:** no new infra (Vertex predict IAM + the `*.googleapis.com` private route already exist); the regional Vertex host (e.g. `us-east5-aiplatform.googleapis.com`) resolves via the private DNS the gke module set.

### Phase F3 — the identity model (finding #2): per-seam impersonation (or in-cluster)
Pick ONE; **per-seam impersonation is the lighter, faithful local path**, in-cluster is the eventual production model.
- **Option A (recommended for the exit): per-seam SA impersonation in c7_live.** Let each provider client authenticate as the *right* SA: keybroker-gcp → the **keybroker SA** (`console7-keybroker`); secrets-gcp/evidence-gcs/cloud-gcp → the **control-plane/workload SA**. Wire it via `option.WithCredentials`/impersonated credentials per provider in `wire_production.go` (each provider's `New` already takes `...option.ClientOption`). The operator then needs `tokenCreator` on **both** SAs — **no CA key to a human, no fused SAs**. This restores the keybroker's distinct signing identity (tenet) while still running c7 locally. Add a `C7_KEYBROKER_SA_EMAIL` env.
- **Option B (production end-state): in-cluster control-plane + keybroker.** Build the control-plane image + the separate keybroker image, deploy as distinct Deployments with distinct KSAs bound (Workload Identity) to the control-plane GSA and the keybroker GSA. The c7 CLI becomes a thin client of the in-cluster control plane. This is the real §6.4 trust-tier separation but is a large multi-PR effort (two images + manifests + WI bindings + the UI/API surface). Track as the post-exit hardening; not required to *demonstrate* the exit if Option A is in place.
- **Acceptance for the exit:** the lineage CA is signed by the **keybroker SA** (not a human, not the workload SA), verified in the evidence chain.

### Phase F4 — the full (Vertex) exit run + B13
- Redeploy `console7-poc1` (CD; `CONSOLE7_REF` → the post-F0–F3 main), mirror the (signed) sandbox image incl. the new sidecar, set the **Vertex** env (`C7_INFERENCE=vertex`, region with Claude — e.g. `us-east5` + `claude-sonnet-4-5@…`, or `global` via the #1 fix + `claude-haiku-4-5@…`), per-seam SAs (F3).
- Run `c7 launch` → assert: engine on **Vertex** → KMS-signed commit → push → **real PR** → WORM verified, **with the keybroker SA as the signing identity** and **no CA-key-to-human grant**.
- Verify controls (signed commit, WORM chain, egress/metadata deny). **Destroy same day** — and either set the evidence module `force_destroy=true` for a clean teardown or accept the WORM orphan (decide; see lessons).
- **B13 true non-author walkthrough:** tonight was maintainer-as-operator. A genuine non-author following only `docs/RUNBOOK.md` (now updated with the GitHub App + the per-seam SA setup + the sidecar) is the remaining proof. Update the RUNBOOK with everything F1–F3 changed first.

---

## Durable lessons (bake into RUNBOOK / DESIGN / future work)

1. **The engine consumes Vertex auth via google-auth-library, never a pre-minted bearer env.** Any pre-minted-token design MUST inject at the wire (auth-proxy sidecar). `CLOUDSDK_AUTH_ACCESS_TOKEN`/`GOOGLE_OAUTH_ACCESS_TOKEN` are NOT read by claude-code 1.0.44; `SKIP_VERTEX_AUTH=1` sends empty headers (needs an external auth proxy).
2. **A single local identity cannot hold the production identity split.** The control plane's components (secrets/keybroker/evidence) have deliberately distinct, scoped SAs; collapsing them into one ADC forces either a human holding the lineage CA or fused SAs — both tenet violations. Run with per-seam impersonation locally, or in-cluster.
3. **Credential delivery must gate pod readiness.** Inject (a bounded `kubectl exec`) cannot precede pod-Ready; the only readiness gate was in `RunTask`. Provision now waits.
4. **GitHub App PR-create needs `contents:read`** in addition to `pull_requests:write` (to read the head/base refs), and a brief **post-push retry** for ref eventual-consistency.
5. **The authoritative WORM bucket policy locks out even project owner** (finding-#38 hardening) — and `force_destroy=false` correctly blocks teardown of a non-empty evidence bucket. A clean teardown needs `force_destroy=true` (deletes the WORM proof) or accept a ~$0 orphan. Decide per run.
6. **The classifier hard-gates CA-key / WORM-bucket / impersonation IAM grants** even with a broad allow-rule; they need explicit, specific, per-action user authorization (the user naming the exact role+resource). Plan for these as interactive checkpoints in any live run.
7. **Operational:** `guard-bash` blocks the literal ` bundle` (the `bunx?` token) — hyphenate (`git-bundle`) or write commit/PR/ledger bodies to a temp file. `! ` does not work over Claude Code remote — the user approves the agent's Bash cloud commands instead. The MacBook is the operator host; its public IP must match `GKE_MASTER_CIDR`.
8. **The DLP gap is concrete:** the proposed diff is the pre-egress content channel (it leaked `.claude.json`); broadening the exclude is a stopgap, a real pre-egress DLP scan on `CommitBundle` is the control of record.

---

## Operational quick-reference (for the resume session)
- Live env: project `console7-poc1` / region `us-east4` (cluster) — torn down; redeploy via `console7-deploy` CD (`CONSOLE7_REF` bump → push to its `main` auto-applies). See `console7-deploy-repo` memory.
- GitHub App + target repo: `console7-exit-poc-github-app` memory (App 4132830, install 142331280, key on `~/Desktop`, repo `console7/exit-poc`).
- Vertex regions serving Claude: `us-east5`/`europe-west1` (sonnet-4-5), `global` (haiku-4-5, sonnet-4-5/4-6). `us-east4` serves none. Use the `v1beta1/publishers/anthropic/models` endpoint to check (the `verify-vertex-model.sh` script hits `v1` — fix it to `v1beta1`, a bonus finding).
- Branch `fix/e4-live-run-findings` (pushed) = the F0 starting point.
