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

### Scope — which exit clauses this plan closes
The `ROADMAP.md` §Phase 1 **Exit** sentence reads: "*…deployable by an adopter in their own GCP project
with their own **Vertex** backend and their own **subscription**, maintainer-uninvolved.*" — and the
Phase-1 deliverable list also names a "**Web-CLI UI** sufficient to launch, watch, and review one
session." This plan **closes the Vertex-backend clause** (F2) and the lineage/evidence/egress clauses
(F0–F4). It **explicitly does NOT close**, and defers with rationale:
- **Subscription backend.** The subscription *consumption* leg is already live-proven out-of-tree
  (console7-cloud-local #9); per tenet 7 it is *attended single-user only*, so it is out of scope for
  this orchestrated/headless exit lane and does not need in-cluster re-proof here. Tracked under
  `console7-subscription-oauth-model` (the grant/refresh lifecycle).
- **Web-CLI UI.** No web UI exists yet (`control-plane/ui` is the `c7` CLI only). The exit is
  *demonstrated* via `c7 launch`; the Web-CLI UI is deferred to the Option-B in-cluster build (F3), where
  the API/UI surface lands naturally. Flagged here so "full Phase-1 EXIT" is not read as UI-complete.

---

## The 7 findings → work items

| # | Finding | Root cause | Fix | State |
|---|---|---|---|---|
| 1 | wire_production rejects `C7_VERTEX_REGION=global` | passed as `Config.Region`; inference-vertex's host-injection guard rejects "global" | map `global` → `inferencevertex.Config{Global:true}` | open |
| 2 | **Local single-identity can't honour the production identity split** (headline) | one `c7` process = one ADC, but prod splits workload-SA / keybroker-SA / evidence-writer; the run granted a human the CA key + fused SAs | per-seam SA impersonation in c7_live (or in-cluster control-plane) | open |
| 3 | Credential delivery races the not-yet-Ready pod (cold gVisor) → "sandbox no longer belongs" | only `RunTask` gated readiness; inject ran first, 30s-bounded | readiness gate before the first exec in `kubeEngineRunner.Run` (pod Ready + proxy Available) | **fixed on branch `fix/e4-live-run-findings`** |
| 4 | **Vertex 401 — engine can't use a pre-minted bearer (R-V1)** | engine 1.0.44 Vertex auth = google-auth-library ADC (needs a token *fetch*); `CLOUDSDK_AUTH_ACCESS_TOKEN` is ignored (gcloud-only; not read by google-auth-library-nodejs) | **own-pod (per-session) auth-proxy with its own Workload Identity** — the documented `ANTHROPIC_VERTEX_BASE_URL` + `CLAUDE_CODE_SKIP_VERTEX_AUTH=1` gateway contract; **no bearer ever enters the sandbox pod** | open |
| 5 | PR-create 422 "not all refs are readable" | PR token was `pull_requests:write` only; GitHub must read head+base refs | add `contents:read` to `pullRequestPermissions` | **fixed on branch** |
| 6 | (defence) post-push ref race could 422 | GitHub eventual-consistency after a push | bounded retry on the transient in `CreatePullRequest` | **fixed on branch** |
| 7 | Proposed diff includes `.claude.json`/`.claude.json.backup` | `engineDotfileExcludes` covers `.claude/` (dir) not root `.claude.json*` | broaden the exclude; this is also the pre-egress DLP point | open |

---

## Sequenced plan (each phase = one reviewable PR unless noted)

### Phase F0 — land the in-flight fixes (branch `fix/e4-live-run-findings`)
The branch already carries #3, #5, #6 + a reusable build-tagged App preflight (`providers/scm-github/preflight_test.go`). **Before merge:**
- **Reconcile `providers/scm-github/doc.go`** — it still says the PR token is "pull_requests:write only, NOT contents"; that's now false (it's `+contents:read`). Update the prose + the `pullRequestPermissions` comment.
- **Tests:** (a) cloud-gcp — assert the readiness gate runs **in `kubeEngineRunner.Run` before the first exec** (it waits pod `condition=Ready` + the per-session proxy `condition=Available`); the fix moved the gate *out of* `Provision` (which now returns straight after apply+annotate) and *into* `Run`, so test `Run`, not `Provision`; (b) scm-github — `pullRequestPermissions` includes `contents:read` and intersects correctly; (c) scm-github — `CreatePullRequest` retries `isTransientRefRace` and gives up after the bound (fake `PullRequestOpener` that fails N times then succeeds — note the real adapter is `ghApp`, so test the retry helper or refactor the loop to be unit-testable).
- **Gates:** `go build` (both tags) · `go vet` · `go test ./...` · `golangci-lint` (both tags) · coverage floors · `gofmt`. Run `./scripts/coverage-gate.sh` AFTER any reconciliation edit (a skipped local gate has sunk CI before).
- pre-pr-review (3-lens) + ledger entry. CO-04, CO-06.

### Phase F1 — small wins + hygiene
- **Finding #1:** `control-plane/ui/cmd/c7/wire_production.go` `buildInference`: when `C7_VERTEX_REGION == "global"`, build `inferencevertex.Config{ProjectID, Global: true}` (no `Region`); else `Config{ProjectID, Region}`. Add a wire-level test. (Confirm `inference-vertex.Resolve` with `Global:true` returns `https://aiplatform.googleapis.com` + the derived egress allowlist matches.)
- **Finding #7:** `providers/cloud-gcp/kube_exec.go` `engineDotfileExcludes` → add `.claude.json`, `.claude.json.backup` (and audit what else 1.0.44 drops at the workspace root — `.claude.json*` glob if the seed's `.git/info/exclude` supports it, else enumerate). Add a `seed_test.go` assertion. Tie to the DLP note (the proposed diff is the pre-egress DLP surface).
- **Hygiene (ops, not a PR):** revoke the lingering local-run IAM grants on `console7-poc1` (classifier-gated, user-authorized): `davosparent` `tokenCreator` on `console7-cp-secrets`; `davosparent` + `console7-cp-secrets` `signerVerifier` on `console7-nhi-ca`. They let a human sign as the lineage CA post-teardown.

### Phase F2.0 — Vertex-auth spike (throwaway; gates F2's design)
The whole F2 design rests on the engine honouring the documented gateway contract. The contract is real
(`ANTHROPIC_VERTEX_BASE_URL` "for custom endpoints or routing through an LLM gateway" +
`CLAUDE_CODE_SKIP_VERTEX_AUTH=1` "if gateway handles GCP auth"), **but the docs reflect current Claude
Code and the repo pins engine @1.0.44.** Spike (no PR, throwaway): point a pinned-1.0.44 `claude -p` at a
trivial local listener via `ANTHROPIC_VERTEX_BASE_URL` + `SKIP_VERTEX_AUTH=1` and confirm it (a) sends
the request there, (b) attaches **no** Google `Authorization` header, (c) accepts a header the listener
adds and reaches real Vertex `:rawPredict`. If 1.0.44 lacks the base-URL override, **bump the pinned
engine** to a version that has it before building F2. (Watch the known presence-not-value bug in
`CLAUDE_CODE_USE_VERTEX` handling, GH #2804/#13663 — benign for us since we want Vertex *on*.)

### Phase F2 — the Vertex lane (finding #4): own-pod auth-proxy with Workload Identity
This is the substantive Vertex build. The engine implements **no** Vertex auth of its own — it delegates
to Google's ADC chain — and there is **no env/file way to feed it a pre-minted bearer** (confirmed:
`CLOUDSDK_AUTH_ACCESS_TOKEN` is gcloud-only and unread by `google-auth-library-nodejs`; every ADC file
type performs a network mint). The engine's *native* path is ambient ADC via the pod's Workload
Identity — which Console7 **cannot** grant the **untrusted, metadata-free** sandbox. So relocate the
ambient-ADC identity into a **trusted auth-proxy pod** the sandbox reaches over the network.
- **Design:** a small **auth-proxy runs as its own (per-session) Deployment** — alongside the existing
  per-session Squid proxy (the `<session>-proxy` namespace pattern) — bound by **Workload Identity** to a
  dedicated, Vertex-scoped GSA. It mints/refreshes its own Vertex token just-in-time from *its* metadata
  server (standard Go ADC), adds `Authorization: Bearer <token>`, and forwards to
  `{region}-aiplatform.googleapis.com`. The engine is configured with `CLAUDE_CODE_USE_VERTEX=1`,
  `CLAUDE_CODE_SKIP_VERTEX_AUTH=1`, `ANTHROPIC_VERTEX_BASE_URL=<auth-proxy address>`,
  `ANTHROPIC_VERTEX_PROJECT_ID`, `CLOUD_ML_REGION`. **No bearer is ever delivered into the sandbox pod;
  the sandbox holds no GCP credential and stays metadata-free.**
- **Egress / tenet 3:** sandbox→auth-proxy is an in-cluster `NetworkPolicy` hop (add the auth-proxy to
  the sandbox's egress allowlist by IP — there is no in-sandbox DNS); the auth-proxy's own egress to the
  pinned Vertex host is governed by its own allowlist (or chains through Squid). Default-deny holds; the
  authoritative perimeter is unchanged. `inference-vertex.Resolve` targets the auth-proxy address.
- **cloud-gcp changes:** `engineRunScript` (Vertex lane) — **DROP `CLOUDSDK_AUTH_ACCESS_TOKEN`** (dead;
  retire the **RISKS R-9** gosec suppression with it) and set the gateway env above; render the
  per-session auth-proxy Deployment + Service + NetworkPolicy (model it on the Squid renderer).
- **The auth-proxy artifact:** a tiny Go reverse proxy (mint token via ADC → set header → forward),
  built as a **distinct signed image** (not fused with the sandbox base image — distinct trust tiers,
  ARCHITECTURE.md §6.4). Token refresh is the proxy's own ADC concern (auto-refreshed from metadata).
- **Three control-plane guards (bake in):** (i) **project-ID precedence** — ensure
  `GOOGLE_APPLICATION_CREDENTIALS`/`GOOGLE_CLOUD_PROJECT`/`GCLOUD_PROJECT` do **not** leak into the engine
  env (they override `ANTHROPIC_VERTEX_PROJECT_ID`); assert in the render test. (ii) **`gcpAuthRefresh`
  is command-execution** — `policyHelper.Render`'s locked managed-settings should forbid/null it (a repo
  `.claude/settings.json` must not define a refresh command; tenet 2). (iii) **least-priv IAM** — bind the
  auth-proxy GSA to a **custom role with only `aiplatform.endpoints.predict`**, not broad
  `roles/aiplatform.user`; revoking the binding/WI is the kill switch (`/logout` is unavailable under
  Vertex — auth is pure IAM).
- **Rejected alternatives (record why):**
  - **Sidecar in the sandbox pod** (delivered bearer): a KSA is *pod-level*, so a WI-minting sidecar
    grants the untrusted engine container the same identity → not metadata-free; and a *delivered* bearer
    lands in a volume the same-uid (65532) engine can read (0600 doesn't isolate same-uid containers) +
    needs delivery/refresh plumbing. Strictly worse on security and complexity.
  - **Fold auth into Squid:** Squid cannot inject a header inside a CONNECT/TLS tunnel without SSL-bump
    (MITM the egress), and it fuses credential-holding with the authoritative perimeter (tenet 2). No.
  - **Adopt LiteLLM as the gateway:** proves the contract but a large, unaudited dependency next to
    untrusted code (a recent LiteLLM release was compromised). Build the ~tiny proxy instead.
  - **Pre-minted bearer to the engine (the old R-V1 lever):** no consumable path exists; engine ignores it.
- **Tests:** render test (engine env points at the auth-proxy + skip-auth, **no** `CLOUDSDK_AUTH_ACCESS_TOKEN`,
  no project-overriding vars; auth-proxy Deployment/NetworkPolicy present); hermetic auth-proxy unit test
  (mints via an injected token source, sets the header, forwards). Live proof is the exit run (F4).
- **Deploy:** add the auth-proxy GSA + custom role + WI binding in `deploy/gcp/modules/gke`; the Vertex
  predict route + `*.googleapis.com` private DNS already exist.

### Phase F3 — the identity model (finding #2): per-seam impersonation (or in-cluster)
Pick ONE; **per-seam impersonation is the lighter, faithful local path**, in-cluster is the eventual production model.
- **Option A (recommended to *demonstrate* the exit): per-seam SA impersonation in c7_live.** Let each
  GCP provider client authenticate as the *right* SA: keybroker-gcp → the **keybroker SA**
  (`console7-keybroker`); secrets-gcp/evidence-gcs/cloud-gcp → the **control-plane/workload SA**. Wire it
  via `option.WithCredentials`/impersonated credentials per provider in `wire_production.go` (each GCP
  provider's `New` already takes `...option.ClientOption`). The operator then needs `tokenCreator` on
  both SAs. Add a `C7_KEYBROKER_SA_EMAIL` env.
  - **scm-github is out of scope here by design:** it authenticates as the **GitHub App** (via
    `ghinstallation`), not a GCP SA — its `New` does not (and need not) take `option.ClientOption`. Its
    identity separation is the App installation, orthogonal to the per-seam GCP impersonation.
  - **Honest framing — demonstrable, NOT tenet-complete.** This removes the static CA key and the fused
    SAs (both real wins), but `tokenCreator` on the keybroker SA still lets the human operator
    *impersonate* it and thus **sign as the lineage CA** — i.e. the capability to forge lineage remains in
    human hands. That is the exact wall only Option B closes. Per CLAUDE.md's stance (a tenet deviation is
    a regression, not a trade-off), record this as a known residual of the local exit, not as "clean."
- **Option B (production end-state, closes the residual): in-cluster control-plane + keybroker.** Build
  the control-plane image + the separate keybroker image, deploy as distinct Deployments with distinct
  KSAs bound (Workload Identity) to the control-plane GSA and the keybroker GSA — so **no human can mint
  keybroker tokens**. The c7 CLI becomes a thin client of the in-cluster control plane (and the Web-CLI
  UI/API surface lands here — see Scope). The real §6.4 trust-tier separation; a large multi-PR effort.
  Required for the *defensible* posture; not required to *demonstrate* the exit if Option A is in place.
- **Acceptance for the exit:** the lineage CA signature is produced **via the keybroker SA** (not a
  static key, not the workload SA), verified in the evidence chain — **with the residual above recorded**.

### Phase F4 — the full (Vertex) exit run + B13
- Redeploy `console7-poc1` (CD; `CONSOLE7_REF` → the post-F0–F3 main), mirror the (signed) sandbox image + the (signed) auth-proxy image, set the **Vertex** env (`C7_INFERENCE=vertex`, region with Claude — e.g. `us-east5` + `claude-sonnet-4-5@…`, or `global` via the #1 fix + `claude-haiku-4-5@…`), per-seam SAs (F3).
- Run `c7 launch` → assert: engine on **Vertex** (via the auth-proxy; sandbox metadata-free) → KMS-signed commit → push → **real PR** → WORM verified, **with the keybroker SA as the signing identity** and **no static-CA-key grant** (the Option-A impersonation residual is recorded, not eliminated).
- Verify controls (signed commit, WORM chain, **egress/metadata deny including the auth-proxy hop**). **Destroy same day** — and either set the evidence module `force_destroy=true` for a clean teardown or accept the WORM orphan (decide; see lessons).
- **B13 true non-author walkthrough:** tonight was maintainer-as-operator. A genuine non-author following only `docs/RUNBOOK.md` (now updated with the GitHub App + the per-seam SA setup + the auth-proxy GSA/WI) is the remaining proof. Update the RUNBOOK with everything F1–F3 changed first.

---

## Durable lessons (bake into RUNBOOK / DESIGN / future work)

1. **The engine consumes Vertex auth via google-auth-library (ADC), never a pre-minted bearer env**, so the supported way to control it is the documented **gateway contract** (`ANTHROPIC_VERTEX_BASE_URL` + `CLAUDE_CODE_SKIP_VERTEX_AUTH=1` → the engine sends no Google credential, the gateway injects it). `CLOUDSDK_AUTH_ACCESS_TOKEN`/`GOOGLE_OAUTH_ACCESS_TOKEN` are NOT read by `google-auth-library-nodejs` (gcloud-only). **The gateway belongs in an own (trusted) pod with its own Workload Identity — NOT a sidecar in the untrusted sandbox pod** (a pod-level KSA leaks the identity to the engine), and **NOT inside Squid** (it can't add headers in a CONNECT/TLS tunnel without SSL-bump). The point of the design is that no GCP credential ever enters the metadata-free sandbox.
2. **A single local identity cannot hold the production identity split.** The control plane's components (secrets/keybroker/evidence) have deliberately distinct, scoped SAs; collapsing them into one ADC forces either a human holding the lineage CA or fused SAs — both tenet violations. Run with per-seam impersonation locally, or in-cluster.
3. **Credential delivery must gate pod readiness.** Inject (a bounded `kubectl exec`) cannot precede pod-Ready. The gate now lives at the top of `kubeEngineRunner.Run` (waits pod `Ready` + per-session proxy `Available`) — *not* in `Provision`, which returns straight after apply+annotate (so it never holds `p.mu` across the cold-scale wait).
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
