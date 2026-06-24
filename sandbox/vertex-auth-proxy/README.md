# `sandbox/vertex-auth-proxy/` — the Vertex credential-attaching auth-proxy

**Trust tier:** data plane — **credentialed**. This artifact **holds a Vertex credential**: it attaches
a Google `cloud-platform` access token to every forwarded request. It is therefore a **CONTROL-side /
credentialed data-plane** artifact, with a **distinct build and signing identity** from the **untrusted**
sandbox base image (`ARCHITECTURE.md` §6.4; `DESIGN.md` §8) — *the thing that holds the keys must not
share a build identity with the thing that runs untrusted code*. It ships as a **distinct,
separately-signed image** (`.github/workflows/auth-proxy-image-release.yml`), never fused with
`sandbox/base-image`, and runs as a **separate per-session pod** (NOT a sandbox sidecar — a sidecar would
share the sandbox pod and expose the delivered bearer to the untrusted engine).

## Why this exists

The pinned Claude Code engine (`@1.0.44`) honours the LLM-gateway contract. With

```
CLAUDE_CODE_SKIP_VERTEX_AUTH=1
ANTHROPIC_VERTEX_BASE_URL=http://<this-proxy>
```

the engine sends its Vertex requests to `<this-proxy>` with **no Google `Authorization` header**, at

```
/projects/{project}/locations/{region}/publishers/anthropic/models/{model}:rawPredict
/projects/{project}/locations/{region}/publishers/anthropic/models/{model}:streamRawPredict
```

— model verbatim, and **critically, with no `/v1` prefix** (the engine only adds `/v1` for its
built-in `https://{region}-aiplatform.googleapis.com/v1` host; under a base-URL override it omits it).
The real Vertex host serves under `/v1` and requires a Google bearer. This proxy closes that gap: it
**validates the request is a permitted (pinned) anthropic predict call, prepends `/v1`, attaches a Google
bearer, and streams** the response back (SSE for `:streamRawPredict` is not buffered).

This is the *currency* fix for the live-run finding **R-V1**: engine `1.0.44` ignores
`CLOUDSDK_AUTH_ACCESS_TOKEN`, so a credential cannot be injected into the engine directly — a gateway
auth-proxy is the verified path.

## Where the bearer comes from (deployment modes)

- **PRIMARY — delivered-file (what this repo runs):** `deploy/` is google-provider-only with **no
  persistent in-cluster workload** (the control plane runs locally; only per-session sandbox + Squid are
  in-cluster). So this proxy holds **no Workload Identity**. The control plane **mints** the short-lived
  Vertex bearer (workload-SA self-impersonation, the existing `InjectInferenceCredential` seam) and
  **delivers** it (per session) into this pod's token file at `C7_AUTHPROXY_BEARER_FILE`. `fileTokenSource`
  re-reads that file **per request** (so a re-delivered/rotated token is picked up), never caches, and
  **fails closed** on a missing/empty file.
- **SECONDARY — ambient ADC:** if `C7_AUTHPROXY_BEARER_FILE` is unset, the proxy uses the pod's own
  Workload Identity via the metadata server. Kept for a **future** persistent/shared deployment that does
  not yet exist in this repo.

The proxy carries **no** static credential; the effective authority is bounded by **(a)** the IAM role on
the minting SA (least privilege — bind only the Vertex predict role; **F2b**) **and (b)** the request
**pin** below.

## Security invariants

- **Pin (anti-open-relay):** only an `anthropic`-publisher Vertex **predict** call (`rawPredict` /
  `streamRawPredict`) for the configured **project/region/model** is forwarded; anything else is **404**'d
  with the bearer **never attached**. So even though the credential-free sandbox can reach this proxy, it
  cannot use the org bearer for arbitrary Vertex APIs.
- **Fail closed:** no token available ⇒ **503**, forward **nothing** (never unauthenticated).
- **Adds nothing of its own:** uses `ReverseProxy.Rewrite` (not `Director`), so no `X-Forwarded-For` is
  added; strips any inbound forwarding headers; overwrites any inbound `Authorization`.
- **No leakage:** never logs token material, request/response bodies, or request-derived paths. Bounded
  connect + response-header timeouts (the stream body stays unbounded for SSE).

## What's here

- **`proxy.go`** — the testable handler: `requestPin.allow` (the pin), `withV1Prefix`, `resolveUpstream`,
  `fileTokenSource` + `selectTokenSource`, and the streaming `ReverseProxy` wiring.
- **`main.go`** — the thin process: read env, resolve upstream, select the token source, build the pin, serve.
- **`proxy_test.go`** — hermetic tests (httptest, fake token source; **no network, no GCP**): the `/v1`
  prefix, the injected `Authorization: Bearer …`, method/body/header preservation, the **fail-closed
  503-no-forward** invariant, the **pin reject (404, never forwarded)**, no-`X-Forwarded-For`, and the
  delivered-file token source (incl. rotation).
- **`Dockerfile`** — two-stage: static Go build → **distroless static** (digest-pinned), **non-root uid
  65532**, OCI labels incl. `dev.console7.trust-tier=data-plane-credentialed`.

## Configuration (environment)

| Env | Meaning | Default |
|---|---|---|
| `C7_AUTHPROXY_LISTEN` | listen address | `:8080` |
| `CLOUD_ML_REGION` | Vertex region → `https://{region}-aiplatform.googleapis.com`; `global` → `https://aiplatform.googleapis.com` | required (unless override) |
| `C7_AUTHPROXY_UPSTREAM` | explicit upstream override (absolute **https** URL; scheme+host only) | — |
| `C7_AUTHPROXY_BEARER_FILE` | path to the control-plane-delivered bearer file; **set ⇒ delivered-file mode**, unset ⇒ ambient ADC | — |
| `C7_AUTHPROXY_PROJECT` | pin: only forward predict calls for this Vertex project | `""` = any |
| `C7_AUTHPROXY_MODEL` | pin: only forward predict calls for this model | `""` = any anthropic model |

(The region pin is always applied from `CLOUD_ML_REGION`; the request **shape** + `anthropic` publisher +
predict verb are always enforced regardless of the optional project/model pins.)

## Build & verify

```bash
docker build -f sandbox/vertex-auth-proxy/Dockerfile -t console7-vertex-auth-proxy .
# Verify a published, digest-pinned image was signed by the pinned release identity:
scripts/verify-auth-proxy-image.sh ghcr.io/console7/vertex-auth-proxy@sha256:...
```

The release is **keyless-signed** (GitHub Actions OIDC → Sigstore/Fulcio); the verify script and the
release workflow share the pinned identity/issuer anchors. An adopter mirrors the **verified,
digest-pinned** image into their own in-tenancy Artifact Registry before use (no runtime maintainer
path; `GOAL.md` tenet 1).

## Not wired here (follow-ups)

This artifact is **not yet wired into a session** — that is **F2c**:

- **F2c (wiring):** render the per-session auth-proxy Deployment alongside Squid; **redirect** the minted
  Vertex bearer delivery to this pod (not the sandbox); set the engine env
  (`CLAUDE_CODE_SKIP_VERTEX_AUTH=1`, `ANTHROPIC_VERTEX_BASE_URL`=this proxy, **`NO_PROXY`** for it so the
  engine reaches it directly rather than via Squid); add the **sandbox→proxy** and **proxy→Vertex**
  NetworkPolicies (the proxy needs its own egress to the Vertex host); lock out `gcpAuthRefresh` in
  `policyHelper`.
- **F2b (deploy):** ensure the minting (workload) SA holds **only** the least-privilege Vertex predict
  role (`aiplatform.endpoints.predict`).
