# `sandbox/vertex-auth-proxy/` — the Vertex credential-attaching auth-proxy

**Trust tier:** data plane — **credentialed**. This artifact **holds a Vertex credential**: it mints
and attaches a Google `cloud-platform` access token (from the pod's **own** ambient Workload
Identity) to every forwarded request. It is therefore a **CONTROL-side / credentialed data-plane**
artifact, with a **distinct build and signing identity** from the **untrusted** sandbox base image
(`ARCHITECTURE.md` §6.4; `DESIGN.md` §8) — *the thing that holds the keys must not share a build
identity with the thing that runs untrusted code*. It ships as a **distinct, separately-signed
image** (`.github/workflows/auth-proxy-image-release.yml`), never fused with `sandbox/base-image`.

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
built-in `https://{region}-aiplatform.googleapis.com/v1` host; under a base-URL override it omits
it). The real Vertex host serves under `/v1` and requires a Google bearer. This proxy closes that
gap: it **accepts the credential-free request, prepends `/v1`, attaches a freshly-minted Google
bearer, and streams** the response back (SSE for `:streamRawPredict` is not buffered).

This is the *currency* fix for the live-run finding **R-V1**: engine `1.0.44` ignores
`CLOUDSDK_AUTH_ACCESS_TOKEN`, so a credential cannot be injected into the engine directly — a sidecar
auth-proxy is the verified path.

## What's here

- **`proxy.go`** — the testable handler. Mints a token **first** and **fails closed** (HTTP **503**,
  forwards **nothing**) if no valid token is available; never forwards unauthenticated; never logs
  token material or bodies. `resolveUpstream` derives the upstream Vertex host from config;
  `withV1Prefix` adds the prefix idempotently; the forward uses a streaming `httputil.ReverseProxy`.
- **`main.go`** — the thin process: read config from env, build the **ambient ADC** token source
  (`golang.org/x/oauth2/google.DefaultTokenSource`, which caches+refreshes), serve.
- **`proxy_test.go`** — hermetic tests (httptest, a fake token source; **no network, no GCP**)
  asserting the `/v1` prefix, the injected `Authorization: Bearer …`, method/body/header
  preservation, and the **fail-closed 503-no-forward** invariant.
- **`Dockerfile`** — two-stage: static Go build → **distroless static** (digest-pinned), **non-root
  uid 65532**, read-only-friendly, OCI labels incl. `dev.console7.trust-tier=data-plane-credentialed`.

## Configuration (environment)

| Env | Meaning | Default |
|---|---|---|
| `C7_AUTHPROXY_LISTEN` | listen address | `:8080` |
| `CLOUD_ML_REGION` | Vertex region → `https://{region}-aiplatform.googleapis.com`; `global` → `https://aiplatform.googleapis.com` | required (unless override) |
| `C7_AUTHPROXY_UPSTREAM` | explicit upstream override (must be an absolute **https** URL); scheme+host only | — |

The bearer is minted from **ambient ADC** — the pod's own Workload Identity via the metadata server.
The proxy carries **no** static credential; the effective authority is bounded by the **GSA/WI IAM
role** bound at deploy time (least privilege — bind only the Vertex predict role).

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

This task (**F2a**) is the **artifact only** — it is **not wired into anything**:

- **F2c (wiring):** the engine env (`CLAUDE_CODE_SKIP_VERTEX_AUTH`, `ANTHROPIC_VERTEX_BASE_URL`),
  the egress-wall `NetworkPolicy`/`NO_PROXY` so only the sandbox's Vertex traffic reaches this
  sidecar, and the per-session sidecar topology.
- **F2b (deploy):** the GSA, the Workload Identity binding, and the least-privilege Vertex IAM role
  this proxy's ADC mints against.
