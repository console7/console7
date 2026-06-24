# syntax=docker/dockerfile:1
#
# Console7 Vertex auth-proxy image — a tiny reverse proxy that bridges the
# CREDENTIAL-FREE sandbox to a real Vertex AI host: it adds the `/v1` path prefix the
# pinned Claude Code engine omits under an ANTHROPIC_VERTEX_BASE_URL override, and
# attaches a Google bearer minted from the POD's OWN ambient Workload Identity.
#
# TRUST TIER (ARCHITECTURE.md §6.4; DESIGN.md §8): this artifact HOLDS A CREDENTIAL (it
# mints + attaches a cloud-platform Google token), so it is a CONTROL-side /
# credentialed data-plane artifact and is a DISTINCT, separately-signed image from the
# untrusted sandbox base image — "the thing that holds the keys must not share a build
# identity with the thing that runs untrusted code." It is wired in as a per-session
# sidecar so the sandbox itself stays metadata-/credential-free; the egress wall sends
# only the sandbox's Vertex traffic to this proxy (F2c wiring; F2b deploy GSA/WI/role).

# ---- Stage 1: build the static Go binary ----
# Pinned to the module toolchain (go.mod `go 1.25.11`) AND by DIGEST (content-addressed
# so the tag cannot be moved under us). Bump the tag and the digest together; the
# signed-release pipeline (.github/workflows/auth-proxy-image-release.yml) publishes/attests.
FROM golang:1.25.11-bookworm@sha256:bbb255b0e131db500cf0520adc97441d2260cf629c7fa7e39e025ddf53995a24 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# CGO off + trimpath for a static, reproducible binary.
RUN CGO_ENABLED=0 go build -trimpath -o /out/console7-vertex-auth-proxy ./sandbox/vertex-auth-proxy

# ---- Stage 2: the runtime (distroless static, non-root) ----
# Distroless static is digest-pinned alongside the tag (bump both together). It ships a
# nonroot (uid 65532) user and CA certs (needed for the TLS dial to the real Vertex
# host and to the metadata server's token endpoint), and nothing else — no shell, no
# package manager, minimal attack surface for a credentialed component.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:d093aa3e30dbadd3efe1310db061a14da60299baff8450a17fe0ccc514a16639 AS runtime

COPY --from=build /out/console7-vertex-auth-proxy /usr/local/bin/console7-vertex-auth-proxy

LABEL org.opencontainers.image.title="console7-vertex-auth-proxy" \
      org.opencontainers.image.description="Console7 Vertex auth-proxy: adds the /v1 prefix the engine omits under a base-URL override and attaches a Google bearer from the pod's own Workload Identity; HOLDS a Vertex credential, so a distinct build/signing identity from the untrusted sandbox base image." \
      org.opencontainers.image.source="https://github.com/console7/console7" \
      org.opencontainers.image.licenses="Apache-2.0" \
      dev.console7.trust-tier="data-plane-credentialed"

# Non-root (the distroless nonroot user is uid:gid 65532:65532). Read-only-friendly:
# the binary needs no writable filesystem at runtime.
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/console7-vertex-auth-proxy"]
