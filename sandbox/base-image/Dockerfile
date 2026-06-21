# syntax=docker/dockerfile:1
#
# Console7 sandbox base image — wraps the GENUINE, PINNED Claude Code engine (DESIGN.md §1.4;
# GOAL.md "what Console7 is not": orchestrate the engine, do not reimplement it). This image runs UNTRUSTED agent
# code, so it is a DISTINCT, separately-signed release artifact from the control-plane and
# key-broker images (DESIGN.md §8; ARCHITECTURE.md §6.4): "the thing that runs untrusted code must
# not share a build identity with the thing that holds the keys." It holds NO standing credential,
# runs as a non-root user, and refuses to start without its locked policy.

# ---- Stage 1: build the policyhelper renderer + the tripwire hook (Go) ----
# Pinned to the module's toolchain patch (go.mod `go 1.25.11`). Production SHOULD pin this and the
# runtime base below by DIGEST.
FROM golang:1.25.11-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# CGO off + trimpath for static, reproducible binaries.
RUN CGO_ENABLED=0 go build -trimpath -o /out/console7-policyhelper ./sandbox/policyhelper/cmd/policyhelper \
    && CGO_ENABLED=0 go build -trimpath -o /out/console7-tripwire ./sandbox/policyhelper/cmd/tripwire

# ---- Stage 2: the runtime (the wrapped engine) ----
FROM node:22-bookworm-slim AS runtime

# The genuine Claude Code engine, PINNED. Upgrades MUST be canaried before fleet rollout (DESIGN.md
# §1.4) — bump this deliberately, never float to latest. Production SHOULD additionally pin the
# base images above by digest.
ARG CLAUDE_CODE_VERSION=1.0.44
# DL3016: the engine is version-pinned (the load-bearing pin); its transitive npm tree is resolved
# at build without a lockfile. Vendoring a lockfile + generating an SBOM over it is part of the
# deferred signed-release pipeline (DESIGN.md §8) — tracked, not done here.
# hadolint ignore=DL3016
RUN npm install -g "@anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}" \
    && npm cache clean --force

# The non-root user the untrusted agent runs as. No sudo, no login shell, home is the ephemeral
# workspace. The locked-policy dirs are root-owned and NOT writable by this user (the in-image half
# of the "the agent cannot disable its own guards" lock; the out-of-band read-only mount is the
# authoritative half).
RUN groupadd --system --gid 65532 sandbox \
    && useradd --system --uid 65532 --gid sandbox --home-dir /workspace --shell /usr/sbin/nologin sandbox \
    && mkdir -p /workspace /etc/console7/hooks /etc/claude-code \
    && chown sandbox:sandbox /workspace \
    # Locked-policy dirs: owned root, GROUP sandbox, mode 2750 (setgid, no world bits). The agent
    # (group sandbox) traverses + reads via its group; root owns and writes, the agent never can.
    # setgid makes root-rendered files inherit group sandbox so the agent can read them.
    && chown root:sandbox /etc/console7 /etc/console7/hooks /etc/claude-code \
    && chmod 2750 /etc/console7 /etc/console7/hooks /etc/claude-code

COPY --from=build /out/console7-policyhelper /usr/local/bin/console7-policyhelper
COPY --from=build /out/console7-tripwire /usr/local/bin/console7-tripwire
COPY sandbox/base-image/entrypoint.sh /usr/local/bin/console7-entrypoint
RUN chmod 0555 /usr/local/bin/console7-policyhelper /usr/local/bin/console7-tripwire /usr/local/bin/console7-entrypoint

LABEL org.opencontainers.image.title="console7-sandbox-base" \
      org.opencontainers.image.description="Console7 sandbox base image: wraps the genuine, pinned Claude Code engine; runs untrusted agent code; distinct build/signing identity from the control-plane image." \
      org.opencontainers.image.source="https://github.com/console7/console7" \
      org.opencontainers.image.licenses="Apache-2.0" \
      dev.console7.trust-tier="data-plane-untrusted" \
      dev.console7.engine.version="${CLAUDE_CODE_VERSION}"

WORKDIR /workspace
USER sandbox
ENTRYPOINT ["/usr/local/bin/console7-entrypoint"]
