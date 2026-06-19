# `providers/cloud-gcp/` — reference `CloudProvider`

**Trust tier:** reference provider implementation.

Reference implementation of [`CloudProvider`](../../sdk/interfaces/cloud.go) on **GCP**:
sandbox isolation via **gVisor**; arbitrary-egress default-deny via **VPC firewall
rules** (egress routed through NAT / a forward proxy), with **VPC Service Controls**
layered on top to guard the **Google API** surface (`ARCHITECTURE.md` §5). Must uphold
the interface's SECURITY contracts — isolation at the syscall boundary, default-deny
egress applied out-of-band before the workload runs, irreversible ephemeral teardown.

The GCP egress realisation MUST make the wall **unbypassable** (see
[`sandbox/egress-proxy/`](../../sandbox/egress-proxy/) and `docs/THREAT-MODEL.md`):

- **No in-sandbox DNS for non-allowlisted names.**
- **VPC firewall — not VPC-SC — drops arbitrary egress.** Direct TCP to any
  non-allowlisted destination MUST be dropped by VPC firewall / NAT / forward-proxy
  routing, never reliant on a proxy env var. VPC Service Controls constrains supported
  **Google Cloud APIs** only and does **not** block raw TCP/HTTPS to third-party
  internet hosts; treating VPC-SC as the arbitrary-egress control leaves a bypass.
- **Scope egress enforcement per sandbox, not per node.** VPC firewall rules target by
  service account / network tag at the **node** level, so two sandbox pods with
  different allowlists sharing a GKE node would share egress — one sandbox inheriting
  another's allowlist violates the per-session `EgressPolicy`. The default MUST require
  **isolated node placement or pod-level egress enforcement** (e.g. per-pod
  NetworkPolicy / egress sidecar) in addition to the VPC firewall.
- **Block every GCE metadata endpoint** from the sandbox — IPv4 `169.254.169.254`,
  IPv6 `fd20:ce::254`, and the DNS names `metadata.google.internal` **and the
  `metadata.goog` alias** — and, on GKE, the **node-local GKE metadata server at
  `169.254.169.252` (ports 988 and 987; older clusters use `127.0.0.1` on those
  ports)** used by Workload Identity. Enforce at the **node / pod network boundary**,
  not only a gateway hop: on GKE the metadata request is intercepted on-node and never
  leaves the VM, so a gateway-only block misses it.
- **Add no maintainer-controlled hosts to the allowlist** (`GOAL.md` tenet 1).

> P0: placeholder — no implementation.
