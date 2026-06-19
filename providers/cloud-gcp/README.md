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
- **Block every GCE metadata endpoint** from the sandbox — IPv4 `169.254.169.254`,
  IPv6 `fd20:ce::254`, and the DNS names `metadata.google.internal` **and the
  `metadata.goog` alias** — and, on GKE, the **node-local GKE metadata server at
  `169.254.169.252` (port 988)** used by Workload Identity. Enforce at the **node / pod
  network boundary**, not only a gateway hop: on GKE the metadata request is intercepted
  on-node and never leaves the VM, so a gateway-only block misses it.
- **Add no maintainer-controlled hosts to the allowlist** (`GOAL.md` tenet 1).

> P0: placeholder — no implementation.
