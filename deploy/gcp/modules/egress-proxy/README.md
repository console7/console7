# `modules/egress-proxy/` — the out-of-band forward proxy (Squid)

**Trust tier:** trusted infra (control side). Runs on the **non-sandbox control pool** (NAT egress);
no untrusted agent code runs here.

The **authoritative content-aware egress perimeter**. A NetworkPolicy is IP-based and cannot match
FQDNs, so the per-pod NetworkPolicy only pins a sandbox to **this proxy**; the proxy decides which
**FQDNs:port** a session may reach. It is the missing piece that makes both inference egress and the
non-allowlisted/metadata egress-deny tests real (rather than a vacuous deny-all).

## What's here (kubectl-applied, not Terraform)

`proxy.yaml` is a Kubernetes manifest — Namespace + Squid Deployment + Service + a default-deny
`squid.conf` ConfigMap — applied by the operator with `kubectl apply -f proxy.yaml`. It is kept
**out of Terraform** so the deploy stays google-provider-only, exactly like
[`modules/gke/reaper.yaml`](../gke/reaper.yaml).

- **Namespace `console7-egress-proxy`** carries `console7.dev/egress-proxy: "true"` — the label the
  sandbox NetworkPolicy's `namespaceSelector` (`providers/cloud-gcp`) selects as the **only**
  permitted egress destination. PSA `baseline`.
- **`squid.conf` is DEFAULT-DENY** (`http_access deny all`): it admits **nothing** — no maintainer
  destinations, adopter-composed only (`GOAL.md` tenet 1). The orchestrator injects the **per-session
  allowlist** ACLs above the deny line (B8).
- **Squid image is digest-pinned** (`ubuntu/squid@sha256:…`), content-addressed.
- It schedules on the control pool by virtue of the gVisor sandbox pool's **structural taint**
  (no `nodeSelector` needed).

## The two-layer sandbox→proxy path

| Layer | Control | Where |
|---|---|---|
| VPC firewall | sandbox-tag → pod range **:3128** ALLOW (priority 900, above the deny floor) | `modules/networking` (`egress_proxy_port`) |
| Pod NetworkPolicy | sandbox egress pinned to the `console7.dev/egress-proxy` namespace only | `providers/cloud-gcp` `renderNamespaceAndEgress` |
| Proxy ACL | per-session FQDN allowlist; default-deny | this module + the orchestrator (B8) |

Keep the port (**3128**) in sync across all three (`var.egress_proxy_port`, the NetworkPolicy, and
`providers/cloud-gcp` `proxyPort`).

## Deferred

- **The per-session allowlist injection** (the orchestrator composes the `host:port` ACLs and updates
  the proxy/ConfigMap; the sandbox is given the proxy IP + `HTTPS_PROXY`) is **B8**.
- **Reachability + the egress-deny proof** (non-allowlisted host and every metadata endpoint fail
  *through* the proxy; genuine inference succeeds) is the live **B11** integration test.
- **PSA `restricted`** for the proxy namespace, once the Squid image is confirmed to run non-root.
