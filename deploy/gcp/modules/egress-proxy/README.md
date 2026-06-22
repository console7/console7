# `modules/egress-proxy/` — the out-of-band forward proxy (Squid)

**Trust tier:** trusted infra (control side). Runs on the **non-sandbox control pool** (NAT egress);
no untrusted agent code runs here.

The **authoritative content-aware egress perimeter**. A NetworkPolicy is IP-based and cannot match
FQDNs, so the per-pod NetworkPolicy only pins a sandbox to **its proxy**; the proxy decides which
**FQDNs:port** a session may reach. It is the missing piece that makes both inference egress and the
non-allowlisted/metadata egress-deny tests real (rather than a vacuous deny-all).

## Per-session, not shared — and rendered in code

The authoritative runtime proxy is **rendered per session by the `CloudProvider`**
([`providers/cloud-gcp/kube_exec.go`](../../../../providers/cloud-gcp/kube_exec.go):
`renderPerSessionProxy` / `renderSquidConf`), **not** applied from a static manifest. Each session
gets **its own** Squid in **its own `<session-id>-proxy` namespace**, created by `EgressController.Set`
before the sandbox pod and torn down with the session by `Clear`.

This resolves three things a single shared proxy could not (the B7→B8 decision):

- **Source isolation (tenet 4 / scope-follows-artefact).** A shared Squid with `dstdomain`-only
  allows would admit each session's hosts to **every** client on the listener — a cluster-wide
  **union** of allowlists. A proxy that serves exactly one sandbox makes the discriminator
  **structural**: the sandbox NetworkPolicy pins egress to the per-session
  `console7.dev/proxy-for: <id>` label, and the proxy's own ingress NetworkPolicy admits only the
  matching `console7.dev/session: <id>` namespace.
- **Config reload.** `squid.conf` is subPath-mounted (frozen at pod creation). A narrow re-renders
  the config, changes its `console7.dev/squid-config-hash` pod-template annotation, and **rolls** a
  fresh Squid pod with the new ACLs — no in-place ConfigMap edit, no SIGHUP sidecar.
- **Blast radius.** A proxy failure or node drain severs egress for **one** session (fail-*safe* —
  egress denies, never opens), not the whole data plane.

## What's here

[`proxy.yaml`](./proxy.yaml) is the **operator-inspectable reference** of the hardened single-proxy
shape (Namespace + Squid Deployment + Service + default-deny `squid.conf`). It is **NOT applied as a
shared proxy** — it documents the shape the per-session renderer produces, and the **digest-pinned
`ubuntu/squid` image** an adopter may mirror into their in-tenancy Artifact Registry. The same
hardening (non-root uid 65532, read-only root FS, dropped caps, RuntimeDefault seccomp, PSA
`restricted`, readiness gate) is applied in the rendered per-session proxy.

## The two-layer sandbox→proxy path (per session)

| Layer | Control | Where |
|---|---|---|
| VPC firewall | sandbox-tag → pod range **:3128** ALLOW (priority 900, above the deny floor) | `modules/networking` (`egress_proxy_port`) |
| Pod NetworkPolicy | sandbox egress pinned to **its own** `console7.dev/proxy-for: <id>` proxy namespace | `providers/cloud-gcp` `renderNamespaceAndEgress` |
| Proxy ingress | per-session proxy admits **only** its `console7.dev/session: <id>` sandbox namespace | `providers/cloud-gcp` `renderPerSessionProxy` |
| Proxy ACL | per-session FQDN allowlist as Squid host:port allows over a deny-all floor | `providers/cloud-gcp` `renderSquidConf` |

The per-session proxy pods sit in the pod CIDR, so the existing VPC ALLOW rule (sandbox-tag → pod
range:3128) already covers them — **no networking change**. Keep the port (**3128**) in sync across
`var.egress_proxy_port`, the NetworkPolicy, and `providers/cloud-gcp` `proxyPort`.

## Deferred (to B11, the live integration proof)

- **Reachability + the egress-deny proof** — that a non-allowlisted host and **every** metadata
  endpoint fail *through* the proxy while genuine inference succeeds — is the live **B11** test
  (`providers/cloud-gcp/integration_test.go`, `//go:build cloud_gcp_integration`). B11 also adds the
  pod-readiness gate (wait for both the sandbox pod and its proxy Deployment before the first exec).
- **HA within a session** is intentionally single-replica: the proxy is as ephemeral as its one
  session, so there is no cross-session availability to protect (a shared multi-replica proxy is the
  thing this design deliberately removed).
