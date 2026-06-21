# `modules/networking` — default-deny egress perimeter (static floor)

The **authoritative** network control of record (`DESIGN.md` §5.2; `GOAL.md` tenet 3):
the static, always-on default-deny egress floor the ephemeral sandboxes run inside. It
lands **boundary-first** (`ROADMAP.md` sequencing #2) — the wall exists before any sandbox
node pool (`modules/gke`) or per-session egress proxy, so a sandbox is default-deny from
the moment it can run.

**Owns (the static DENY floor):** a custom-mode VPC + sandbox subnet (primary + pod/service
secondary ranges, VPC flow logs, private Google access); an **EGRESS default-DENY** firewall
rule scoped to the sandbox node tag; and an explicit **metadata/IMDS deny** for the *routed*
IP endpoints (IPv4 `169.254.169.254`, GKE node-local `169.254.169.252`, IPv6 `fd20:ce::254`)
as one layer of defence-in-depth with a distinct logged signal.

**Deliberately deferred** (each is an ALLOW/escape path or needs the cluster, so it lands
with the thing it serves — `modules/gke` + `providers/cloud-gcp`, PR-2; base image, PR-3):

- the **sanctioned egress path** — Cloud Router + NAT and the narrow ALLOW rules to the
  egress proxy / Google APIs. NAT is SNAT for *permitted* flows; landing it here, where the
  only routable range is the sandbox's own (which is denied), would point translation at the
  ranges the floor denies and rest the guarantee on tag fidelity. It lands with the
  non-sandbox subnet/proxy that legitimately needs it.
- the **per-session egress allowlist** (dynamic; programmed at the out-of-band proxy by the
  orchestrator's `ApplyEgressPolicy` narrow step);
- the **per-pod NetworkPolicy** routing sandbox pods to the proxy only, and the
  **authoritative node-level metadata block**: on GKE the node-local metadata server is
  intercepted on the VM (incl. the legacy `127.0.0.1:988/987` Workload-Identity path, which a
  VPC firewall structurally **cannot** match) and never reaches the VPC, so the real sandbox
  metadata block is *no Workload Identity on the sandbox node pool*. The IP-deny here is the
  VPC-dataplane **layer** of that defence-in-depth, not the whole of it.
- the **DNS legs** — in-sandbox "no arbitrary resolver" (base image) and the metadata DNS
  names `metadata.google.internal` / `metadata.goog`. A VPC firewall is IP-based and cannot
  match names; here those names are covered only transitively (they resolve to the IPs the
  deny drops).

The IPv6 entries (`fd20:ce::254/128`, `::/0`) are **inert on this IPv4-only subnet** — accepted
by the firewall API but matching no traffic — and future-proof the floor for a dual-stack node
pool. The firewall rules target `var.sandbox_node_tag`, which no instance carries until
`modules/gke` creates the sandbox node pool with that tag — the reserved floor, applied the
instant the tagged nodes appear. Nothing here grants egress.
