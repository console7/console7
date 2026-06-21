# `modules/networking` — default-deny egress perimeter (static floor)

The **authoritative** network control of record (`DESIGN.md` §5.2; `GOAL.md` tenet 3):
the static, always-on default-deny egress floor the ephemeral sandboxes run inside. It
lands **boundary-first** (`ROADMAP.md` sequencing #2) — the wall exists before any sandbox
node pool (`modules/gke`) or per-session egress proxy, so a sandbox is default-deny from
the moment it can run.

**Owns (the static DENY floor):** enabling the Compute Engine API; a custom-mode VPC +
sandbox subnet (primary + pod/service secondary ranges, VPC flow logs, private Google
access); and a single **effective EGRESS default-DENY** firewall rule (IPv4) scoped to the
sandbox node tag (overrides GCP's implied allow-egress at priority 65535), logged so every
denied attempt is visible.

**Deliberately deferred** (each is an ALLOW/escape path, needs the cluster, or *cannot be
enforced at the VPC layer at all*, so it lands with the thing that can actually enforce it —
`modules/gke` + `providers/cloud-gcp`, PR-2; base image, PR-3):

- the **sanctioned egress path** — Cloud Router + NAT and the narrow ALLOW rules to the
  egress proxy / Google APIs. NAT is SNAT for *permitted* flows; landing it here, where the
  only routable range is the sandbox's own (denied) range, would point translation at the
  ranges the floor denies and rest the guarantee on tag fidelity.
- the **per-session egress allowlist** (dynamic; programmed at the out-of-band proxy by the
  orchestrator's `ApplyEgressPolicy` narrow step) and the **per-pod NetworkPolicy**.
- the **metadata / IMDS block** — and this is explicitly **not** a VPC firewall control: GCP
  documents VM-to-metadata-server traffic (`169.254.169.254` and the link-local GKE metadata
  server) as **always allowed and not subject to VPC firewall rules**, so a firewall "deny" to
  those ranges would neither block the traffic nor log it. The authoritative block is a
  **node/pod-config** control — *no Workload Identity on the sandbox node pool* + GKE metadata
  concealment (`modules/gke`) — plus the legacy `127.0.0.1:988/987` path and the metadata DNS
  names (`metadata.google.internal` / `metadata.goog`), none of which a VPC firewall can match.
  PR-1 does not pretend to enforce metadata at the VPC.
- **IPv6 egress denial** — this subnet is single-stack IPv4 and a VPC firewall rule cannot mix
  IP families, so the IPv6 catch-all (`::/0`) lands as its own rule when `modules/gke` makes the
  node pool dual-stack. On an IPv4-only subnet there is no IPv6 egress path to deny.
- the **in-sandbox DNS** leg — the base image ships the sandbox no general resolver (PR-3).

The firewall rule targets `var.sandbox_node_tag`, which no instance carries until `modules/gke`
creates the sandbox node pool with that tag — the reserved floor, applied the instant the tagged
nodes appear. Nothing here grants egress.
