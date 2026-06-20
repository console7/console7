# `modules/networking` — default-deny egress perimeter (stub)

Stub. Filled by the **boundary-first** sandbox PR: VPC firewall / NAT default-deny
egress — the *authoritative* perimeter (`GOAL.md` tenet 3) — blocking all metadata /
IMDS endpoints, with per-pod NetworkPolicy routing to the egress proxy only. No
resources yet; this README reserves the partition so the boundary PR lands atomically.
