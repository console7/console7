# `providers/cloud-gcp/` — reference `CloudProvider`

**Trust tier:** reference provider implementation.

Reference implementation of [`CloudProvider`](../../sdk/interfaces/cloud.go) on **GCP**:
sandbox isolation via **gVisor**, networking and the default-deny perimeter via **VPC
Service Controls** (`ARCHITECTURE.md` §5). Must uphold the interface's SECURITY
contracts — isolation at the syscall boundary, default-deny egress applied
out-of-band before the workload runs, irreversible ephemeral teardown.

The GCP egress realisation MUST make the wall **unbypassable** (see
[`sandbox/egress-proxy/`](../../sandbox/egress-proxy/) and `docs/THREAT-MODEL.md`):
no in-sandbox DNS for non-allowlisted names; VPC firewall / VPC-SC dropping direct TCP
to non-allowlisted destinations (not reliant on a proxy env var); **block the GCE
metadata server `169.254.169.254`** from the sandbox; and add no maintainer-controlled
hosts to the allowlist (`GOAL.md` tenet 1).

> P0: placeholder — no implementation.
