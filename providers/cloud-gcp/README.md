# `providers/cloud-gcp/` — reference `CloudProvider`

**Trust tier:** reference provider implementation.

Reference implementation of [`CloudProvider`](../../sdk/interfaces/cloud.go) on **GCP**:
sandbox isolation via **gVisor**, networking and the default-deny perimeter via **VPC
Service Controls** (`ARCHITECTURE.md` §5). Must uphold the interface's SECURITY
contracts — isolation at the syscall boundary, default-deny egress applied
out-of-band before the workload runs, irreversible ephemeral teardown.

> P0: placeholder — no implementation.
