# `deploy/` — reference deployment

**Trust tier:** deployment scaffolding (deploys into the **adopter's** tenancy;
maintainer runs nothing — `GOAL.md` tenet 1).

Reference **Kubernetes / Helm / Terraform** for standing Console7 up in the adopter's
cloud (`ARCHITECTURE.md` §4, §6.3): control-plane services as a small hardened
namespace; sandboxes as gVisor-isolated pods or microVMs, short-lived and
network-policied **to the egress proxy only**. The cloud-specific pieces (sandbox
isolation, egress perimeter, secrets/KMS, workload identity) sit behind the provider
interfaces so AWS and Azure are parity targets, not rewrites.

**Resilience is an adopter choice, exposed as configuration** — single-region,
multi-region active-active, and an optional isolated break-glass instance are
deployment options; Console7's requirement is to be *deployable* HA, the posture is
the adopter's (`ARCHITECTURE.md` §4).

The distinct trust tiers deploy as **distinct, separately-signed artifacts** —
control-plane image, key-broker/signing image, sandbox base image — and **MUST NOT**
be fused (`ARCHITECTURE.md` §6.4).

The **adoption & deployment model** — how adopters consume Console7 by pinned
reference, refresh by reviewed version bump, and deploy keyless with no runtime
phone-home — is recorded in [`docs/adr/0002-adoption-deployment-model.md`](../docs/adr/0002-adoption-deployment-model.md).
This subtree is **partitioned by target** (e.g. `deploy/gcp/`) so parallel targets
do not collide.

> P0 scaffolding: directory + responsibilities only — **no manifests, no real config,
> no secrets.**
