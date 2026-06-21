# `modules/gke` — gVisor sandbox cluster + Workload Identity + NAT

The compute substrate for the per-session sandboxes: a hardened regional GKE cluster, a
**gVisor (sandboxed)** node pool for the ephemeral sandbox pods, a separate control-plane
node pool, the Workload-Identity binding the control plane impersonates the `modules/secrets`
SA through, and the Cloud Router + NAT that gives the **sanctioned** (non-sandbox-tagged)
egress path its outbound route (deferred here from `modules/networking`, PR-1). It is the
compute half of the boundary the networking module's default-deny egress wall established.

**Two load-bearing security properties, preflighted by `providers/cloud-gcp` `New()`** (a
misconfigured cluster fails closed at provider construction):

1. **`GKE_METADATA` mode (Workload Identity) on every node pool.** The GKE metadata server
   conceals the node service account, serving only WI tokens for a pod's bound KSA. Sandbox
   pods are bound to **no** KSA (and run `automountServiceAccountToken: false`), so they get no
   token. This — **not** "disable Workload Identity" — is the authoritative metadata block:
   disabling WI leaves `GCE_METADATA`, which *exposes* the node SA token, the standing
   credential a prompt-injected sandbox could mint. A VPC firewall cannot block the node-local
   metadata path, so it is a node-config control.
2. **Dataplane V2 (`ADVANCED_DATAPATH`)** so the sandbox's per-session egress NetworkPolicy is
   actually enforced (an unenforced CNI makes the perimeter silently inert).

The **sandbox node pool carries `var.sandbox_node_tag`** so the networking module's default-deny
egress firewall applies to it; the control-plane pool does not, so it keeps NAT egress.

**Hardening:** private nodes, master-authorized-networks-scoped control-plane endpoint, shielded
nodes (secure boot + integrity monitoring), a dedicated least-privilege node SA (not the default
Compute SA), legacy-endpoints/ABAC off, release-channel auto-upgrade.

**String-exact outputs** (`cluster_name`, `cluster_location`, `sandbox_node_pool`) feed
`providers/cloud-gcp` `Config.{Cluster,Location,NodePool}` verbatim.

> **Gating precondition (operability).** `gke_master_authorized_cidrs` defaults to **empty =
> fail-closed**: the control-plane endpoint is unreachable from outside Google's network, so the
> cluster **applies** but is **unadministrable** (the keyless CD's `kubectl apply -f reaper.yaml`
> and the provider's `gcloud … get-credentials` are refused) until you add the CD/operator egress
> range. This is deliberate (secure by default), not a bug — but the deploy is inert for external
> operators until that CIDR is supplied.

> **Residual deferred to PR-3 (sandbox base-image).** `GKE_METADATA` conceals the node SA for
> normal pods, but a pod requesting **`hostNetwork: true`** reaches the node-local metadata server
> via the host netns and bypasses concealment. The `cloud-gcp` pod manifest correctly never sets
> hostNetwork (and runs `automountServiceAccountToken: false`), but nothing here enforces it at
> admission. A **Pod Security Admission `restricted`** label on the sandbox namespaces (forbids
> hostNetwork/privileged) is the structural control; it rides with the sandbox base-image work
> (the namespace is rendered by `cloud-gcp`). Until then, the no-standing-credential guarantee
> rests on the renderer not setting hostNetwork — in-band, per tenet 3 a defence-in-depth layer,
> not the boundary.

## The namespace-TTL reaper

`reaper.yaml` is the CronJob + RBAC that enforces the **absolute** session deadline: it deletes
`console7`-managed sandbox namespaces whose `console7.dev/expires-at` annotation (stamped by the
provider at provision) has passed. The pod's `activeDeadlineSeconds` is only a pod-StartTime-
relative backstop; this reaper is the authoritative absolute-deadline enforcement. It is a
Kubernetes workload, applied by the operator/bootstrap via `kubectl apply -f reaper.yaml` (kept
out of Terraform so the deploy stays google-provider-only and the apply identity needs no cluster
credentials).
