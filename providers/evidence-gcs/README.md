# `providers/evidence-gcs/` — GCS-backed WORM evidence Store

**Trust tier:** reference provider implementation (runs in the Tier-1 control plane; holds no key
at rest).

Reference durable backing for the Console7 evidence log on **Google Cloud Storage**. It implements
[`control-plane/evidence.Store`](../../control-plane/evidence/store.go) — the narrow, append-only
persistence seam the real `EvidenceSink` commits hash-chained, sink-signed records through
(`ARCHITECTURE.md` §5; `DESIGN.md` §6). In-tree reference implementation; community providers live
out-of-tree against the published SDK.

> **Note on the seam.** `control-plane/evidence` already *is* the real `EvidenceSink` (append-only,
> hash-chained, checkpoint-signing, fail-closed). It owns the integrity layer and persists every
> sealed `Entry` through a `Store`. This package is that `Store` — the durable WORM backing — not a
> second `EvidenceSink`.

## What it upholds

- **Append-only / WORM — at two trust levels.** Each committed `Entry` is one GCS object at
  `<prefix>/<zero-padded-sequence>`.
  - *Against the append identity* (the workload SA: `create`/`get`/`list`, **no** `delete`): GCS
    requires `storage.objects.delete` to overwrite as well as to delete an object, so the append
    path can neither overwrite nor remove a committed record. The `DoesNotExist` precondition and
    the no-delete-path in the package are in-band defence-in-depth on top.
  - *Against a privileged actor* (the deploy identity can delete objects and remove an **unlocked**
    retention policy): the authoritative control is the bucket's **retention policy + lock**
    (`deploy/gcp/modules/evidence`) — the boundary control of record (GOAL.md tenet 3; tenet 7).
    The lock is **off by default**, so the shipped default is **tamper-evident** (the Sink's signed
    hash-chain detects mutation/truncation), **not tamper-resistant** against a privileged actor;
    **production must set `is_locked=true`**.
- **Integrity in both directions.** Every write carries a CRC32C the server verifies; every read
  re-verifies the bytes against the stored CRC32C — a corrupted record can neither be silently
  persisted nor silently returned.
- **Chain-hash-faithful codec.** Records are encoded with the two timestamps as explicit int64
  UnixNano (exactly what `chainHash` consumes), so a rehydrated log re-derives byte-identical
  hashes and `VerifyChain` passes.
- **Separate from the operational DB** and in the adopter's tenancy — evidence is never egressed to
  the maintainer (GOAL.md tenet 1).

## Architecture

```
EvidenceSink (integrity: hash-chain + signed checkpoints)   control-plane/evidence
  └─ evidence.Store  ← THIS package
        └─ objectIO port  ──► gcsObjectIO (cloud.google.com/go/storage)   gcs_gcp.go
                          └─► InMemoryObjectIO (fake, credential-free)     fakes.go
```

The GCS SDK is confined to `gcs_gcp.go` behind the `objectIO` port; all Store logic
(sequence→name, no-overwrite/no-gap, codec, count) runs against the fake in `go test ./...` with no
bucket and no credentials.

## Wiring

```go
store, err := evidencegcs.New(ctx, evidencegcs.Config{Bucket: "console7-evidence"})
if err != nil { /* ... */ }
defer store.Close()
sink := evidence.New(store, sinkSigner, caRoot, ckptEvery) // control-plane/evidence
```

`New` is the context-taking, erroring constructor a fallible durable backing needs: it pre-flights
connectivity and hydration so a GCS fault surfaces before the Store backs a Sink.

## Real vs deferred

| Property | This PR | Deferred / residual |
|---|---|---|
| Durable append-only record store | **real** (no-overwrite precondition, no-gap, CRC32C, hydration, fail-closed) | — |
| WORM vs the append identity | **real** (workload SA has no `delete`; GCS overwrite needs `delete`) | — |
| WORM vs a privileged actor (bucket-lock immutability) | retention policy authored; lock **optional** (`is_locked`, **default off** → tamper-evident only) | production sets the lock deliberately (irreversible) |
| Deploy-identity least-privilege | APPLY uses project-wide `roles/storage.admin` for bucket create | custom bucket-mgmt role (excl. `objects.*`) is a future tightening (already self-grant-capable via `projectIamAdmin`) |
| Durable checkpoint persistence | — | Sink checkpoints stay an in-memory parallel log; persisting them (closing tail-truncation durably) is a later hardening on this Store |
| SIEM forward (`EvidenceSink.Stream`) | — | a real adopter-SIEM webhook is a separate port in a later PR |

## Tests

- `go test ./providers/evidence-gcs/...` — white-box invariants (no-overwrite, no-gap, fail-closed,
  codec→chain-hash equivalence, hydration) + the end-to-end `VerifyChain` over the real Sink backed
  by this Store.
- `conformance/evidence_gcs_test.go` — the `EvidenceSink` contracts run against the real Sink backed
  by this Store, credential-free.
- `go test -tags evidence_gcs_integration ./providers/evidence-gcs/...` (opt-in, env-gated, never in
  CI) — live GCS create-if-absent / read / count + no-overwrite.

## Deploy

`deploy/gcp/modules/evidence` provisions the bucket (uniform access, public-access-prevention,
versioning, retention policy, optional lock) and a least-privilege custom role
(`storage.objects.create`/`get`/`list` only — no delete, no overwrite) bound to the workload SA at
bucket scope. It is instantiated from `deploy/gcp/main.tf`; the bucket name is surfaced as the root
output `evidence_bucket_name`.
