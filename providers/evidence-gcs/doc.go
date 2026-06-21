// Package evidencegcs is the Console7 reference durable backing for the WORM evidence
// log on Google Cloud Storage (ARCHITECTURE.md §5; DESIGN.md §6). It implements the
// control-plane/evidence.Store seam — the narrow, append-only persistence port the real
// EvidenceSink (control-plane/evidence) commits hash-chained, sink-signed records through.
// It is an in-tree reference implementation; community providers live out-of-tree against
// the published SDK.
//
// # Where it sits
//
// The EvidenceSink (control-plane/evidence) already owns the integrity layer: it stamps the
// authoritative AppendedAt, hash-chains each record, signs checkpoints through the keybroker,
// and fails closed. It holds NO durability of its own — it persists every sealed Entry through
// a control-plane/evidence.Store. This package is the production Store: a GCS bucket whose
// immutability is enforced at the storage layer by a retention policy + (optionally) a bucket
// lock. The hash-chain is integrity ON TOP; the bucket-lock is durability/immutability UNDER it.
//
//	Sink (integrity: chain + checkpoints + signing)  — control-plane/evidence
//	  └─ Store (durable, append-only WORM)            — THIS package, over GCS
//
// # Sequence → object mapping (the append-only contract over GCS)
//
// Each committed Entry is ONE GCS object named "<prefix>/<zero-padded-sequence>" (fixed width,
// so lexical listing order equals numeric order). The contract Store.Append requires — commit
// at exactly the next slot, never a gap, never a rewrite — is realised structurally:
//
//   - NO REWRITE: the object is written with a DoesNotExist precondition (ifGenerationMatch=0),
//     so a write to an already-occupied slot fails atomically server-side, independent of any
//     in-memory count. This is the WORM property that matters: committed history cannot be
//     overwritten even by a buggy or racing writer.
//   - NO GAP: Append requires the immediate predecessor object to exist (for sequence>0). With
//     the no-rewrite precondition this yields exactly next-slot semantics (sequence == count)
//     without an O(n) listing on the append path.
//
// There is deliberately NO delete and NO overwrite path anywhere in this package, mirroring the
// memStore the seam ships with.
//
// # Who can mutate the log — the two trust levels (read this for the real WORM posture)
//
// "WORM" here is a layered guarantee, and what holds depends on WHO the adversary is:
//
//   - The APPEND identity (the workload SA) is granted object create/get/list ONLY. GCS requires
//     storage.objects.delete to OVERWRITE an existing object as well as to delete one, so the
//     append path can neither overwrite nor remove a committed record — append-only WORM holds
//     against the writer by IAM, plus the DoesNotExist precondition as in-band defence-in-depth.
//   - A PRIVILEGED actor — notably the deploy/Terraform identity, which holds bucket-admin and
//     can delete objects and REMOVE an unlocked retention policy — is held back ONLY by the
//     bucket's retention policy + LOCK (deploy/gcp/modules/evidence). That lock is the
//     authoritative boundary control (GOAL.md tenet 3; the immutable-evidence success criterion,
//     tenet 7). It is OFF BY DEFAULT (so dev/dogfood buckets stay destroyable), which means the
//     SHIPPED DEFAULT posture is tamper-EVIDENT — the Sink's signed hash-chain detects any
//     mutation or truncation — but NOT tamper-RESISTANT against a privileged actor. Production
//     MUST set is_locked=true to make the WORM guarantee authoritative (and irreversible).
//
// # The on-disk codec preserves the chain hash
//
// control-plane/evidence.chainHash derives a record's tamper-evidence link from its sequence,
// the two timestamps via UnixNano (Location-independent), and the string/[]byte fields. The
// codec here encodes the two times as explicit int64 UnixNano (not RFC3339), so the round-trip
// Entry → object bytes → Entry reproduces a byte-identical chain hash and VerifyChain passes
// over a rehydrated GCS log. This is asserted directly (provider_test.go) and end-to-end by the
// conformance run (the real Sink backed by this Store).
//
// # The GCS SDK is confined behind a port
//
// The Store logic (store.go: sequence→name, the precondition writes, the codec, the count)
// depends only on the objectIO port (ports.go); the cloud.google.com/go/storage client is
// confined to the adapter (gcs_gcp.go) wired by New (new.go). Tests and the conformance harness
// wire the in-memory fake (fakes.go) instead, so the contract logic runs under `go test ./...`
// with no GCS bucket and no credentials — the same logic-vs-fake split the other GCP providers
// use. The exported fake also lets out-of-tree providers conformance-test themselves.
//
// # Real vs deferred in this PR
//
//   - REAL: durable append-only record store — sequence→object mapping, atomic no-overwrite
//     (DoesNotExist precondition), no-gap enforcement, CRC32C integrity on every write, hydration
//     of an existing log, fail-closed on any GCS durability fault, append-only WORM against the
//     workload identity by IAM (create/get/list, no delete). A distinct bucket from the
//     operational database (GOAL.md tenet 1: evidence stays in the adopter's tenancy, never
//     egressed to the maintainer). NOTE: tamper-RESISTANCE against a privileged actor is the
//     retention LOCK's job, which is off by default — see the two-trust-levels section above.
//   - DEFERRED — durable checkpoint persistence: the Sink's signed checkpoints remain its
//     in-memory parallel log this phase (control-plane/evidence Checkpoint doc). Persisting them
//     to GCS (so a resumed Sink continues, rather than restarts, the checkpoint chain — closing
//     the tail-truncation residual durably) is a later hardening on this same Store.
//   - DEFERRED — SIEM forward: EvidenceSink.Stream is the Sink's existing fail-closed ref check;
//     a real adopter-SIEM webhook (to the ADOPTER's SIEM only, never the maintainer — GOAL.md
//     tenet 1) is a separate port in a later PR.
//   - RESIDUAL — the bucket lock (default off): the deploy module always sets a retention policy
//     but leaves the lock OPTIONAL (is_locked, default off) so dev/dogfood buckets stay
//     destroyable. The lock is the AUTHORITATIVE WORM control against a privileged actor (GOAL.md
//     tenet 3: the boundary wins; tenet 7: evidence recorded immutably); with it off the default
//     posture is tamper-evident, not tamper-resistant (above). Production sets it deliberately
//     (irreversible). This package's no-overwrite precondition and the Sink's hash-chain are
//     in-band defence-in-depth on top of it.
//   - RESIDUAL — deploy-identity privilege: deploy/gcp/bootstrap grants the APPLY identity
//     project-wide roles/storage.admin (for bucket create + retention/lock). That identity
//     already holds resourcemanager.projectIamAdmin (secrets module), i.e. it can self-grant any
//     role, so storage.admin does not raise its ceiling — but a least-privilege custom role
//     (buckets.create/get/update/setRetentionPolicy/lockRetentionPolicy, excluding objects.*) is
//     a tracked future tightening (GOAL.md tenet 5).
package evidencegcs
