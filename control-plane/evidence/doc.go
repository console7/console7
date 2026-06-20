// Package evidence is the real Tier-1 control-plane EvidenceSink: the append-only/WORM,
// hash-chained, sink-signed, fail-closed system of record for verification (DESIGN.md §6). It
// upgrades the bench double sdk/devkit.MemEvidence to the production sink and is wired as the
// orchestrator's default EvidenceSink; MemEvidence remains the lightweight test double.
//
// # Trust tier
//
// Tier-1 (control plane), and it HOLDS NO KEY AT REST. Sink-level checkpoint signing goes
// through an injected CheckpointSigner backed by the keybroker (the only key-holder), exactly
// as the orchestrator signs per-record evidence through broker.SignSession — the control plane
// never owns a private key (GOAL.md tenet 1/4; ARCHITECTURE.md §6.4).
//
// # Two distinct signatures
//
// Each evidence record already carries a PER-RECORD lineage signature the orchestrator embeds
// in its payload ("human → NHI signed this event"). On top of that, the sink periodically
// signs a CHECKPOINT over its chain head ("THIS sink committed a chain with this head").
// Checkpoints form their own hash chain, so the set of them is itself tamper-evident. The
// sink's checkpoint signer is long-lived (not session-deadline-bound), so a session that
// overran its deadline can still seal its close-out — partially closing the PR1 teardown
// residual (the per-record close-out lineage signature still needs a teardown-scoped session
// signer, tracked for the keybroker).
//
// # Storage seam
//
// Records commit through the narrow, append-only Store seam (no Update/Delete by
// construction). The in-memory backing here is for the bench and conformance; a durable
// backing (providers/evidence-gcs: GCS bucket-lock + retention + SIEM webhook) slots in behind
// the seam in a later Phase-1 PR (docs/ROADMAP.md) without reopening the fail-closed Append path.
//
// # Bench-mitigated vs real residual
//
//	Property                       | Bench (this PR)                                  | Real residual
//	-------------------------------|--------------------------------------------------|------------------------------------------------
//	Append-only / WORM             | Store type has no update/delete; memStore         | GCS bucket-lock / retention policy (evidence-gcs)
//	                               | accepts the next sequence only                    |
//	Hash-chained tamper-evidence   | full, real (SHA-256 chain; VerifyChain). Detects  | unchanged in the real backing
//	                               | record mutation and INTERIOR checkpoint drop/     |
//	                               | reorder.                                          |
//	Tail-truncation / rollback     | NOT detected in-band (dropping the latest          | GCS bucket-lock + retention (evidence-gcs);
//	                               | checkpoints leaves a valid signed prefix); an     | and/or an out-of-band signed high-water mark
//	                               | auditor must pin an expected high-water mark      | the verifier pins (future)
//	Sink-level signed (attributed) | full, real (ed25519 checkpoints chaining to the   | DevCA → real org CA / Sigstore-keyless +
//	                               | DevCA root; SinkID bound + pinned by Verify)      | transparency log (keybroker hardening)
//	Fail-closed on durability fault| exercised via a store-error stub; in-memory has   | real durability faults surfaced by the GCS
//	                               | no real fault                                     | provider (evidence-gcs)
//	Separate from operational DB   | structural (Sink holds only a Store)              | distinct GCS bucket + IAM separation (evidence-gcs)
//	Stream to SIEM only            | no-op + fail-closed ref check; no off-box egress  | real SIEM webhook to the adopter endpoint
//	Holds no key at rest           | full, real (Sink takes a CheckpointSigner)        | SinkSigner moves fully behind broker custody
//
// Do not mistake a green run on the in-memory backing for a durable WORM store.
package evidence
