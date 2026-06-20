package interfaces

import (
	"context"
	"time"
)

// EvidenceRecord is one tamper-evident entry in the session's evidence chain: a
// tool call, sub-agent action, commit, decision, or lifecycle event. It carries the
// lineage stamp so attribution survives sub-agent spawning (DESIGN.md §2.3, §10.5).
type EvidenceRecord struct {
	SessionID SessionID
	// Subject is the human at the root of the lineage chain.
	Subject Subject
	Persona Persona
	// Type is the event kind, e.g. "tool-call", "egress-denied", "commit",
	// "session-end".
	Type string
	// ObservedAt is the event time as recorded by the (untrusted) caller. It is
	// retained for context but MUST NOT be relied on for chronology — a buggy or
	// compromised session could back/post-date it. The authoritative time is
	// RecordRef.AppendedAt, stamped by the sink.
	ObservedAt time.Time
	// Payload is the opaque, already-DLP-scanned event body. The caller is
	// responsible for not placing secrets or production data here.
	Payload []byte
}

// RecordRef is the position of an appended record in the hash chain.
type RecordRef struct {
	// Sequence is the monotonically increasing index in the chain.
	Sequence uint64
	// Hash is this record's chained hash (over its content and the prior hash),
	// the tamper-evidence link.
	Hash []byte
	// AppendedAt is the authoritative time the sink committed the record, stamped by
	// the sink itself — the trustworthy timeline for assurance.
	AppendedAt time.Time
}

// EvidenceSink abstracts the WORM evidence store plus SIEM stream (ARCHITECTURE.md
// §5; default ref: GCS bucket-lock + SIEM webhook). It is the system of record for
// verification and is separate from the operational database (DESIGN.md §6).
type EvidenceSink interface {
	// Append writes one record to the append-only, hash-chained log and returns its
	// position.
	//
	// SECURITY: the store MUST be append-only/WORM — the implementation MUST NEVER
	// expose a path to update or delete a previously written record, and MUST chain
	// each record and cryptographically sign the chain — per-record and/or via signed
	// checkpoints over the chain head — for tamper-evidence (DESIGN.md §6). It MUST
	// stamp its own authoritative AppendedAt and chain on that, NEVER trusting
	// rec.ObservedAt for ordering. It MUST fail closed: if the record cannot be durably
	// and immutably committed, Append MUST error rather than drop it silently. It MUST
	// NOT route evidence through, or share a mutable backing store with, the operational
	// database.
	Append(ctx context.Context, rec EvidenceRecord) (RecordRef, error)

	// Stream forwards a record to the adopter's SIEM.
	//
	// SECURITY: streaming is to the ADOPTER's SIEM only; the implementation MUST NOT
	// egress evidence to the maintainer or any maintainer-operated service (GOAL.md
	// tenet 1). It is an addition to, never a replacement for, the durable WORM
	// append.
	Stream(ctx context.Context, ref RecordRef) error
}
