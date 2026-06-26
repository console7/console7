package devkit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"sync"
	"time"

	"github.com/console7/console7/sdk/interfaces"
)

// MemEvidence is an in-memory stand-in for an EvidenceSink (interfaces.EvidenceSink). It
// models the WORM, hash-chained evidence log the contract requires: each Append links to
// the prior record's hash, the sink stamps its OWN authoritative AppendedAt (never trusting
// the caller's ObservedAt for ordering), the sequence is monotonic, and there is
// deliberately no method to update or delete a written record. It lets the orchestration
// spine and the conformance suite exercise the EvidenceSink contract on a bench.
//
// SCOPE: this is tamper-EVIDENT (a mutated record is detectable via VerifyChain), not
// tamper-PROOF — the backing slice lives in process memory with no durability or external
// anchoring, and Append cannot fail-closed on a durability fault that an in-memory store
// never has. A real sink (providers/evidence-gcs: GCS bucket-lock + signing + SIEM
// webhook) lands in a later Phase-1 PR (docs/ROADMAP.md). Do not mistake a green run here
// for a durable WORM store.
type MemEvidence struct {
	mu      sync.Mutex
	records []chainEntry
}

// chainEntry is one committed record plus the chain position returned in its RecordRef.
type chainEntry struct {
	rec interfaces.EvidenceRecord
	ref interfaces.RecordRef
}

// NewMemEvidence returns an empty evidence sink.
func NewMemEvidence() *MemEvidence {
	return &MemEvidence{}
}

// Append commits a record to the append-only, hash-chained log and returns its position.
func (e *MemEvidence) Append(ctx context.Context, rec interfaces.EvidenceRecord) (interfaces.RecordRef, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	var prior []byte
	if n := len(e.records); n > 0 {
		prior = e.records[n-1].ref.Hash
	}
	seq := uint64(len(e.records))
	// Stamp the sink's OWN authoritative time. rec.ObservedAt is caller-supplied and
	// untrusted, so it is hashed as content (a back-dated value is therefore covered by
	// the chain) but is NEVER used as the timeline — AppendedAt is.
	appendedAt := time.Now().UTC()
	// Defensively copy the caller's payload before committing it: a WORM record the caller
	// can still mutate by retaining the slice is not append-only. The hash is freshly
	// allocated per call, so the stored copy and the returned copy never alias.
	stored := rec
	stored.Payload = cloneBytes(rec.Payload)
	h := chainHash(prior, seq, appendedAt, stored)
	e.records = append(e.records, chainEntry{
		rec: stored,
		ref: interfaces.RecordRef{Sequence: seq, Hash: h, AppendedAt: appendedAt},
	})
	return interfaces.RecordRef{Sequence: seq, Hash: cloneBytes(h), AppendedAt: appendedAt}, nil
}

// cloneBytes returns an independent copy of b (nil for nil), so committed records never
// share a backing array with a caller's slice.
func cloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	c := make([]byte, len(b))
	copy(c, b)
	return c
}

// Stream mirrors a committed record to the adopter's SIEM.
func (e *MemEvidence) Stream(ctx context.Context, ref interfaces.RecordRef) error {
	// In-memory there is no external SIEM and, by tenet 1, MUST be no off-box egress — so
	// Stream verifies the ref names a record this sink actually committed (fail closed on a
	// forged/unknown ref) and is otherwise a no-op. It is an addition to, never a
	// replacement for, the durable WORM append.
	e.mu.Lock()
	defer e.mu.Unlock()
	if ref.Sequence >= uint64(len(e.records)) {
		return errors.New("devkit: MemEvidence cannot stream an unknown record ref")
	}
	if !bytes.Equal(e.records[ref.Sequence].ref.Hash, ref.Hash) {
		return errors.New("devkit: MemEvidence stream ref does not match the committed record")
	}
	return nil
}

// NextSequence returns the chain position the next Append will assign (Append uses len(records)).
func (e *MemEvidence) NextSequence(ctx context.Context) (uint64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return uint64(len(e.records)), nil
}

// Len returns the number of committed records. Test-only inspection hook.
func (e *MemEvidence) Len() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.records)
}

// At returns the committed record and its ref at sequence i. Test-only inspection hook. It
// returns copies so an inspector cannot reach into the committed chain and mutate it.
func (e *MemEvidence) At(i int) (interfaces.EvidenceRecord, interfaces.RecordRef, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if i < 0 || i >= len(e.records) {
		return interfaces.EvidenceRecord{}, interfaces.RecordRef{}, false
	}
	rec := e.records[i].rec
	rec.Payload = cloneBytes(rec.Payload)
	ref := e.records[i].ref
	ref.Hash = cloneBytes(ref.Hash)
	return rec, ref, true
}

// VerifyChain recomputes the hash chain and reports the first break. It is how a bench
// proves the log is intact (and how a test proves a mutated record is DETECTED). It is a
// verification path, never a mutation path.
func (e *MemEvidence) VerifyChain() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	var prior []byte
	for i, ent := range e.records {
		if ent.ref.Sequence != uint64(i) {
			return fmt.Errorf("devkit: MemEvidence sequence gap at index %d (got %d)", i, ent.ref.Sequence)
		}
		want := chainHash(prior, ent.ref.Sequence, ent.ref.AppendedAt, ent.rec)
		if !bytes.Equal(want, ent.ref.Hash) {
			return fmt.Errorf("devkit: MemEvidence chain broken at sequence %d", ent.ref.Sequence)
		}
		prior = ent.ref.Hash
	}
	return nil
}

// chainHash computes the tamper-evidence link over the prior hash and this record's
// committed content (sequence, sink-stamped time, and every record field — including the
// untrusted ObservedAt, so a back-dated timestamp is itself covered). Fields are
// length-prefixed so no field-boundary ambiguity can let two distinct records collide.
func chainHash(prior []byte, seq uint64, appendedAt time.Time, rec interfaces.EvidenceRecord) []byte {
	h := sha256.New()
	h.Write(prior)
	writeUint64(h, seq)
	writeUint64(h, uint64(appendedAt.UnixNano()))
	writeField(h, []byte(rec.SessionID))
	writeField(h, []byte(rec.Subject))
	writeField(h, []byte(rec.Persona))
	writeField(h, []byte(rec.Type))
	writeUint64(h, uint64(rec.ObservedAt.UnixNano()))
	writeField(h, rec.Payload)
	return h.Sum(nil)
}

// writeField writes a length-prefixed byte field into the hash.
func writeField(h hash.Hash, b []byte) {
	writeUint64(h, uint64(len(b)))
	h.Write(b)
}

// writeUint64 writes a fixed-width big-endian uint64 into the hash.
func writeUint64(h hash.Hash, v uint64) {
	var u8 [8]byte
	binary.BigEndian.PutUint64(u8[:], v)
	h.Write(u8[:])
}
