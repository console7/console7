package evidence

import (
	"context"
	"fmt"
	"sync"

	"github.com/console7/console7/sdk/interfaces"
)

// Store is the narrow, append-only durability seam the Sink commits records through. It is
// WORM by CONSTRUCTION: there is deliberately no Update and no Delete method, so the type
// system — not a runtime guard or a comment — forbids rewriting committed history. A real
// backing (providers/evidence-gcs: GCS bucket-lock + retention) slots in behind this seam in
// a later Phase-1 PR (docs/ROADMAP.md) without touching the Sink's fail-closed Append path.
//
// SECURITY: a Store implementation MUST NOT share a mutable backing with the operational
// database (DESIGN.md §6) — the evidence record of verification is separate from operational
// state by design. The in-memory memStore below satisfies this structurally (it is a private
// store the Sink owns); a real provider satisfies it with a distinct bucket and IAM boundary.
type Store interface {
	// Append durably commits one already-sealed entry at exactly entry.Ref.Sequence. It MUST
	// reject a sequence that is not the next expected slot (a gap or a rewrite is fail-closed)
	// and MUST NOT overwrite an existing slot. On any durability fault it returns an error, and
	// the Sink then fails the Append closed (the record is never silently dropped).
	Append(ctx context.Context, entry Entry) error
	// Len returns the number of committed entries (equivalently, the next sequence).
	Len(ctx context.Context) (uint64, error)
	// At returns the committed entry at seq (ok=false if absent). It is read-only.
	At(ctx context.Context, seq uint64) (Entry, bool, error)
}

// Entry is one committed evidence record plus the chain position returned in its RecordRef.
// The Sink computes and seals it; a Store only persists the bytes it is handed.
type Entry struct {
	Record interfaces.EvidenceRecord
	Ref    interfaces.RecordRef
}

// memStore is the in-process, NON-PRODUCTION backing for the bench and conformance. It models
// the append-only contract (next-sequence-only, no rewrite) but, like devkit.MemEvidence, is
// tamper-EVIDENT not tamper-PROOF: the slice lives in memory with no durability or external
// anchoring, so Append cannot fail-closed on a durability fault an in-memory store never has.
// The real WORM guarantee arrives with providers/evidence-gcs (docs/ROADMAP.md).
type memStore struct {
	mu      sync.Mutex
	entries []Entry
}

// newMemStore returns an empty in-memory store.
func newMemStore() *memStore {
	return &memStore{}
}

// Append commits entry iff it lands in the next free slot, deep-copying it so a caller that
// retains the record/ref slices cannot mutate committed history afterwards.
func (m *memStore) Append(ctx context.Context, entry Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if entry.Ref.Sequence != uint64(len(m.entries)) {
		return fmt.Errorf("evidence: memStore append at sequence %d, want next slot %d (no gaps, no rewrite)", entry.Ref.Sequence, len(m.entries))
	}
	m.entries = append(m.entries, cloneEntry(entry))
	return nil
}

// Len returns the number of committed entries.
func (m *memStore) Len(ctx context.Context) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return uint64(len(m.entries)), nil
}

// At returns a defensive copy of the committed entry at seq, so an inspector cannot reach
// into committed history and mutate it.
func (m *memStore) At(ctx context.Context, seq uint64) (Entry, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if seq >= uint64(len(m.entries)) {
		return Entry{}, false, nil
	}
	return cloneEntry(m.entries[seq]), true, nil
}

// cloneEntry returns an independent copy of entry: the record payload and the ref hash are
// freshly allocated, so a committed entry never shares a backing array with any caller slice.
func cloneEntry(entry Entry) Entry {
	entry.Record.Payload = cloneBytes(entry.Record.Payload)
	entry.Ref.Hash = cloneBytes(entry.Ref.Hash)
	return entry
}
