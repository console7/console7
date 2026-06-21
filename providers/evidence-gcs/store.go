package evidencegcs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/console7/console7/control-plane/evidence"
	"github.com/console7/console7/sdk/interfaces"
)

// errSlotOccupied is the sentinel an objectIO returns (wrapped) when a PutIfAbsent target
// already exists. Store.Append maps it to a fail-closed "rewrite rejected" error, mirroring the
// memStore's next-slot guard.
var errSlotOccupied = errors.New("evidencegcs: object already exists")

// seqWidth zero-pads the sequence in the object name so lexical listing order equals numeric
// order. 20 digits holds the full uint64 range (max 20 digits).
const seqWidth = 20

// Store implements control-plane/evidence.Store over GCS via the objectIO port. It owns the
// sequence→object-name mapping, the no-overwrite/no-gap enforcement, and the chain-hash-
// preserving codec; the cloud.google.com/go/storage client is confined to gcs_gcp.go. Build it
// with New (production) or NewWithObjectIO (tests/conformance), then hand it to
// control-plane/evidence.New as the Sink's durable backing.
type Store struct {
	obj    objectIO
	prefix string
	// closer releases the GCS client New opened; nil for a fake-backed Store (NewWithObjectIO).
	closer io.Closer
}

var _ evidence.Store = (*Store)(nil)

// objectName is the deterministic key for the record at seq: "<prefix>/<zero-padded seq>".
func (s *Store) objectName(seq uint64) string {
	return fmt.Sprintf("%s/%0*d", s.prefix, seqWidth, seq)
}

// Append durably commits entry at exactly entry.Ref.Sequence. It is fail-closed and preserves
// the append-only, contiguous-run shape:
//   - no rewrite: the object is written with a DoesNotExist precondition, so a write to an
//     occupied slot fails atomically server-side (mapped from errSlotOccupied), independent of
//     any in-memory count.
//   - no gap: for sequence>0 the immediate predecessor must already exist. Because the store has
//     no delete path, the committed objects are always a contiguous 0..n-1 run (induction from
//     empty); given that invariant, predecessor-exists + the DoesNotExist precondition imply
//     exactly next-slot semantics (sequence == count) WITHOUT an O(n) listing on the append path,
//     and the result stays contiguous. (The reference memStore checks sequence == len directly;
//     this is the equivalent under the no-delete invariant, traded for cheaper writes.)
//
// Any GCS fault surfaces as an error so the Sink fails the Append closed and never advances its
// chain over a record that did not durably commit. Object immutability against a privileged actor
// is the bucket retention lock's job (doc.go), not this in-band guard's.
func (s *Store) Append(ctx context.Context, entry evidence.Entry) error {
	seq := entry.Ref.Sequence
	if seq > 0 {
		ok, err := s.obj.Exists(ctx, s.objectName(seq-1))
		if err != nil {
			return fmt.Errorf("evidencegcs: predecessor check failed at sequence %d: %w", seq, err)
		}
		if !ok {
			return fmt.Errorf("evidencegcs: append at sequence %d has no predecessor %d (no gaps)", seq, seq-1)
		}
	}
	data, err := marshalEntry(entry)
	if err != nil {
		return fmt.Errorf("evidencegcs: encode entry at sequence %d: %w", seq, err)
	}
	if err := s.obj.PutIfAbsent(ctx, s.objectName(seq), data); err != nil {
		if errors.Is(err, errSlotOccupied) {
			return fmt.Errorf("evidencegcs: sequence %d already committed (no rewrite): %w", seq, err)
		}
		return fmt.Errorf("evidencegcs: durable append failed at sequence %d: %w", seq, err)
	}
	return nil
}

// Len returns the number of committed entries (the next free sequence), counting objects under
// the prefix. The Sink calls it at hydration and on Verify/Seal, not on the append path.
func (s *Store) Len(ctx context.Context) (uint64, error) {
	n, err := s.obj.Count(ctx, s.prefix+"/")
	if err != nil {
		return 0, fmt.Errorf("evidencegcs: count failed: %w", err)
	}
	return n, nil
}

// At returns the committed entry at seq. An absent slot is (Entry{},false,nil), not an error.
func (s *Store) At(ctx context.Context, seq uint64) (evidence.Entry, bool, error) {
	data, found, err := s.obj.Get(ctx, s.objectName(seq))
	if err != nil {
		return evidence.Entry{}, false, fmt.Errorf("evidencegcs: read failed at sequence %d: %w", seq, err)
	}
	if !found {
		return evidence.Entry{}, false, nil
	}
	entry, err := unmarshalEntry(data)
	if err != nil {
		return evidence.Entry{}, false, fmt.Errorf("evidencegcs: decode entry at sequence %d: %w", seq, err)
	}
	// The object body carries its own Ref.Sequence; it MUST match the slot it was addressed by, or
	// the backing has been tampered with / mis-imported (a direct GCS write under the workload
	// creds, say). At is the Store boundary the Sink's hydrate/Seal/Stream all trust, so fail
	// closed here rather than hand back a record as a slot it does not belong to.
	if entry.Ref.Sequence != seq {
		return evidence.Entry{}, false, fmt.Errorf("evidencegcs: object at sequence %d carries mismatched sequence %d (corrupt/tampered) — refusing", seq, entry.Ref.Sequence)
	}
	return entry, true, nil
}

// wireEntry is the on-disk encoding of an evidence.Entry. Times are explicit int64 UnixNano —
// exactly what control-plane/evidence.chainHash consumes (Location-independent) — so the
// round-trip reproduces a byte-identical chain hash and VerifyChain passes over a rehydrated
// log. The field set is the full EvidenceRecord + RecordRef; nothing is dropped or derived.
type wireEntry struct {
	SessionID        string `json:"session_id"`
	Subject          string `json:"subject"`
	Persona          string `json:"persona"`
	Type             string `json:"type"`
	ObservedUnixNano int64  `json:"observed_unix_nano"`
	Payload          []byte `json:"payload"`
	Sequence         uint64 `json:"sequence"`
	Hash             []byte `json:"hash"`
	AppendedUnixNano int64  `json:"appended_unix_nano"`
}

// marshalEntry encodes an entry to its durable object bytes.
func marshalEntry(e evidence.Entry) ([]byte, error) {
	return json.Marshal(wireEntry{
		SessionID:        string(e.Record.SessionID),
		Subject:          string(e.Record.Subject),
		Persona:          string(e.Record.Persona),
		Type:             e.Record.Type,
		ObservedUnixNano: e.Record.ObservedAt.UnixNano(),
		Payload:          e.Record.Payload,
		Sequence:         e.Ref.Sequence,
		Hash:             e.Ref.Hash,
		AppendedUnixNano: e.Ref.AppendedAt.UnixNano(),
	})
}

// unmarshalEntry reverses marshalEntry. Times are reconstructed in UTC; only their UnixNano
// matters to the chain hash, so the absolute instant — and therefore the hash — is preserved.
func unmarshalEntry(data []byte) (evidence.Entry, error) {
	var w wireEntry
	if err := json.Unmarshal(data, &w); err != nil {
		return evidence.Entry{}, err
	}
	return evidence.Entry{
		Record: interfaces.EvidenceRecord{
			SessionID:  interfaces.SessionID(w.SessionID),
			Subject:    interfaces.Subject(w.Subject),
			Persona:    interfaces.Persona(w.Persona),
			Type:       w.Type,
			ObservedAt: time.Unix(0, w.ObservedUnixNano).UTC(),
			Payload:    w.Payload,
		},
		Ref: interfaces.RecordRef{
			Sequence:   w.Sequence,
			Hash:       w.Hash,
			AppendedAt: time.Unix(0, w.AppendedUnixNano).UTC(),
		},
	}, nil
}
