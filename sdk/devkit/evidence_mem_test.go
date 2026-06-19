package devkit

import (
	"context"
	"testing"
	"time"

	"github.com/console7/console7/sdk/interfaces"
)

func appendN(t *testing.T, e *MemEvidence, n int) []interfaces.RecordRef {
	t.Helper()
	refs := make([]interfaces.RecordRef, n)
	for i := 0; i < n; i++ {
		ref, err := e.Append(context.Background(), interfaces.EvidenceRecord{
			SessionID:  "s1",
			Subject:    "alice",
			Persona:    interfaces.PersonaAuthor,
			Type:       "event",
			ObservedAt: time.Unix(int64(1000-i), 0).UTC(), // decreasing: must not affect ordering.
			Payload:    []byte{byte(i)},
		})
		if err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
		refs[i] = ref
	}
	return refs
}

func TestMemEvidence_Append_MonotonicAndStampsOwnTime(t *testing.T) {
	e := NewMemEvidence()
	refs := appendN(t, e, 3)
	for i, ref := range refs {
		if ref.Sequence != uint64(i) {
			t.Errorf("record %d has sequence %d", i, ref.Sequence)
		}
		if ref.AppendedAt.IsZero() {
			t.Errorf("record %d has no sink-stamped AppendedAt", i)
		}
		if len(ref.Hash) == 0 {
			t.Errorf("record %d has no chain hash", i)
		}
	}
	// AppendedAt is the sink's own clock, unrelated to the (decreasing) ObservedAt values.
	if refs[2].AppendedAt.Before(refs[0].AppendedAt) {
		t.Error("AppendedAt went backwards — sink ordered by ObservedAt, not its own clock")
	}
}

func TestMemEvidence_VerifyChain_IntactThenTampered(t *testing.T) {
	e := NewMemEvidence()
	appendN(t, e, 4)
	if err := e.VerifyChain(); err != nil {
		t.Fatalf("intact chain should verify: %v", err)
	}
	// White-box tamper: mutate a committed record's payload in place. The recomputed hash
	// must no longer match — the chain is tamper-evident.
	e.records[2].rec.Payload = []byte("tampered")
	if err := e.VerifyChain(); err == nil {
		t.Error("expected VerifyChain to detect a mutated record")
	}
}

func TestMemEvidence_Stream_KnownRefOKUnknownFailsClosed(t *testing.T) {
	e := NewMemEvidence()
	refs := appendN(t, e, 1)
	if err := e.Stream(context.Background(), refs[0]); err != nil {
		t.Errorf("streaming a committed record should succeed: %v", err)
	}
	if err := e.Stream(context.Background(), interfaces.RecordRef{Sequence: 99}); err == nil {
		t.Error("expected streaming an unknown ref to fail closed")
	}
	// A ref with a forged hash at a valid sequence must also be rejected.
	forged := refs[0]
	forged.Hash = []byte("not-the-hash")
	if err := e.Stream(context.Background(), forged); err == nil {
		t.Error("expected streaming a ref with a mismatched hash to fail closed")
	}
}
