package evidencegcs

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/console7/console7/control-plane/evidence"
	"github.com/console7/console7/keybroker/signing"
	"github.com/console7/console7/sdk/interfaces"
)

// entryAt builds a synthetic committed Entry at seq for direct Store tests (the Store does not
// interpret the hash, so a marker value suffices here; the end-to-end chain integrity is proven
// through the real Sink in TestStore_SinkRoundTripVerifies).
func entryAt(seq uint64) evidence.Entry {
	return evidence.Entry{
		Record: interfaces.EvidenceRecord{
			SessionID:  interfaces.SessionID("sess"),
			Subject:    interfaces.Subject("alice"),
			Persona:    interfaces.Persona("author"),
			Type:       "tool-call",
			ObservedAt: time.Unix(0, int64(seq)*1000).UTC(),
			Payload:    []byte("event"),
		},
		Ref: interfaces.RecordRef{
			Sequence:   seq,
			Hash:       []byte{byte(seq), 0xaa, 0xbb},
			AppendedAt: time.Unix(0, int64(seq)*2000).UTC(),
		},
	}
}

func TestStore_AppendAtReadBack(t *testing.T) {
	s := NewWithObjectIO(NewInMemoryObjectIO(), "records")
	ctx := context.Background()
	for i := uint64(0); i < 3; i++ {
		if err := s.Append(ctx, entryAt(i)); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	n, err := s.Len(ctx)
	if err != nil || n != 3 {
		t.Fatalf("Len = %d, %v; want 3", n, err)
	}
	got, ok, err := s.At(ctx, 1)
	if err != nil || !ok {
		t.Fatalf("At(1) = ok %v, err %v", ok, err)
	}
	want := entryAt(1)
	if got.Ref.Sequence != 1 || !bytes.Equal(got.Ref.Hash, want.Ref.Hash) ||
		got.Record.Type != want.Record.Type || !bytes.Equal(got.Record.Payload, want.Record.Payload) {
		t.Fatalf("At(1) round-trip mismatch: got %+v", got)
	}
	if got.Ref.AppendedAt.UnixNano() != want.Ref.AppendedAt.UnixNano() {
		t.Fatalf("AppendedAt UnixNano mismatch: got %d want %d", got.Ref.AppendedAt.UnixNano(), want.Ref.AppendedAt.UnixNano())
	}
}

func TestStore_AtMissingIsNotFound(t *testing.T) {
	s := NewWithObjectIO(NewInMemoryObjectIO(), "records")
	_, ok, err := s.At(context.Background(), 7)
	if err != nil || ok {
		t.Fatalf("At(missing) = ok %v, err %v; want false,nil", ok, err)
	}
}

func TestStore_RejectsRewrite(t *testing.T) {
	s := NewWithObjectIO(NewInMemoryObjectIO(), "records")
	ctx := context.Background()
	if err := s.Append(ctx, entryAt(0)); err != nil {
		t.Fatalf("first append: %v", err)
	}
	// Re-committing sequence 0 must fail closed (the DoesNotExist precondition / occupied slot).
	err := s.Append(ctx, entryAt(0))
	if err == nil {
		t.Fatal("expected a rewrite at sequence 0 to be rejected")
	}
	if !errors.Is(err, errSlotOccupied) {
		t.Fatalf("rewrite error should wrap errSlotOccupied, got %v", err)
	}
}

func TestStore_RejectsGap(t *testing.T) {
	s := NewWithObjectIO(NewInMemoryObjectIO(), "records")
	ctx := context.Background()
	if err := s.Append(ctx, entryAt(0)); err != nil {
		t.Fatalf("seq 0: %v", err)
	}
	// Jumping to sequence 2 (predecessor 1 absent) must be rejected — no gaps.
	if err := s.Append(ctx, entryAt(2)); err == nil {
		t.Fatal("expected a gap (append at 2 with 1 absent) to be rejected")
	}
}

func TestStore_FailClosedOnDurabilityFault(t *testing.T) {
	fake := NewInMemoryObjectIO()
	s := NewWithObjectIO(fake, "records")
	fake.SetFailPut(true)
	if err := s.Append(context.Background(), entryAt(0)); err == nil {
		t.Fatal("expected Append to fail closed when the backing put faults")
	}
}

func TestCodec_RoundTripPreservesChainFields(t *testing.T) {
	in := entryAt(42)
	b, err := marshalEntry(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out, err := unmarshalEntry(b)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// The fields chainHash consumes must survive byte-identically (times via UnixNano).
	if out.Record.SessionID != in.Record.SessionID || out.Record.Subject != in.Record.Subject ||
		out.Record.Persona != in.Record.Persona || out.Record.Type != in.Record.Type ||
		out.Record.ObservedAt.UnixNano() != in.Record.ObservedAt.UnixNano() ||
		!bytes.Equal(out.Record.Payload, in.Record.Payload) ||
		out.Ref.Sequence != in.Ref.Sequence || !bytes.Equal(out.Ref.Hash, in.Ref.Hash) ||
		out.Ref.AppendedAt.UnixNano() != in.Ref.AppendedAt.UnixNano() {
		t.Fatalf("codec round-trip altered a chain-hash field:\n in=%+v\nout=%+v", in, out)
	}
}

// TestStore_SinkRoundTripVerifies is the end-to-end proof: the REAL Sink, backed by this Store
// over the in-memory fake, appends records through the GCS codec and VerifyChain re-derives every
// hash from the rehydrated bytes — so the durable round-trip preserves the chain.
func TestStore_SinkRoundTripVerifies(t *testing.T) {
	ctx := context.Background()
	ca := signing.NewDevCA()
	signer, err := signing.NewSinkSigner(ca, "test-evidence-sink")
	if err != nil {
		t.Fatalf("sink signer: %v", err)
	}
	fake := NewInMemoryObjectIO()
	sink := evidence.New(NewWithObjectIO(fake, "records"), signer, ca.Root(), 0)
	for i := 0; i < 5; i++ {
		if _, err := sink.Append(ctx, interfaces.EvidenceRecord{
			SessionID: "sess-1", Subject: "alice", Persona: "author",
			Type: "tool-call", ObservedAt: time.Now(), Payload: []byte{byte('a' + i)},
		}); err != nil {
			t.Fatalf("sink append %d: %v", i, err)
		}
	}
	if err := sink.VerifyChain(); err != nil {
		t.Fatalf("VerifyChain over the GCS-codec-backed log failed: %v", err)
	}

	// A SECOND sink over the SAME backing must hydrate the existing head and continue the chain
	// (rather than collide at sequence 0), and the combined log must still verify.
	sink2 := evidence.New(NewWithObjectIO(fake, "records"), signer, ca.Root(), 0)
	if _, err := sink2.Append(ctx, interfaces.EvidenceRecord{
		SessionID: "sess-1", Subject: "alice", Persona: "author",
		Type: "session-end", ObservedAt: time.Now(), Payload: []byte("bye"),
	}); err != nil {
		t.Fatalf("resumed append: %v", err)
	}
	if err := sink2.VerifyChain(); err != nil {
		t.Fatalf("VerifyChain after resume failed: %v", err)
	}
	if n, _ := NewWithObjectIO(fake, "records").Len(ctx); n != 6 {
		t.Fatalf("expected 6 committed records after resume, got %d", n)
	}
}

func TestStore_AtRejectsMismatchedSequence(t *testing.T) {
	fake := NewInMemoryObjectIO()
	s := NewWithObjectIO(fake, "records")
	ctx := context.Background()
	// Write an entry whose body claims sequence 9 into the object addressed as slot 0 (models a
	// direct/tampered GCS write). At(0) must fail closed, not return it as slot 0.
	bad, err := marshalEntry(entryAt(9))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := fake.PutIfAbsent(ctx, s.objectName(0), bad); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, _, err := s.At(ctx, 0); err == nil {
		t.Fatal("expected At to reject an object whose Ref.Sequence != the requested slot")
	}
}

func TestPreflight_RejectsMissingTail(t *testing.T) {
	fake := NewInMemoryObjectIO()
	s := NewWithObjectIO(fake, "records")
	ctx := context.Background()
	// Inflate the count with a stray object under the prefix that is NOT a real tail record, so
	// Len==1 but At(0) is not found. preflight must fail closed, not treat the store as usable.
	if err := fake.PutIfAbsent(ctx, "records/stray", []byte("x")); err != nil {
		t.Fatalf("seed stray: %v", err)
	}
	if err := s.preflight(ctx); err == nil {
		t.Fatal("expected preflight to reject a non-empty store whose tail slot is missing")
	}
}

func TestPreflight_SurfacesReadFault(t *testing.T) {
	ctx := context.Background()
	fake := NewInMemoryObjectIO()
	s := NewWithObjectIO(fake, "records")
	if err := s.Append(ctx, entryAt(0)); err != nil {
		t.Fatalf("seed append: %v", err)
	}
	// A non-empty backing whose tail read faults must surface from preflight, not look empty.
	fake.SetFailGet(true)
	if err := s.preflight(ctx); err == nil {
		t.Fatal("expected preflight to surface the tail-read fault")
	}
	// An empty backing preflights clean.
	if err := NewWithObjectIO(NewInMemoryObjectIO(), "records").preflight(ctx); err != nil {
		t.Fatalf("empty-store preflight should be nil, got %v", err)
	}
}

func TestConfig_NormalizeValidates(t *testing.T) {
	if _, err := (Config{}).normalize(); err == nil {
		t.Fatal("empty Bucket should be rejected")
	}
	cfg, err := (Config{Bucket: "evi"}).normalize()
	if err != nil || cfg.ObjectPrefix != DefaultObjectPrefix {
		t.Fatalf("normalize default prefix: cfg=%+v err=%v", cfg, err)
	}
	if _, err := (Config{Bucket: "evi", ObjectPrefix: "bad/slash"}).normalize(); err == nil {
		t.Fatal("a prefix containing a slash should be rejected")
	}
}

func TestNewWithObjectIO_DefaultsPrefixAndCloseNoops(t *testing.T) {
	s := NewWithObjectIO(NewInMemoryObjectIO(), "")
	if s.prefix != DefaultObjectPrefix {
		t.Fatalf("empty prefix should default to %q, got %q", DefaultObjectPrefix, s.prefix)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close on a fake-backed Store should be a no-op, got %v", err)
	}
}
