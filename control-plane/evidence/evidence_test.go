package evidence

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/console7/console7/keybroker/signing"
	"github.com/console7/console7/sdk/interfaces"
)

// newTestSink returns a Sink over an in-memory store plus the DevCA root that verifies its
// checkpoints. ckptEvery selects the checkpoint cadence under test.
func newTestSink(t *testing.T, ckptEvery int) (*Sink, ed25519.PublicKey) {
	t.Helper()
	ca := signing.NewDevCA()
	signer, err := signing.NewSinkSigner(ca, "test-evidence-sink")
	if err != nil {
		t.Fatalf("NewSinkSigner: %v", err)
	}
	return NewInMemory(signer, ca.Root(), ckptEvery), ca.Root()
}

func rec(typ string, observed time.Time, payload string) interfaces.EvidenceRecord {
	return interfaces.EvidenceRecord{
		SessionID:  "sess-1",
		Subject:    "alice",
		Persona:    interfaces.PersonaAuthor,
		Type:       typ,
		ObservedAt: observed,
		Payload:    []byte(payload),
	}
}

func TestAppend_MonotonicChain(t *testing.T) {
	s, _ := newTestSink(t, 0)
	ctx := context.Background()

	// The SECOND record carries an EARLIER ObservedAt than the first — the sink must still order
	// by its own append (monotonic Sequence + stamped AppendedAt), never by the untrusted time.
	late := time.Unix(1<<31, 0).UTC()
	early := time.Unix(0, 0).UTC()
	first, err := s.Append(ctx, rec("a", late, "x"))
	if err != nil {
		t.Fatalf("first append: %v", err)
	}
	second, err := s.Append(ctx, rec("b", early, "y"))
	if err != nil {
		t.Fatalf("second append: %v", err)
	}
	if second.Sequence != first.Sequence+1 {
		t.Errorf("sequence not monotonic: first=%d second=%d", first.Sequence, second.Sequence)
	}
	if first.AppendedAt.IsZero() || second.AppendedAt.IsZero() {
		t.Error("sink did not stamp its own AppendedAt")
	}
	if second.AppendedAt.Before(first.AppendedAt) {
		t.Error("chain ordered by the caller's ObservedAt, not the sink's AppendedAt")
	}
	if len(first.Hash) == 0 || len(second.Hash) == 0 {
		t.Error("an appended record carries no chain hash")
	}
	if string(first.Hash) == string(second.Hash) {
		t.Error("records are not distinctly hash-chained")
	}
	if err := s.VerifyChain(); err != nil {
		t.Errorf("freshly appended chain does not verify: %v", err)
	}
}

func TestVerifyChain_DetectsTamper(t *testing.T) {
	s, _ := newTestSink(t, 0)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if _, err := s.Append(ctx, rec("e", time.Unix(int64(i), 0).UTC(), "p")); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	if err := s.VerifyChain(); err != nil {
		t.Fatalf("intact chain should verify: %v", err)
	}
	// White-box mutation of committed history: a real WORM backing forbids this, but the test
	// reaches into the in-memory store to prove the hash chain DETECTS it.
	ms := s.store.(*memStore)
	ms.entries[1].Record.Payload = []byte("tampered")
	if err := s.VerifyChain(); err == nil {
		t.Error("VerifyChain accepted a mutated record")
	}
}

func TestSeal_SignsHeadAndVerifies(t *testing.T) {
	s, caRoot := newTestSink(t, 0)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if _, err := s.Append(ctx, rec("e", time.Unix(int64(i), 0).UTC(), "p")); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	if err := s.Seal(ctx); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	cps := s.Checkpoints()
	if len(cps) != 1 {
		t.Fatalf("got %d checkpoints, want 1", len(cps))
	}
	ckpt := cps[0]
	if ckpt.HeadSequence != 2 || ckpt.Count != 3 {
		t.Errorf("checkpoint pins head=%d count=%d, want head=2 count=3", ckpt.HeadSequence, ckpt.Count)
	}
	headRec, headRef, ok := s.At(int(ckpt.HeadSequence))
	if !ok || string(headRef.Hash) != string(ckpt.HeadHash) {
		t.Errorf("checkpoint HeadHash does not match the committed head (record %q)", headRec.Type)
	}
	if err := s.VerifyCheckpoints(caRoot, s.SinkID()); err != nil {
		t.Errorf("sealed checkpoint does not verify: %v", err)
	}
	if err := s.Verify(); err != nil {
		t.Errorf("full Verify failed: %v", err)
	}
}

func TestVerifyCheckpoints_RejectsForgedSig(t *testing.T) {
	s, caRoot := newTestSink(t, 0)
	ctx := context.Background()
	if _, err := s.Append(ctx, rec("e", time.Unix(0, 0).UTC(), "p")); err != nil {
		t.Fatal(err)
	}
	if err := s.Seal(ctx); err != nil {
		t.Fatal(err)
	}
	// Corrupt the stored checkpoint signature; verification must reject it.
	s.checkpoints[0].Sig.Sig[0] ^= 0xff
	if err := s.VerifyCheckpoints(caRoot, s.SinkID()); err == nil {
		t.Error("verified a checkpoint with a forged signature")
	}
}

func TestVerifyCheckpoints_RejectsWrongCARoot(t *testing.T) {
	s, _ := newTestSink(t, 0)
	ctx := context.Background()
	if _, err := s.Append(ctx, rec("e", time.Unix(0, 0).UTC(), "p")); err != nil {
		t.Fatal(err)
	}
	if err := s.Seal(ctx); err != nil {
		t.Fatal(err)
	}
	otherRoot, _, _ := ed25519.GenerateKey(nil)
	if err := s.VerifyCheckpoints(otherRoot, s.SinkID()); err == nil {
		t.Error("verified a checkpoint against an untrusted CA root")
	}
}

func TestVerifyCheckpoints_RejectsTamperedHeadHash(t *testing.T) {
	s, caRoot := newTestSink(t, 0)
	ctx := context.Background()
	if _, err := s.Append(ctx, rec("e", time.Unix(0, 0).UTC(), "p")); err != nil {
		t.Fatal(err)
	}
	if err := s.Seal(ctx); err != nil {
		t.Fatal(err)
	}
	// Altering the pinned head breaks the signature (the head is in the signed TBS).
	s.checkpoints[0].HeadHash[0] ^= 0xff
	if err := s.VerifyCheckpoints(caRoot, s.SinkID()); err == nil {
		t.Error("verified a checkpoint whose pinned head hash was altered")
	}
}

func TestVerifyCheckpoints_RejectsMalformedKeyLength(t *testing.T) {
	s, _ := newTestSink(t, 0)
	ctx := context.Background()
	if _, err := s.Append(ctx, rec("e", time.Unix(0, 0).UTC(), "p")); err != nil {
		t.Fatal(err)
	}
	if err := s.Seal(ctx); err != nil {
		t.Fatal(err)
	}
	// A wrong-length root must error, not panic.
	if err := s.VerifyCheckpoints(ed25519.PublicKey{1, 2, 3}, s.SinkID()); err == nil {
		t.Error("verified checkpoints against a malformed CA root key")
	}
}

func TestVerifyCheckpoints_RejectsWrongSinkIdentity(t *testing.T) {
	// Two sinks off the SAME CA root (the org-CA deployment shape). A checkpoint sealed by sink
	// A must not verify when an auditor pins sink B's identity — the seal is attributable.
	ca := signing.NewDevCA()
	signerA, _ := signing.NewSinkSigner(ca, "sink-A")
	a := NewInMemory(signerA, ca.Root(), 0)
	ctx := context.Background()
	if _, err := a.Append(ctx, rec("e", time.Unix(0, 0).UTC(), "p")); err != nil {
		t.Fatal(err)
	}
	if err := a.Seal(ctx); err != nil {
		t.Fatal(err)
	}
	// Same CA root, but the auditor expects a different sink identity.
	if err := a.VerifyCheckpoints(ca.Root(), "sink-B"); err == nil {
		t.Error("a checkpoint sealed by sink-A verified when sink-B was the expected sealer")
	}
	// Its own identity still verifies.
	if err := a.VerifyCheckpoints(ca.Root(), "sink-A"); err != nil {
		t.Errorf("sink-A's own checkpoint should verify: %v", err)
	}
}

func TestCheckpointChain_DetectsDroppedCheckpoint(t *testing.T) {
	s, caRoot := newTestSink(t, 0)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if _, err := s.Append(ctx, rec("e", time.Unix(int64(i), 0).UTC(), "p")); err != nil {
			t.Fatal(err)
		}
		if err := s.Seal(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.VerifyCheckpoints(caRoot, s.SinkID()); err != nil {
		t.Fatalf("three intact checkpoints should verify: %v", err)
	}
	// Drop the middle checkpoint: the PrevCkptHash chain (and CkptSeq monotonicity) must break.
	s.checkpoints = append(s.checkpoints[:1], s.checkpoints[2:]...)
	if err := s.VerifyCheckpoints(caRoot, s.SinkID()); err == nil {
		t.Error("verified a checkpoint set with a dropped checkpoint")
	}
}

// errStore is a Store that fails closed on Append, to prove the Sink surfaces a durability
// fault without advancing the chain.
type errStore struct{}

func (errStore) Append(context.Context, Entry) error { return errors.New("simulated durability fault") }
func (errStore) Len(context.Context) (uint64, error) { return 0, nil }
func (errStore) At(context.Context, uint64) (Entry, bool, error) {
	return Entry{}, false, nil
}

func TestAppend_FailsClosedOnStoreError(t *testing.T) {
	ca := signing.NewDevCA()
	signer, _ := signing.NewSinkSigner(ca, "test-evidence-sink")
	s := New(errStore{}, signer, ca.Root(), 0)

	_, err := s.Append(context.Background(), rec("e", time.Unix(0, 0).UTC(), "p"))
	if err == nil {
		t.Fatal("expected Append to fail closed on a store durability fault")
	}
	// No in-memory state may have advanced: a failed commit is not a committed record.
	if s.count != 0 || s.head != nil {
		t.Errorf("chain advanced despite a failed commit: count=%d headSet=%v", s.count, s.head != nil)
	}
}

// errSigner is a CheckpointSigner that always fails, to prove a seal failure does not
// un-commit or corrupt an already-committed record.
type errSigner struct{}

func (errSigner) SinkID() string { return "err-signer" }
func (errSigner) SignCheckpoint(context.Context, []byte) (signing.SinkSignature, error) {
	return signing.SinkSignature{}, errors.New("simulated signer fault")
}

func TestAppend_FailsClosedOnSignerError(t *testing.T) {
	ca := signing.NewDevCA()
	// ckptEvery=1 forces an in-line seal on every append, so the failing signer is exercised on
	// the Append path.
	s := New(newMemStore(), errSigner{}, ca.Root(), 1)

	ref, err := s.Append(context.Background(), rec("e", time.Unix(0, 0).UTC(), "p"))
	if err == nil {
		t.Fatal("expected Append to surface the checkpoint-seal failure")
	}
	// The record itself must remain committed and chained — losing it would violate "never drop".
	if s.count != 1 {
		t.Errorf("record was dropped on a seal failure: count=%d, want 1", s.count)
	}
	if _, _, ok := s.At(int(ref.Sequence)); !ok {
		t.Error("committed record is not retrievable after a seal failure")
	}
	if err := s.VerifyChain(); err != nil {
		t.Errorf("chain must stay valid despite a seal failure: %v", err)
	}
	if len(s.checkpoints) != 0 {
		t.Errorf("a failed seal must not append a partial checkpoint, got %d", len(s.checkpoints))
	}
}

func TestStoreSeparation(t *testing.T) {
	// Structural separation: the Sink reaches durable evidence ONLY through its own Store and
	// exposes no path to a mutable operational backing. Two sinks over distinct stores share no
	// state — a record in one is invisible to the other.
	a, _ := newTestSink(t, 0)
	b, _ := newTestSink(t, 0)
	ctx := context.Background()
	if _, err := a.Append(ctx, rec("e", time.Unix(0, 0).UTC(), "p")); err != nil {
		t.Fatal(err)
	}
	if a.Len() != 1 {
		t.Errorf("sink a should hold its record, got Len=%d", a.Len())
	}
	if b.Len() != 0 {
		t.Errorf("sink b shares state with sink a (Len=%d), stores are not separate", b.Len())
	}
}

func TestStream_FailsClosed(t *testing.T) {
	s, _ := newTestSink(t, 0)
	ctx := context.Background()
	ref, err := s.Append(ctx, rec("e", time.Unix(0, 0).UTC(), "p"))
	if err != nil {
		t.Fatal(err)
	}
	// A committed record streams without error.
	if err := s.Stream(ctx, ref); err != nil {
		t.Errorf("streaming a committed record failed: %v", err)
	}
	// An out-of-range ref is rejected.
	if err := s.Stream(ctx, interfaces.RecordRef{Sequence: 1 << 40}); err == nil {
		t.Error("streamed an uncommitted record reference instead of failing closed")
	}
	// A ref naming an existing sequence but a TAMPERED hash is rejected.
	forged := ref
	forged.Hash = append([]byte(nil), ref.Hash...)
	forged.Hash[0] ^= 0xff
	if err := s.Stream(ctx, forged); err == nil {
		t.Error("streamed a ref with a forged hash instead of failing closed")
	}
}

func TestAppend_PeriodicCheckpointCadence(t *testing.T) {
	s, caRoot := newTestSink(t, 2)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		if _, err := s.Append(ctx, rec("e", time.Unix(int64(i), 0).UTC(), "p")); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	// ckptEvery=2 over 5 records ⇒ checkpoints after records 2 and 4 (the 5th is unsealed until
	// the next cadence boundary or an explicit Seal).
	if got := len(s.Checkpoints()); got != 2 {
		t.Errorf("got %d periodic checkpoints, want 2", got)
	}
	if err := s.VerifyCheckpoints(caRoot, s.SinkID()); err != nil {
		t.Errorf("periodic checkpoints do not verify: %v", err)
	}
}
