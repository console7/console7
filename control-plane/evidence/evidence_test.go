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
// un-commit or corrupt an already-committed record, and is surfaced at the authoritative Seal.
type errSigner struct{}

func (errSigner) SinkID() string { return "err-signer" }
func (errSigner) SignCheckpoint(context.Context, []byte) (signing.SinkSignature, error) {
	return signing.SinkSignature{}, errors.New("simulated signer fault")
}

func TestAppend_SignerFailureKeepsRecordAndSurfacesAtSeal(t *testing.T) {
	ca := signing.NewDevCA()
	// ckptEvery=1 forces a due in-line seal on every append, so the failing signer is exercised
	// on the Append path.
	s := New(newMemStore(), errSigner{}, ca.Root(), 1)

	ref, err := s.Append(context.Background(), rec("e", time.Unix(0, 0).UTC(), "p"))
	// Append's error contract: a non-nil error means NOT committed. A post-commit seal failure
	// must NOT be reported as an append error (callers would skip Stream for a committed record).
	if err != nil {
		t.Fatalf("Append must succeed once the record is committed, got: %v", err)
	}
	// The record is committed and chained — losing it would violate "never drop".
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
	// The persistent signer failure surfaces at the authoritative Seal (e.g. session-end).
	if err := s.Seal(context.Background()); err == nil {
		t.Error("expected Seal to surface the persistent signer failure")
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

func TestVerify_RejectsUnsealedTail(t *testing.T) {
	s, _ := newTestSink(t, 0)
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if _, err := s.Append(ctx, rec("e", time.Unix(int64(i), 0).UTC(), "p")); err != nil {
			t.Fatal(err)
		}
	}
	// Records appended but never sealed: the full Verify (unbroken AND sealed) must reject it,
	// even though the prefix-only checks pass.
	if err := s.Verify(); err == nil {
		t.Error("Verify accepted a non-empty log with no checkpoint sealing the head")
	}
	if err := s.VerifyChain(); err != nil {
		t.Errorf("VerifyChain (prefix-only) should still pass: %v", err)
	}
	if err := s.VerifyCheckpoints(s.caRoot, s.SinkID()); err != nil {
		t.Errorf("VerifyCheckpoints (prefix-only) should still pass: %v", err)
	}
	// After sealing the head, the full Verify passes.
	if err := s.Seal(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.Verify(); err != nil {
		t.Errorf("Verify after sealing the head: %v", err)
	}
	// A further append leaves an unsealed tail past the last checkpoint → Verify rejects again.
	if _, err := s.Append(ctx, rec("more", time.Unix(9, 0).UTC(), "p")); err != nil {
		t.Fatal(err)
	}
	if err := s.Verify(); err == nil {
		t.Error("Verify accepted an unsealed tail appended after the last checkpoint")
	}
}

func TestAppend_AppendedAtMonotonicAcrossClockRollback(t *testing.T) {
	s, _ := newTestSink(t, 0)
	ctx := context.Background()
	// Simulate the previous append carrying a FUTURE timestamp (as if the wall clock has since
	// stepped backward): the next append must clamp to >= it, never regress the authoritative
	// timeline.
	future := time.Now().UTC().Add(time.Hour)
	s.lastAppendedAt = future
	ref, err := s.Append(ctx, rec("e", time.Unix(0, 0).UTC(), "p"))
	if err != nil {
		t.Fatal(err)
	}
	if ref.AppendedAt.Before(future) {
		t.Errorf("AppendedAt %v regressed below the previous append %v", ref.AppendedAt, future)
	}
}

func TestSeal_CoversStoreHeadGrownByAnotherSink(t *testing.T) {
	// A shared Store grown by a second Sink: Seal must cover the store's CURRENT head, not this
	// sink's stale cached prefix (else it signs an old head and reports success while later
	// records stay unsealed).
	ca := signing.NewDevCA()
	signer, _ := signing.NewSinkSigner(ca, "shared")
	store := newMemStore()
	ctx := context.Background()

	s1 := New(store, signer, ca.Root(), 0)
	if _, err := s1.Append(ctx, rec("a", time.Unix(0, 0).UTC(), "p")); err != nil {
		t.Fatal(err)
	}
	s2 := New(store, signer, ca.Root(), 0)
	if _, err := s2.Append(ctx, rec("b", time.Unix(1, 0).UTC(), "p")); err != nil {
		t.Fatal(err)
	}
	// s1's cached head is record 0, but the store head is now record 1.
	if err := s1.Seal(ctx); err != nil {
		t.Fatal(err)
	}
	cps := s1.Checkpoints()
	last := cps[len(cps)-1]
	if last.Count != 2 || last.HeadSequence != 1 {
		t.Errorf("seal covered head=%d count=%d, want head=1 count=2 (sealed a stale prefix)", last.HeadSequence, last.Count)
	}
	if err := s1.Verify(); err != nil {
		t.Errorf("verify after sealing the current head: %v", err)
	}
}

// emptyIDSigner is a miswired CheckpointSigner that reports no identity.
type emptyIDSigner struct{}

func (emptyIDSigner) SinkID() string { return "" }
func (emptyIDSigner) SignCheckpoint(context.Context, []byte) (signing.SinkSignature, error) {
	return signing.SinkSignature{}, nil
}

func TestSeal_NilStoreErrorsNotPanics(t *testing.T) {
	ca := signing.NewDevCA()
	signer, _ := signing.NewSinkSigner(ca, "x")
	// A miswired sink (nil store) must return a clean error from Seal, never panic — a panic on
	// the orchestrator's terminal seal path would crash teardown.
	s := New(nil, signer, ca.Root(), 0)
	if err := s.Seal(context.Background()); err == nil {
		t.Error("Seal on a nil-store sink should error")
	}
}

func TestSeal_RejectsEmptySinkID(t *testing.T) {
	ca := signing.NewDevCA()
	s := New(newMemStore(), emptyIDSigner{}, ca.Root(), 0)
	ctx := context.Background()
	if _, err := s.Append(ctx, rec("e", time.Unix(0, 0).UTC(), "p")); err != nil {
		t.Fatal(err)
	}
	// An empty sink identity must fail closed rather than commit an unattributed checkpoint.
	if err := s.Seal(ctx); err == nil {
		t.Error("Seal committed a checkpoint with an empty sink identity")
	}
	if len(s.Checkpoints()) != 0 {
		t.Errorf("no checkpoint should be committed with an empty sink identity, got %d", len(s.Checkpoints()))
	}
}

func TestSeal_RejectsUnverifiableSignature(t *testing.T) {
	// The sink trusts ca1's root, but the injected signer is certified by a DIFFERENT CA, so its
	// checkpoint signature will not verify under the sink's root. Seal must fail closed and
	// commit NO checkpoint, rather than store one VerifyCheckpoints would later reject (so the
	// orchestrator cannot report a "successful" terminal seal from a miswired signer).
	ca1 := signing.NewDevCA()
	ca2 := signing.NewDevCA()
	signer, _ := signing.NewSinkSigner(ca2, "x")
	s := New(newMemStore(), signer, ca1.Root(), 0)
	ctx := context.Background()
	if _, err := s.Append(ctx, rec("e", time.Unix(0, 0).UTC(), "p")); err != nil {
		t.Fatal(err)
	}
	if err := s.Seal(ctx); err == nil {
		t.Error("Seal committed a checkpoint whose signature does not verify under the sink's CA root")
	}
	if len(s.Checkpoints()) != 0 {
		t.Errorf("a non-verifying seal must not be committed, got %d checkpoints", len(s.Checkpoints()))
	}
}

func TestVerify_RejectsTailAppendedByAnotherSink(t *testing.T) {
	// A shared/durable Store can grow via another Sink instance. Verify must read the store's
	// length, not this sink's cached counter, or it would accept a longer unsealed tail.
	ca := signing.NewDevCA()
	signer, _ := signing.NewSinkSigner(ca, "shared")
	store := newMemStore()
	ctx := context.Background()

	s1 := New(store, signer, ca.Root(), 0)
	if _, err := s1.Append(ctx, rec("a", time.Unix(0, 0).UTC(), "p")); err != nil {
		t.Fatal(err)
	}
	if err := s1.Seal(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s1.Verify(); err != nil {
		t.Fatalf("s1 is fully sealed and should verify: %v", err)
	}

	// A second sink over the SAME store appends a record but does not seal it.
	s2 := New(store, signer, ca.Root(), 0)
	if _, err := s2.Append(ctx, rec("b", time.Unix(1, 0).UTC(), "p")); err != nil {
		t.Fatal(err)
	}
	// s1's cached count is stale (1) but the store now holds 2 records with an unsealed tail.
	if err := s1.Verify(); err == nil {
		t.Error("Verify accepted a store tail appended by another sink without sealing (trusted the cached counter)")
	}
}

func TestNew_HydratesFromNonEmptyStore(t *testing.T) {
	ca := signing.NewDevCA()
	signer, _ := signing.NewSinkSigner(ca, "resume-sink")
	store := newMemStore()
	ctx := context.Background()

	s1 := New(store, signer, ca.Root(), 0)
	for i := 0; i < 3; i++ {
		if _, err := s1.Append(ctx, rec("e", time.Unix(int64(i), 0).UTC(), "p")); err != nil {
			t.Fatal(err)
		}
	}
	// A fresh sink over the SAME populated store (a process restart). Without hydration its next
	// Append would collide with the next-sequence-only store at sequence 0.
	s2 := New(store, signer, ca.Root(), 0)
	if s2.Len() != 3 {
		t.Fatalf("resumed sink Len = %d, want 3", s2.Len())
	}
	ref, err := s2.Append(ctx, rec("resumed", time.Unix(3, 0).UTC(), "p"))
	if err != nil {
		t.Fatalf("resumed Append failed (head/count not hydrated): %v", err)
	}
	if ref.Sequence != 3 {
		t.Errorf("resumed append at sequence %d, want 3", ref.Sequence)
	}
	// The hash chain continues unbroken across the construction boundary.
	if err := s2.VerifyChain(); err != nil {
		t.Errorf("chain broken across resume: %v", err)
	}
}

func TestVerify_ConcurrentWithAppend(t *testing.T) {
	// Append/Seal/Verify run concurrently on one sink (the orchestrator shares a single sink
	// across sessions). Verify reads the store length and checkpoint snapshot under s.mu, so this
	// must be race-free (run under -race) and never panic.
	s, _ := newTestSink(t, 0)
	ctx := context.Background()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 60; i++ {
			if _, err := s.Append(ctx, rec("e", time.Unix(int64(i), 0).UTC(), "p")); err != nil {
				t.Errorf("append %d: %v", i, err)
				return
			}
			if err := s.Seal(ctx); err != nil {
				t.Errorf("seal %d: %v", i, err)
				return
			}
		}
	}()
	for {
		select {
		case <-done:
			return
		default:
			_ = s.Verify()
			_ = s.VerifyChain()
		}
	}
}
