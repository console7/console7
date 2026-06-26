package evidence

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"sync"
	"time"

	"github.com/console7/console7/keybroker/signing"
	"github.com/console7/console7/sdk/interfaces"
)

// CheckpointSigner seals the sink's chain head. The sink defines this NARROW interface and
// depends only on it, so the signing KEY lives in the keybroker (the only key-holder) and
// NEVER in this Tier-1 control-plane package (GOAL.md tenet 1/4; ARCHITECTURE.md §6.4). The
// keybroker's *signing.SinkSigner satisfies it; in a real deployment the call crosses to the
// hardened broker, which is why the seam carries a context and can error.
type CheckpointSigner interface {
	// SinkID is the sink identity the signer seals for; the sink binds it into the signed
	// checkpoint bytes so a verifier can pin WHICH sink sealed the chain.
	SinkID() string
	SignCheckpoint(ctx context.Context, tbs []byte) (signing.SinkSignature, error)
}

// Checkpoint is a sink-signed attestation over the record chain head at a point in time. It
// is DISTINCT from the per-record lineage signature the orchestrator embeds in each record's
// payload: that proves "human → NHI signed this event"; a checkpoint proves "THIS sink
// committed a chain with this head" (the SinkID is bound into the signature). Checkpoints form
// their OWN hash chain (PrevCkptHash), so an INTERIOR drop or reorder is detected. Note this
// in-band chain does NOT by itself detect TAIL truncation/rollback (dropping the most recent
// checkpoints leaves a valid signed prefix) — that is resisted by the durable backing's
// retention lock (providers/evidence-gcs), tracked in the doc.go residual table.
type Checkpoint struct {
	// SinkID is the identity that sealed this checkpoint. It is bound into the signed bytes, so
	// a checkpoint sealed by a DIFFERENT CA-certified sink cannot be passed off as this log's.
	SinkID         string
	CkptSeq        uint64
	HeadSequence   uint64
	HeadHash       []byte
	Count          uint64
	CheckpointedAt time.Time
	PrevCkptHash   []byte
	Sig            signing.SinkSignature
}

// Sink is the real Tier-1 control-plane EvidenceSink (interfaces.EvidenceSink): append-only/
// WORM, hash-chained, sink-level signed, fail-closed, and separate from the operational DB.
// It holds NO signing key — it seals checkpoints through an injected CheckpointSigner backed
// by the keybroker. It upgrades the bench double devkit.MemEvidence to the production sink;
// the in-memory backing here is the bench/conformance store, with GCS landing behind the
// Store seam in a later PR (docs/ROADMAP.md). See doc.go for the bench-vs-real scope table.
type Sink struct {
	mu     sync.Mutex
	store  Store
	signer CheckpointSigner
	// caRoot is the trust anchor self-verification (Verify) checks against. It is the CA's
	// PUBLIC key (an ed25519.PublicKey from the DevCA, or a KMS root's public key), never a
	// signing key — storing it does not make this a key-holder. crypto.PublicKey so the sink
	// pins whichever root algorithm the keybroker uses; VerifySinkSignature dispatches on its type.
	caRoot crypto.PublicKey
	// sinkID is this sink's identity, read from the signer; bound into every checkpoint and
	// pinned by Verify so a chain's seal is attributable to THIS sink.
	sinkID string

	// ckptEvery is the periodic checkpoint cadence in records. 0 means checkpoints are produced
	// only by an explicit Seal (the orchestrator seals at session-end/teardown), which is the
	// natural per-session assurance unit.
	ckptEvery int

	head    []byte
	headSeq uint64
	count   uint64
	// lastAppendedAt is the previous record's stamped AppendedAt, used to keep the authoritative
	// timeline monotonic even if the host wall clock steps backward (NTP) between appends.
	lastAppendedAt time.Time
	sinceCkpt      int
	checkpoints    []Checkpoint
}

// New returns a Sink committing through store and sealing checkpoints through signer. caRoot
// is the trust anchor Verify pins. A nil store or signer is a construction error surfaced on
// first Append/Seal. ckptEvery<=0 produces checkpoints only on Seal.
//
// If store already holds records (e.g. a durable Store after a process restart), New hydrates
// the in-memory chain head/sequence/count from it, so the next Append continues the existing
// log rather than colliding with the next-sequence-only store at sequence 0. NOTE: the
// checkpoint log is NOT persisted in the Store this phase (checkpoints are an in-memory
// parallel log), so a resumed sink starts a FRESH checkpoint chain over the hydrated head;
// durable checkpoint persistence/resume is a providers/evidence-gcs concern (see doc.go). A
// fallible durable Store should add a context-taking, erroring constructor there; New uses a
// background context and best-effort hydration because the in-memory store cannot fault.
func New(store Store, signer CheckpointSigner, caRoot crypto.PublicKey, ckptEvery int) *Sink {
	var sinkID string
	if signer != nil {
		sinkID = signer.SinkID()
	}
	s := &Sink{
		store:  store,
		signer: signer,
		// The anchor is a long-lived pinned public key the caller does not mutate, so storing the
		// reference is sound (no defensive copy — a crypto.PublicKey may be a pointer type such as
		// *ecdsa.PublicKey, not a slice we could copy uniformly).
		caRoot:    caRoot,
		sinkID:    sinkID,
		ckptEvery: ckptEvery,
	}
	if store != nil {
		// Best-effort hydration: the in-memory store cannot fault, and a fallible durable store
		// gets a context-taking, erroring constructor in providers/evidence-gcs.
		_ = s.refreshFromStoreLocked(context.Background())
	}
	return s
}

// refreshFromStoreLocked syncs the in-memory chain head/sequence/count and the
// monotonic-time watermark from the Store, which is the source of truth. The caller holds
// s.mu (New calls it pre-publication, where there is no contention). It lets Seal cover the
// Store's CURRENT head — not a stale cached prefix — when a durable Store has grown since this
// sink last wrote, and lets New resume an existing log.
func (s *Sink) refreshFromStoreLocked(ctx context.Context) error {
	n, err := s.store.Len(ctx)
	if err != nil {
		return err
	}
	if n == 0 {
		s.head, s.headSeq, s.count, s.lastAppendedAt = nil, 0, 0, time.Time{}
		return nil
	}
	last, ok, err := s.store.At(ctx, n-1)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("evidence: store reports %d records but head %d is missing", n, n-1)
	}
	s.head = cloneBytes(last.Ref.Hash)
	s.headSeq = last.Ref.Sequence
	s.count = n
	s.lastAppendedAt = last.Ref.AppendedAt
	return nil
}

// NewInMemory is the bench/conformance convenience: a Sink over an in-memory Store. The real
// durable backing (GCS bucket-lock) is a later PR; do not mistake a green run here for a
// durable WORM store (see doc.go).
func NewInMemory(signer CheckpointSigner, caRoot crypto.PublicKey, ckptEvery int) *Sink {
	return New(newMemStore(), signer, caRoot, ckptEvery)
}

// Append commits a record to the append-only, hash-chained, WORM store and returns its
// position. It stamps the sink's OWN authoritative AppendedAt (never trusting the caller's
// ObservedAt for ordering), defensively copies the payload, commits through the Store before
// advancing any in-memory state (so a durability fault fails closed without a half-written
// chain), and — if a periodic checkpoint is due — seals the new head.
//
// Append's error contract is unambiguous, matching the EvidenceSink seam: a non-nil error
// means the record was NOT durably committed. Once the store commit succeeds, Append returns
// success even if a DUE periodic checkpoint then fails to sign — the record is committed (and
// must be Streamed); the unsealed tail is hash-linked and will be covered by the next
// checkpoint, and a PERSISTENT signer failure surfaces at the authoritative session-end Seal
// (which does return its error). Conflating a post-commit seal failure with an append failure
// would make callers like orchestrator.appendSigned skip Stream for a record that IS committed.
func (s *Sink) Append(ctx context.Context, rec interfaces.EvidenceRecord) (interfaces.RecordRef, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.store == nil || s.signer == nil {
		return interfaces.RecordRef{}, errors.New("evidence: sink is not fully constructed (nil store or signer)")
	}

	prior := s.head
	seq := s.count
	// The sink's authoritative time. rec.ObservedAt is caller-supplied and untrusted, so it is
	// hashed as content (a back-dated value is therefore covered by the chain) but is NEVER the
	// timeline — AppendedAt is. Clamp it to be monotonic non-decreasing against the previous
	// append: the Go monotonic clock reading is stripped once stored, so a backward wall-clock
	// step (NTP) must not let a later sequence carry an earlier authoritative timestamp.
	appendedAt := time.Now().UTC()
	if appendedAt.Before(s.lastAppendedAt) {
		appendedAt = s.lastAppendedAt
	}
	// A WORM record the caller can still mutate via a retained slice is not append-only, so copy
	// the payload before committing it.
	stored := rec
	stored.Payload = cloneBytes(rec.Payload)
	h := chainHash(prior, seq, appendedAt, stored)
	committed := interfaces.RecordRef{Sequence: seq, Hash: h, AppendedAt: appendedAt}

	// Commit through the WORM store FIRST. If it cannot durably commit, fail closed: return the
	// error and advance NO in-memory state, so the chain is never half-written and the record is
	// never silently dropped.
	if err := s.store.Append(ctx, Entry{Record: stored, Ref: committed}); err != nil {
		return interfaces.RecordRef{}, fmt.Errorf("evidence: append failed closed: %w", err)
	}

	// The record is now durable. Advance the chain head.
	s.head = h
	s.headSeq = seq
	s.count++
	s.sinceCkpt++
	s.lastAppendedAt = appendedAt

	out := interfaces.RecordRef{Sequence: seq, Hash: cloneBytes(h), AppendedAt: appendedAt}

	// A periodic checkpoint due? The record is ALREADY committed, so a seal failure must neither
	// un-commit it (that would violate "never drop") nor fail the Append (that would make callers
	// skip Stream for a committed record). It is therefore best-effort: on failure leave sinceCkpt
	// so the next Append/Seal retries, and let the chain stay valid (an unsealed-but-chained
	// record is hash-linked and the next checkpoint covers it). A persistent signer failure is
	// caught at the authoritative session-end Seal, which returns its error.
	if s.ckptEvery > 0 && s.sinceCkpt >= s.ckptEvery {
		_, _ = s.sealLocked(ctx)
	}
	return out, nil
}

// Stream mirrors a committed record to the adopter's SIEM. On the bench there is no external
// SIEM and, by tenet 1, MUST be no off-box egress — so it fails closed on a forged/unknown
// ref (verifying the ref names a record this sink actually committed, by sequence AND hash)
// and is otherwise a no-op. The real SIEM webhook lands with providers/evidence-gcs. It
// supplements, never replaces, the durable WORM append.
func (s *Sink) Stream(ctx context.Context, ref interfaces.RecordRef) error {
	entry, ok, err := s.store.At(ctx, ref.Sequence)
	if err != nil {
		return fmt.Errorf("evidence: stream lookup failed: %w", err)
	}
	if !ok {
		return errors.New("evidence: cannot stream an unknown record ref")
	}
	if !bytes.Equal(entry.Ref.Hash, ref.Hash) {
		return errors.New("evidence: stream ref does not match the committed record")
	}
	return nil
}

// Seal forces a sink-signed checkpoint over the current chain head. The orchestrator calls
// Seal at session-end and on abort/teardown: because the sink's checkpoint signer is
// long-lived (not session-deadline-bound like the per-record lineage signer), a session that
// overran its work deadline can still seal its close-out — partially closing the PR1 teardown
// residual. The sealed checkpoint is readable via Checkpoints; Seal returns only an error so
// it satisfies the orchestrator's narrow, type-asserted sealer capability.
func (s *Sink) Seal(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.signer == nil {
		return errors.New("evidence: cannot seal without a checkpoint signer")
	}
	_, err := s.sealLocked(ctx)
	return err
}

// sealLocked builds, signs, and appends a checkpoint over the current head. The caller holds
// s.mu. Sealing an EMPTY chain is a no-op (nothing to attest), so every emitted checkpoint
// pins a real committed head. A signer failure leaves the checkpoint log untouched (no
// partial checkpoint).
func (s *Sink) sealLocked(ctx context.Context) (Checkpoint, error) {
	// Cover the Store's CURRENT head, not a stale cached prefix: if a durable Store grew since
	// this sink last wrote, sealing the old head would sign only a prefix and report success
	// while the latest records stay unsealed. Fail (do not commit a checkpoint) if the head
	// cannot be read.
	if s.store == nil || s.signer == nil {
		return Checkpoint{}, errors.New("evidence: cannot seal — sink is not fully constructed (nil store or signer)")
	}
	if err := s.refreshFromStoreLocked(ctx); err != nil {
		return Checkpoint{}, err
	}
	if s.count == 0 {
		return Checkpoint{}, nil
	}
	// Fail closed rather than commit an UNATTRIBUTED checkpoint: an external signer that reports
	// an empty SinkID would otherwise produce a seal that "verifies" against a pinned "" identity
	// but names no concrete sink. (NewSinkSigner already rejects empty IDs; this guards the seam.)
	if s.sinkID == "" {
		return Checkpoint{}, errors.New("evidence: refusing to seal a checkpoint with an empty sink identity")
	}
	var prev []byte
	if n := len(s.checkpoints); n > 0 {
		prev = checkpointHash(s.checkpoints[n-1])
	}
	ckpt := Checkpoint{
		SinkID:         s.sinkID,
		CkptSeq:        uint64(len(s.checkpoints)),
		HeadSequence:   s.headSeq,
		HeadHash:       cloneBytes(s.head),
		Count:          s.count,
		CheckpointedAt: time.Now().UTC(),
		PrevCkptHash:   prev,
	}
	tbs := checkpointTBS(ckpt)
	sig, err := s.signer.SignCheckpoint(ctx, tbs)
	if err != nil {
		return Checkpoint{}, err
	}
	// Fail closed if the external signer (an out-of-process seam) returned a signature this
	// sink's own verifier would later reject — a miswired/compromised signer must NOT yield a
	// checkpoint the orchestrator can report as a "successful" seal. The sink already holds the
	// CA root and its expected identity, so it validates before committing.
	if sig.SinkID != s.sinkID {
		return Checkpoint{}, fmt.Errorf("evidence: checkpoint signer returned sink id %q, want %q", sig.SinkID, s.sinkID)
	}
	if err := signing.VerifySinkSignature(s.caRoot, tbs, sig); err != nil {
		return Checkpoint{}, fmt.Errorf("evidence: checkpoint signature does not verify, refusing to commit it: %w", err)
	}
	ckpt.Sig = sig
	s.checkpoints = append(s.checkpoints, ckpt)
	s.sinceCkpt = 0
	return cloneCheckpoint(ckpt), nil
}

// SinkID returns this sink's identity (the one bound into its checkpoints). An auditor pins it
// when calling VerifyCheckpoints to assert which sink sealed a chain.
func (s *Sink) SinkID() string {
	return s.sinkID
}

// NextSequence returns the chain position the next Append will assign (Append uses s.count under the
// same lock), so the orchestrator can bind it into the per-record signature before appending.
func (s *Sink) NextSequence(ctx context.Context) (uint64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.count, nil
}

// Len returns the number of committed records. Test/inspection hook, signature-compatible
// with devkit.MemEvidence so call sites swap without change.
//
// TODO(evidence-gcs): the in-memory store cannot error, so collapsing a Store error to 0 is
// harmless today; against a fallible (GCS) backing this would read a transient fault as
// "empty". The assurance path (VerifyChain) reads the store directly and DOES surface errors,
// so this swallow never sits on a security check — but revisit the signature when a real Store
// lands so an inspector cannot misread a backing fault as an empty log.
func (s *Sink) Len() int {
	n, err := s.store.Len(context.Background())
	if err != nil {
		return 0
	}
	return int(n)
}

// At returns the committed record and ref at sequence i (copies, so an inspector cannot
// mutate committed history). Test/inspection hook, signature-compatible with MemEvidence.
// See the Len TODO re: Store-error swallowing against a future fallible backing.
func (s *Sink) At(i int) (interfaces.EvidenceRecord, interfaces.RecordRef, bool) {
	if i < 0 {
		return interfaces.EvidenceRecord{}, interfaces.RecordRef{}, false
	}
	entry, ok, err := s.store.At(context.Background(), uint64(i))
	if err != nil || !ok {
		return interfaces.EvidenceRecord{}, interfaces.RecordRef{}, false
	}
	return entry.Record, entry.Ref, true
}

// Checkpoints returns defensive copies of the sealed checkpoints. Test/inspection hook.
func (s *Sink) Checkpoints() []Checkpoint {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Checkpoint, len(s.checkpoints))
	for i, c := range s.checkpoints {
		out[i] = cloneCheckpoint(c)
	}
	return out
}

// chainHash computes the tamper-evidence link over the prior hash and this record's committed
// content. It is intentionally IDENTICAL to devkit.MemEvidence.chainHash (SHA-256,
// length-prefixed fields, prior-hash + seq + sink-stamped AppendedAt + every record field —
// including the untrusted ObservedAt, so a back-dated timestamp is itself covered): the real
// sink and the bench double must produce the same chain so they are interchangeable behind the
// EvidenceSink seam. The duplication of this small, security-reviewed helper is deliberate —
// extracting a shared package would pull structure forward beyond this PR's scope.
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

// checkpointDomain separates checkpoint-signed bytes from every other signing context (the
// lineage cert "c7-cert-v1", commit "c7-commit-v1", per-record evidence "c7-evidence-v1", sink
// cert "c7-sinkcert-v1"), so a checkpoint signature can never be replayed as another.
const checkpointDomain = "c7-ckpt-v1"

// checkpointTBS is the canonical, domain-tagged, length-prefixed "to-be-signed" encoding of a
// checkpoint. The signature (and the checkpoint hash) cover exactly these bytes, so altering
// any field — including the pinned HeadHash or the PrevCkptHash chain link — breaks verification.
func checkpointTBS(c Checkpoint) []byte {
	var b []byte
	b = append(b, checkpointDomain...)
	b = appendBytesField(b, []byte(c.SinkID))
	b = appendUint64(b, c.CkptSeq)
	b = appendUint64(b, c.HeadSequence)
	b = appendBytesField(b, c.HeadHash)
	b = appendUint64(b, c.Count)
	b = appendUint64(b, uint64(c.CheckpointedAt.UnixNano()))
	b = appendBytesField(b, c.PrevCkptHash)
	return b
}

// checkpointHash is the SHA-256 of a checkpoint's signed bytes, used as the PrevCkptHash link
// of the next checkpoint so the checkpoint set is itself a tamper-evident chain.
func checkpointHash(c Checkpoint) []byte {
	sum := sha256.Sum256(checkpointTBS(c))
	return sum[:]
}

// cloneBytes returns an independent copy of b (nil for nil).
func cloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	c := make([]byte, len(b))
	copy(c, b)
	return c
}

// cloneCheckpoint returns a copy of c whose byte slices (head/prev hashes and the embedded
// signature material) are freshly allocated, so a returned checkpoint never aliases internal
// state.
func cloneCheckpoint(c Checkpoint) Checkpoint {
	c.HeadHash = cloneBytes(c.HeadHash)
	c.PrevCkptHash = cloneBytes(c.PrevCkptHash)
	c.Sig.Sig = cloneBytes(c.Sig.Sig)
	c.Sig.Cert.Pub = cloneBytes(c.Sig.Cert.Pub)
	c.Sig.Cert.CASig = cloneBytes(c.Sig.Cert.CASig)
	return c
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

// appendUint64 appends a fixed-width big-endian uint64 to b.
func appendUint64(b []byte, v uint64) []byte {
	var u8 [8]byte
	binary.BigEndian.PutUint64(u8[:], v)
	return append(b, u8[:]...)
}

// appendBytesField appends an 8-byte big-endian length prefix followed by the field bytes, so
// no field-boundary ambiguity can let two distinct checkpoints collide.
func appendBytesField(b, field []byte) []byte {
	b = appendUint64(b, uint64(len(field)))
	return append(b, field...)
}
