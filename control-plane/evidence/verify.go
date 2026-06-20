package evidence

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/console7/console7/keybroker/signing"
)

// Verify is the full integrity check: the record hash chain is intact, every checkpoint is a
// valid signature by THIS sink over the head it pins (against the trust anchor the Sink was
// constructed with), AND the current record head is actually sealed (the latest checkpoint
// covers the last committed record). It is the single call an auditor uses to assert "this
// evidence log is unbroken AND fully sealed by this sink". A non-empty log with an unsealed
// tail (records appended after the last checkpoint, or never sealed) is rejected — use
// VerifyChain + VerifyCheckpoints directly for prefix-only verification.
func (s *Sink) Verify() error {
	if err := s.VerifyChain(); err != nil {
		return err
	}
	if err := s.VerifyCheckpoints(s.caRoot, s.sinkID); err != nil {
		return err
	}
	// Read the STORE's actual length, not this sink's cached counter: a shared/durable Store can
	// be appended through another Sink instance or process, leaving a longer unsealed tail this
	// sink never sealed. Trusting s.count would accept that tail as fully sealed. Take the length
	// AND the checkpoint snapshot under the SAME s.mu (the lock Append/Seal serialize on) so a
	// concurrent append cannot slip a new unsealed tail in between the two reads and let a stale
	// length match a stale checkpoint.
	s.mu.Lock()
	n, err := s.store.Len(context.Background())
	var head Checkpoint
	sealed := len(s.checkpoints) > 0
	if sealed {
		head = s.checkpoints[len(s.checkpoints)-1]
	}
	s.mu.Unlock()
	if err != nil {
		return fmt.Errorf("evidence: head-seal length read failed: %w", err)
	}

	if n == 0 {
		return nil
	}
	if !sealed {
		return errors.New("evidence: log has records but no checkpoint seals the head")
	}
	// The latest checkpoint must cover the store's current head: every committed record is sealed.
	if head.Count != n || head.HeadSequence != n-1 {
		return fmt.Errorf("evidence: head not sealed — latest checkpoint covers %d of %d records", head.Count, n)
	}
	return nil
}

// VerifyChain recomputes the record hash chain from genesis and reports the first break. It is
// how a test proves a mutated record is DETECTED. It is a verification path, never a mutation
// path.
func (s *Sink) VerifyChain() error {
	ctx := context.Background()
	n, err := s.store.Len(ctx)
	if err != nil {
		return fmt.Errorf("evidence: chain length read failed: %w", err)
	}
	var prior []byte
	for i := uint64(0); i < n; i++ {
		entry, ok, err := s.store.At(ctx, i)
		if err != nil {
			return fmt.Errorf("evidence: chain read failed at sequence %d: %w", i, err)
		}
		if !ok {
			return fmt.Errorf("evidence: chain gap at sequence %d", i)
		}
		if entry.Ref.Sequence != i {
			return fmt.Errorf("evidence: sequence gap at index %d (got %d)", i, entry.Ref.Sequence)
		}
		want := chainHash(prior, entry.Ref.Sequence, entry.Ref.AppendedAt, entry.Record)
		if !bytes.Equal(want, entry.Ref.Hash) {
			return fmt.Errorf("evidence: chain broken at sequence %d", entry.Ref.Sequence)
		}
		prior = entry.Ref.Hash
	}
	return nil
}

// VerifyCheckpoints checks, against the trusted CA root and an EXPECTED sink identity: (a)
// each checkpoint is sealed by expectedSinkID (the bound SinkID and the signature's SinkID
// both match, and that id is covered by the signature), (b) each checkpoint's signature chains
// to caRoot, (c) the checkpoint hash chain (PrevCkptHash) is intact (so no checkpoint was
// dropped or reordered in the interior), and (d) each checkpoint pins the real chain head it
// claims (HeadHash matches the committed record at HeadSequence). Combined with VerifyChain
// (which re-derives those record hashes from content), this proves: records intact AND a
// THIS-sink-signed attestation covers the head.
//
// Pinning expectedSinkID is what makes the attestation attributable: without it, ANY
// CA-certified sink's checkpoint would verify under a shared org CA root. Note this proves an
// internally-consistent, attributed PREFIX — tail truncation/rollback past the last verified
// checkpoint is resisted by the durable backing's retention lock, not by this in-band check
// (see doc.go residual table).
func (s *Sink) VerifyCheckpoints(caRoot ed25519.PublicKey, expectedSinkID string) error {
	s.mu.Lock()
	ckpts := make([]Checkpoint, len(s.checkpoints))
	copy(ckpts, s.checkpoints)
	s.mu.Unlock()

	ctx := context.Background()
	var prev []byte
	for i, c := range ckpts {
		if c.CkptSeq != uint64(i) {
			return fmt.Errorf("evidence: checkpoint sequence gap at index %d (got %d)", i, c.CkptSeq)
		}
		// The checkpoint must be sealed by the sink the auditor expects. The bound SinkID is
		// covered by the signature (checkpointTBS), so a mismatch is both an identity-pin failure
		// here and a signature failure below; checking it explicitly gives a precise error and
		// rejects a checkpoint whose signature SinkID was swapped to a different certified sink.
		if c.SinkID != expectedSinkID || c.Sig.SinkID != expectedSinkID {
			return fmt.Errorf("evidence: checkpoint %d sealed by %q, want %q", c.CkptSeq, c.SinkID, expectedSinkID)
		}
		if !bytes.Equal(c.PrevCkptHash, prev) {
			return fmt.Errorf("evidence: checkpoint chain broken at checkpoint %d", c.CkptSeq)
		}
		if err := signing.VerifySinkSignature(caRoot, checkpointTBS(c), c.Sig); err != nil {
			return fmt.Errorf("evidence: checkpoint %d signature invalid: %w", c.CkptSeq, err)
		}
		// Every emitted checkpoint pins a real committed head (empty seals are no-ops).
		entry, ok, err := s.store.At(ctx, c.HeadSequence)
		if err != nil {
			return fmt.Errorf("evidence: checkpoint %d head read failed: %w", c.CkptSeq, err)
		}
		if !ok || !bytes.Equal(entry.Ref.Hash, c.HeadHash) {
			return fmt.Errorf("evidence: checkpoint %d head hash does not match the record chain", c.CkptSeq)
		}
		prev = checkpointHash(c)
	}
	return nil
}
