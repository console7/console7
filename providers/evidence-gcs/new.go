package evidencegcs

import (
	"context"
	"fmt"

	"cloud.google.com/go/storage"
	"google.golang.org/api/option"
)

// New constructs the production Store, dialing GCS. Credentials resolve from Application Default
// Credentials (GKE Workload Identity in deployment) — no key file. Pass option.ClientOptions for
// tests/integration (e.g. an emulator endpoint); production passes none.
//
// New is the context-taking, erroring constructor control-plane/evidence.Store anticipates for a
// fallible durable backing: it PRE-FLIGHTS connectivity and hydration with the caller's context
// (a Len, and an At over the current tail) so a GCS fault surfaces HERE — before the Store is
// handed to control-plane/evidence.New, whose own hydration is best-effort over a background
// context. A backing that cannot be read at startup must not masquerade as empty (which would
// collide with the next-sequence-only Append at sequence 0).
//
// Call Close at shutdown to release the client.
func New(ctx context.Context, cfg Config, opts ...option.ClientOption) (*Store, error) {
	cfg, err := cfg.normalize()
	if err != nil {
		return nil, err
	}
	client, err := storage.NewClient(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("evidencegcs: dial Cloud Storage: %w", err)
	}
	s := &Store{
		obj:    &gcsObjectIO{bucket: client.Bucket(cfg.Bucket)},
		prefix: cfg.ObjectPrefix,
		closer: client,
	}
	if err := s.preflight(ctx); err != nil {
		_ = client.Close()
		return nil, err
	}
	return s, nil
}

// NewWithObjectIO wires a Store over an explicit objectIO (the in-memory fake in tests and
// conformance, or an out-of-tree adapter). It performs no I/O and has no client to close.
func NewWithObjectIO(obj objectIO, prefix string) *Store {
	if prefix == "" {
		prefix = DefaultObjectPrefix
	}
	return &Store{obj: obj, prefix: prefix}
}

// preflight verifies the backing is readable: it counts the log and, if non-empty, reads the
// tail entry, surfacing any GCS fault (and decode/hydration faults) before the Store is used.
func (s *Store) preflight(ctx context.Context) error {
	n, err := s.Len(ctx)
	if err != nil {
		return fmt.Errorf("evidencegcs: startup connectivity/hydration check failed: %w", err)
	}
	if n == 0 {
		return nil
	}
	// SAST-DEFERRED VVAH-2026-06-25 #16: preflight verifies the tail slot EXISTS, not that its hash
	// chains from its predecessor. Since chainHash uses no secret, a workload-SA holder who reads the
	// real tail can craft a valid forward record at the next slot and fork the chain. A tail
	// chain-integrity recompute here (and sequence-bound signatures, #31) is deferred to Phase 2
	// (evidence hardening); production retention-LOCK is the boundary control. See docs/ROADMAP.md
	// "SAST carry-forward". KNOWN/ACCEPTED, not an open finding. (The stray-object count inflation
	// half of this finding IS fixed — Count() now filters to record-shaped keys.)
	_, ok, err := s.At(ctx, n-1)
	if err != nil {
		return fmt.Errorf("evidencegcs: startup tail read failed at sequence %d: %w", n-1, err)
	}
	if !ok {
		// The count is non-zero but the tail slot is absent: a gap (e.g. a privileged delete) or a
		// stray non-record object under the prefix inflating the count. Fail closed rather than let
		// evidence.New's best-effort hydration publish a sink that looks empty and collides at 0.
		return fmt.Errorf("evidencegcs: store reports %d records but the tail at sequence %d is missing — refusing to start on a gapped/tampered backing", n, n-1)
	}
	return nil
}

// Close releases the GCS client New opened. It is safe to call on a fake-backed Store
// (NewWithObjectIO), where it is a no-op.
func (s *Store) Close() error {
	if s.closer == nil {
		return nil
	}
	return s.closer.Close()
}
