//go:build evidence_gcs_integration

// Opt-in live integration test against a real GCS bucket (e.g. an evidence bucket in
// console7-dev). It is NEVER part of the CI gate — it compiles only under
// `-tags evidence_gcs_integration` and skips unless the environment names a bucket. It
// exercises the REAL Cloud Storage create-if-absent / read / count paths and the no-overwrite
// precondition.
//
// Run (against a SCRATCH bucket — appends are immutable under a retention policy):
//
//	C7_GCS_BUCKET=console7-dev-evidence-scratch \
//	go test -tags evidence_gcs_integration -run TestIntegration ./providers/evidence-gcs/...
//
// Credentials resolve from Application Default Credentials (e.g. `gcloud auth
// application-default login`, or Workload Identity Federation in CD). An optional
// C7_GCS_PREFIX overrides the object prefix so repeat runs do not collide on sequence 0.
package evidencegcs

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/console7/console7/control-plane/evidence"
	"github.com/console7/console7/sdk/interfaces"
)

func TestIntegration_AppendReadNoOverwrite(t *testing.T) {
	bucket := os.Getenv("C7_GCS_BUCKET")
	if bucket == "" {
		t.Skip("set C7_GCS_BUCKET to run the live integration test")
	}
	prefix := os.Getenv("C7_GCS_PREFIX")
	if prefix == "" {
		prefix = "records"
	}
	ctx := context.Background()
	s, err := New(ctx, Config{Bucket: bucket, ObjectPrefix: prefix})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = s.Close() }()

	base, err := s.Len(ctx)
	if err != nil {
		t.Fatalf("Len: %v", err)
	}
	rec := evidence.Entry{
		Record: interfaces.EvidenceRecord{
			SessionID: "it-sess", Subject: "it-subject", Persona: "author",
			Type: "tool-call", ObservedAt: time.Now(), Payload: []byte("live"),
		},
		Ref: interfaces.RecordRef{Sequence: base, Hash: []byte{0x01, 0x02}, AppendedAt: time.Now()},
	}
	if err := s.Append(ctx, rec); err != nil {
		t.Fatalf("Append: %v", err)
	}
	got, ok, err := s.At(ctx, base)
	if err != nil || !ok || !bytes.Equal(got.Record.Payload, []byte("live")) {
		t.Fatalf("At(%d) = ok %v err %v payload %q", base, ok, err, got.Record.Payload)
	}
	// A second write to the same slot must be rejected by the DoesNotExist precondition.
	if err := s.Append(ctx, rec); !errors.Is(err, errSlotOccupied) {
		t.Fatalf("expected errSlotOccupied on rewrite of sequence %d, got %v", base, err)
	}
}
