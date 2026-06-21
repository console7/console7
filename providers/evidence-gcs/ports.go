package evidencegcs

import "context"

// objectIO is the narrow port confining cloud.google.com/go/storage. The real adapter
// (gcs_gcp.go) wraps a *storage.BucketHandle; the in-memory fake (fakes.go) lets all Store
// logic — sequence→name mapping, the no-overwrite/no-gap rules, the codec, the count — run
// credential-free in tests and conformance.
//
// SECURITY: the port exposes only create-if-absent, read, exists, and count. There is
// deliberately NO update and NO delete method, so the provider has no in-band code path to
// rewrite or remove committed history (control-plane/evidence.Store WORM contract). This is
// in-band defence-in-depth (GOAL.md tenet 3); object immutability is enforced AUTHORITATIVELY
// beneath this port by the GCS retention policy + bucket LOCK (deploy/gcp/modules/evidence) —
// the boundary control of record against a privileged actor. With the lock off (the default),
// that authoritative layer is absent and the posture is tamper-evident, not tamper-resistant
// (see doc.go).
type objectIO interface {
	// PutIfAbsent writes data at name iff name does not already exist, atomically (the GCS
	// DoesNotExist / ifGenerationMatch=0 precondition). It MUST return an error for which
	// errors.Is(err, errSlotOccupied) is true if the object already exists, so Append can fail
	// closed on an attempted rewrite. It carries and verifies a CRC32C checksum so a corrupted
	// write cannot be silently persisted.
	PutIfAbsent(ctx context.Context, name string, data []byte) error
	// Get returns the object's bytes. A missing object is (nil,false,nil), NOT an error, so the
	// caller distinguishes "absent slot" from a backend fault.
	Get(ctx context.Context, name string) (data []byte, found bool, err error)
	// Exists reports whether name is present, reading metadata only (no body download). A
	// missing object is (false,nil), not an error.
	Exists(ctx context.Context, name string) (bool, error)
	// Count returns the number of objects under prefix (equivalently the next free sequence).
	// It backs Store.Len; the Sink hydrates from it at startup and Verify/Seal walk it, but the
	// append path does not call it.
	Count(ctx context.Context, prefix string) (uint64, error)
}
