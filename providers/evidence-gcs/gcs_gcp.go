package evidencegcs

import (
	"context"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net/http"

	"cloud.google.com/go/storage"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/iterator"
)

// maxObjectBytes caps a single evidence-object read. Records are small metadata (sub-KB in practice);
// this ceiling is generous headroom while bounding the heap an oversized/planted object can force.
const maxObjectBytes = 1 << 20 // 1 MiB

// gcsObjectIO is the real objectIO: append-only record objects in a GCS bucket. Immutability
// holds at two trust levels (see doc.go for the full statement):
//   - The APPEND identity (the workload SA) holds object create/get/list only. GCS requires
//     storage.objects.delete to OVERWRITE an existing object as well as to delete one, so
//     omitting delete means the append path can neither overwrite nor remove a committed record.
//   - Against a PRIVILEGED actor (the deploy identity can delete objects and remove an UNLOCKED
//     retention policy), the authoritative durability control is the bucket retention policy +
//     LOCK (deploy/gcp/modules/evidence; GOAL.md tenet 3, tenet 7). The lock is off by default,
//     so the default posture is tamper-EVIDENT (the Sink's hash-chain detects mutation), not
//     tamper-RESISTANT against a privileged actor — that needs the production lock.
//
// The DoesNotExist precondition below is in-band defence-in-depth on top of both.
//
// Every write carries a CRC32C checksum the server verifies (SendCRC32C), and every read
// re-verifies the bytes against the object's stored CRC32C — integrity in both directions, so a
// corrupted record can neither be silently persisted nor silently returned.
type gcsObjectIO struct {
	bucket *storage.BucketHandle
}

var _ objectIO = (*gcsObjectIO)(nil)

// crc32cTable is the Castagnoli polynomial table GCS uses for its CRC32C checksums.
var crc32cTable = crc32.MakeTable(crc32.Castagnoli)

func crc32cSum(b []byte) uint32 { return crc32.Checksum(b, crc32cTable) }

// PutIfAbsent writes data at name with a DoesNotExist precondition (no rewrite) in a single
// request (ChunkSize=0) so the server verifies the CRC32C. A pre-existing object surfaces as
// errSlotOccupied; any other fault is returned for the caller to fail closed on.
func (g *gcsObjectIO) PutIfAbsent(ctx context.Context, name string, data []byte) error {
	obj := g.bucket.Object(name).If(storage.Conditions{DoesNotExist: true})
	w := obj.NewWriter(ctx)
	w.ChunkSize = 0 // single-request upload so SendCRC32C is honoured
	w.SendCRC32C = true
	w.CRC32C = crc32cSum(data)
	if _, err := w.Write(data); err != nil {
		_ = w.Close()
		return asSlotOccupied(fmt.Errorf("evidencegcs: write object failed: %w", err))
	}
	if err := w.Close(); err != nil {
		// The DoesNotExist precondition failing (an occupied slot) surfaces here as HTTP 412.
		return asSlotOccupied(fmt.Errorf("evidencegcs: commit object failed: %w", err))
	}
	// Belt-and-suspenders: confirm the server-recorded CRC32C matches what we sent.
	if attrs := w.Attrs(); attrs != nil && attrs.CRC32C != w.CRC32C {
		return fmt.Errorf("evidencegcs: object CRC32C mismatch after write (corrupt) — refusing to trust the commit")
	}
	return nil
}

// Get reads the object and re-verifies its CRC32C. A missing object is (nil,false,nil).
func (g *gcsObjectIO) Get(ctx context.Context, name string) ([]byte, bool, error) {
	r, err := g.bucket.Object(name).NewReader(ctx)
	if err != nil {
		if errors.Is(err, storage.ErrObjectNotExist) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("evidencegcs: open object failed: %w", err)
	}
	defer func() { _ = r.Close() }()
	// Bound the read: an entity with storage.objects.create can plant an oversized object at an
	// unwritten evidence slot; an unbounded io.ReadAll would OOM the control plane on the preflight
	// read of that slot. An evidence record is small metadata; maxObjectBytes is far above any real
	// record. Reading one byte past the cap lets us reject "over cap" with a clear error.
	data, err := io.ReadAll(io.LimitReader(r, maxObjectBytes+1))
	if err != nil {
		return nil, false, fmt.Errorf("evidencegcs: read object failed: %w", err)
	}
	if int64(len(data)) > maxObjectBytes {
		return nil, false, fmt.Errorf("evidencegcs: object %q exceeds %d bytes — refusing to read (possible oversized-object DoS)", name, maxObjectBytes)
	}
	if got := crc32cSum(data); got != r.Attrs.CRC32C {
		return nil, false, fmt.Errorf("evidencegcs: object CRC32C mismatch on read (corrupt) — refusing to return the record")
	}
	return data, true, nil
}

// Exists reports presence via an attrs (metadata-only) read; absent is (false,nil).
func (g *gcsObjectIO) Exists(ctx context.Context, name string) (bool, error) {
	_, err := g.bucket.Object(name).Attrs(ctx)
	if err != nil {
		if errors.Is(err, storage.ErrObjectNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("evidencegcs: object attrs failed: %w", err)
	}
	return true, nil
}

// Count returns the number of objects under prefix, requesting names only to keep listing cheap.
func (g *gcsObjectIO) Count(ctx context.Context, prefix string) (uint64, error) {
	q := &storage.Query{Prefix: prefix}
	if err := q.SetAttrSelection([]string{"Name"}); err != nil {
		return 0, fmt.Errorf("evidencegcs: list projection failed: %w", err)
	}
	it := g.bucket.Objects(ctx, q)
	var n uint64
	for {
		attrs, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return 0, fmt.Errorf("evidencegcs: list objects failed: %w", err)
		}
		// Count only record-shaped keys (<prefix>/<20-digit seq>): a stray/crafted object under the
		// prefix (e.g. "records/notes") must not inflate the count, which preflight reads as the tail
		// sequence — one stray would otherwise point At() at an unwritten slot and DoS startup.
		if isRecordKey(attrs.Name, prefix) {
			n++
		}
	}
	return n, nil
}

// isRecordKey reports whether name is a record key under prefix: the prefix followed by exactly
// seqWidth decimal digits (the deterministic key shape from Store.objectName). prefix here is the
// listing prefix (s.prefix + "/").
func isRecordKey(name, prefix string) bool {
	if len(name) != len(prefix)+seqWidth || name[:len(prefix)] != prefix {
		return false
	}
	for _, c := range name[len(prefix):] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// asSlotOccupied tags a precondition-failed (HTTP 412) error as errSlotOccupied so Append can
// distinguish an attempted rewrite from a genuine durability fault.
func asSlotOccupied(err error) error {
	var apiErr *googleapi.Error
	if errors.As(err, &apiErr) && apiErr.Code == http.StatusPreconditionFailed {
		return fmt.Errorf("%w: %v", errSlotOccupied, err)
	}
	return err
}
