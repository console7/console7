package evidencegcs

import (
	"context"
	"fmt"
	"sync"
)

// This file provides a NON-PRODUCTION in-memory implementation of the objectIO port so the
// Store's contract logic — sequence→name mapping, no-overwrite/no-gap enforcement, the codec —
// can be exercised with no GCS bucket and no credentials: by this package's white-box tests, by
// the conformance harness (the real Sink backed by this Store over the fake), and by out-of-tree
// providers wanting the same coverage. It models the BEHAVIOURAL contract (atomic create-if-
// absent, no rewrite) but gives NONE of the durability or immutability a real bucket-lock gives.
// Never wire one into a deployment.

// InMemoryObjectIO is a fake objectIO backed by a map. It stores object BYTES (so the Store's
// codec is exercised, not bypassed), enforces create-if-absent, and can be told to fail to
// exercise the Store's fail-closed durability paths.
type InMemoryObjectIO struct {
	mu      sync.Mutex
	objects map[string][]byte
	failPut bool
	failGet bool
}

var _ objectIO = (*InMemoryObjectIO)(nil)

// NewInMemoryObjectIO returns an empty fake object store.
func NewInMemoryObjectIO() *InMemoryObjectIO {
	return &InMemoryObjectIO{objects: make(map[string][]byte)}
}

// SetFailPut makes PutIfAbsent return a (non-occupied) durability error, to exercise the Sink's
// fail-closed Append path.
func (m *InMemoryObjectIO) SetFailPut(fail bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failPut = fail
}

// SetFailGet makes Get return an error, to exercise read-fault handling.
func (m *InMemoryObjectIO) SetFailGet(fail bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failGet = fail
}

// PutIfAbsent writes iff name is absent; a re-write returns errSlotOccupied (modelling the GCS
// DoesNotExist precondition).
func (m *InMemoryObjectIO) PutIfAbsent(ctx context.Context, name string, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failPut {
		return fmt.Errorf("evidencegcs/fake: induced PutIfAbsent failure")
	}
	if _, exists := m.objects[name]; exists {
		return fmt.Errorf("evidencegcs/fake: %s: %w", name, errSlotOccupied)
	}
	cp := make([]byte, len(data))
	copy(cp, data)
	m.objects[name] = cp
	return nil
}

// Get returns a copy of the object's bytes; a missing object is (nil,false,nil).
func (m *InMemoryObjectIO) Get(ctx context.Context, name string) ([]byte, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failGet {
		return nil, false, fmt.Errorf("evidencegcs/fake: induced Get failure")
	}
	data, ok := m.objects[name]
	if !ok {
		return nil, false, nil
	}
	cp := make([]byte, len(data))
	copy(cp, data)
	return cp, true, nil
}

// Exists reports whether name is present.
func (m *InMemoryObjectIO) Exists(ctx context.Context, name string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.objects[name]
	return ok, nil
}

// Count returns the number of objects whose name starts with prefix.
func (m *InMemoryObjectIO) Count(ctx context.Context, prefix string) (uint64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var n uint64
	for name := range m.objects {
		// Mirror gcsObjectIO.Count: count only record-shaped keys so a stray object cannot inflate
		// the count (and thus the inferred tail sequence).
		if isRecordKey(name, prefix) {
			n++
		}
	}
	return n, nil
}
