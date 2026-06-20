package secretsgcp

import (
	"context"
	"crypto/rand"
	"errors"
	"sync"

	"github.com/console7/console7/sdk/interfaces"
)

// This file provides NON-PRODUCTION in-memory implementations of the KEKWrapper and
// SecretStore ports so the provider's contract logic can be exercised with no GCP project and
// no credentials — by this package's white-box tests, by the conformance harness, and by
// out-of-tree providers wanting the same coverage. They model the BEHAVIOURAL contract (AAD
// binding, per-user keying, crypto-shred) but give none of the cryptographic-boundary
// guarantees a real KMS/HSM provides. Never wire one into a deployment.

// InMemoryKEK is a fake KEKWrapper backed by a single process-local AES-256-GCM key standing
// in for the Cloud KMS KEK. It honours the AAD binding (a wrong AAD fails to unwrap) and can
// be told to fail wrap/unwrap to exercise the provider's fail-closed paths.
type InMemoryKEK struct {
	mu         sync.Mutex
	key        []byte
	version    string
	failWrap   bool
	failUnwrap bool
}

var _ KEKWrapper = (*InMemoryKEK)(nil)

// NewInMemoryKEK returns a fake KEK with a freshly-generated random key.
func NewInMemoryKEK() *InMemoryKEK {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic("secretsgcp: crypto/rand failed generating fake KEK: " + err.Error())
	}
	return &InMemoryKEK{key: key, version: "fake-kek/cryptoKeyVersions/1"}
}

// SetFailWrap makes WrapDEK return an error, to exercise a store-time KMS failure.
func (k *InMemoryKEK) SetFailWrap(fail bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.failWrap = fail
}

// SetFailUnwrap makes UnwrapDEK return an error, to exercise the inject-time fail-closed path.
func (k *InMemoryKEK) SetFailUnwrap(fail bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.failUnwrap = fail
}

// WrapDEK seals the DEK under the process key (binding aad), modelling KMS Encrypt.
func (k *InMemoryKEK) WrapDEK(ctx context.Context, dek, aad []byte) ([]byte, string, error) {
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.failWrap {
		return nil, "", errors.New("secretsgcp/fake: induced WrapDEK failure")
	}
	wrapped, err := seal(k.key, dek, aad)
	if err != nil {
		return nil, "", err
	}
	return wrapped, k.version, nil
}

// UnwrapDEK opens the wrapped DEK under the process key (binding aad), modelling KMS Decrypt.
// A wrong aad fails authentication, as a real KMS would.
func (k *InMemoryKEK) UnwrapDEK(ctx context.Context, wrapped []byte, kekVersion string, aad []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.failUnwrap {
		return nil, errors.New("secretsgcp/fake: induced UnwrapDEK failure")
	}
	return open(k.key, wrapped, aad)
}

// InMemoryStore is a fake SecretStore backed by a map. It records a version counter (so a
// re-login is observably a new version) and tombstones destroyed secrets, and exposes
// inspection hooks for tests.
type InMemoryStore struct {
	mu       sync.Mutex
	payloads map[string][]byte
	versions map[string]int
}

var _ SecretStore = (*InMemoryStore)(nil)

// NewInMemoryStore returns an empty fake store.
func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{
		payloads: make(map[string][]byte),
		versions: make(map[string]int),
	}
}

// Put records a new version of the secret's payload.
func (s *InMemoryStore) Put(ctx context.Context, secretID string, payload []byte) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.versions[secretID]++
	cp := make([]byte, len(payload))
	copy(cp, payload)
	s.payloads[secretID] = cp
	return secretIDVersion(secretID, s.versions[secretID]), nil
}

// Get returns the latest payload; a missing secret is (nil,false,nil).
func (s *InMemoryStore) Get(ctx context.Context, secretID string) ([]byte, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.payloads[secretID]
	if !ok {
		return nil, false, nil
	}
	cp := make([]byte, len(p))
	copy(cp, p)
	return cp, true, nil
}

// Destroy removes the secret and all its versions; absent is success (idempotent).
func (s *InMemoryStore) Destroy(ctx context.Context, secretID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.payloads, secretID)
	delete(s.versions, secretID)
	return nil
}

// Stored returns the raw stored payload for a secret, for test inspection (e.g. asserting it
// does not contain the plaintext). It is the fake's test-only read path; the production
// SecretStore has no such hook.
func (s *InMemoryStore) Stored(secretID string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.payloads[secretID]
	if !ok {
		return nil, false
	}
	cp := make([]byte, len(p))
	copy(cp, p)
	return cp, true
}

// Versions returns how many versions have been stored for a secret (0 if absent), letting a
// test assert a re-login added a new version.
func (s *InMemoryStore) Versions(secretID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.versions[secretID]
}

func secretIDVersion(secretID string, n int) string {
	return secretID + "/versions/" + itoa(n)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// denyInjector is the fail-closed Injector New wires until the real data-plane sandbox exists:
// it owns nothing and delivers nothing, so a production InjectSubscriptionToken refuses rather
// than delivering into an unverified sandbox (docs/THREAT-MODEL.md §1; GOAL.md tenet 2 — the
// boundary wins, fail closed).
type denyInjector struct{}

var _ Injector = denyInjector{}

func (denyInjector) Owns(interfaces.SandboxHandle, interfaces.Subject, interfaces.SessionID) bool {
	return false
}

func (denyInjector) DeliverIfOwned(interfaces.SandboxHandle, interfaces.Subject, interfaces.SessionID, []byte) bool {
	return false
}
