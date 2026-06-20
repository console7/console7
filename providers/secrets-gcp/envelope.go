package secretsgcp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
)

// AES-256-GCM envelope helpers, identical in shape to sdk/devkit's: the provider seals the
// subscription token under a per-user DEK and (in the in-memory fake KEK) wraps the DEK under
// the process key. The real KEK wrap is Cloud KMS, not these helpers.

// mintDEK returns a fresh random 32-byte data-encryption key (=> AES-256). A distinct DEK per
// store is what makes pooling impossible by construction.
func mintDEK() ([]byte, error) {
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return nil, errors.New("secretsgcp: crypto/rand failed minting DEK")
	}
	return dek, nil
}

// seal returns nonce||ciphertext for plaintext under key using AES-256-GCM, binding aad as
// additional authenticated data (pass nil for none). The nonce is random per call — GCM is
// catastrophic under nonce reuse.
func seal(key, plaintext, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, errors.New("secretsgcp: crypto/rand failed generating nonce")
	}
	return gcm.Seal(nonce, nonce, plaintext, aad), nil
}

// open reverses seal: it splits nonce||ciphertext and authenticates+decrypts under key and
// aad. A mismatched aad (or any tampering) fails authentication.
func open(key, blob, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(blob) < ns {
		return nil, errors.New("secretsgcp: sealed blob too short")
	}
	nonce, ct := blob[:ns], blob[ns:]
	return gcm.Open(nil, nonce, ct, aad)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key) // 32-byte key => AES-256.
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// zero overwrites a byte slice in place — best-effort hygiene for transient plaintext.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// randHex returns n cryptographically-random bytes hex-encoded. It panics on the
// (practically impossible) failure of the system CSPRNG rather than returning a predictable
// value — a predictable lease ref would be a security defect.
func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("secretsgcp: crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}
