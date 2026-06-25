package secretsgcp

import (
	"context"
	"encoding/binary"
	"errors"
	"time"

	"github.com/console7/console7/sdk/interfaces"
)

// AccessTokenMinter mints a short-lived GCP OAuth2 access token for the provider's workload
// identity, so the in-tenancy inference lane (Vertex) authenticates from a delivered short-lived
// token rather than the node metadata server (which the egress boundary / GKE metadata config denies
// the sandbox — the authoritative control). The real adapter is IAM Credentials generateAccessToken
// (self-impersonation of the workload SA — iamcredentials_gcp.go); the fake (fakes.go) returns a
// deterministic token for tests/conformance. The minted token is the ONLY thing that crosses this
// boundary: InjectInferenceCredential delivers it straight into the owning sandbox and never returns
// it to the control plane.
type AccessTokenMinter interface {
	// MintAccessToken mints an access token scoped to scopes, requesting a lifetime of `lifetime`.
	// The provider has already capped lifetime to the session deadline; the adapter MAY further cap
	// to the platform maximum (IAM access tokens default to 1h). It returns the token material and
	// its actual expiry, and MUST fail rather than return a token longer-lived than requested.
	MintAccessToken(ctx context.Context, scopes []string, lifetime time.Duration) (token []byte, expiry time.Time, err error)
}

// The provider logic depends only on these three ports; the cloud.google.com/go clients
// are confined to the adapters that satisfy them (kms_gcp.go, secretmanager_gcp.go) and to
// the in-memory fakes (fakes.go). They are exported so the conformance harness — and
// out-of-tree providers — can assemble a fully-faked provider via NewWithPorts without any
// GCP credentials.

// KEKWrapper performs provider-side envelope encryption: it wraps and unwraps a per-user
// data-encryption key (DEK) under a key-encryption key (KEK) the wrapper owns. The KEK
// material never crosses this boundary — only DEK plaintext (in) and KEK-wrapped ciphertext
// (out). The real adapter is Cloud KMS Encrypt/Decrypt against a single crypto key.
type KEKWrapper interface {
	// WrapDEK encrypts dek under the KEK and returns the ciphertext plus the KEK key
	// VERSION that performed the wrap (recorded for audit; unwrap does not need it because
	// KMS resolves the version from the ciphertext). aad is bound into the wrap as
	// Additional Authenticated Data so a wrapped DEK only unwraps under the same aad — the
	// provider passes the per-subject secret ID, cryptographically binding a DEK to its owner.
	WrapDEK(ctx context.Context, dek, aad []byte) (wrapped []byte, kekVersion string, err error)
	// UnwrapDEK reverses WrapDEK. It MUST fail (not return a bogus key) if aad does not match
	// the value used to wrap, so a swapped or confused secret cannot be unwrapped.
	UnwrapDEK(ctx context.Context, wrapped []byte, kekVersion string, aad []byte) (dek []byte, err error)
}

// SecretStore persists the per-subject sealed payload. One secret per subject. The real
// adapter is GCP Secret Manager. There is deliberately no list method — the provider
// addresses a subject's secret by its derived ID, never by enumeration.
type SecretStore interface {
	// Put creates the secret if absent and adds a new version carrying payload, returning the
	// version resource name. A re-login adds a new version that becomes "latest"; superseded
	// versions are not pruned here (the granted IAM role has no versions.destroy) — they remain
	// sealed under the same per-user DEK/AAD and are all crypto-shredded together by Destroy on
	// revoke. Pruning superseded versions is a future hardening (it would add versions.destroy).
	Put(ctx context.Context, secretID string, payload []byte) (version string, err error)
	// Get returns the latest enabled version's payload. A missing secret is (nil,false,nil),
	// NOT an error — the caller distinguishes "no stored token" from a backend failure.
	Get(ctx context.Context, secretID string) (payload []byte, found bool, err error)
	// Destroy makes the subject's material unrecoverable (destroy all versions + delete the
	// secret). It MUST be idempotent: destroying an absent secret is success, not an error.
	Destroy(ctx context.Context, secretID string) error
}

// Injector is the ownership oracle and delivery sink for subscription-token injection. Its
// method set matches what sdk/devkit.SandboxRegistry already exposes, so the registry
// satisfies it directly in tests and conformance. In production it is implemented by the
// data-plane sandbox attestation path — the providers/cloud-gcp Provider (Owns/DeliverIfOwned,
// B5) — which the orchestrator wires in via NewWithPorts. This convenience New still defaults to a
// fail-closed implementation (see denyInjector) until that wiring lands.
type Injector interface {
	// Owns reports whether h is a sandbox owned by exactly this subject and session. An
	// unknown, mismatched, or expired handle is not owned (fail closed).
	Owns(h interfaces.SandboxHandle, subject interfaces.Subject, session interfaces.SessionID) bool
	// DeliverIfOwned atomically re-checks ownership and, only if it still holds, delivers a
	// copy of material into the sandbox, returning whether it delivered. The single-step
	// check-and-deliver closes the race where a teardown between a separate Owns and a deliver
	// would let material land in a sandbox that is already gone.
	DeliverIfOwned(h interfaces.SandboxHandle, subject interfaces.Subject, session interfaces.SessionID, material []byte) bool
	// DeliverInferenceIfOwned is DeliverIfOwned for the INFERENCE lane: same atomic ownership re-check,
	// but it delivers the minted short-lived inference credential (the Vertex bearer) to the session's
	// per-session AUTH-PROXY gateway, NOT into the sandbox. The auth-proxy is the credential-attaching
	// reverse proxy the engine reaches Vertex through, so the SANDBOX STAYS CREDENTIAL-FREE — it never
	// holds the cloud bearer (the egress/metadata boundary denies it the metadata server). The
	// providers/cloud-gcp Provider satisfies this by exec'ing the auth-proxy binary's -deliver-token
	// mode. Returns whether it delivered; any error is non-delivery (fail closed).
	DeliverInferenceIfOwned(h interfaces.SandboxHandle, subject interfaces.Subject, session interfaces.SessionID, material []byte) bool
}

// payload is the cleartext-free envelope stored as one Secret Manager secret version. It
// carries no key the KEK doesn't wrap and no token the DEK doesn't seal: wrappedDEK is the
// per-user DEK under the KEK, sealedToken is the subscription token under that DEK, and
// kekVersion records which KEK version wrapped the DEK (audit only).
type payload struct {
	kekVersion  string
	wrappedDEK  []byte
	sealedToken []byte
}

// payloadMagic versions the on-the-wire format so a schema change is detectable rather than
// silently misparsed. Bump the trailing byte when the layout changes.
var payloadMagic = [4]byte{'C', '7', 'E', '1'}

// marshal encodes the payload as magic || len-prefixed(kekVersion) || len-prefixed(wrappedDEK)
// || len-prefixed(sealedToken). A length-prefixed binary form (not JSON) keeps the ciphertext
// out of any accidental string/JSON logging path and avoids base64 bloat.
func (p payload) marshal() []byte {
	out := make([]byte, 0, len(payloadMagic)+12+len(p.kekVersion)+len(p.wrappedDEK)+len(p.sealedToken))
	out = append(out, payloadMagic[:]...)
	out = appendField(out, []byte(p.kekVersion))
	out = appendField(out, p.wrappedDEK)
	out = appendField(out, p.sealedToken)
	return out
}

func appendField(dst, field []byte) []byte {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(field)))
	dst = append(dst, hdr[:]...)
	return append(dst, field...)
}

// unmarshalPayload reverses marshal, rejecting a wrong magic or any truncation.
func unmarshalPayload(b []byte) (payload, error) {
	if len(b) < len(payloadMagic) || [4]byte{b[0], b[1], b[2], b[3]} != payloadMagic {
		return payload{}, errors.New("secretsgcp: stored payload has unknown format")
	}
	rest := b[len(payloadMagic):]
	kekVersion, rest, err := takeField(rest)
	if err != nil {
		return payload{}, err
	}
	wrappedDEK, rest, err := takeField(rest)
	if err != nil {
		return payload{}, err
	}
	sealedToken, rest, err := takeField(rest)
	if err != nil {
		return payload{}, err
	}
	if len(rest) != 0 {
		return payload{}, errors.New("secretsgcp: stored payload has trailing bytes")
	}
	return payload{kekVersion: string(kekVersion), wrappedDEK: wrappedDEK, sealedToken: sealedToken}, nil
}

func takeField(b []byte) (field, rest []byte, err error) {
	if len(b) < 4 {
		return nil, nil, errors.New("secretsgcp: stored payload truncated (length header)")
	}
	n := binary.BigEndian.Uint32(b[:4])
	b = b[4:]
	if uint32(len(b)) < n {
		return nil, nil, errors.New("secretsgcp: stored payload truncated (field body)")
	}
	return b[:n], b[n:], nil
}
