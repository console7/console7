package signing

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"errors"

	"github.com/console7/console7/sdk/interfaces"
)

// CA is the certificate-authority ROOT signing identity — the trust anchor every lineage Cert and
// SinkCert chains to. It is the ONLY thing a binder/sink-signer needs from the root: a way to sign a
// domain-tagged certificate TBS with the root key. DevCA (ca_dev.go) is the in-process ed25519 dev
// implementation; a KMS-backed EC-P256 implementation lands behind this same interface (the
// keybroker's distinct, hardened signing identity). Keeping CA to just Sign means the root key
// material — whether an in-process ed25519 key or a Cloud KMS handle — never leaves the implementation.
//
// The per-session NHI keys and the sink checkpoint keys are SEPARATE, ephemeral ed25519 leaf keys
// minted by the binder/sink-signer; only this ROOT identity's algorithm varies, which is why the
// verifiers (Verify / VerifySinkSignature) take a crypto.PublicKey anchor and dispatch on its type.
type CA interface {
	// Sign signs tbs (a domain-tagged cert TBS) with the CA root key, returning the CASig a verifier
	// checks against the trust anchor. It returns an error so a real (e.g. KMS) backend can fail
	// rather than panic; the in-process DevCA never errors.
	Sign(tbs []byte) ([]byte, error)
}

// SessionSigner signs commits and artefacts on behalf of one session's NHI. It holds the
// ephemeral private key (unexported, never returned) and the CA certificate that binds
// the NHI to the human Subject.
type SessionSigner struct {
	Subject   interfaces.Subject
	SessionID interfaces.SessionID
	Persona   interfaces.Persona
	NHI       string

	priv ed25519.PrivateKey
	cert Cert
}

// Signature is a signed artefact carrying its full lineage: the NHI that signed, the
// human Subject the NHI acts for, the session, the signature over the payload, and the
// CA certificate proving the NHI key legitimately speaks for the Subject.
type Signature struct {
	NHI       string
	Subject   interfaces.Subject
	SessionID interfaces.SessionID
	Sig       []byte
	Cert      Cert
}

// Sign signs payload (e.g. a commit digest) with the session NHI's key and returns a
// Signature stamped with the lineage. The orchestrator records this as evidence.
func (s *SessionSigner) Sign(payload []byte) Signature {
	return Signature{
		NHI:       s.NHI,
		Subject:   s.Subject,
		SessionID: s.SessionID,
		Sig:       ed25519.Sign(s.priv, payload),
		// Deep-copy the certificate: a shallow copy would alias this long-lived signer's own
		// cert.Pub/cert.CASig backing arrays, so a caller mutating the returned signature's cert
		// bytes would corrupt the signer (mirrors SinkSigner.SignCheckpoint).
		Cert: s.cert.clone(),
	}
}

// Verify checks a Signature against a trusted CA root and the original payload. It
// confirms the unbroken chain: (1) the CA root certifies the NHI key for the Subject,
// (2) that key signed the payload, and (3) the signature's lineage fields agree with the
// certificate. Any break is an error — lineage that does not verify is no lineage.
func Verify(caRoot crypto.PublicKey, payload []byte, sig Signature) error {
	// (0) guard the LEAF key size before ed25519.Verify — it PANICS on a wrong-length public key,
	// so a malformed (e.g. externally-decoded) evidence record must be rejected, not crash the
	// verifier. The ROOT key is guarded inside verifyRoot (it dispatches on the anchor's type).
	if len(sig.Cert.Pub) != ed25519.PublicKeySize {
		return errors.New("signing: certificate public key has the wrong length")
	}
	// (3) the signature's claimed lineage must match what the certificate binds — NHI,
	// Subject, and Session are all certified fields, so each is bound exactly (a free
	// sig.SessionID would otherwise be forgeable metadata an evidence consumer might trust).
	if sig.NHI != sig.Cert.NHI || sig.Subject != sig.Cert.Subject || sig.SessionID != sig.Cert.Session {
		return errors.New("signing: signature lineage does not match its certificate")
	}
	// (1) the CA root must have certified this NHI->session->Subject->key binding.
	if !verifyRoot(caRoot, certTBS(sig.Cert.NHI, sig.Cert.Session, sig.Cert.Subject, sig.Cert.Pub), sig.Cert.CASig) {
		return errors.New("signing: certificate does not chain to the trusted CA root")
	}
	// (2) the certified NHI key must have signed the payload.
	if !ed25519.Verify(sig.Cert.Pub, payload, sig.Sig) {
		return errors.New("signing: payload signature does not verify under the NHI key")
	}
	return nil
}

// verifyRoot checks a CA-root signature over msg, dispatching on the trust anchor's public-key
// TYPE so a verifier pins either the in-process ed25519 DevCA root or (added with the KMS adapter)
// a Cloud KMS EC-P256 root, without re-rippling every caller. It fails closed — a wrong-length key,
// a nil/unknown anchor type, or a bad signature all return false (never a panic). The ed25519 case
// guards the key length itself (ed25519.Verify panics on a wrong-length key).
func verifyRoot(caRoot crypto.PublicKey, msg, sig []byte) bool {
	switch k := caRoot.(type) {
	case ed25519.PublicKey:
		return len(k) == ed25519.PublicKeySize && ed25519.Verify(k, msg, sig)
	case *ecdsa.PublicKey:
		// The KMS-backed root: a Cloud KMS EC_SIGN_P256_SHA256 key signs the SHA-256 DIGEST of the
		// TBS and returns an ASN.1/DER ECDSA signature. PIN exactly that algorithm (curve P-256) and
		// guard EVERY field VerifyASN1 dereferences (Curve/X/Y) so a wrong-curve or partially-decoded
		// anchor (e.g. from a malformed KMS public-key PEM) fails CLOSED rather than panicking — and
		// so the arm enforces exactly the algorithm it names, not any NIST curve.
		if k == nil || k.Curve != elliptic.P256() || k.X == nil || k.Y == nil {
			return false
		}
		h := sha256.Sum256(msg)
		return ecdsa.VerifyASN1(k, h[:], sig)
	default:
		// An unrecognised anchor type fails closed rather than silently accepting an unverifiable chain.
		return false
	}
}
