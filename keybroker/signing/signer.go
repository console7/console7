package signing

import (
	"crypto/ed25519"
	"errors"

	"github.com/console7/console7/sdk/interfaces"
)

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
func Verify(caRoot ed25519.PublicKey, payload []byte, sig Signature) error {
	// (0) guard key sizes before any ed25519.Verify — it PANICS on a wrong-length public
	// key, so a malformed (e.g. externally-decoded) evidence record must be rejected, not
	// allowed to crash the verifier.
	if len(caRoot) != ed25519.PublicKeySize {
		return errors.New("signing: CA root key has the wrong length")
	}
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
	if !ed25519.Verify(caRoot, certTBS(sig.Cert.NHI, sig.Cert.Session, sig.Cert.Subject, sig.Cert.Pub), sig.Cert.CASig) {
		return errors.New("signing: certificate does not chain to the trusted CA root")
	}
	// (2) the certified NHI key must have signed the payload.
	if !ed25519.Verify(sig.Cert.Pub, payload, sig.Sig) {
		return errors.New("signing: payload signature does not verify under the NHI key")
	}
	return nil
}
