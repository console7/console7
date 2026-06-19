package signing

import (
	"crypto/ed25519"
	"errors"
	"strings"

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
		Cert:      s.cert,
	}
}

// Verify checks a Signature against a trusted CA root and the original payload. It
// confirms the unbroken chain: (1) the CA root certifies the NHI key for the Subject,
// (2) that key signed the payload, and (3) the signature's lineage fields agree with the
// certificate. Any break is an error — lineage that does not verify is no lineage.
func Verify(caRoot ed25519.PublicKey, payload []byte, sig Signature) error {
	// (3) the signature's claimed lineage must match what the certificate binds. The
	// Subject and NHI are certified directly; the SessionID is not a separate certified
	// field, so it is bound transitively by requiring the certified NHI to encode it
	// (nhi/<session>/<persona>) — otherwise sig.SessionID would be forgeable metadata an
	// evidence consumer might trust.
	if sig.NHI != sig.Cert.NHI || sig.Subject != sig.Cert.Subject {
		return errors.New("signing: signature lineage does not match its certificate")
	}
	if !strings.HasPrefix(sig.Cert.NHI, nhiPrefix(sig.SessionID)) {
		return errors.New("signing: signature session does not match the certified NHI")
	}
	// (1) the CA root must have certified this NHI->key->Subject binding.
	if !ed25519.Verify(caRoot, certTBS(sig.Cert.NHI, sig.Cert.Subject, sig.Cert.Pub), sig.Cert.CASig) {
		return errors.New("signing: certificate does not chain to the trusted CA root")
	}
	// (2) the certified NHI key must have signed the payload.
	if !ed25519.Verify(sig.Cert.Pub, payload, sig.Sig) {
		return errors.New("signing: payload signature does not verify under the NHI key")
	}
	return nil
}
