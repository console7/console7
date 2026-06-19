package signing

import (
	"crypto/ed25519"
	"encoding/binary"

	"github.com/console7/console7/sdk/interfaces"
)

// DevCA is an in-process, NON-PRODUCTION certificate authority modelling an org CA or a
// Sigstore-keyless issuer. It issues short-lived certificates that bind a per-session
// NHI name and its public key to the human Subject the NHI acts for. Its root key is the
// trust anchor a verifier checks against.
type DevCA struct {
	rootPriv ed25519.PrivateKey
	rootPub  ed25519.PublicKey
}

// Cert binds a non-human identity to a public key and to the human Subject it acts for,
// signed by the CA root. It is the verifiable link in the lineage chain: a verifier that
// trusts the CA root can confirm a given NHI key legitimately speaks for a given Subject
// in a given session.
type Cert struct {
	NHI     string
	Session interfaces.SessionID
	Subject interfaces.Subject
	Pub     ed25519.PublicKey
	// CASig is the CA root's signature over the canonical (NHI, Session, Subject, Pub)
	// tuple. Session is certified as its own field — not inferred from the NHI string —
	// so a Signature's SessionID is bound exactly, not by a prefix match.
	CASig []byte
}

// NewDevCA generates a fresh CA root key. It panics on CSPRNG failure rather than
// returning a CA with a predictable key.
func NewDevCA() *DevCA {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic("signing: ed25519 key generation failed: " + err.Error())
	}
	return &DevCA{rootPriv: priv, rootPub: pub}
}

// Issue signs a certificate binding nhi + session + subject + pub. The CA does not retain
// the certificate; the holder (a SessionSigner) carries it and presents it at verify time.
func (c *DevCA) Issue(nhi string, session interfaces.SessionID, subject interfaces.Subject, pub ed25519.PublicKey) Cert {
	sig := ed25519.Sign(c.rootPriv, certTBS(nhi, session, subject, pub))
	return Cert{NHI: nhi, Session: session, Subject: subject, Pub: pub, CASig: sig}
}

// Root returns the CA's public key — the trust anchor a verifier pins.
func (c *DevCA) Root() ed25519.PublicKey {
	return c.rootPub
}

// certTBS is the canonical "to-be-signed" encoding of a certificate's bound fields. Each
// field is length-prefixed so the encoding is unambiguous: no choice of NHI or Subject
// (both derived from external input — an SSO assertion, a session ID) can re-partition
// the tuple and bind a chosen key to a different (NHI, Subject), the way a delimiter-only
// encoding could. The domain tag separates these bytes from any other signing context.
func certTBS(nhi string, session interfaces.SessionID, subject interfaces.Subject, pub ed25519.PublicKey) []byte {
	var b []byte
	b = append(b, "c7-cert-v1"...)
	b = appendField(b, []byte(nhi))
	b = appendField(b, []byte(session))
	b = appendField(b, []byte(subject))
	b = appendField(b, pub)
	return b
}

// appendField appends a 4-byte big-endian length prefix followed by the field bytes.
func appendField(b, field []byte) []byte {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(field)))
	b = append(b, n[:]...)
	return append(b, field...)
}
