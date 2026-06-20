package signing

import (
	"context"
	"crypto/ed25519"
	"errors"
)

// SinkCert binds a sink IDENTITY (a long-lived service name, e.g. an evidence WORM sink)
// to its checkpoint-signing public key, signed by the CA root. It is deliberately NOT a
// lineage certificate: it carries no NHI/Session/Subject, because a sink is not a human
// principal and its chain outlives any single session. A verifier that trusts the CA root
// can confirm a given key legitimately speaks for a given sink identity.
type SinkCert struct {
	SinkID string
	Pub    ed25519.PublicKey
	// CASig is the CA root's signature over the canonical (SinkID, Pub) tuple under a domain
	// tag distinct from the lineage certificate's, so a sink cert can never be presented as a
	// lineage cert (or vice versa).
	CASig []byte
}

// SinkSignature is a sink's signature over some bytes (a chain-head checkpoint), plus the
// certificate proving the signing key chains to the CA root. It is the sink-level analogue
// of Signature, minus the lineage fields a sink does not have.
type SinkSignature struct {
	SinkID string
	Sig    []byte
	Cert   SinkCert
}

// IssueSink signs a certificate binding a sink identity to its public key. The CA does not
// retain the certificate; the holder (a SinkSigner) carries it and presents it at verify
// time, exactly as for a lineage Cert.
func (c *DevCA) IssueSink(sinkID string, pub ed25519.PublicKey) SinkCert {
	sig := ed25519.Sign(c.rootPriv, sinkCertTBS(sinkID, pub))
	return SinkCert{SinkID: sinkID, Pub: pub, CASig: sig}
}

// SinkSigner holds a sink's long-lived checkpoint-signing key (unexported, never returned)
// and its CA certificate. Unlike a SessionSigner it is NOT session-deadline-bound: the
// keybroker custodies it across sessions so a sink can seal a checkpoint at any time —
// including a session teardown that overran its work deadline. It lives in the keybroker
// (the only key-holder); the control plane reaches it only through a narrow signer seam, so
// the evidence sink itself holds no key (GOAL.md tenet 1/4; ARCHITECTURE.md §6.4).
type SinkSigner struct {
	sinkID string

	priv ed25519.PrivateKey
	cert SinkCert
}

// NewSinkSigner mints a fresh checkpoint key for sinkID and has the CA certify it. It errors
// (rather than returning a signer with a predictable or empty identity) on a missing id or a
// CSPRNG failure.
func NewSinkSigner(ca *DevCA, sinkID string) (*SinkSigner, error) {
	if sinkID == "" {
		return nil, errors.New("signing: cannot mint a sink signer without a sink id")
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, errors.New("signing: sink signer key generation failed")
	}
	return &SinkSigner{sinkID: sinkID, priv: priv, cert: ca.IssueSink(sinkID, pub)}, nil
}

// SinkID returns the sink identity this signer seals for. The evidence sink binds it into the
// checkpoint bytes it signs, so a verifier can pin which sink sealed a chain (not merely that
// some CA-certified sink did).
func (s *SinkSigner) SinkID() string {
	return s.sinkID
}

// SignCheckpoint signs tbs (a domain-tagged checkpoint encoding the caller builds) with the
// sink key and returns a verifiable SinkSignature. The context/error shape mirrors a real
// out-of-process keybroker call, even though the in-process dev signer cannot fail here.
func (s *SinkSigner) SignCheckpoint(ctx context.Context, tbs []byte) (SinkSignature, error) {
	// Return a DEEP copy of the certificate: a shallow struct copy would alias this long-lived
	// signer's own cert.Pub/cert.CASig backing arrays, so a caller mutating the returned
	// signature's cert bytes would corrupt the signer and break every later signature's
	// verification.
	return SinkSignature{
		SinkID: s.sinkID,
		Sig:    ed25519.Sign(s.priv, tbs),
		Cert:   s.cert.clone(),
	}, nil
}

// clone returns a copy of the certificate whose byte slices are freshly allocated, so a
// returned SinkSignature never aliases the signer's internal certificate.
func (c SinkCert) clone() SinkCert {
	c.Pub = append(ed25519.PublicKey(nil), c.Pub...)
	c.CASig = append([]byte(nil), c.CASig...)
	return c
}

// VerifySinkSignature checks a SinkSignature against a trusted CA root and the original tbs.
// It confirms the chain: (1) the CA root certifies the sink key for the SinkID, (2) that key
// signed tbs, and (3) the signature's SinkID agrees with the certificate. Key lengths are
// guarded first — ed25519.Verify PANICS on a wrong-length key, so a malformed (e.g.
// externally-decoded) checkpoint must be rejected, not allowed to crash the verifier.
func VerifySinkSignature(caRoot ed25519.PublicKey, tbs []byte, sig SinkSignature) error {
	if len(caRoot) != ed25519.PublicKeySize {
		return errors.New("signing: CA root key has the wrong length")
	}
	if len(sig.Cert.Pub) != ed25519.PublicKeySize {
		return errors.New("signing: sink certificate public key has the wrong length")
	}
	// (3) the signature's claimed identity must match what the certificate binds.
	if sig.SinkID != sig.Cert.SinkID {
		return errors.New("signing: sink signature id does not match its certificate")
	}
	// (1) the CA root must have certified this SinkID->key binding.
	if !ed25519.Verify(caRoot, sinkCertTBS(sig.Cert.SinkID, sig.Cert.Pub), sig.Cert.CASig) {
		return errors.New("signing: sink certificate does not chain to the trusted CA root")
	}
	// (2) the certified sink key must have signed the checkpoint bytes.
	if !ed25519.Verify(sig.Cert.Pub, tbs, sig.Sig) {
		return errors.New("signing: checkpoint signature does not verify under the sink key")
	}
	return nil
}

// sinkCertTBS is the canonical, length-prefixed "to-be-signed" encoding of a sink
// certificate's bound fields. Its domain tag ("c7-sinkcert-v1") is distinct from the lineage
// certificate's ("c7-cert-v1"), so a CA signature minted for one can never be replayed as the
// other — the cross-domain separation the lineage/commit/evidence tags already maintain.
func sinkCertTBS(sinkID string, pub ed25519.PublicKey) []byte {
	var b []byte
	b = append(b, "c7-sinkcert-v1"...)
	b = appendField(b, []byte(sinkID))
	b = appendField(b, pub)
	return b
}
