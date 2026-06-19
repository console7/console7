package signing

import (
	"crypto/ed25519"
	"errors"

	"github.com/console7/console7/sdk/interfaces"
)

// NHIBinder mints a per-session non-human identity for an authenticated Subject and
// issues it an ephemeral signing key certified by the CA. The minted NHI is what the
// human acts through for the life of the session; it is the anchor the orchestrator
// stamps onto every action (DESIGN.md §2.3).
type NHIBinder struct {
	ca *DevCA
}

// NewNHIBinder returns a binder that certifies identities under ca.
func NewNHIBinder(ca *DevCA) *NHIBinder {
	return &NHIBinder{ca: ca}
}

// nhiPrefix is the session-scoped prefix of an NHI name, "nhi/<session>/". The persona
// is appended to form the full name. Verify uses this prefix to bind a Signature's
// SessionID to its certified NHI.
func nhiPrefix(session interfaces.SessionID) string {
	return "nhi/" + string(session) + "/"
}

// Bind mints a per-session NHI for subject and returns a SessionSigner holding its
// ephemeral signing key and CA certificate. The NHI name encodes the session and persona
// so it is unique per session and self-describing in evidence.
//
// SECURITY: the ephemeral private key is generated here and never leaves the returned
// SessionSigner — it is not stored by the binder, not returned to a caller, and dies with
// the session value. A long-lived or shared signing key would break the per-session
// lineage guarantee.
func (b *NHIBinder) Bind(subject interfaces.Subject, session interfaces.SessionID, persona interfaces.Persona) (*SessionSigner, error) {
	if subject == "" {
		return nil, errors.New("signing: cannot bind an NHI to an empty subject")
	}
	if session == "" {
		return nil, errors.New("signing: cannot bind an NHI without a session")
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, errors.New("signing: ephemeral key generation failed")
	}
	// The NHI name encodes the session and persona. Uniqueness per human derives from
	// SessionID uniqueness — a session runs as exactly one subject (interfaces.SessionID)
	// — so the same name cannot be minted for two subjects. The CA certificate is the
	// authoritative binding regardless; the name is a self-describing evidence label, not
	// an identity key.
	nhi := nhiPrefix(session) + string(persona)
	cert := b.ca.Issue(nhi, subject, pub)
	return &SessionSigner{
		Subject:   subject,
		SessionID: session,
		Persona:   persona,
		NHI:       nhi,
		priv:      priv,
		cert:      cert,
	}, nil
}
