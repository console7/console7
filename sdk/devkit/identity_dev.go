package devkit

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/console7/console7/sdk/interfaces"
)

// DevIdentity is an in-memory, NON-PRODUCTION IdentityProvider. It stands in for a real
// OIDC IdP (Okta/Entra): an AuthnToken is a compact, ed25519-signed dev assertion, and
// Authenticate cryptographically verifies it against the dev IdP's public key before
// returning a Subject. It models the contract invariant — never trust a client-asserted
// subject without verifying the signature — not a real OIDC verification (issuer/
// audience/JWKS rotation are Phase-1+).
//
// The dev assertion format is:
//
//	base64url(subject)|expiryUnixSeconds|base64url(ed25519 sig)
//
// where the signature is over "base64url(subject)|expiryUnixSeconds". The subject is
// base64url-encoded (not raw) because Subject is an unrestricted string — a raw subject
// containing the "|" delimiter would otherwise be parsed as multiple fields.
type DevIdentity struct {
	pub    ed25519.PublicKey // the dev IdP verifying key.
	groups map[interfaces.Subject][]interfaces.Group
	now    func() time.Time
}

var _ interfaces.IdentityProvider = (*DevIdentity)(nil)

// NewDevIdentity returns a DevIdentity that verifies assertions against pub. groups is
// the authoritative group membership the IdP would return; a nil map means no groups.
func NewDevIdentity(pub ed25519.PublicKey, groups map[interfaces.Subject][]interfaces.Group) *DevIdentity {
	return &DevIdentity{pub: pub, groups: groups, now: time.Now}
}

// Authenticate verifies the dev assertion's signature and expiry and returns the
// Subject. A forged, malformed, or expired token yields an error — the claimed subject
// is never returned unverified.
func (d *DevIdentity) Authenticate(ctx context.Context, token interfaces.AuthnToken) (interfaces.Subject, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	parts := strings.Split(string(token), "|")
	if len(parts) != 3 {
		return "", errors.New("devkit: malformed dev assertion")
	}
	subjB64, expStr, sigB64 := parts[0], parts[1], parts[2]
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return "", errors.New("devkit: dev assertion signature not valid base64url")
	}
	signed := subjB64 + "|" + expStr
	// Verify the signature BEFORE trusting any claim in the token.
	if !ed25519.Verify(d.pub, []byte(signed), sig) {
		return "", errors.New("devkit: dev assertion signature does not verify")
	}
	subjBytes, err := base64.RawURLEncoding.DecodeString(subjB64)
	if err != nil {
		return "", errors.New("devkit: dev assertion subject not valid base64url")
	}
	if len(subjBytes) == 0 {
		return "", errors.New("devkit: dev assertion has empty subject")
	}
	expUnix, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil {
		return "", errors.New("devkit: dev assertion has invalid expiry")
	}
	if !time.Unix(expUnix, 0).After(d.now()) {
		return "", errors.New("devkit: dev assertion expired")
	}
	return interfaces.Subject(subjBytes), nil
}

// ResolveGroups returns the subject's groups from the authoritative in-memory map. The
// subject cannot self-assert or widen membership — the only input is the subject name,
// and the answer comes from the IdP-side map, never from the caller.
func (d *DevIdentity) ResolveGroups(ctx context.Context, subject interfaces.Subject) ([]interfaces.Group, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return append([]interfaces.Group(nil), d.groups[subject]...), nil
}

// IssueDevAssertion mints a signed dev assertion for subject valid until exp. It is the
// test/bench analogue of a browser completing SSO and presenting a token; it lives here
// (not in a _test.go) so the broker bench in another package can drive a login.
func IssueDevAssertion(priv ed25519.PrivateKey, subject interfaces.Subject, exp time.Time) interfaces.AuthnToken {
	subjB64 := base64.RawURLEncoding.EncodeToString([]byte(subject))
	signed := subjB64 + "|" + strconv.FormatInt(exp.Unix(), 10)
	sig := ed25519.Sign(priv, []byte(signed))
	return interfaces.AuthnToken(signed + "|" + base64.RawURLEncoding.EncodeToString(sig))
}
