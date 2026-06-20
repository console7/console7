package inferenceanthropic

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// FirstPartyBaseURL is Anthropic's first-party API endpoint. ModeSubscription ALWAYS
// resolves to this and it is structurally un-overridable (there is no subscription-endpoint
// config field) — a personal seat token must never be pointed off first-party Anthropic
// (DESIGN.md §3; GOAL.md tenet 7). It is also the ModeOrgAPI default when no gateway is set.
const FirstPartyBaseURL = "https://api.anthropic.com"

// Config configures the provider. The zero value is valid and yields a first-party-only
// backend with subscription routing DISABLED (fail-closed default: an enterprise opts INTO
// subscription, it is not on by accident).
type Config struct {
	// SubscriptionEnabled is the enterprise policy flip behind the attended/unattended seam
	// (DESIGN.md §3 — flip policy, not architecture). When false, even a valid attended,
	// single-beneficiary ModeSubscription selection is refused (a deliberate error, never a
	// silent downgrade to org-API). When true, such a selection routes to FirstPartyBaseURL.
	SubscriptionEnabled bool

	// OrgAPIBaseURL optionally points the ModeOrgAPI route at an adopter-run gateway/proxy
	// fronting the org API key. Empty ⇒ FirstPartyBaseURL. When set it MUST be an absolute
	// https URL (normalize rejects http:// and malformed values — fail closed). It applies to
	// the org-API route ONLY: it can NEVER move the subscription endpoint, by construction.
	OrgAPIBaseURL string
}

// normalize validates and returns the effective config so New does not mutate the caller's
// value. It resolves OrgAPIBaseURL to a concrete endpoint (FirstPartyBaseURL when unset).
func (c Config) normalize() (Config, error) {
	if c.OrgAPIBaseURL == "" {
		c.OrgAPIBaseURL = FirstPartyBaseURL
		return c, nil
	}
	u, err := url.Parse(c.OrgAPIBaseURL)
	if err != nil {
		// Do NOT echo the raw value: a malformed value may still carry userinfo a caller logs.
		return Config{}, errors.New("inferenceanthropic: Config.OrgAPIBaseURL is not a valid URL")
	}
	// Reject embedded credentials FIRST, before any error echoes the value — never bake a
	// credential into config, and never leak one into a construction error a caller logs
	// (DESIGN.md §2.1; the provider holds no key).
	if u.User != nil {
		return Config{}, errors.New("inferenceanthropic: Config.OrgAPIBaseURL must not embed userinfo")
	}
	// Require an absolute https URL with a host and no query/fragment: an org-API gateway should
	// not be fronted by a cleartext, relative, or non-base endpoint. http://, scheme-less,
	// hostless (incl. ":443"-style authorities), and query/fragment-bearing values fail closed.
	// Errors below echo u.Redacted() (userinfo already rejected), never the raw config string.
	if !strings.EqualFold(u.Scheme, "https") {
		return Config{}, fmt.Errorf("inferenceanthropic: Config.OrgAPIBaseURL %q must use https", u.Redacted())
	}
	if u.Hostname() == "" {
		return Config{}, fmt.Errorf("inferenceanthropic: Config.OrgAPIBaseURL %q must be an absolute https URL with a host", u.Redacted())
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return Config{}, fmt.Errorf("inferenceanthropic: Config.OrgAPIBaseURL %q must be a base URL with no query or fragment", u.Redacted())
	}
	return c, nil
}
