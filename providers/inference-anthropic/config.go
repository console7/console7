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
		return Config{}, fmt.Errorf("inferenceanthropic: Config.OrgAPIBaseURL %q is not a valid URL: %w", c.OrgAPIBaseURL, err)
	}
	// Require an absolute https URL with a host, no userinfo, no query/fragment: an org-API
	// gateway should not be fronted by a cleartext, relative, or credential-bearing endpoint,
	// and a base URL carries no query/fragment. http://, scheme-less, userinfo-bearing, and
	// query/fragment-bearing values fail closed.
	if !strings.EqualFold(u.Scheme, "https") {
		return Config{}, fmt.Errorf("inferenceanthropic: Config.OrgAPIBaseURL %q must use https", c.OrgAPIBaseURL)
	}
	if u.Host == "" {
		return Config{}, errors.New("inferenceanthropic: Config.OrgAPIBaseURL must be an absolute URL with a host")
	}
	if u.User != nil {
		// Never bake a credential into config — the provider holds no key (DESIGN.md §2.1).
		return Config{}, errors.New("inferenceanthropic: Config.OrgAPIBaseURL must not embed userinfo")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return Config{}, errors.New("inferenceanthropic: Config.OrgAPIBaseURL must be a base URL with no query or fragment")
	}
	return c, nil
}
