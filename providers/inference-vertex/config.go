package inferencevertex

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// GlobalHost is Vertex AI's location-independent endpoint. Config.Global selects it
// instead of the regional host; inference still runs in the adopter's GCP project, just
// not pinned to a single region.
const GlobalHost = "https://aiplatform.googleapis.com"

// regionPattern bounds Config.Region to GCP's location grammar (e.g. "us-east5",
// "europe-west1"). Region is interpolated into the regional host
// "https://{region}-aiplatform.googleapis.com", so an unvalidated value could forge a
// different host (e.g. "evil.com" ⇒ "https://evil.com-aiplatform.googleapis.com", or a
// value with a slash/dot escaping the intended authority). Validating it here is a
// host-injection guard, not cosmetics.
//
// The single-hyphen "<geo>-<direction><number>" form is intentional and matches every GCP
// region (incl. multi-token geos like "northamerica-northeast1", "australia-southeast1",
// "me-central2") — those have one hyphen and pass; the provider_test.go "accept" table pins
// this so a future tightening cannot silently reject a legitimate region. Anchored ^...$ (Go
// $ is end-of-text, not end-of-line) so embedded newlines/authorities cannot slip through.
var regionPattern = regexp.MustCompile(`^[a-z]+-[a-z]+[0-9]+$`)

// Config configures the provider. There is no zero-value-valid form: a Vertex backend
// needs a project, and (unless Global) a region. New rejects an incomplete or malformed
// Config rather than resolving to an unusable or forged endpoint — fail closed.
type Config struct {
	// ProjectID is the adopter's GCP project that owns and is billed for the inference.
	// Required. It is not part of the resolved host (the wrapped engine carries it as
	// ANTHROPIC_VERTEX_PROJECT_ID, emitted to the sandbox later); it is required here so a
	// misconfigured backend fails at construction, not at session time.
	ProjectID string

	// Region is the Vertex location, e.g. "us-east5". Required unless Global. It is
	// validated against regionPattern and interpolated into the regional host.
	Region string

	// Global selects the location-independent GlobalHost instead of the regional host.
	// When true, Region is not required (and is ignored for host resolution).
	Global bool

	// EndpointBaseURL optionally overrides the resolved host with an adopter-run
	// Private Service Connect / VPC-SC endpoint fronting Vertex (e.g.
	// "https://{region}-aiplatform.{network}.p.googleapis.com"). When set it takes
	// precedence over Region/Global and MUST be an absolute https URL with a host and no
	// userinfo/query/fragment (normalize fails closed otherwise). It exists so an adopter
	// whose egress only permits a private path can point inference at it without leaving
	// the seam.
	EndpointBaseURL string
}

// normalize validates the config and returns it with the effective endpoint host resolved
// into EndpointBaseURL, so New does not mutate the caller's value and Provider holds a
// single ready-to-serve URL. Precedence: EndpointBaseURL override → Global → regional.
func (c Config) normalize() (Config, error) {
	if strings.TrimSpace(c.ProjectID) == "" {
		return Config{}, errors.New("inferencevertex: Config.ProjectID is required")
	}

	// An explicit override wins and is validated like any adopter-supplied endpoint.
	if c.EndpointBaseURL != "" {
		if err := validateEndpointOverride(c.EndpointBaseURL); err != nil {
			return Config{}, err
		}
		return c, nil
	}

	if c.Global {
		c.EndpointBaseURL = GlobalHost
		return c, nil
	}

	// Regional host: Region is required and must match the GCP location grammar.
	if c.Region == "" {
		return Config{}, errors.New("inferencevertex: Config.Region is required unless Config.Global is set")
	}
	if !regionPattern.MatchString(c.Region) {
		// Echo the bad value (it is a region identifier, never a credential) so the
		// misconfiguration is diagnosable, and point at the two other endpoint shapes — the
		// global endpoint (Config.Global) and any non-regional host such as a multi-region
		// (us/eu) or PSC/VPC-SC endpoint (Config.EndpointBaseURL) — so an adopter is not stuck.
		return Config{}, fmt.Errorf("inferencevertex: Config.Region %q is not a regional Vertex location like \"us-east5\" (host-injection guard); for the global endpoint set Config.Global, and for a multi-region (us/eu) or private endpoint set Config.EndpointBaseURL", c.Region)
	}
	c.EndpointBaseURL = fmt.Sprintf("https://%s-aiplatform.googleapis.com", c.Region)
	return c, nil
}

// validateEndpointOverride enforces that an adopter-supplied PSC/VPC-SC endpoint is an
// absolute https base URL with a host and no embedded credential. It mirrors the org-API
// gateway validation in providers/inference-anthropic: reject userinfo FIRST (before any
// error echoes the value), require https, require a host (u.Hostname() catches ":443"-style
// authorities where u.Host is non-empty), and reject query/fragment. Errors echo
// u.Redacted(), never the raw string.
func validateEndpointOverride(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		// Do NOT echo the raw value: a malformed value may still carry userinfo a caller logs.
		return errors.New("inferencevertex: Config.EndpointBaseURL is not a valid URL")
	}
	if u.User != nil {
		return errors.New("inferencevertex: Config.EndpointBaseURL must not embed userinfo")
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return fmt.Errorf("inferencevertex: Config.EndpointBaseURL %q must use https", u.Redacted())
	}
	if u.Hostname() == "" {
		return fmt.Errorf("inferencevertex: Config.EndpointBaseURL %q must be an absolute https URL with a host", u.Redacted())
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("inferencevertex: Config.EndpointBaseURL %q must be a base URL with no query or fragment", u.Redacted())
	}
	return nil
}
