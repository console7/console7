package inferencevertex

// New constructs the production Provider. It validates the config (rejecting a missing
// project/region or a malformed PSC/VPC-SC override) and resolves the effective Vertex
// endpoint, failing fast rather than surfacing the error on the first Resolve. There is no
// client to dial: Resolve is a pure routing decision that makes no network call (see doc.go),
// so New takes no context and the Provider holds no resources.
func New(cfg Config) (*Provider, error) {
	cfg, err := cfg.normalize()
	if err != nil {
		return nil, err
	}
	// normalize has resolved cfg.Region to the engine's CLOUD_ML_REGION value: the configured region
	// for a regional host, "global" for the location-independent endpoint, or the adopter's value
	// (possibly empty) for a PSC/VPC-SC override.
	return &Provider{endpointURL: cfg.EndpointBaseURL, projectID: cfg.ProjectID, region: cfg.Region}, nil
}
