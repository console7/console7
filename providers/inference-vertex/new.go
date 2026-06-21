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
	return &Provider{endpointURL: cfg.EndpointBaseURL}, nil
}
