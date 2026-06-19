package interfaces

import "context"

// TelemetryQuery is a read against production observability data, issued by an
// operate-lane session to diagnose.
type TelemetryQuery struct {
	SessionID SessionID
	// Target is the resource whose telemetry is being read; its tier sets redaction
	// depth and the right to attach.
	Target ResourceRef
	Tier   Tier
	// Query is the read expression (e.g. a log/metrics query). It is read-only by
	// construction; see the SECURITY contract on Query.
	Query string
}

// TelemetryResult is the redacted, audited result of a telemetry read.
type TelemetryResult struct {
	// Rows is the already-redacted result body. Redaction depth scales with the
	// target's tier.
	Rows []byte
	// Truncated reports that rate-limiting or volume caps dropped data.
	Truncated bool
}

// ObserveGateway abstracts redacting, query-audited, rate-limited reads of
// production telemetry for the operate lane (ARCHITECTURE.md §5; default ref:
// pluggable adapter). It is the façade that makes production observability safe to
// switch on — never raw log-store credentials (DESIGN.md §5.4).
type ObserveGateway interface {
	// Query reads production telemetry through the gateway.
	//
	// SECURITY: the gateway is READ-ONLY and MUST expose no mutation path whatsoever
	// — it MUST reject any query that is not a pure read, and the operate session's
	// underlying cloud identity MUST itself be read-only (IAM is the authoritative
	// block; this is defence-in-depth, DESIGN.md §5.4). The implementation MUST
	// redact before returning (depth scaling with q.Tier), MUST audit every query,
	// MUST rate-limit, and MUST NEVER hand back raw log-store credentials or
	// un-redacted high-tier data. A detected mutating attempt MUST be denied and
	// emitted as an incident to the EvidenceSink.
	Query(ctx context.Context, q TelemetryQuery) (TelemetryResult, error)
}
