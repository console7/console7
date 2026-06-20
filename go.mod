// Console7 — the canonical SDK and core are one Go module (docs/adr/0001-language.md).
// The module was dependency-free through P0 scaffolding (the sdk/interfaces contracts
// are pure type declarations). The FIRST real dependencies arrive here, as planned,
// with the first reference provider: providers/secrets-gcp pulls the Cloud KMS +
// Secret Manager clients (and their shared cloud.google.com/go / gRPC / protobuf base,
// the baseline the rest of the GCP reference set will reuse). Every dependency is a
// governed decision — released versions only, go.sum committed, govulncheck-clean,
// vetted through the chokepoint (docs/standards/console7-sdlc-standard.md, CO-5/CO-12.7;
// GOAL.md tenet 10). The core (sdk/, control-plane/, keybroker/) stays import-free of
// these; they are reachable only from providers/secrets-gcp.
//
// The dependency closure raised the go directive to the 1.25 line; it is pinned to a
// PATCHED 1.25.x (not 1.25.0) so the govulncheck gate is clean — CI installs exactly this
// version via go-version-file, and the .0 release carries stdlib CVEs (net/textproto,
// crypto/x509, net/http, …) fixed only in later 1.25.x patches. Bump this when govulncheck
// flags a newer stdlib fix.
module github.com/console7/console7

go 1.25.11

require (
	cloud.google.com/go/kms v1.31.0
	cloud.google.com/go/secretmanager v1.20.0
	google.golang.org/api v0.274.0
	google.golang.org/grpc v1.80.0
)

require (
	cloud.google.com/go v0.123.0 // indirect
	cloud.google.com/go/auth v0.18.2 // indirect
	cloud.google.com/go/auth/oauth2adapt v0.2.8 // indirect
	cloud.google.com/go/compute/metadata v0.9.0 // indirect
	cloud.google.com/go/iam v1.7.0 // indirect
	cloud.google.com/go/longrunning v0.9.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/google/s2a-go v0.1.9 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.3.14 // indirect
	github.com/googleapis/gax-go/v2 v2.21.0 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.61.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.61.0 // indirect
	go.opentelemetry.io/otel v1.42.0 // indirect
	go.opentelemetry.io/otel/metric v1.42.0 // indirect
	go.opentelemetry.io/otel/trace v1.42.0 // indirect
	golang.org/x/crypto v0.50.0 // indirect
	golang.org/x/net v0.53.0 // indirect
	golang.org/x/oauth2 v0.36.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.43.0 // indirect
	golang.org/x/text v0.36.0 // indirect
	golang.org/x/time v0.15.0 // indirect
	google.golang.org/genproto v0.0.0-20260319201613-d00831a3d3e7 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20260401024825-9d38bb4040a9 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260401001100-f93e5f3e9f0f // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)
