package conformance

import "testing"

// Conformance cases, one per provider-interface method, keyed to the must-never SECURITY
// clause each asserts. The four Phase-0 seams (Secrets, Identity, SCM, Inference) call
// runContract, which drives the real assertion in sdk/testkit against the dev/in-memory
// providers; the remaining seams have no implementation yet and skip via
// skipUnimplemented until their providers land (docs/ROADMAP.md). The clauses are quoted
// from sdk/interfaces so a reviewer can read the contract surface here without
// cross-referencing.

// --- CloudProvider (sandbox isolation, networking, perimeter) ---

func TestCloudProvider_ProvisionSandbox(t *testing.T) {
	skipUnimplemented(t, "CloudProvider", "ProvisionSandbox", "provision egress broader than the spec allowlist, reuse a sandbox across sessions/users, or isolate by request rather than at the syscall boundary")
}

func TestCloudProvider_ApplyEgressPolicy(t *testing.T) {
	skipUnimplemented(t, "CloudProvider", "ApplyEgressPolicy", "widen egress beyond the session profile, or fail open when a policy cannot be applied")
}

func TestCloudProvider_DestroySandbox(t *testing.T) {
	skipUnimplemented(t, "CloudProvider", "DestroySandbox", "snapshot, archive, or otherwise persist sandbox contents or injected credentials")
}

// --- SecretsProvider (secret storage, envelope encryption, KMS) ---

func TestSecretsProvider_MintEphemeral(t *testing.T) {
	runContract(t, "SecretsProvider", "MintEphemeral")
}

func TestSecretsProvider_StoreSubscriptionToken(t *testing.T) {
	runContract(t, "SecretsProvider", "StoreSubscriptionToken")
}

func TestSecretsProvider_InjectSubscriptionToken(t *testing.T) {
	runContract(t, "SecretsProvider", "InjectSubscriptionToken")
}

func TestSecretsProvider_RevokeSubject(t *testing.T) {
	runContract(t, "SecretsProvider", "RevokeSubject")
}

// --- IdentityProvider (SSO/OIDC, group/role mapping) ---

func TestIdentityProvider_Authenticate(t *testing.T) {
	runContract(t, "IdentityProvider", "Authenticate")
}

func TestIdentityProvider_ResolveGroups(t *testing.T) {
	runContract(t, "IdentityProvider", "ResolveGroups")
}

// --- SCMProvider (clone, branch, PR, short-lived tokens) ---

func TestSCMProvider_MintWorkingCredential(t *testing.T) {
	runContract(t, "SCMProvider", "MintWorkingCredential")
}

func TestSCMProvider_OpenPullRequest(t *testing.T) {
	runContract(t, "SCMProvider", "OpenPullRequest")
}

// --- InferenceBackend (subscription / Vertex / Bedrock / direct) ---

func TestInferenceBackend_Resolve(t *testing.T) {
	runContract(t, "InferenceBackend", "Resolve")
}

// --- PolicyEngine (rule evaluation) ---

func TestPolicyEngine_Evaluate(t *testing.T) {
	skipUnimplemented(t, "PolicyEngine", "Evaluate", "default-allow on error/timeout/ambiguity, or widen scope beyond the supplied facts")
}

// --- PolicySoR (authoritative tier × stratum lookup) ---

func TestPolicySoR_ResolveRepo(t *testing.T) {
	skipUnimplemented(t, "PolicySoR", "ResolveRepo", "derive tier/stratum from an in-repo file, or fail open to a permissive default on an unknown target")
}

func TestPolicySoR_ResolveResource(t *testing.T) {
	skipUnimplemented(t, "PolicySoR", "ResolveResource", "let a permissive origin confer a stricter target's reach, or fail open on an unknown resource")
}

// --- EvidenceSink (WORM store + SIEM stream) ---

func TestEvidenceSink_Append(t *testing.T) {
	skipUnimplemented(t, "EvidenceSink", "Append", "expose an update/delete path for a written record, drop a record silently, or share a mutable store with the operational DB")
}

func TestEvidenceSink_Stream(t *testing.T) {
	skipUnimplemented(t, "EvidenceSink", "Stream", "egress evidence to the maintainer or any non-adopter service, or replace the durable WORM append")
}

// --- ObserveGateway (redacting, audited telemetry reads) ---

func TestObserveGateway_Query(t *testing.T) {
	skipUnimplemented(t, "ObserveGateway", "Query", "expose a mutation path, return un-redacted high-tier data or raw log-store credentials, or skip the query audit")
}
