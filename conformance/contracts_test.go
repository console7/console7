package conformance

import "testing"

// Conformance cases, one per provider-interface method, keyed to the must-never SECURITY
// clause each asserts. The seven seams with a dev/in-memory implementation — Cloud,
// Secrets, Identity, SCM, Inference, PolicySoR, Evidence (Cloud/PolicySoR/Evidence added in
// the Phase-1 orchestration spine) — call runContract, which drives the real assertion in
// sdk/testkit against those providers; the remaining seams (PolicyEngine, ObserveGateway)
// have no implementation yet and skip via skipUnimplemented until their providers land in
// Phases 2–3 (docs/ROADMAP.md). The clauses are quoted from sdk/interfaces so a reviewer
// can read the contract surface here without cross-referencing.

// --- CloudProvider (sandbox isolation, networking, perimeter) ---

func TestCloudProvider_ProvisionSandbox(t *testing.T) {
	runContract(t, "CloudProvider", "ProvisionSandbox")
}

func TestCloudProvider_ApplyEgressPolicy(t *testing.T) {
	runContract(t, "CloudProvider", "ApplyEgressPolicy")
}

func TestCloudProvider_DestroySandbox(t *testing.T) {
	runContract(t, "CloudProvider", "DestroySandbox")
}

func TestCloudProvider_RunTask(t *testing.T) {
	runContract(t, "CloudProvider", "RunTask")
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

func TestSecretsProvider_InjectOrgCredential(t *testing.T) {
	runContract(t, "SecretsProvider", "InjectOrgCredential")
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
	runContract(t, "PolicySoR", "ResolveRepo")
}

func TestPolicySoR_ResolveResource(t *testing.T) {
	runContract(t, "PolicySoR", "ResolveResource")
}

// --- EvidenceSink (WORM store + SIEM stream) ---

func TestEvidenceSink_Append(t *testing.T) {
	runContract(t, "EvidenceSink", "Append")
}

func TestEvidenceSink_Stream(t *testing.T) {
	runContract(t, "EvidenceSink", "Stream")
}

// --- ObserveGateway (redacting, audited telemetry reads) ---

func TestObserveGateway_Query(t *testing.T) {
	skipUnimplemented(t, "ObserveGateway", "Query", "expose a mutation path, return un-redacted high-tier data or raw log-store credentials, or skip the query audit")
}
