package conformance

import "testing"

// Stub conformance cases, one per provider-interface method, keyed to the must-never
// SECURITY clause each will assert. No logic yet — every case skips (P0 scaffolding).
// The clauses are quoted from sdk/interfaces so a reviewer can read the contract
// surface here without cross-referencing.

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
	skipUnimplemented(t, "SecretsProvider", "MintEphemeral", "return long-lived or plaintext credential material to the control plane, or grant wider scope/TTL than requested")
}

func TestSecretsProvider_StoreSubscriptionToken(t *testing.T) {
	skipUnimplemented(t, "SecretsProvider", "StoreSubscriptionToken", "store under a shared key, leave a standing operator read path, or pool the token")
}

func TestSecretsProvider_InjectSubscriptionToken(t *testing.T) {
	skipUnimplemented(t, "SecretsProvider", "InjectSubscriptionToken", "return plaintext to the caller, inject into a non-owner sandbox, or back an unattended session")
}

func TestSecretsProvider_RevokeSubject(t *testing.T) {
	skipUnimplemented(t, "SecretsProvider", "RevokeSubject", "retain a recoverable copy of revoked material")
}

// --- IdentityProvider (SSO/OIDC, group/role mapping) ---

func TestIdentityProvider_Authenticate(t *testing.T) {
	skipUnimplemented(t, "IdentityProvider", "Authenticate", "trust client-asserted claims without cryptographic verification, or mint/persist a long-lived session secret")
}

func TestIdentityProvider_ResolveGroups(t *testing.T) {
	skipUnimplemented(t, "IdentityProvider", "ResolveGroups", "let a subject self-assert or widen its own group membership")
}

// --- SCMProvider (clone, branch, PR, short-lived tokens) ---

func TestSCMProvider_MintWorkingCredential(t *testing.T) {
	skipUnimplemented(t, "SCMProvider", "MintWorkingCredential", "issue a durable token, allow push beyond the working branch, or let the sandbox git client see long-lived material")
}

func TestSCMProvider_OpenPullRequest(t *testing.T) {
	skipUnimplemented(t, "SCMProvider", "OpenPullRequest", "push to/merge a protected branch, or self-approve or actuate the change")
}

// --- InferenceBackend (subscription / Vertex / Bedrock / direct) ---

func TestInferenceBackend_Resolve(t *testing.T) {
	skipUnimplemented(t, "InferenceBackend", "Resolve", "back an unattended or multi-beneficiary session with a subscription credential, or pool a subscription across beneficiaries")
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
