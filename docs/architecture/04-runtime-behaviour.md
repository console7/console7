# 04 — Runtime Behaviour (Sequence Diagrams)

**Audience:** engineers reasoning about ordering and failure modes; security reviewers
tracing authN/authZ and the egress crossing.
**Question answered:** *In what order do the parts collaborate on the critical paths, and
where are the security decisions made?*

Four paths are shown: **(1)** the primary session lifecycle, **(2)** authN/authZ + scope
resolution, **(3)** the data-egress / inference crossing (the privileged path), and
**(4)** the operate-lane read-only flow. Paths 1–3 are grounded in `orchestrator.Run`,
`broker`, `evidence`, and the reference providers; path 4 follows `DESIGN.md` §5.4 and the
`ObserveGateway` contract and is marked **(planned)** where the container is still a
scaffold.

---

## 4.1 Primary session lifecycle (launch → signed PR → sealed teardown)

```mermaid
sequenceDiagram
  autonumber
  actor U as User (browser)
  participant UI as ui (Web-CLI)
  participant O as Orchestrator
  participant P as PDP / PolicySoR
  participant B as Key broker (+signing)
  participant SEC as SecretsProvider
  participant CL as CloudProvider (sandbox)
  participant INF as InferenceBackend
  participant SCM as SCMProvider
  participant E as Evidence Sink

  U->>UI: SSO authenticate, then launch(persona, repo, branch, attended, useSubscription)
  UI->>O: Run(LaunchRequest)
  Note over O: prepare() — no sandbox yet, fail-closed
  O->>B: Authenticate(authn)
  B-->>O: Subject (verified assertion)
  O->>P: ResolveProfile(repo, persona)
  P-->>O: SessionProfile (egress allowlist, ceiling, human-gate)
  O->>B: MintSessionIdentity(Subject, SessionID, Persona, repo, branch, deadline)
  Note over B: Bind ephemeral NHI (Ed25519+cert); MintEphemeral; MintWorkingCredential
  B-->>O: MintedSession{NHI, SCM ref} (no key material)
  O->>E: Append("session-start") [NHI-signed]
  O->>CL: ProvisionSandbox(SandboxSpec, default-deny egress)
  CL-->>O: SandboxHandle
  Note over O: resolveInference()
  O->>B: ResolveInference(Mode, Attended, Beneficiaries)
  B->>INF: Resolve(selection)
  INF-->>B: BackendEndpoint{Mode, URL}
  B-->>O: endpoint
  O->>O: onAllowlist(URL)? else ABORT (boundary authoritative)
  O->>CL: ApplyEgressPolicy(narrow to URL)
  opt useSubscription && attended
    O->>B: InjectSubscription
    B->>SEC: InjectSubscriptionToken (attended + 1 beneficiary + ownership)
    SEC->>CL: deliver plaintext into owning sandbox ONLY
  end
  Note over CL,INF: agentic loop — engine runs; egress default-deny;<br/>only allowlisted endpoint reachable (live engine: planned)
  Note over O: propose()
  O->>B: SignSession(commitDigest)
  B-->>O: Signature (NHI-signed commit)
  O->>E: Append("pr-opening")
  O->>B: OpenPullRequest(PR)
  B->>SCM: OpenPullRequest (head≠base, not protected)
  SCM-->>B: PRRef{URL, Number}
  B-->>O: PRRef
  O->>E: Append("pr-opened")
  Note over O: teardown — context.WithoutCancel (cannot be cancelled away)
  O->>CL: DestroySandbox (irreversible; wipe injected creds)
  O->>E: Append("session-end")
  O->>E: sealCheckpoint (SinkSigner-signed)
  O-->>UI: Summary{Subject, NHI, PR, CommitSig, recordCount}
```

**What to notice:** the profile is resolved from the **target** before anything is
provisioned; the sandbox is born default-deny and only widened to the *exact* allowlisted
endpoint; the subscription token is injected by reference into the owning sandbox only; and
teardown + checkpoint sealing run on a non-cancellable context so evidence is sealed even
on failure (`abort()` path).

---

## 4.2 AuthN / AuthZ and scope resolution (scope follows the artefact)

```mermaid
sequenceDiagram
  autonumber
  actor U as User
  participant O as Orchestrator
  participant ID as IdentityProvider
  participant SoR as PolicySoR (GRC)
  participant PE as PolicyEngine (OPA)
  participant B as Key broker (signing)

  U->>O: launch with SSO/OIDC assertion (AuthnToken)
  O->>ID: Authenticate(AuthnToken)
  Note over ID: verify signature, issuer, audience, expiry;<br/>NEVER trust client-asserted claims
  ID-->>O: Subject (identity assertion, not a credential)
  O->>ID: ResolveGroups(Subject)
  ID-->>O: []Group (read from IdP; cannot be self-asserted)
  O->>SoR: ResolveRepo(target)
  Note over SoR: AUTHORITATIVE tier×stratum — from system-of-record,<br/>NOT an in-repo file; unknown ⇒ MOST RESTRICTIVE (fail-closed)
  SoR-->>O: TierStratum
  rect rgb(244,244,244)
  Note over O,PE: target state (P3) — not yet coded/landed
  opt cross-repo reach (P3, planned)
    O->>SoR: ResolveResource(other targets)
    Note over O: take-the-max + step-up, or BLOCK<br/>(permissive origin must not confer a stricter target's reach)
  end
  opt action-boundary decision (P3, planned)
    O->>PE: Evaluate(PolicyQuery{Input facts})
    Note over PE: deterministic; any error/timeout/ambiguity ⇒ DENY
    PE-->>O: Decision{Allow, Reason, Obligations}
  end
  end
  O->>B: MintSessionIdentity(Subject, SessionID, Persona)
  Note over B: NHI cert binds Subject→key→SessionID→Persona<br/>(the lineage anchor for every later action)
  B-->>O: SessionIdentity (NHI)
```

**What to notice:** authentication produces an *assertion*, never a credential; groups come
from the IdP, not the principal; authorization scope is derived from the **target's**
tier × stratum (the self-relaxation threat is blocked because policy is never read from the
governed repo); and both the SoR and the policy engine are **fail-closed**. The
cross-repo/take-the-max and `PolicyEngine.Evaluate` legs are **(planned, P3)** — today P1
admits only the Author × T3/S1 lane.

---

## 4.3 Data-egress / inference crossing (the privileged path)

```mermaid
sequenceDiagram
  autonumber
  participant O as Orchestrator
  participant B as Key broker
  participant INF as InferenceBackend
  participant SEC as SecretsProvider
  participant CL as Sandbox + egress perimeter
  participant DLP as Pre-egress DLP
  participant M as Model backend (external)

  Note over CL: egress is DEFAULT-DENY at the sandbox boundary from birth
  O->>B: ResolveInference(Mode, Attended, Beneficiaries)
  B->>INF: Resolve(selection)
  Note over INF: ModeUnspecified ⇒ error; Subscription requires Attended && 1 beneficiary;<br/>Vertex refuses subscription entirely (ADR-0004); Anthropic pins subscription to first-party
  INF-->>B: BackendEndpoint{Mode, URL}
  B-->>O: endpoint
  O->>O: onAllowlist(URL)? else ABORT
  O->>CL: ApplyEgressPolicy(allowlist = [URL]) — narrow-only, fail-closed
  opt attended subscription
    O->>B: InjectSubscription
    B->>SEC: InjectSubscriptionToken
    Note over SEC: re-check attended + 1 beneficiary + sandbox ownership;<br/>KMS-unwrap per-user DEK; deliver plaintext to owning sandbox ONLY
    SEC->>CL: deliver token (never returned to caller)
  end
  Note over CL,M: engine issues model call (live engine: planned)
  CL->>CL: egress perimeter checks allowlist (deny ⇒ incident to Evidence)
  CL->>M: prompts + responses — THE ONLY trust-boundary crossing
  M-->>CL: completion
  rect rgb(244,244,244)
  Note over O,DLP: anything committed/sent is DLP-scanned pre-egress (blocks T1/T2) — planned
  O->>DLP: scan(commit / artefact)
  DLP-->>O: allow OR block + incident
  end
```

**What to notice:** this path is where the **lethal-trifecta** default is enforced — the
agent has private context and untrusted content, so the third leg (open egress) is removed:
default-deny boundary, a single allowlisted destination, and pre-egress DLP. The egress
perimeter is the **authoritative** control (out-of-band firewall/NAT), not the engine's own
proxy. DLP and the live engine egress are **(planned, P2/P1)**; the routing/injection
refusals are implemented today.

---

## 4.4 Operate lane: read-only telemetry → propose (planned, P2)

```mermaid
sequenceDiagram
  autonumber
  actor Ops as Operator
  participant O as Orchestrator
  participant OG as ObserveGateway
  participant SoR as PolicySoR
  participant E as Evidence Sink
  participant SCM as SCMProvider
  participant PIPE as Adopter pipeline (human gate)

  rect rgb(244,244,244)
  Note over Ops,PIPE: entire operate lane is target state (P2) — not yet coded/landed
  Ops->>O: launch Operate session (read-only persona)
  Note over O,OG: operate NHI carries a READ-ONLY cloud identity<br/>(IAM is the authoritative mutation block)
  O->>OG: Query(TelemetryQuery{Target, query})
  OG->>SoR: ResolveResource(Target) → tier
  Note over OG: redaction depth scales with tier; audit EVERY query;<br/>rate-limit; reject any mutation ⇒ incident
  OG-->>O: TelemetryResult{rows redacted, truncated}
  O->>E: Append(query-evidence)
  Note over O: PreToolUse tripwire denies mutating commands in-sandbox ⇒ incident (defence-in-depth)
  O->>SCM: OpenPullRequest(proposed fix / IaC / runbook)
  SCM-->>O: PRRef
  Note over O,PIPE: NO actuation from the session — the pipeline actuates later, under a human gate
  O-->>PIPE: change proposed (out of band)
  end
```

**What to notice:** "observe is not actuate." Even a fully compromised operate session holds
only a *read* token (the authoritative control), the gateway redacts and audits every read,
and the only exit is a **proposed** PR — actuation is the adopter pipeline's job under a
human gate, and **no session ever holds author + approve + actuate**. This entire path is
**(planned, P2)**: `ObserveGateway`, the operate persona's IAM, and the tripwire are
specified but not yet implemented.

## Notes & confidence
- Sequences 4.1–4.3 reflect the implemented `orchestrator.Run` ordering and the real
  fail-closed checks in the broker, secrets, SCM, inference, and evidence code. Items
  marked **(planned)** — live engine egress, DLP, the operate lane, cross-repo step-up, and
  `PolicyEngine.Evaluate` — are drawn from the normative spec, not yet from code.
- Sandbox-emitted per-tool-call evidence (the inner agentic loop in `ARCHITECTURE.md` §7)
  depends on the sandbox base image and is **(planned, P1/P2)**; today the orchestrator
  stamps the lifecycle records (session-start, pr-opening, pr-opened, session-end).
