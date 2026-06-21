# 03 — Component View (C4 Level 3)

**Audience:** engineers modifying these containers; security reviewers tracing how keys,
lineage, and evidence integrity are actually enforced in code.
**Question answered:** *Inside the three most security- and complexity-significant
containers, what are the components, how do they collaborate, and where exactly are the
load-bearing invariants enforced?*

The three chosen containers are the ones that carry the system's hardest guarantees and
are **fully implemented today**: the **key broker** (custodies every key and signs every
artefact), the **orchestrator** (drives the lifecycle and stamps unbroken lineage), and
the **evidence sink** (the tamper-evident system of record). The placeholder containers
(`ui`, `dlp`, sandbox trio) are intentionally omitted — there is no code to decompose yet.

---

## 3.1 Key broker (`keybroker/broker` + `keybroker/signing`)

*Why this one:* it is the blast-radius-limiting component — Console7 "holds everyone's
keys," so this is peeled into a separate, separately-signed artifact (`ARCHITECTURE.md`
§6.2). The control plane never sees key material; it gets back opaque refs and signatures.

```mermaid
flowchart TB
  ORCH["orchestrator (control plane)<br/>calls broker; never sees keys"]

  subgraph KB["key broker artifact (Tier-1, distinct signing identity)"]
    direction TB
    BRK["Broker<br/>fields: Identity, Secrets, SCM, Inference, Binder<br/>signers map[SessionID]&rarr;SessionSigner (mu)"]
    subgraph SIGNPKG["signing"]
      BIND["NHIBinder.Bind(subject, sessionID, persona)<br/>&rarr; ephemeral Ed25519 keypair + Cert"]
      SS["SessionSigner{priv, cert}<br/>.Sign(payload) &rarr; Signature"]
      CA["DevCA{rootPriv}<br/>.Issue(nhi, session, subject, pub)<br/>domain tag 'c7-cert-v1'"]
      SINK["SinkSigner (long-lived)<br/>.SignCheckpoint &rarr; SinkSignature<br/>domain tag 'c7-sinkcert-v1'"]
    end
  end

  IDP["⬡ IdentityProvider<br/>(OIDC / DevIdentity)"]
  SEC["⬡ SecretsProvider<br/>(secrets-gcp: KMS+SM)"]
  SCM["⬡ SCMProvider<br/>(scm-github: GitHub App)"]
  INF["⬡ InferenceBackend<br/>(vertex / anthropic)"]

  ORCH -->|"MintSessionIdentity"| BRK
  ORCH -->|"SignSession(sessionID, tbs)"| BRK
  ORCH -->|"StoreSubscription / InjectSubscription"| BRK
  ORCH -->|"ResolveInference / OpenPullRequest"| BRK
  ORCH -->|"ReleaseSession (defer)"| BRK

  BRK -->|"Authenticate(authn)"| IDP
  BRK -->|"Bind(...)"| BIND
  BIND --> SS
  BIND --> CA
  BRK -->|"MintEphemeral (opaque CredentialRef)"| SEC
  BRK -->|"MintWorkingCredential (branch-scoped)"| SCM
  BRK -->|"StoreSubscriptionToken / InjectSubscriptionToken"| SEC
  BRK -->|"Resolve (fail-closed routing)"| INF
  BRK -->|"OpenPullRequest (PR-only exit)"| SCM
  SINK -. "checkpoint signing for evidence" .-> ORCH

  classDef broker fill:#e7d6f5,stroke:#7b3fab,color:#3a1d52;
  classDef seam fill:#d8f0dd,stroke:#27ae60,color:#13502a;
  class BRK,BIND,SS,CA,SINK broker;
  class IDP,SEC,SCM,INF seam;
```

**Load-bearing invariants (read in source):**
- **Session signing keys never leave the broker.** `MintSessionIdentity` calls
  `Binder.Bind`, which generates an ephemeral Ed25519 keypair held *inside* a
  `SessionSigner`; the broker keeps it in its `signers` map and exposes only
  `SignSession`. `ReleaseSession` discards it at teardown — the key dies with the session.
- **Only opaque refs cross the seam.** Cloud and SCM credentials come back as
  `CredentialRef{Ref, Expiry}`; the subscription token is sealed/injected by the
  `SecretsProvider` and **never returned to the broker or control plane**.
- **Lineage is cryptographic.** Every `Signature` carries `{NHI, Subject, SessionID, Sig,
  Cert}` and `Verify` checks the CA-root → NHI-key → payload chain *and* that the cert's
  Subject/SessionID match. Domain-separation tags (`c7-cert-v1`, `c7-sinkcert-v1`,
  `c7-evidence-v1`, `c7-ckpt-v1`) prevent cross-context signature reuse.
- **`DevCA` is dev-only.** Ed25519 root generated in-process; production Sigstore-keyless
  / org CA is **(assumed/planned)**.

---

## 3.2 Orchestrator (`control-plane/orchestrator`)

*Why this one:* it is the most complex control-flow in the system and the single place
the **human→NHI→action lineage is stamped** (the engine's own sub-agent lineage is
leaky). It is fully synchronous and fail-closed, with cancellation-resilient teardown.

```mermaid
flowchart TB
  REQ["LaunchRequest{Authn, SessionID, Persona, Repo, Branch, Attended, UseSubscription}"]

  subgraph ORCH["Orchestrator.Run (synchronous, fail-closed)"]
    direction TB
    PREP["prepare()<br/>Authenticate &rarr; ResolveProfile(PDP) &rarr; MintSessionIdentity"]
    REL["defer ReleaseSession()<br/>(registered before any fallible step)"]
    ST1["stamp 'session-start' (lineage anchor)"]
    PROV["Cloud.ProvisionSandbox(SandboxSpec, default-deny egress)"]
    RINF["resolveInference()<br/>Resolve &rarr; onAllowlist() &rarr; ApplyEgressPolicy(narrow) &rarr; InjectSubscription?"]
    PROP["propose()<br/>Cloud.RunTask(EngineTask) &rarr; SignSession(commitTBS(EngineResult.CommitDigest)) &rarr; stamp 'pr-opening' &rarr; OpenPullRequest &rarr; stamp 'pr-opened'<br/>(no-op run &rarr; stamp 'no-change', no PR)"]
    TDN["teardown (cleanupCtx = WithoutCancel)<br/>DestroySandbox &rarr; stamp 'session-end'/'aborted' &rarr; sealCheckpoint"]
    APP["appendSigned()/stamp(): wrap each record's payload with NHI signature<br/>payloadTBS domain 'c7-evidence-v1'"]
    VRP["VerifyRecordPayload(caRoot, rec)<br/>checks lineage sig + persona&harr;NHI cert binding"]
  end

  BRK["key broker"]
  PDPC["pdp.ResolveProfile &rarr; PolicySoR.ResolveRepo"]
  CLOUD["⬡ CloudProvider"]
  EVID["evidence Sink (EvidenceSink)"]

  REQ --> PREP
  PREP --> REL --> ST1 --> PROV --> RINF --> PROP --> TDN
  PREP -->|"Authenticate / MintSessionIdentity"| BRK
  PREP --> PDPC
  RINF -->|"ResolveInference / InjectSubscription"| BRK
  PROP -->|"SignSession / OpenPullRequest"| BRK
  PROV --> CLOUD
  RINF -->|"ApplyEgressPolicy"| CLOUD
  TDN -->|"DestroySandbox"| CLOUD
  ST1 & RINF & PROP & TDN --> APP --> EVID
  EVID -.-> VRP

  classDef tier1 fill:#cfe3f7,stroke:#1168bd,color:#11304a;
  classDef ext fill:#ececec,stroke:#888,color:#111;
  class PREP,REL,ST1,PROV,RINF,PROP,TDN,APP,VRP tier1;
  class BRK,PDPC,CLOUD,EVID ext;
```

**Load-bearing invariants (read in source):**
- **Scope follows the target, not the launcher.** `prepare()` resolves the profile from
  the **repo** via `PolicySoR.ResolveRepo`; P1 admits only Author × T3/S1 and rejects
  every other coordinate fail-closed.
- **The boundary is narrowed before work runs.** The sandbox is provisioned default-deny;
  `resolveInference()` only widens egress to the *exact* resolved endpoint after
  `onAllowlist()` confirms it — a resolved URL that is not allowlisted aborts the session.
- **Subscription injection is gated.** Tokens are injected by reference only when
  `UseSubscription && Attended` (and the seam re-checks attended + single-beneficiary +
  sandbox ownership).
- **Teardown cannot be cancelled away.** All exit paths destroy the sandbox using a
  `context.WithoutCancel` clone, then seal a signed checkpoint — evidence is sealed even
  on error/abort.
- **Persona is bound to the cert, not just the bytes.** `VerifyRecordPayload` rejects a
  record whose `Persona` does not match the NHI certificate — defence against
  cross-persona forgery.

---

## 3.3 Evidence sink (`control-plane/evidence`)

*Why this one:* it is the tamper-evident system of record — the thing an auditor trusts.
Its integrity rests on two chained structures and a strict append-only store.

```mermaid
flowchart TB
  CALL["orchestrator: Append(rec) / Stream(ref) / Verify()"]

  subgraph SINK["evidence.Sink (append-only, hash-chained, signed)"]
    direction TB
    APPEND["Append: chainHash(prior, seq, AppendedAt, rec)<br/>then Store.Append; advance head only on success"]
    CHAIN["record hash chain<br/>SHA-256, length-prefixed over all record fields"]
    CKPT["checkpoint chain<br/>checkpointHash over {SinkID, seq, headHash, count, time, PrevCkptHash}"]
    STREAM["Stream(ref): lookup by seq, verify hash (fail-closed)"]
    VERIFY["Verify = VerifyChain + VerifyCheckpoints + no-unsealed-tail"]
  end

  STORE["⬡ Store (append-only seam)<br/>Append (next-seq-only) · Len · At<br/>memStore | evidence-gcs (GCS, DoesNotExist, no delete)"]
  CKSIGN["CheckpointSigner &larr; keybroker SinkSigner"]
  SIEM[("SIEM (Stream target)")]

  CALL --> APPEND --> CHAIN
  APPEND --> STORE
  APPEND -. "periodic" .-> CKPT
  CKPT -->|"SignCheckpoint (tbs)"| CKSIGN
  CALL --> STREAM --> STORE
  CALL --> VERIFY
  VERIFY --> CHAIN
  VERIFY --> CKPT
  STREAM -. "real webhook (planned)" .-> SIEM

  classDef tier1 fill:#cfe3f7,stroke:#1168bd,color:#11304a;
  classDef seam fill:#d8f0dd,stroke:#27ae60,color:#13502a;
  classDef store fill:#ececec,stroke:#888,color:#111;
  class APPEND,CHAIN,CKPT,STREAM,VERIFY tier1;
  class STORE,CKSIGN seam;
  class SIEM store;
```

**Load-bearing invariants (read in source):**
- **Append-only by construction.** The `Store` seam exposes only `Append/Len/At` — no
  update or delete. `memStore` accepts a write **only** if `Ref.Sequence == len(entries)`
  ("no gaps, no rewrite"); `evidence-gcs` maps each sequence to one object and writes with
  a GCS `DoesNotExist` precondition, with a workload SA that has create/get/list but **no
  delete**.
- **The sink stamps authoritative time.** `AppendedAt` is set by the sink, never trusted
  from the caller's `ObservedAt`; two records with reversed `ObservedAt` still order by
  sink time.
- **Two chains, both verified.** `VerifyChain` recomputes every record hash from genesis;
  `VerifyCheckpoints` validates each checkpoint's **signature** (pinned to the expected
  `SinkID`), its `PrevCkptHash` link, and that its `HeadHash` matches the committed record
  — then confirms the latest checkpoint covers **all** records (no unsealed tail).
- **WORM has two strengths.** Against the workload SA it is append-only by IAM +
  precondition (tamper-*resistant*); against a privileged actor it is the signed hash
  chain (tamper-*evident*) unless the GCS **bucket-lock retention** is enabled (off by
  default — production must set it; see view [05](05-deployment.md) and `docs/RISKS.md`).

## Notes & confidence
- All three components were read in source and are implemented. Checkpoint persistence is
  currently in-memory in the Sink (durable checkpoint persistence to GCS is a tracked
  follow-up that closes the tail-truncation residual); the `evidence-gcs` *record* store is
  real and durable.
- `console7-cloud-local` supplies a **file-backed** `Store` (append-only JSONL, fsync,
  `VerifyChain` on load) — the same seam, a different durability substrate — see view
  [05](05-deployment.md).
