# `sandbox/base-image/` — the wrapped engine + policyHelper

**Trust tier:** data plane — runs untrusted agent code. **Distinct build identity** from the
control-plane and key-broker images (`ARCHITECTURE.md` §6.4; `DESIGN.md` §8) — *the thing that
runs untrusted code must not share a build identity with the thing that holds the keys*.

Wraps the **genuine Claude Code engine** (headless CLI), **pinned** via the `CLAUDE_CODE_VERSION`
build arg — Console7 **orchestrates** the engine and **MUST NOT reimplement the agent** (`GOAL.md`
"what Console7 is not"; `DESIGN.md` §1.4). Upgrades are **canaried** before fleet rollout (an
upstream change can shift permission/hook behaviour), so the version is bumped deliberately, never
floated. The build and runtime base images are tag-pinned; **production MUST pin them by digest**
before the signed release (this is the artifact that runs untrusted code).

## What's here

- **`Dockerfile`** — multi-stage: builds the `console7-policyhelper` renderer + the
  `console7-tripwire` hook (Go), then a `node`-based runtime that installs the pinned engine,
  creates a **non-root** `sandbox` user (no sudo, no login shell, no standing credential), and roots
  the locked-policy dir (`/etc/claude-code`, `root:sandbox` setgid) so the agent reads but cannot
  write it. Ends `USER sandbox`.
- **`entrypoint.sh`** — launches the engine as the non-root user and **fails closed** if the locked
  `managed-settings.json` is absent (the engine never runs without the policy that constrains it).
- **`../policyhelper/`** — the Go package + `console7-policyhelper` (renders the locked
  managed-settings) + `console7-tripwire` (the operate mutating-command hook binary).

## policyHelper — the locked policy

`policyhelper.Render(profile)` produces the **managed-settings.json** (Claude Code's
highest-precedence settings tier, which the agent cannot override) from the session's resolved
`SessionProfile` (persona × tier). It is the **in-band, defence-in-depth** layer — **never the
control of record** (`GOAL.md` tenet 3): the authoritative controls are least-privilege identity and
the default-deny egress perimeter. If the two disagree, the boundary wins.

- **author** → development-capable permissions; self-modification + obvious actuation denied.
- **operate** → **read-only** (every file-mutating tool denied; Bash allowed for read-only CLI per
  `DESIGN.md` §5.4) + the **PreToolUse mutating-command tripwire** (the `console7-tripwire` binary)
  on Bash — a **best-effort heuristic** (quote-aware tokenizer; recurses into `sh -c`/`eval`; denies
  interpreter inline-eval; matches subcommands past global flags), fail-closed, denies in-sandbox. It
  is a baked binary (fully table-tested), **not a reliable block**: residual bypasses (`$(...)`,
  encoded payloads) are disclosed, and the **authoritative** local-FS control is the **read-only /
  ephemeral workspace mount** (a sandbox-runtime boundary control, `DESIGN.md` §5.1 — lands with the
  engine wiring). Cloud mutations are blocked authoritatively by the read-only IAM identity.
- both → bypass-permissions mode disabled; **lower-scope (project/user) hooks + permission rules
  locked out** (`allowManagedHooksOnly` / `allowManagedPermissionRulesOnly`) so an untrusted target
  repo's `.claude/settings.json` cannot inject its own hooks or auto-approve rules; the engine's
  non-essential outbound traffic / auto-update / telemetry disabled (`tenet 1` — the engine must not
  phone home from in-sandbox). *(The exact managed-settings field names/placement are validated
  against the pinned engine when the orchestrator is wired — synthetic in this PR.)*

The renderer runs **control-side** (the orchestrator renders + injects the managed-settings
read-only) or, for the local dogfood, **inside the image as root** (where the locked dir exists):
`console7-policyhelper < session-profile.json`, then start the engine.

## How the rendering reaches the engine

```
SessionProfile ──Render──▶ managed-settings.json (→ /etc/claude-code, 0444, root:sandbox)
                                  │  references the BAKED tripwire binary
                                  │  (/usr/local/bin/console7-tripwire) for the operate Bash hook
                                  │  injected read-only / written by the control plane before start
                                  ▼
                           entrypoint.sh ──exec──▶ claude (non-root, locked by managed-settings)
```

## Real vs deferred (PR-3)

- **REAL:** the policyHelper renderer (author + operate, tested), the operate tripwire binary
  (robust + table-tested), the Dockerfile + entrypoint (fail-closed), and the hadolint gate.
- **DEFERRED — the signed-release pipeline:** building the image and signing it with a **distinct
  signing identity** + SBOM + SLSA provenance (`DESIGN.md` §8; the ROADMAP Phase-1 "first signed
  release" milestone) is a separate workstream; this PR lands the artifact + its static-lint gate.
- **DEFERRED — engine wiring:** the orchestrator stays synthetic, so wrapping the engine end to end
  (and the tripwire's "emit an incident to the evidence sink" half) is a clean follow-up — which is
  also the trigger to pivot the out-of-tree `console7-cloud-local` dogfood to its real-engine loop.
