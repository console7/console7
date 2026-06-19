# `sandbox/base-image/` — the wrapped engine + tooling

**Trust tier:** data plane — runs untrusted agent code. **Distinct build identity**
from the control-plane and key-broker images (`ARCHITECTURE.md` §6.4).

Wraps the **genuine Claude Code engine** (headless CLI / Agent SDK) and its tooling —
Console7 **orchestrates** the engine and **MUST NOT reimplement the agent**
(`DESIGN.md` §1.4; `GOAL.md` tenet 8). The upstream version is **pinned** and
upgrades are **canaried** before fleet rollout (an upstream change can shift
permission/hook behaviour). `policyHelper` renders the composed, **locked**
managed-settings + PreToolUse hooks for the session's persona × tier (`ARCHITECTURE.md`
§8).

> P0: placeholder — no implementation.
