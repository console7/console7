# `control-plane/ui/` — web-CLI front end + API gateway

**Trust tier:** Tier-1 (control plane). **Thin; holds no secrets.**

Authenticates the user against the adopter IdP (SSO), streams the live Claude Code
session to the browser (SSE), and accepts launch requests (`ARCHITECTURE.md` §2).
The browser is a governed window onto a real server-side session, not the session
itself (`DESIGN.md` §1.1). May use web tooling in its own build
(`docs/adr/0001-language.md`).

> P0: placeholder — no implementation.
