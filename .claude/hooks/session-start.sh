#!/usr/bin/env bash
#
# SessionStart hook for Console7 — orients a session to the SDLC posture and
# checks that the supply-chain tooling it will be held to is present. Purely
# informational + non-fatal: it prints context to the session, never blocks.

set -uo pipefail

note() { printf '%s\n' "$1"; }

note "Console7 — Tier-1 public OSS control plane. Governed by docs/standards/console7-sdlc-standard.md."
note "  • Changes land via signed, DCO-signed-off commits on a feature branch + PR (never push to main)."
note "  • PRs map each change to the doc section / CO it implements (CO-14.2)."
note "  • Dependency installs route through Socket Firewall ('sfw …') or a lockfile-faithful install (CO-5/CO-12.7)."
note "  • Skills/agents under .claude/ are first-party/self-authored only and are reviewed as code (CO-12.7/12.8)."

if ! command -v sfw >/dev/null 2>&1; then
  note ""
  note "  [advisory] Socket Firewall ('sfw') not found on PATH. Install out-of-band before adding"
  note "            dependencies:  npm i -g sfw   (or see https://socket.dev). The Bash guard will"
  note "            otherwise block bare package installs."
fi

exit 0
