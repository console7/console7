---
name: supply-chain-policy
description: Console7's dependency and software-supply-chain policy — how to add, install, pin, and scan third-party code safely (Socket Firewall, lockfiles, govulncheck, SHA-pinned actions). Use when installing packages, adding a dependency, writing a CI workflow, or wiring build tooling in the console7 repository.
---

# Console7 supply-chain policy (CO-5, CO-8, CO-12.7)

Console7 is a Tier-1 control plane; a compromised dependency here is a supply-chain
compromise of every adopter. The software supply chain is treated as adversary-
relevant: provenance, pinning, scanning, and least privilege are mandatory.

## Installing packages — route through Socket Firewall

[Socket](https://socket.dev) detects malicious packages (install-time RCE, typo-squats,
cred stealers) that a CVE feed does not yet know about. Install **through** it:

```bash
sfw npm ci            # not: npm install / npm i
sfw pip install -r requirements.txt
```

- Bare `npm install`, `npm i`, `npx`, `pip install`, `pnpm add`, `yarn add`, `uv add`,
  `bun add`, `gem install` are **blocked** by the Bash guard unless routed through
  `sfw` or lockfile-faithful (`npm ci`, `--frozen-lockfile`, `--immutable`).
- `sfw` not installed? `npm i -g sfw` once, out-of-band (this bootstrap is allowed).
- **Never** `curl … | sh` / `wget … | bash` — download, review, pin, then run.

## Pinning — nothing floats

- **GitHub Actions:** pin to a full commit SHA, with the human-readable tag in a
  trailing comment: `uses: actions/checkout@<40-hex> # v4`. Dependabot keeps the SHA
  fresh. (OpenSSF Scorecard: Pinned-Dependencies; CO-5.5.)
- **Go:** depend on released versions only — never `go get …@latest`/`@main`. Commit
  `go.mod` **and** `go.sum`. Run `govulncheck ./...`.
- **npm/pip (UI, tooling):** commit the lockfile; install lockfile-faithfully.

## Scanning — what runs, and what it means

| Surface | Tool (CI gate) | CO |
|---|---|---|
| Secrets | gitleaks + GitHub push protection (block-on-detect) | CO-8.1 |
| Malicious deps | Socket (GitHub App on PRs + `sfw` at install) | CO-5.1 |
| Known vulns (Go) | `govulncheck` | CO-5.5 / CO-11 |
| SAST | semgrep (now) + CodeQL (when Go code lands) | CO-7.1 |
| Action/config posture | OpenSSF Scorecard (private for now) | CO-5/6 |

## Choosing to add a dependency at all

Adding a dependency is a governed decision, not a reflex. Prefer the Go standard
library or a dependency already in `go.mod`. If you must add one, check its Socket
score, maintenance/provenance, and licence compatibility (Apache-2.0-compatible)
first, and say why in the PR.

## Deferred (tracked targets — see standard §5)

SBOM, SLSA L3 provenance, and signed-release + admission verification bind when build
artifacts exist. Don't claim them yet; don't silently skip them — they are dated
accepted-gaps in the standard.
