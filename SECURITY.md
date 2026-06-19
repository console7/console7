# Security Policy

Console7 is a security control plane. It runs untrusted agent code, holds the keys to
many sandboxes, and is meant to be trusted inside other organisations' tenancies.
We treat vulnerabilities accordingly.

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.** Report it privately via
GitHub Security Advisories (Security → Report a vulnerability) or to the security
contact below.

<!-- PLACEHOLDER: set a monitored address (e.g. a dedicated alias or a
     security.txt / RFC 9116 contact) before public launch. -->
- **SECURITY_CONTACT:** `<SECURITY_CONTACT — TBD>` (e.g. `security@console7.example`)

Please include: affected component (e.g. `keybroker`, `control-plane`, `sandbox`,
a provider, the SDK), version/commit, a description, and reproduction steps. We aim
to acknowledge within `<ACK_SLA — TBD>` business days and to coordinate a fix and
disclosure timeline with you.

## Scope (high-priority areas)

Findings in these areas are highest severity, mirroring the threat model
(`docs/DESIGN.md` §10):

- **Control-plane-as-target** — any path to read stored credentials, escalate from
  the control plane to the key broker, or have an operator read a user's session.
- **Credential handling** — long-lived secrets at rest, subscription-token leakage
  or pooling, a credential reachable by a sandbox that should not hold it.
- **Egress / isolation escape** — bypassing the default-deny egress boundary,
  exfiltration over an allowed channel, or filesystem/network escape from a sandbox.
- **Scope / policy bypass** — a session obtaining reach beyond its target's
  tier × stratum, cross-tier escalation, or actuation of production from a session.
- **Supply chain** — tampering with build, provenance, or signing of any artifact.

## Supported versions

<!-- PLACEHOLDER: replace this table at the first tagged release. Until then the
     project is pre-alpha and no version is supported for production use. -->

| Version | Supported |
| ------- | --------- |
| `<LATEST — TBD>` | :white_check_mark: |
| < `<LATEST — TBD>` | :x: |

Pre-alpha: no released version is yet supported for production use; security fixes
land on `main` only until the first tagged release.

## Our commitments

- We ship signed releases with SBOMs and provenance.
- We publish a threat model and abuse-case register and keep them current.
- We credit reporters who wish to be credited.
