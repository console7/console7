# Governance

Console7 is early-stage open source. This document states how decisions are made and
who is accountable — proportionate to the project's size — and is itself a controlled
artifact under the SDLC standard
([`docs/standards/console7-sdlc-standard.md`](docs/standards/console7-sdlc-standard.md), CO-1).

## Roles

- **Maintainers** — the accountable owners (1LoD). They review and merge PRs, cut
  releases, and own the security response. Current maintainers are the code owners in
  [`.github/CODEOWNERS`](.github/CODEOWNERS).
- **Contributors** — anyone who opens an issue or PR under
  [`CONTRIBUTING.md`](CONTRIBUTING.md).

## How decisions are made

- **Code / design changes** land via reviewed PR, each mapped to the doc section /
  control objective it implements.
- **Significant, hard-to-reverse decisions** are recorded as ADRs (`docs/adr/`).
- **Posture / control changes** update the SDLC standard (the controlled artifact),
  not just code.
- Disagreement is worked out in the issue or PR thread; maintainers make the final
  call and record the rationale. If a tenet is thought wrong, it is challenged openly
  in the PR — never silently deviated from.

## Segregation of duties (current state)

The project currently has a **single maintainer**, so the standard's two-person
independent-review control (CO-4.3 / CO-4.4) is a **documented, dated accepted-gap**
(standard §5 #1). It is compensated by automated CI gates + independent automated
review + a **mandatory human merge gate** (no self-approving automation). When a
**second maintainer** joins — targeted before GA — required independent human approval
and `enforce_admins` are turned on.

## Security

Vulnerabilities are handled privately per [`SECURITY.md`](SECURITY.md)
(GitHub Security Advisories or `security@naanya.biz`). Do not open public issues for
vulnerabilities.

## Releases

Pre-alpha: no supported release yet. The first tagged release ships **signed, with an
SBOM and provenance** (ROADMAP Phase 1).

## Changing this document

Via reviewed PR, like any other controlled artifact.
