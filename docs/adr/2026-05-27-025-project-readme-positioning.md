# ADR-025: Project README — audience, positioning, logo, and status framing

**Date:** 2026-05-27
**Status:** Accepted
**Decision makers:** liam.helmer (maintainer) + star-chamber (gemini-3.1-pro, gpt-5.4) + codex council seat

## Context

The repository's `README.md` is a 13-line stub that predates the current
0.x spec. It still claims the repo "currently contains background research
only," which is now false: the protocol is fully drafted at
`docs/spec/heterodyne.md` (v0.3.0), with 24 ADRs, an architecture overview,
a threat model, a glossary, and a conformance test-vector format. The stub
undersells the project and gives a newcomer no reason to care.

The maintainer wants a README that explains the protocol's **purpose and what
it means to people** — a social network that is fully open, where no provider
owns the user's data, that runs on minimal compute, resists censorship, is
hard to shut down, decouples identity from any single account or provider while
keeping users findable, authenticates messages, encrypts private communication
against well-resourced adversaries, and lets anyone build an interoperable
client by following the specification. The supplied brand logo
(`HeterodyneProtocolLogo.png`, which already contains the wordmark) is to be
incorporated.

A key tension: the vision is expansive, but the project is at the
**specification stage with no reference client yet**. The README must sell the
vision without misrepresenting maturity.

## Decision

Replace the stub with a **comprehensive, vision-forward** README that opens
with a balanced hook (accessible to the curious public) and then progressively
discloses the technical model for builders. Specifically:

- **Hero:** the brand logo, centered, copied into the repo at
  `docs/assets/heterodyne-logo.png` and referenced with a centered HTML block.
  The logo already carries the wordmark, so no separate H1 title image is
  needed.
- **Audience:** balanced — a human "what it means to you" section first, then a
  "how it works" section (Nostr identity + Matrix transport) for implementers.
- **Status:** honest. A visible status note states the spec is a v0.3.0 DRAFT
  in its 0.x in-flux phase, the protocol is fully specified, a reference client
  is the next milestone, and contributions are welcome. Vision is sold fully,
  but maturity is not overstated.
- **Scope:** comprehensive — logo/tagline, what-it-means-to-you, how-it-works,
  the room taxonomy table, project status & roadmap, repository navigation,
  build-your-own-client / contributing, and license placeholder.
- **Accuracy:** all protocol claims trace to the current spec/CLAUDE.md; links
  point to real files (`docs/spec/heterodyne.md`, `docs/architecture.md`,
  `docs/glossary.md`, `docs/security/threat-model.md`, `CHANGELOG.md`,
  `docs/adr/`, `research/INDEX.md`).

## Requirements (RFC 2119)

- The README MUST display the Heterodyne logo at the top, sourced from an
  in-repo path (`docs/assets/heterodyne-logo.png`), not an external URL.
- The README MUST explain the protocol's purpose in human terms covering:
  data ownership, openness, minimal compute, censorship resistance,
  difficulty of shutdown, identity portability across providers/accounts,
  findability, message authentication, and strong private-message encryption.
- The README MUST state that any party can build an interoperable client by
  conforming to the specification.
- The README MUST disclose current project status accurately: specification
  stage, v0.3.0 DRAFT, 0.x in-flux until 1.0, no reference client yet.
- The README MUST NOT claim the repository contains "background research only"
  or otherwise misrepresent the spec's completeness.
- All factual protocol claims in the README MUST be consistent with
  `docs/spec/heterodyne.md` and `CLAUDE.md`.
- Internal links in the README MUST resolve to files that exist in the repo.
- The README SHOULD progressively disclose detail: an accessible hook before
  technical mechanics.
- The README SHOULD include the room taxonomy and a repository navigation
  section so readers can find the normative material.
- The README SHOULD invite contribution and describe the next milestones
  (test vectors, reference client).
- The README MAY include a license section; when no `LICENSE` file exists yet,
  it MAY mark licensing as to-be-determined rather than asserting a license.
- Security/privacy claims SHOULD be framed against the spec's actual guarantees
  (Megolm/MLS group E2EE, homeserver blind to plaintext) and SHOULD NOT promise
  unconditional unbreakability.

## Consequences

- `README.md` grows from a 13-line stub into the project's primary entry point;
  it must be kept in sync with the spec as 0.x evolves (a maintenance cost).
- A binary asset (`docs/assets/heterodyne-logo.png`, ~900 KB) enters version
  control. This is a deliberate, one-time addition flagged by document mode's
  eligibility gate and accepted by the maintainer.
- New contributors get an accurate picture of both the ambition and the
  current (pre-implementation) stage, reducing the risk of mismatched
  expectations.
- The README becomes a claims surface: future spec changes that alter a stated
  guarantee require a corresponding README edit.
