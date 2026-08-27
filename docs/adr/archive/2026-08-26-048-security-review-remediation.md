# ADR-048: Security review remediation for heterodyne/0.6.0

**Status:** Accepted
**Date:** 2026-08-26

This record is non-canonical. The live specification family, protocol schemas,
and registry contain the complete protocol. If this record and those artifacts
disagree, the specification family and normative artifacts govern.

## Decision

An external model review of the 0.5.0 family identified seven structural
findings. The family adopts the following remediations and moves to
`heterodyne/0.6.0`. The full agreed design is
`docs/superpowers/specs/2026-08-26-security-review-remediation-design.md`.

**Replaceable-state timestamp bounds.** Source-neutral selection gains a
premature-candidate bound (`heterodyne:0.6.0#core-created-at-bound`): a
candidate whose `created_at` exceeds trusted verifier time by more than 900
seconds is quarantined out of the selection union until its time arrives,
closing the durable future-dated-capture primitive. A new optional profile
`core.ots-anchor.v1` (`heterodyne:0.6.0#core-ots-anchor`) adopts NIP-03 kind
`1040` OpenTimestamps attestations: a matured Bitcoin attestation that proves
`created_at` materially exceeds true existence time permanently refutes the
event, defusing future-dated time bombs for late-synchronizing verifiers.
Anchoring is never required for baseline interoperability.

**Privacy-tier re-cut.** Tiers are now: Tier 1 public plaintext; Tier 2
audience ciphertext on public carriers, directly cross-compatible with
encrypted Nostr posts on public relays; Tier 3 audience ciphertext confined to
authorized private-repository interfaces
(`heterodyne:0.6.0#comms-tier3-confinement`), including the kind `31011`
wraps, kind `31012` rosters, and rotation records — confining audience
membership metadata to allowed nodes. Plaintext in a private repository is
demoted from a tier to an orthogonal repository-visibility setting with its
honesty duties intact. This supersedes the tier definitions of ADR-028 as
amended by ADR-037.

**Workspace governance requires Assurance.** A workspace persona must hold a
window-complete `verified` Assurance enrollment bound at inception
(`heterodyne:0.6.0#workspace-governance-assurance`); authority mutations fail
closed without it while ordinary writes continue, and the `active-account`
compromise-reset class is forbidden for workspaces — the hot key can no longer
authorize its own succession. Repository owners and claim-ledger/OIDC
authorities receive SHOULD-level enrollment with a mandatory client warning.

**Enrollment contest window.** A reciprocal enrollment becomes pin-eligible
only after 604,800 seconds of observably public, conflict-free existence
(`heterodyne:0.6.0#assurance-enrollment-window`), witnessable by receipts for
late verifiers. Same-key contests (kind `31006`) and competing enrollments
fail closed to baseline. A duplicity conflict resolves only to an enrollment
with both a matured OpenTimestamps anchor proving materially earlier existence
and witness receipts spanning the gap
(`heterodyne:0.6.0#assurance-enrollment-tiebreak`) — established enrollments
recover from equivocation stalls, and no rule ever favors a key thief.

**SHA-1 per-binding analysis.** The blanket compartmentalization argument is
replaced by a per-binding table (`heterodyne:0.6.0#core-sha1-bindings`)
covering the RID locator, the kind `31010` `repo_head` possession snapshot,
and the Workspace `repository_head` carrier context. Authority bindings now
normatively require SHA-256 or stronger, and implementations should prefer
Radicle's `sha256` object format where available.

**Declared authorization-freshness bound.** The fixed 300-second
authorization-view window becomes the deployment-declared signed
continuity-manifest member `authorization_view_max_age` (default 300 seconds,
hard ceiling 86,400 seconds). Invariants test the declared value, relying
parties can read it before trusting a deployment, and declaring a long window
is disclosed as declaring slow revocation.

**Scope honesty.** Comms §12 gains an explicit OIDC non-goals statement
(private-network and workload authentication; not censorship-resistant). The
threat model gains a carrier-withholding/equivocation entry, and the registry
gains an `intentionally_coarse` flag reconciling Core §13.2 coarsening with
the Workspace distinct-outcomes rule.

## Accepted risks

- `compromise_time` selection within
  `[current_head.created_at, succession.created_at]` remains a recovery-holder
  power; OpenTimestamps anchors on legitimate events provide third-party
  dispute evidence, but the protocol does not adjudicate the choice.
- Carrier withholding for pure-relay readers is inherited from the Nostr
  carrier model and accepted with disclosure.
- Tier 2 and Tier 3 have no forward secrecy; users needing it use the
  Marmot/MLS path.
- A key thief can deny Assurance enrollment (bounded harm; baseline
  impersonation was already possible with the key).
- SHA-1 remains in the Radicle substrate; it is constrained, not replaced.

## Vectors

`docs/spec/vectors` is deliberately untouched by this change. The current
vector lane remains pinned at `heterodyne/0.5.0` (generator `FAMILY_VERSION`)
and its `draft:check` fails on the version pin until a follow-up change
regenerates vectors at 0.6.0, adds this ADR to the docs-lint allowlist, and
bumps the generator pin. The conformance vitest suite is version-agnostic and
remains green.
