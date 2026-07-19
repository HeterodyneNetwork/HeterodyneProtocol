# Split Task 8 implementation report

Baseline: `a256011`

Implementation commit: `7392ef7`

## Corpus inventory

- Existing authored IDs at baseline: 194.
- Existing IDs preserved: 194; missing or renamed: 0.
- New split-specific IDs: 28.
- Final vectors: 222.
- Coverage owner distribution: Core 114, Comms 32, Social 76, Control 0.
- Control coverage state: `incomplete-draft`; no Control conformance claim or
  vector exists.

## RED

The initial focused run was:

```text
npm --prefix docs/spec/vectors/generator test -- src/schema.test.ts src/author.test.ts src/coverage.test.ts src/stamping.test.ts
```

It failed for the intended reasons: the schema and authored vectors still used
scalar `spec_version`, `coverage.ts` and `stamping.ts` did not exist, and the
author test observed the legacy envelope. Subsequent focused RED cycles proved:

1. null `profile` was accepted by the schema before exact optional-field
   enforcement;
2. the registry-approved Tier-3 stamping-profile vector was absent;
3. legacy `decision_trace` metadata was incorrectly normalized as expected
   implementation output rather than vector input context; and
4. Core-owned cache authentication/stale-source recovery vectors were still
   assigned to Social.

Each failure was observed before its production change.

## GREEN

- Focused schema/author/coverage/stamping suite: 4 files, 20 tests passed.
- Full `check`: TypeScript build passed; 12 files, 129 tests passed; 222
  vectors verified.
- `family:check`: `validated protocol document family`.
- Archive check:
  `cmp -s docs/spec/heterodyne.md docs/spec/archive/heterodyne-0.4.0.md`
  passed.
- `git diff --cached --check`: passed.
- Final metadata audit: exact fixture map and registry revision; no vector
  envelope scalar `spec_version`; qualified owner/dependency versions and
  permanent references; no Control owner; sorted unique manifest.
- The compatibility reason-code JSON is byte-identical to
  `docs/spec/registry/reason-codes.json`.

## Regeneration proof

After staging the generated corpus, the following sequence ran successfully:

```text
npm --prefix docs/spec/vectors/generator run author
npm --prefix docs/spec/vectors/generator run coverage
npm --prefix docs/spec/vectors/generator run author
npm --prefix docs/spec/vectors/generator run coverage
git diff --exit-code -- docs/spec/vectors
```

Both author runs reported 222 vectors. Both coverage runs completed, and the
second regeneration produced no unstaged bytes.

## New vector IDs

- `acceptance-gating/authentication-before-policy`
- `acceptance-gating/message-request-no-receipt`
- `acceptance-gating/social-mute-tightens`
- `acceptance-gating/social-policy-cannot-loosen`
- `comms-envelope/nostr-native-event-valid`
- `comms-envelope/owner-stamp-valid`
- `core-redundancy/radicle-multihost-replication`
- `core-redundancy/stale-seed-rejected`
- `registry/downref-nonfrozen-rejected`
- `registry/frozen-entry-immutable`
- `stamping/control-carrier-comms-owner`
- `stamping/control-profile-retains-core-owner`
- `stamping/dr-outer-unstamped`
- `stamping/heterodyne-empty-content-tag-owner`
- `stamping/heterodyne-json-content-owner`
- `stamping/legacy-monolith-explicit`
- `stamping/legacy-monolith-inferred`
- `stamping/legacy-upstream-not-inferable`
- `stamping/no-restamp-existing-bytes`
- `stamping/non-stamping-profile-unchanged`
- `stamping/tier3-profile-owner`
- `stamping/upstream-profile-owner`
- `stamping/upstream-unstamped`
- `versioning/core-capability-bootstrap`
- `versioning/per-document-negotiation`
- `versioning/qualified-version-unqualified-rejected`
- `versioning/qualified-version-valid`
- `versioning/unknown-asynchronous-stamp-rejected`

## Contract implemented

- Replaced vector-envelope `spec_version` with the exact family interface.
- Replaced fixture scalar version with bare-semver `document_versions` and
  `registry_revision: 1`.
- Exhaustively assigned every existing and new vector ID exactly once, with
  per-vector ADR-033 corrections rather than directory ownership inference.
- Derived dependency pins only from the approved family DAG.
- Added registry-driven, fail-closed `stampOwner()` and `inferLegacyOwner()`
  across allocated JSON/tag forms, adopted upstream profiles, Tier-3,
  non-stamping breadcrumbs, DR outers, inactive Control, Comms carriers,
  unknown inputs, scoped monolith inference, and no-restamp behavior.
- Added the required Nostr-native Comms, Radicle Core redundancy, Comms hook,
  Social tighten-only, Core version/capability/stamping/legacy, and registry
  vectors with new IDs.
- Generated one sorted JSON coverage manifest and all five Markdown views
  strictly from that manifest.
- Made the vector reason-code artifacts generated compatibility projections of
  the authoritative registry container.
- Replaced the stale one-spec vector README with family metadata, ownership,
  coverage, reason-code authority, determinism, and generator guidance.

## File audit

The commit contains 250 files, all under `docs/spec/vectors/`. It includes the
generator source/tests, generated schema/fixtures/reason projections, all 194
existing regenerated vectors, 28 new vectors, coverage manifest/views, and
the family-aware README. No registry authority file, family document,
archive, or `research/sources/` file changed.

## Remediation after review

Review remediation on top of `7392ef7` closes the carrier, historical-byte,
metadata, profile, acceptance, signature, and deterministic-tree gaps.

- Final corpus: 262 vectors: Core 123, Comms 57, Social 82, Control 0.
- Historical production audit: 11 former production vectors are now explicit
  `consume`/verification obligations with `source_schema=monolith/0.4.0`, the
  original input and expected bytes nested unchanged, and an explicit
  no-restamp result. Eleven new `-v050` IDs produce separately signed current
  forms with the correct qualified owner/profile stamp.
- Profile coverage: all 14 active revision-1 profiles have concrete coverage,
  including both breadcrumbs, all six Tier-3 kinds, DR 1059/1060/30078,
  Social mute/org-feed, and Comms 31015/31016. The inactive Control profile
  appears exactly once as reservation coverage and creates no Control claim.
- Acceptance coverage now closes established ordinary accept, new ordinary
  hold without sender-observable signals, authentication reject, valid
  credential accept, unavailable-authority hold, five distinct credential
  rejects, Control-enrollment default hold, and Social WoT tighten-only/no-
  loosen composition with explicit follow/reply/distance/overmuted inputs.
- The Nostr-native envelope is now a deterministic complete NIP-01 event with
  a computed id and valid BIP-340 signature plus a signed-byte mutation reject.
  The owner-stamp case is a complete unsigned kind:31016 rumor whose string
  content is the canonical Comms payload frame. Negotiation and Social org-feed
  coverage likewise use complete deterministic carrier forms.
- Runtime validation and the generated JSON Schema enforce the exact owner
  version and exact dependency objects. Runtime reference validation permits
  only the owner and exact dependencies at `0.5.0`. KERI export, materialized
  KEL, and `kel_head` cases now point at their closest permanent anchors.
- Legacy owner inference requires a closed eligible kind and, for an absent
  stamp, positive archived-form evidence with no post-split discriminator,
  profile-only form, or adopted-upstream status. Negative tests cover each
  exclusion.
- Verification is now bidirectional: unexpected committed vectors, missing
  vectors, stale fixtures/schema/reason projections, incomplete manifest, and
  stale coverage Markdown all fail `check`. Six temporary-tree mutation tests
  prove these failures.
- The stale-seed redundancy case now exercises independent current hosts and
  durable canonical-head availability; it no longer duplicates repository
  head-regression behavior.

Remediation RED/GREEN evidence:

- The strict stamping/schema cycle first failed 5 of 27 tests, then passed all
  27 after implementation.
- The closed-tree verifier cycle first failed all 6 drift tests, then passed
  them all.
- Focused final suite: 5 files, 37 tests passed.
- Full final suite: 13 files, 146 tests passed; all 262 vectors verified.
- `family:check` passed and the 0.4 archive remained byte-identical to its
  source snapshot.
