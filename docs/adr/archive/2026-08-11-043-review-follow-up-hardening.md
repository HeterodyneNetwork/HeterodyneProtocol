# ADR 043: Review follow-up hardening

Date: 2026-08-11

Status: Accepted and archived

## Context

Review after the Marmot and invitation migrations found remaining ambiguity in
Tier 3 recipients, generic repo-relay conformance, persona profile projection,
publisher rotation, late retired-key content, node-advertisement time, Marmot
dependency preservation, registry allocations, and claim revision semantics.

## Decision

The accepted specification patch:

- targets Tier 3 wraps to active delegated device publishing keys, permits
  only narrowing, and rotates the audience generation on device removal;
- limits generic repo-relay conformance to clients while retaining the
  complete Radicle-backed Marmot relay server/storage profile;
- makes the public Radicle persona-profile record canonical, with one
  delegated vanilla `kind:0` publisher and repository-indexed address migration;
- treats unanchored content first seen after routine key retirement as
  provisional without weakening compromise cutoffs;
- bounds `kind:31010` initial skew, lifetime, expiry, refresh, and verifier
  clock uncertainty;
- clarifies encrypted-backup recovery for root loss and persona migration for
  suspected root compromise;
- preserves the exact adopted Marmot specification bytes in a closed local
  archive with Git-blob and SHA-256 verification;
- advances the registry to revision 7 with upstream Nostr kinds 1059 and
  22242; and
- fixes v1 claim `registry_revision: 2` as an immutable profile-allocation
  revision distinct from the current family registry pin.

## Consequences

Revision 7 and the rewritten vectors are breaking pre-1.0 corrections. The
specification family, registry, schemas, releases, archive manifest, and
vectors are canonical. This record is historical context only.
