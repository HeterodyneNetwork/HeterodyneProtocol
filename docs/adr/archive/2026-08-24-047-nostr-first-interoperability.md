# ADR-047: Nostr-first interoperability with optional Assurance

**Status:** Accepted
**Date:** 2026-08-24

This record is non-canonical. The live specification family, protocol schemas,
and registry contain the complete protocol. If this record and those artifacts
disagree, the specification family and normative artifacts govern.

## Decision

Adopt a Nostr-first baseline in which exactly one active Nostr public key is a
human or organizational persona's current network identity and Marmot account
identity. A bare active key is a complete, first-class Heterodyne persona.
Baseline identity, Nostr event validity, communication, social behavior, and
workspace participation do not require a cold root, KERI state, succession
authority, witness set, threshold, or epoch key.

Move cold-root continuity, reciprocal enrollment, KERI-style succession and
recovery, witnesses, thresholds, epoch authority, downgrade resistance, and
enhanced associated-key records into an optional Assurance specification.
Assurance depends only on Core. Comms, Control, Social, and Workspace may
compose Assurance but cannot require it for baseline conformance.

Use standard Nostr discovery and outbox behavior: kind `0`, NIP-05, and NIP-65
kind `10002`. Retire required Heterodyne identity pointers and public feed
indexes. NIP-01 authorship, signature, addressing, filtering, and replaceable
event selection remain unchanged by Heterodyne metadata.

Persona- and group-owned Radicle repositories store exact signed Nostr events.
Relay and repository candidates form one source-neutral union; carriers do not
rewrite, normalize, re-sign, or wrap the event as an alternate authorship
object. Current replaceable state is selected by ordinary NIP-01 rules,
regardless of the carrier from which an event arrived.

Trusted seeds are concurrent, replaceable availability providers. A seed may
operate an authorized Radicle writer ref and public or private relay service,
but it gains no persona-key, repository-owner, group-admin, workspace, or MLS
authority. Private service remains bounded by explicit authorization and
fails closed when its required authority state is absent or invalid.

This pre-1.0 redesign is a semantic replacement, not a compatibility-preserving
revision. Existing users select an active Nostr key; former cold roots may be
attached through optional Assurance. Historical events remain governed by
their original rules but do not define current conformance. No pre-1.0 version
number or vector identifier constrains the replacement semantics.

Keep the existing conformance vector corpus frozen as the rolling historical
snapshot tied to its declared source and snapshot commits. Ordinary protocol
editing does not rewrite vector payloads, projections, coverage, metadata, or
snapshot artifacts. A later explicit reconciliation may author a replacement
snapshot against a stabilized full source commit.

## Context

The prior required cold-root and KEL identity model made Heterodyne a parallel
identity system that vanilla Nostr and Marmot implementations could not use as
their native account model. Public discovery and repository behavior also
depended on Heterodyne-specific pointers and indexes even though standard Nostr
already defines profiles, relay discovery, event identity, and replaceable
state.

The protocol is still pre-1.0, so it can replace those semantics without
claiming compatibility. Separating optional continuity assurance from the
active-key baseline allows existing Nostr users to adopt Heterodyne without a
key rotation while retaining a path for stronger recovery and succession.

## Consequences

- The live family has six documents: Core, Assurance, Comms, Control, Social,
  and Workspace.
- Existing Nostr and Marmot implementations need no Heterodyne-specific wire
  changes for baseline participation.
- Assurance-aware clients may verify continuity and recovery without changing
  NIP-01 event identity or Marmot membership rules.
- Repository replicas and relay copies can be reconciled by event ID and exact
  bytes instead of carrier-specific authority.
- Trusted seeds can improve availability without becoming identity or group
  authorities.
- The historical five-document snapshot remains reproducible until a separate,
  deliberate reconciliation replaces it.

## Acceptance and archive

Acceptance followed complete implementation, independent review, and clean
pre- and post-acceptance matrices. The live specification family and normative
machine-readable artifacts are self-contained and stand on their own without
this record. The frozen 482-vector snapshot remains historical and
unreconciled; it records its pinned source rather than current conformance.
This record was accepted and moved to `docs/adr/archive/` only after those
conditions were established.
