# ADR-046: Stabilize the single-family simplification

**Status:** Proposed  
**Date:** 2026-08-17

## Context

The current stabilization work is completing the move to one qualified family
version, shared protocol primitives, explicit feature ownership, and one family
release record. The patch must leave no competing normative models in the live
specification or its machine-readable artifacts.

This ADR records the proposed decision and its integration surface while the
patch is under review. Normative authority remains the live specification and
machine-readable artifacts, not this ADR.

## Decision

1. One exact family version replaces every per-document negotiation artifact.
2. A key-envelope instantiation declares recipient set, typed reference and
   wrapping, carrier, generation form, and extra rotation triggers.
3. Workspace uses `marmot-mls-leaf` to bind the exact authorized MLS leaf.
4. Node-scoped Control JWTs are owned only by Control.
5. One family release manifest replaces per-document release manifests.
6. Authoring checks reject the retired models and terminology.

The complete corresponding changes belong in the live specification, registry,
schemas, release metadata, vectors, and authoring checks. Those normative
artifacts stand on their own and govern if they differ from this record.

## Consequences

The family has one version and one release record, while Core owns the shared
key-envelope contract and Control owns its node-scoped token profile. Workspace
resource delivery names an exact typed MLS leaf, and stale versioning and
terminology cannot pass the maintained authoring checks. The ADR remains
proposed until the integrated normative patch is accepted; it must then be
marked accepted and moved to `docs/adr/archive/`.
