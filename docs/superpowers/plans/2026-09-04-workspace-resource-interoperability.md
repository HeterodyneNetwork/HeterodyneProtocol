# Workspace Resource Interoperability Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans to implement this plan task-by-task. Delegate only when authorized. Steps use checkbox syntax for tracking.

**Goal:** Specify a small common contract for optional workspace resources so independent clients preserve authority and privacy while choosing their own applications and presentation.

**Architecture:** Workspace owns identity, governance, role grants, discovery, and authorization. Optional resource profiles own application formats and state semantics. Implementations choose storage engines, caches, editors, and internal algorithms subject to those contracts.

**Tech Stack:** Existing Markdown specifications, JSON Schema, TypeScript reference semantics, Vitest, Marmot/Nostr carriage, and Radicle authority repositories.

**Spec:** Proposed design below, constrained by `docs/spec/heterodyne-workspace.md` §§1, 9, 12–13 and `docs/spec/heterodyne-comms.md` §7.2. This plan is non-normative; it does not activate protocol requirements.

## Global constraints

- Preserve vanilla Nostr event serialization, signatures, kinds, relay operations, and existing fallback semantics. Allocate no new Nostr kind for this work.
- Preserve Marmot KeyPackages, MLS processing, application-event and media formats, routing, event-ID deduplication, and publish-before-apply behavior.
- Standard-compatible groups remain usable through their advertised ordinary Nostr relays by unmodified clients compatible with the adopted Marmot version. Optional resource features cannot introduce mandatory group extensions or enrollment prerequisites.
- Existing `heterodyne-private` groups remain a separate private Radicle admission profile; never imply that ordinary Marmot clients can join them or add public-relay fallback.
- A vanilla Nostr client is not necessarily a Marmot client. Relay compatibility does not imply encrypted-chat or Workspace-governance support in every client.
- Workspace administration and resource authorization remain enforced by capable validators; an ordinary chat participant is not automatically a Workspace member or authorized resource writer.
- Use repository objects for new profile metadata. Do not inject application-specific control frames into ordinary chat streams or modify standard clients to process them.
- Use existing signed-object conventions, canonicalization, trust boundaries, freshness, and schema/registry revision procedures. Do not hard-code a family version from this planning session when executing on a newer base.
- Do not edit frozen vectors, snapshot metadata, or `research/sources/` during ordinary authoring.
- Verification uses synthetic local fixtures only. No live relay, node, identity-provider, or account testing.
- After implementation verification, push the feature branch and create a PR against its base. Never merge automatically.

## Proposed design

### Common contract

Extend the signed resource advertisement with an optional `profile_binding`. Its presence means that participating clients must understand the binding before reading through a native adapter, mutating, exporting, or converting that resource. Absence retains existing native-resource behavior and must not be interpreted as a privacy or verification guarantee.

The proposed binding contains:

- `profile_id`: stable identifier for the native resource profile;
- `profile_version`: exact profile version, not an inferred compatible range;
- `profile_digest`: SHA-256 binding of the profile definition;
- `schema_digest`: SHA-256 binding of the resource wire schema;
- `required_features`: sorted unique feature identifiers whose semantics are mandatory for this resource;
- `optional_features`: sorted unique identifiers that may be ignored only as their profile permits;
- `privacy_manifest_digest`: SHA-256 binding of the protected privacy declaration.

Profile artifacts use the existing authorized repository resolution boundary. Digests are integrity bindings, not executable downloads, authority credentials, or public discovery tokens. Resolve and validate them only after the containing advertisement is authorized and decrypted. Do not execute retrieved code or fetch arbitrary schema references. A profile may identify a verifier or proof system without requiring a particular client binary or database engine.

Exact version matching is the first interoperable rule. Any cross-version equivalence must be explicitly specified by a profile and tested; no automatic highest-version selection or lowest-common-denominator fallback. An unsupported binding disables that resource's native operations while leaving unrelated resources and ordinary communication available. An authorized directory entry may still be displayed, but its native locator must not be fetched merely to discover what it means.

The common privacy vocabulary describes exposure of content, identifiers, membership associations, structure, timing, sizes, and access patterns, with observer classes such as members, application hosts, custodians, transport operators, and public observers. Each category reports `exposed`, `protected`, or `unspecified`, with a profile-defined explanation. `unspecified` never satisfies a policy requiring protection. This is a declaration checked against signed policy, not cryptographic proof of an implementation's behavior. Unknown required categories fail closed. Keep private manifests and correlatable identifiers out of public projections.

Profile and privacy changes are signed resource-policy transitions under existing governance and effect-time revalidation. Broader disclosure requires the applicable approvals and publicization rules. Host feature advertisements express availability only and cannot weaken the resource binding or grant authority.

### Optional resource profiles

Publish a normative checklist for profiles without implementing a document, task, calendar, database, or Encrypted Spaces profile in this patch. A profile specifies:

1. Stable resource/object identities, wire format, versions, and feature meanings.
2. Operation semantics, deterministic conflict treatment, and mapping to Workspace capabilities. Native ACLs may restrict but never expand effective Workspace authority.
3. Read/write/history eligibility, key-epoch binding, removal, and recovery behavior. Resource membership projections cannot independently grant access.
4. Offline proposals, admission/acceptance rules, and any receipt semantics. Receipts must bind the operation, resource, profile, and authority context; they cannot manufacture trusted time or supersede revocation rules.
5. Persistence, retention, and export semantics, including limitations on erasing copied data and keys.
6. Any state proofs, verification requirements, trusted starting state, freshness source, conflicting-head handling, and proof-system upgrades. A valid transition proof does not establish freshness or global agreement.
7. Conversion behavior, loss reporting, and provenance requirements.

Resource-specific proof formats and retention key hierarchies remain separate future profile work. This patch introduces no ZK dependency, replacement group-key agreement, global consensus service, or mandatory application runtime.

### Conversion boundary

Conversion creates a destination resource/version under current destination authorization and disclosure policy. It preserves an authorized source reference and records known losses, while retaining the original according to its policy. Source signatures authenticate source bytes only; a converter signs its own result. A source profile that cannot be understood cannot be safely converted by guessing. Readable previews are separate declared representations, not implicit authority to retrieve or publish the original.

Presentation changes within one profile need no conversion. Examples include board versus list views, typography, local search ranking, notifications, and navigation. Formulas, comment anchors, edit history, and application workflow transitions are shared semantics when exchanged.

## File map

- Modify `docs/spec/heterodyne-workspace.md`: binding, privacy, capability handling, profile obligations, conversion, and conformance rules.
- Modify `docs/spec/heterodyne-comms.md`: concise compatibility cross-reference only; preserve existing transport requirements.
- Modify `docs/spec/schemas/workspace/resource-advertisement-v1.schema.json`: optional binding and closed nested schema.
- Modify `docs/spec/vectors/generator/src/workspace-schemas.ts`: synchronized authoring schema source.
- Create `docs/spec/schemas/workspace/resource-privacy-manifest-v1.schema.json`: bounded declarative privacy artifact.
- Create `docs/spec/vectors/generator/src/workspace-resource-profiles.ts`: current-draft reference validation through existing verified authority inputs.
- Create `docs/spec/vectors/generator/src/workspace-resource-profiles.test.ts`: semantic and negative conformance tests.
- Update only affected live registry entries using the existing registry authoring/verification path, located with Semble before editing.
- Create a proposed ADR in `docs/adr/` recording the common-contract versus optional-profile decision, and archive it as accepted after review before merge.

## Task 1: Specify and validate profile bindings

**Consumes:** Existing verified resource advertisement and Workspace authorization context.
**Produces:** Signed binding schema and deterministic support decision: supported, unsupported, or invalid. These decisions never replace authorization.

- [ ] Record the baseline commit and use an isolated feature worktree at execution time; preserve unrelated changes.
- [ ] Locate current schema registration, registry tooling, and authoritative-object validation through Semble; follow their existing interfaces.
- [ ] Add failing cases for absent binding retaining existing behavior, exact supported binding, unknown required feature, unknown optional feature, digest mismatch, duplicate/overlapping feature sets, unsupported version, and a host claiming support without an authorized binding.
- [ ] Specify canonical binding validation, bounded identifiers/arrays using existing repository conventions, and protected artifact resolution; implement schema and reference checks.
- [ ] Verify unsupported resources neither fetch native locators nor block unrelated resources or ordinary chat.
- [ ] Run the focused tests and current build; commit prose, schemas, and reference semantics together.

## Task 2: Bind privacy declarations to policy

**Consumes:** Valid profile binding and current verified resource policy.
**Produces:** Protected privacy-manifest validation and policy compatibility result.

- [ ] Add failing cases for `unspecified` versus required protection, unknown required exposure category, digest mismatch, wrong resource/profile context, unauthorized manifest fetch, and private metadata included in a public projection.
- [ ] Define the closed manifest schema with observer/exposure categories and explicit profile context; keep claims distinct from evidence.
- [ ] Require governance revalidation for binding changes and applicable publicization approval for increased exposure; reject attempts to bypass policy with a different host or preview.
- [ ] Synchronize authoring schemas and affected live registry entries, then run focused tests and family validation.
- [ ] Commit the complete privacy contract.

## Task 3: Specify native profile and conversion obligations

**Consumes:** Binding, privacy compatibility, and effective Workspace authority.
**Produces:** Normative profile authoring requirements and conversion acceptance boundaries.

- [ ] Add synthetic cases proving native ACLs cannot expand a role, expired authority leaves an offline write a proposal, removed members cannot obtain future keys, and conversion requires authorized source access and destination writes.
- [ ] Add conversion cases for loss reporting, attempted source-signature reuse on changed bytes, destination visibility expansion, and an unsupported source profile.
- [ ] Write profile obligations and conversion rules in Workspace, including proof freshness and conflict limitations. Use examples as non-normative illustrations, not wire formats for new applications.
- [ ] Implement only common acceptance checks; leave application-specific merges, receipts, proofs, and retention algorithms to their profiles.
- [ ] Run focused semantic tests and commit.

## Task 4: Demonstrate Marmot and Nostr compatibility

**Consumes:** The completed common contract.
**Produces:** Local regression evidence and compatibility documentation.

- [ ] Locate existing current-lane Marmot/Nostr fixture tests through Semble and extend their actual validation paths, rather than introducing mocks that merely assert unchanged constants.
- [ ] Verify the same signed standard Marmot message/media fixtures pass and retain identical event IDs with and without an unrelated optional resource binding.
- [ ] Exercise existing publish-before-apply, event-ID deduplication, and ordinary-relay carriage fixtures with optional-resource support absent.
- [ ] Verify no profile requirement is inserted into standard KeyPackages, MLS extensions, group admission, or ordinary message payloads.
- [ ] Verify resource-only unsupported status does not become group rejection; separately verify private groups still reject undeclared public fallback.
- [ ] Document that plain Nostr relay compatibility, standard Marmot chat participation, Workspace administration, and optional resource editing are distinct capabilities.
- [ ] Commit the compatibility tests and cross-reference.

## Task 5: Review, verification, and PR

- [ ] Review the proposed ADR and normative patch together; ensure the specification stands alone and implementation-specific algorithms remain optional.
- [ ] Verify every added schema is reachable by existing current-draft checks and its authoring input matches. Keep frozen snapshot files unchanged.
- [ ] Run focused tests during each task:

  ```bash
  npm --prefix docs/spec/vectors/generator run test:current -- src/workspace-resource-profiles.test.ts
  npm --prefix docs/spec/vectors/generator run build:current
  ```

- [ ] Run the shared final gate from the repository root:

  ```bash
  scripts/conformance-ci.sh
  ```

  This covers current draft, historical snapshot, and independent conformance. If a Radicle patch is subsequently proposed for merge, also satisfy the delegate-operated isolated podman gate required by AGENTS.md.

- [ ] Check the final diff for unintended transport, group admission, registry, and snapshot changes. Mark/archive the ADR after acceptance review before merge.
- [ ] Push the verified feature branch and create a PR against its base with compatibility evidence and explicit scope. Leave merging to the maintainer.

## Plan self-review

- Common protocol scope: profile identification, safe support handling, authority binding, and privacy declarations are covered by Tasks 1–2.
- Optional profile responsibilities and conversion are covered by Task 3; no application format is silently standardized.
- Marmot and vanilla Nostr invariants are covered by Task 4, including the existing private-group exception.
- Verification and branch finishing are covered by Task 5.
- Encrypted Spaces integration, proof generation, consensus, detailed retention machinery, and application editors require separate proposals after this foundation is evaluated.
