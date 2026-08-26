# Task 7 Post-round Boundary Correction Design

## Status and scope

This design records the approved integration-safety correction after Task 7's five planned fix rounds. It is not a sixth round. It closes aliasing at three trust boundaries without editing frozen topic sources, rolling vectors, snapshot metadata, registry revision 14, projections, baselines, reports outside the Task 7 report, or release artifacts.

The correction owns the current Social implementation and focused tests in `docs/spec/vectors/generator/src/`, plus the affected current Social prose/schema only if executable behavior requires it. The preferred implementation is module-local and schema-specific. A shared generic snapshot helper is rejected because it could accidentally clone opaque authority identities, weaken closed-shape rules, or couple Comms and Social trust policies.

## Comms publication request capture

`signCommsSocialPublication` will treat its complete request as hostile mutable input. Before any semantic read it will call `Object.getOwnPropertyDescriptors` exactly once on the top-level request. The request must be a plain object whose exact enumerable string data descriptors are:

- `authority`
- `registration`
- `token`
- `represented_persona`
- `event`
- `requested_feed`
- `requested_resource`
- `execution_token`
- `request_digest`

Symbols, accessors, unexpected members, inherited data, sparse arrays, and non-enumerable request data are rejected. The captured `authority` descriptor value is retained as one opaque local reference. That same reference is used for the authority WeakMap lookup, trusted clock call, execute-once call, and signed-publication proof branding.

Every other descriptor value is independently copied into a closed immutable snapshot before validation. Objects and arrays are traversed with one own-descriptor read per node, accept only enumerable data descriptors, require the expected schema-specific keys or dense array indices, and are deep-frozen. Registration and unsigned-event shapes remain constrained by their existing closed schema and strict NIP-01 checks. The token permits only its current declared members and sanctioned optional current members; legacy or unexpected members reject. The function never spreads or rereads the caller request or its nested values. Internal token time substitution is constructed from the snapshot, not the caller object.

This makes authority A-to-B laundering, content size substitution, and feed/resource destination substitution fail before signer execution.

## ATProto validation capture and current-record seeding

`validateAtprotoBinding` and `validateAtprotoRevocation` will start with module-local schema-specific capture functions. Each function performs one top-level descriptor capture, preserves only the resolver-authority opaque reference, and recursively snapshots and freezes all data members: coordinate, clock, candidates, lineage, revocations, binding values, Nostr events, DID signatures, resolution evidence, and observation evidence. Closed objects require exact current keys, and arrays require dense data descriptors. Accessors or open shapes reject before semantic validation.

The public wrappers pass only captured snapshots to private validators. Candidate selection validates each captured candidate once. The exact selected validated record object is inserted into the historical/revocation universe before any remaining lineage evidence is processed. The selected caller evidence is never read or validated again. Other candidates and lineage entries may populate the universe only from their already captured values. Selection remains source-neutral: greatest `created_at`, then lowest event id, within the exact expected `(DID, pubkey)` coordinate.

Revocation validation inside binding validation uses the already captured revocation tree and calls a private snapshot-consuming implementation so it does not attempt to recapture or reread caller evidence. This prevents a candidate that presents record A during selection and record B during history construction from removing a revoked selected record from the authenticated universe.

## Observation v2 and proof binding

The durable binding-observation envelope advances to the closed domain `heterodyne-atproto-binding-observation-v2` with signing separator `heterodyne:atproto-binding-observation:v2\0`. It adds:

```text
did_signature_digest = lowercase hex SHA-256(exact 64-byte DID signature)
```

The observation signature covers this member in the canonical fixed field order. V1 observations are not accepted by the corrected current validator.

`validateBindingEvidence` captures one `resolution_evidence` reference from its immutable evidence snapshot and reuses that exact captured value for both DID-proof and observation verification. `authenticateAtprotoBindingObservation` accepts a closed binding-proof snapshot containing the strict Nostr event, canonical binding payload, DID signature, verification-method id, expected binding coordinate/hash/generation, and event creation time together with that same captured resolution evidence.

Before trusting an observation attestation, the observer-validation path:

1. re-authenticates the configured resolution evidence under the same resolver authority at the required historical time;
2. strict-validates the Nostr event and exact event id, author, kind, creation time, canonical content, and binding coordinate;
3. verifies the exact DID signature against the named method and canonical binding payload;
4. matches `did_signature_digest` to the exact captured signature bytes;
5. matches the resolution-envelope digest, policy, version, observation time, and checkpoint; and
6. verifies the resolver's observation signature over the complete v2 envelope.

This makes a resolution A-to-B accessor unusable and makes post-observation DID-signature substitution detectable by the durable observation itself.

## Failure behavior and compatibility

All new capture or proof failures use the existing fail-closed public decisions:

- Comms publication: `agent-signer-mismatch`
- binding validation: `atproto-binding-invalid` or the existing authenticated revocation decision
- direct revocation: `atproto-revocation-invalid`
- observation: `atproto-binding-observation-invalid`

No fallback accepts open, accessor-backed, legacy, or partially captured data. Current accepted callers use ordinary plain data objects and receive the same successful result except that durable observation evidence must use v2.

## Exploit-first verification

Strict TDD will establish RED before production edits for:

- Comms authority A-to-B laundering;
- Comms small-to-large content substitution;
- Comms allowed-to-different feed/resource substitution;
- ATProto candidate A during selection and B during historical/revocation processing;
- binding resolution A-to-B substitution; and
- DID-signature substitution after observation.

Each RED must fail for the intended missing boundary, not because of fixture or type errors. Each minimal implementation is followed by focused GREEN. Final verification runs the affected generator tests and build, family/draft lane, history-bound snapshot lane with exact 482 count, the repository's required conformance gates, a full security diff review, and frozen-boundary checks. The Task 7 report gains a `Post-round boundary correction` section with exact RED/GREEN/full evidence, ownership expansion, and concerns. The final commit message is `fix: snapshot Social trust inputs`.
