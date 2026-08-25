# Task 7 fix round 2 design

## Objective

Close the five remaining Social review findings without changing frozen topic
source bytes, registry revision 14, or frozen vector/snapshot artifacts.

## Runtime isolation

Current Social moderation exports remain current-only. A snapshot runtime
materializes a disposable repository-shaped TypeScript build, changes only the
copied frozen moderation topic's `./agent-moderation.js` import to
`./snapshot-agent-moderation-adapter.js`, emits runnable JavaScript, copies the
required registry/schema JSON, links the locked generator dependencies, and
loads the disposable `topics.js`. Current vector authoring and coverage paths
use this loader. The live module never imports or dispatches the legacy API.

## NIP-72 current-set evaluation

Candidate, approval, and deletion reference tags match required prefixes and
permit upstream trailing relay hints. Only approvals at or after the selected
kind `34550` declaration timestamp count, which makes removal/re-addition a
fresh set revision. Strict signed NIP-09 kind `5` requests exclude only the
deleting author's own referenced approval.

## Comms-to-Social authorization capability

`agent-authorship.ts` produces an opaque capability stored in a module-private
WeakMap. Production has no public constructor or plain-data fallback. The
producer invokes `validateWorkloadRegistration`, `validateAgentAccessToken`,
and `injectAgentAttribution`, then exact-checks represented persona, actual
signer, association, event kind, required publication scope, event time,
current registration/grant bounds, resulting attribution tags, and actual
author. Social accepts a non-active signer only when consuming that exact
capability against the same event/persona binding. Fabricated lookalikes fail.

## ATProto canonical proof and lineage

One explicit ordered serializer defines Nostr content, binding/revocation
hashes, and DID signature bytes. Bindings require canonical `did:web` or
`did:plc`, canonical 20-byte Base58btc `rad:z` RID when present, and an
Ed25519 signature verified directly against the named verification method in
the resolved DID document.

Generation 1 has a null predecessor. Every later binding names the prior
Nostr event id and canonical binding hash. A fresh verifier walks signed
repository-history or relay evidence through every predecessor to generation
1. Revocations enter only as strict signed Nostr events or directly verified
DID proofs. A verified revocation disables that generation; recovery requires
the next generation, a fresh nonce, and fresh Nostr and DID signatures.

## Verification

Each finding begins with a real exploit probe and observed RED. Focused Social,
Comms, registry, and schema tests, generator build, family check, and the
history-bound exact-482 snapshot check must pass. Frozen topic sources and
metadata remain byte-identical.
