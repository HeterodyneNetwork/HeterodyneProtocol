# Task 7 Fix Round 3 Design

## Scope and authority boundaries

This round closes four Social review findings without changing registry
revision 14, frozen topics/vectors, snapshot metadata, projections, or release
artifacts. The resolver attestation described below is a local embedding trust
boundary chosen by a client. It is never protocol identity authority and no
resolver key is registered globally.

## Comms-to-Social authorization

`authorizeCommsSocialPublication` binds an exact requested feed and resource
as well as the represented persona and signed event. Minting re-runs workload
registration, access-token, and attribution validation. It additionally
requires registration audience to equal the token's sole actual and expected
audience, registration subject thumbprint/proof to equal both the token `cnf`
and sender proof, each requested destination to occur in its matching allow
list, and an exact snapshot of every registration field and immutable token,
ledger identity, and generation field.

Comms consumes the capability before signing through a single consuming
function over the exact unsigned event. The consumer deletes the WeakMap entry
before returning, re-runs all validators against caller-supplied current
registration/token state, exact-checks the immutable snapshots, destination,
event, tags, signer, association, scope and time, and requires current
status/ledger/binding/grant bounds. A failed consume also burns the capability.
Success creates a second one-use WeakMap-backed authorship proof bound to the
unsigned event id. Social burns that proof while matching the exact signed
event. A later status, ledger generation, registration, grant change, or proof
replay therefore requires fresh pre-sign validation.

## Authenticated DID resolution

A new opaque `AtprotoDidResolution` capability is backed by a module-private
WeakMap. Its sole producer accepts a closed resolver-attestation envelope, an
Ed25519 or BIP340 signature, and a locally configured trust anchor. The signed
domain-separated envelope binds:

- canonical DID and resolution method;
- the exact canonical `did:web` HTTPS origin/path, or verified PLC log head
  plus log hash;
- canonical DID-document bytes and SHA-256;
- the selected verification method;
- resolution and expiry times; and
- resolver policy and implementation versions.

The producer validates the closed shape, canonical bytes/hash, derived
`did:web` URL or PLC evidence, selected method membership/controller/key,
freshness, and resolver signature before branding. It accepts no validity
boolean and exposes no document-branding shortcut. Fake victim documents,
forged attestations, and stale envelopes cannot mint authority. Production
resolvers must complete the existing WebPKI/address/redirect rules or verify
PLC operation history before attesting.

Binding and revocation verification receive only the opaque capability plus a
payload signature. Consumption exact-checks DID, named method, and freshness,
then verifies Ed25519 using the method stored behind the capability. DID-side
revocation selects the capability's current authenticated method, allowing a
legitimate DID-key rotation; it does not reuse the historical binding method.

## Current ATProto selection

`validateAtprotoBinding` accepts one carrier-tagged union of repository and
relay candidates. It strict-validates every candidate with authenticated DID
resolution, deduplicates by event id, and selects greatest `created_at`, then
lowest event id, without carrier preference. Only that selected event proceeds
through full predecessor/hash lineage and durable-revocation validation. The
API returns one selected event id and binding rather than independently
accepting individual forks.

Lineage entries retain their carrier and authenticated resolution capability.
Nostr-side revocations must be signed by the linked pubkey. ATProto-side
revocations must be signed by the current method in a fresh resolution
capability for the exact DID.

## Snapshot loader hardening

The disposable runtime derives its module path with `fileURLToPath`, copies
both registry and schemas rather than linking live normative data, and wraps
all work after `mkdtemp` in a catch that removes the temporary tree before
rethrowing. Its only rewritten source remains the copied frozen moderation
topic's exact legacy import.

## Verification

Each finding receives an exploit-first RED and focused GREEN. Completion runs
the Task 7 focused tests, generator build, family check, and history-bound
snapshot verification with exactly 482 vectors. The report records commands,
counts, review concerns, and the approved local resolver trust-boundary ruling.
