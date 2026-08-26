# Task 7 Fix Round 5 Design: Close Social Authority Replay

## Scope and invariants

This final hardening round closes four related trust-boundary gaps in the
current Social implementation: authority-instance substitution, mutable
signer results, unobserved backdated ATProto history, and cross-coordinate
candidate or revocation influence. It preserves registry revision 14 and its
entry-set digest. It does not modify frozen topics, vectors, snapshots,
projections, baselines, release artifacts, or generator authoring outputs.

Comms remains independent of Control. The embedding owns its trusted clock and
durable execute-once signer. The configured ATProto resolver authority remains
a local embedding trust boundary rather than protocol identity authority.

## Authority-bound Social publication

`createCommsSocialPublicationAuthority` captures the trusted-clock function
and an immutable bound reference to `signer_execution.executeOnce` at
construction. Later mutation or method replacement on the caller's signer
object cannot change the authority's execution boundary.

Every opaque signed-publication proof is recorded with the exact publication
authority instance that issued it. Social exposes an embedding-created
authorship validator closure bound to one expected authority instance. That
closure accepts active-key self-authorship directly, but automated authorship
burns a proof only when it was minted by the closure's exact authority. There
is no authority-agnostic global consumer. An attacker-created authority,
including one with a backdated clock, cannot produce a proof accepted by the
configured validator.

The proof remains one-use. Revocation after a genuine atomic signing operation
does not retroactively invalidate the already signed event.

## One-read signer-result snapshot

The execute-once result is read exactly once through own-property descriptors.
The accepted shape is a closed tree made only from ordinary objects and arrays,
with the exact permitted own keys, ordinary prototypes, and data descriptors.
Accessors, symbols, holes, unexpected members, and non-data descriptors reject.

JavaScript cannot generally prove that a value is not a Proxy. The validator
therefore makes no such claim. A Proxy can participate in the single descriptor
read, but the validator immediately constructs one independent plain-data
snapshot from those descriptor values, deep-freezes it, and never reads the
original result or its nested values again. Strict NIP-01 validation, exact
unsigned-event comparison, proof storage, and the returned event all use that
same immutable snapshot. An accessor or mutable result cannot present event A
for validation and event B for return.

## Durable historical observation

Historical binding evidence replaces its raw carrier enum with a durable
resolver-signed observation attestation. The closed observation envelope uses
a separate domain and commits:

- the exact Nostr binding event ID;
- the canonical binding hash;
- the exact DID, Nostr pubkey, and generation;
- the observation time;
- an opaque but canonical carrier/checkpoint reference;
- the exact resolver-resolution envelope hash; and
- the resolver policy and semantic version.

The configured resolver authority verifies the observation signature with its
closed trust-anchor set and enforces its policy/version configuration. The
observation must match the binding event and canonical binding, occur at or
after the event's `created_at`, and occur within the referenced authenticated
resolution interval. This proves that the binding existed while the named DID
method was still valid. A compromised historical key cannot create a newly
backdated binding without a prior trusted observation.

The signed observation and signed resolution envelopes are persistable
evidence. A fresh verifier can reauthenticate both without an ephemeral
capability. A candidate authenticated with a resolution that is fresh at the
validator's trusted current time may omit historical observation; every entry
used only as historical lineage or as a historical revocation target requires
it.

## Exact ATProto coordinate

The binding validator input supplies both expected canonical DID and expected
lowercase 32-byte Nostr pubkey before candidate selection. Current candidates,
historical lineage, and revocation targets are filtered to this exact
`(DID, pubkey)` coordinate before validation and source-neutral selection.
Lineages for the same DID under other pubkeys are independent and cannot select
a current binding or create revocation denial of service for the requested
coordinate.

## Errors and tests

Malformed, unbranded, wrong-authority, reused, accessor-backed, or shape-open
publication evidence rejects without signing or publishing. Invalid or missing
historical observations make the affected history unavailable; a chain that
needs it rejects as `atproto-binding-invalid`. Cross-coordinate revocations are
ignored rather than treated as valid revocations for the requested coordinate.

Exploit-first tests cover:

1. an attacker/backdated publication authority rejected by the expected Social
   validator;
2. mutation of `executeOnce` after authority construction having no effect;
3. accessor event A-to-B substitution and open signer-result shapes rejecting;
4. valid one-read immutable signer snapshots publishing once;
5. a binding minted after method compromise without prior observation
   rejecting;
6. durable observed expired history validating for a fresh verifier;
7. forged, mismatched, early, late, wrong-policy, and wrong-version observation
   attestations rejecting; and
8. another Nostr pubkey's lineage and revocation having no effect on the exact
   expected coordinate.
