# Task 7 Fix Round 4 Design

## Scope and layering

This round closes the atomic Social signing, configured resolver authority,
durable historical resolution, and branch-independent revocation findings.
Comms remains independent of Control: it defines and consumes only the
structural durable execute-once contract already established by Task 6. The
embedding supplies the durable implementation and trusted clock. Registry
revision 14, frozen topics and vectors, snapshot metadata, projections,
baselines, reports/debt, and release artifacts remain unchanged.

## Atomic Comms-to-Social signed publication

An embedding creates a Comms Social publication authority that closes over a
trusted `now()` function and a durable execute-once signer capability. The
publication method accepts an unsigned publication intent without `id` or
`sig`, current workload registration and access-token state, represented
persona, requested feed/resource, and an execution token/request digest.

In one call the authority:

1. samples trusted time exactly once;
2. validates current registration, access token, ledger/status, grant bounds,
   audience, sender proof, destinations, persona, signer, association, scope,
   kind, content, and event time at that trusted time;
3. injects the canonical attribution tags and fixes an immutable unsigned
   event snapshot;
4. invokes the embedding-owned durable `executeOnce` boundary with only that
   attributed snapshot;
5. strict-validates the returned NIP-01 event and exact equality with the
   immutable snapshot; and
6. returns the signed event plus a module-private WeakMap-backed, one-use
   signed-publication proof.

No public function accepts a signed event and mints a proof, and no path can
strip `id`/`sig` from an existing event to obtain authority. `event.created_at`
is distinct from trusted current time: both must satisfy applicable bounds,
but equality is not required. Social burns the proof against the exact signed
event, persona, signer, association, and destination. It does not revalidate
mutable grant state, so revocation after a publication was genuinely signed
while authorized does not retroactively invalidate that event.

## Configured resolver authority instances

`createAtprotoResolverAuthority` creates an opaque authority instance whose
module-private record contains deep-cloned and deeply frozen configuration:

- one or more Ed25519/BIP340 local resolver-attestation anchors;
- an exact non-empty allowed resolver-policy set;
- a minimum resolver semantic version; and
- a positive maximum attestation TTL.

Evidence callers provide only the signed durable attestation. They cannot
provide or replace anchors, policies, minimum versions, or TTL. Resolution
capabilities are branded with the exact authority instance that verified them;
every binding or revocation consumer supplies its configured authority and
rejects a capability from another instance. Envelopes, canonical documents,
and selected methods stored behind capabilities are deep cloned and frozen.

Current authentication requires `resolved_at <= trusted_now < expires_at`.
It also enforces the configured policy, minimum version, maximum TTL, exact
envelope shape, URL/PLC metadata, canonical document/hash, selected method,
and a configured-anchor signature. Forged or mutable evidence, attacker
anchors, policy/version downgrades, excessive TTLs, and cross-authority
capabilities reject.

## Durable historical resolution

The persistable resolution evidence is the signed
`{ envelope, signature }`, not the opaque in-memory capability. Binding and
lineage records carry that durable evidence. A fresh verifier reconstructs
authority by re-verifying the attestation under its configured instance.

Current binding candidates are authenticated at trusted current time.
Historical lineage and revocation-target discovery reverify each durable
attestation at the binding event's `created_at`. This allows an expired or
rotated historical verification method to authenticate its historical
binding without granting current authority. Current DID-side revocation uses
a fresh attestation authenticated at trusted current time under the same
configured authority.

## Branch-independent durable revocation

The verifier authenticates the candidate and history universe independently
of which branch wins current selection. Valid revocation evidence for the same
DID/pubkey is evaluated against every authenticated binding in that universe.
Every revoked target must occur on the selected chain. The selected current
binding must descend from it through the next consecutive generation whose
establishment time is strictly after the revocation and whose nonce is fresh.

A revoked sibling, reset, lower-generation fork, or two incompatible revoked
forks cannot be hidden by selection and fails closed. Nostr revocations remain
signed by the linked current pubkey. DID revocations use the configured
authority's fresh current selected DID method.

## Verification

Each exploit probe is run against the prior implementation and its expected
failure is recorded before production edits. Completion runs the Task 7
focused suite, generator build, family check, and history-bound snapshot
verification with exactly 482 vectors. The round report records RED/GREEN
counts, the approved family-layering ruling, ownership costs, and self-review.
