# ADR 042: Review-gap remediation and one-time invites

Date: 2026-08-10

Status: Accepted and archived

## Context

The Marmot Control migration left the Comms admission hook inconsistent with
its acceptance vectors and Social policy, omitted transitive strict-profile
membership, relied on unallocated feature strings, exposed unbounded
unsolicited Control enrollment, incompletely projected RFC 8628, left
authorization freshness unbounded, and did not document the epoch scalar's
combined signing/decryption compromise boundary.

Browser-friendly DM and device bootstrap also needed a provider-independent
one-time invitation mechanism that did not grant authority to a web origin or
deliver private keys.

## Decision

The accepted specification patch:

- separates ordinary Marmot conversation admission from Control-group
  admission and gives unknown valid conversations a no-signal message-request
  state;
- defaults unsolicited Control invitations to off and bounds pending groups,
  Welcome processing, KeyPackage replenishment, and reserved capacity;
- defines one signed fragment envelope with non-convertible `dm`,
  `control-enrollment`, and `device-enrollment` purposes, NIP-59 response
  authentication, secret proof, and restart-safe reservation;
- permits exact prompt-free private-Control preauthorization while forbidding
  it for KERI-authorized devices;
- adds RFC 8628 entropy, guessing, display, polling, and invalidation rules;
- caps token-mint and privileged-request authorization views at 300 seconds;
- allocates a revision-6 feature catalog and separates release-provided from
  dependency-required features;
- corrects `heterodyne-control-strict-v1` to its complete 27-invariant
  flattened membership; and
- treats epoch BIP-340 and NIP-59 use as one compromise domain while requiring
  domain-separated inputs and operational key isolation.

## Consequences

Revision 6 and the rewritten vectors are breaking pre-1.0 corrections.
Implementations must use the current specifications, registry, schemas,
release manifests, and vectors. This record is historical context only and is
not required to implement or validate the protocol.
