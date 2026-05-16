# Threat model

**Status:** DRAFT stub. Will graduate as spec sections mature.

This document enumerates the actors, assets, and threats that the
Heterodyne specification must defend against. It is non-normative; the
normative spec ([`../spec/heterodyne.md`](../spec/heterodyne.md)) flows
from the analysis here.

## Inherited invariants

Heterodyne inherits the following invariants from sibling project
`mxdx`:

- **Every Matrix event in a private context is end-to-end encrypted**,
  including state events (MSC4362). No exceptions.
- **Sensitive material at rest is encrypted.** OS keystore / keychain
  integration is used where available.
- **No homeserver-side parsing of payload.** Bridging logic is purely
  client-side; the homeserver is a blind transport.

## Heterodyne-specific invariants

- **The npub is the authoritative author.** Matrix MXIDs are never the
  source of truth for identity.
- **Delegations are double-signed.** A delegation is only active if both
  the npub and the MXID have signed it; either side alone cannot create
  a binding.
- **No central directory.** Discovery is relationship-mediated; there is
  no global registry of users or personas to compromise.

## Actors

| Actor | Capability assumption |
|---|---|
| **Trusted client** | A conformant Heterodyne client implementation; honest. Holds the user's nsec and Matrix device keys. |
| **Hostile homeserver** | Can drop, delay, reorder events. Can lie about state to clients that don't verify. Cannot decrypt E2EE traffic. May correlate metadata (room IDs, timing, participant MXIDs). |
| **Hostile relay** (vanilla Nostr) | Can drop, delay events. Cannot forge signatures. Can correlate by npub. |
| **Passive network observer** | TLS-bounded. Sees connection metadata (peers, timing, volume); cannot read content. |
| **Compromised delegation** | Attacker controls a previously-authorized Matrix account. Can publish wrapped events claiming the npub *until revoked*. Cannot retroactively forge older events because each one is Nostr-signed at publication time. |
| **Compromised npub root** | Catastrophic for the persona. Recovery requires §3.5 key rotation from a clean device; the identity chain preserves persona continuity but events the attacker published before revocation are valid. |

## Threats and mitigations (initial list)

### Impersonation via friendly homeserver

A homeserver could insert events claiming to be from MXID X.

*Mitigation:* every wrapped event carries an independent Nostr signature;
receivers reject if signature fails or if `nostr.pubkey` doesn't match
the MXID's active delegation. Bare events in DM rooms inherit Matrix's
existing room-message authenticity guarantees (Matrix device-signed
event).

### Phantom delegation

A homeserver inserts a fake `m.heterodyne.delegation.v1` state event into
an identity room it hosts.

*Mitigation:* delegations are double-signed (npub + MXID). The Nostr
signature must validate against the asserted npub, which the homeserver
doesn't control. The Matrix signature must validate against the MXID's
cross-signing master key, which is also outside homeserver control under
Matrix's existing cross-signing model.

### Stale revocation

A compromised key is rotated, but a victim's client hasn't seen the
revocation yet and is still accepting events signed by the revoked key.

*Mitigation:* identity-room state is re-validated on a configurable TTL
and on every Matrix `/sync` cycle. Clients SHOULD display staleness
indicators when verification cache exceeds the configured age. A
defense-in-depth measure: the revocation is published from the
*successor* identity room, so even an attacker holding the old key
cannot prevent the legitimate user from publishing a revocation that
victims will eventually see.

### Cross-persona linking via metadata

Even when content is encrypted, a homeserver can observe that the same
Matrix device participates in multiple identity rooms.

*Mitigation (incomplete):* personas SHOULD be hosted on different
homeservers and/or used via different Matrix accounts. This is an
unsolved problem at the Matrix transport layer and Heterodyne inherits
the limitation. Future work might explore mixnet or onion-routed Matrix
federation; out of scope for v0.1.

### Bridge-side plaintext leak

A traditional appservice bridge would see plaintext before Matrix
encryption.

*Mitigation:* spec §10 forbids server-side bridges entirely. A
user-owned personal bridge is within the user's trust boundary by
construction and is not considered a third-party component.

### Replay across forks of the identity room

An attacker mirrors an outdated identity room and presents it to
verifiers to mislead them about current delegations.

*Mitigation:* receivers resolve to the latest Matrix room state per
standard state resolution. Signed Heterodyne state events have
monotonically increasing `created_at` and stale attestations lose to
fresh ones via combined Matrix state resolution and Nostr signature
timestamp comparison.

### Backdating attacks

An attacker holding a recently-revoked key signs events with a
`created_at` predating the revocation.

*Mitigation:* a defense in depth, not a guarantee. Clients SHOULD
display "signed by previously-revoked key" warnings for events whose
`created_at` is within a configurable suspicion window before
`revoked_at`. Definitive resolution requires future work on signed
timestamping (e.g., Nostr relay receipts or Bitcoin OpenTimestamps as
auxiliary witnesses).

### Hostile relay refusing to deliver

A vanilla Nostr relay deliberately drops a user's events.

*Mitigation:* the user fans out to multiple relays per their
`m.heterodyne.outbox.v1` list, and (separately) publishes to Matrix
outbox rooms whose audience is independent of the Nostr relay set.
Censorship requires colluding with all relays *and* all federating
homeservers, which is the same threshold as for vanilla Matrix or
vanilla Nostr individually.

## Out of scope (for now)

- Defenses against compromised user devices (key extraction via OS-level
  malware). The npub holder is assumed to be in control of their device.
- Traffic analysis against Tor-routed Matrix federation. Matrix's traffic
  pattern is itself fingerprintable; out of scope for the v0.1 spec.
- Quantum-adversary resistance. `secp256k1` is not post-quantum.
  Mitigation strategy will follow Nostr's upstream when it has one.

## Open questions to address before v1.0

1. How does identity-chain rotation interact with Megolm session keys?
   Specifically: do existing Megolm sessions need to be invalidated when
   a delegation revokes, or is that purely a verification-layer issue?
2. What is the conformance requirement for client UI warning vs.
   suppression on verification failure? The current spec leaves this
   loose — should it tighten?
3. How do we handle a user who declares an identity room on a homeserver
   that subsequently goes offline permanently? Cached state has a
   half-life; persistent followers need a graceful re-anchor procedure.
