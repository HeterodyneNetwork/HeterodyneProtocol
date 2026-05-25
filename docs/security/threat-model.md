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
- **Delegations are dual-authenticated.** A delegation is active only if
  the persona's current epoch key signs the Nostr attestation and the
  named MXID self-publishes the Matrix state event via normal
  `/send/state` authorization; either side alone cannot create a binding.
- **No central directory.** Discovery is relationship-mediated; there is
  no global registry of users or personas to compromise.

## Actors

| Actor | Capability assumption |
|---|---|
| **Trusted client** | A conformant Heterodyne client implementation; honest. Holds the user's nsec and Matrix device keys. |
| **Hostile homeserver** | Can drop, delay, reorder events. Can lie about state to clients that don't verify. Cannot decrypt E2EE traffic. May correlate metadata (room IDs, timing, participant MXIDs). |
| **Hostile relay** (vanilla Nostr) | Can drop, delay events. Cannot forge signatures. Can correlate by npub. |
| **Passive network observer** | TLS-bounded. Sees connection metadata (peers, timing, volume); cannot read content. *Mitigation (per ADR-019):* clients ship embedded Tor and offer opt-in egress-over-Tor (§7.7 of the spec); with egress enabled, the observer no longer sees the user's real peer set or location — only a Tor entry guard. Residual: Tor-level timing/volume traffic analysis (below). |
| **Federation peer** (per ADR-016) | A Matrix homeserver participating in a room's server-server federation that is neither the persona's own homeserver nor an adversary. Sees: all unencrypted state in public rooms; Megolm ciphertexts as opaque blobs; full `m.room.member` events; sender MXIDs + `origin_server_ts`; the federation join event graph. Cannot see: Megolm-encrypted content in private rooms; identity/config-room content for personas hosted on homeservers it is not federated with. Mitigation: personas concerned about membership-graph exposure SHOULD host their identity room on a homeserver whose federation peer set they trust. |
| **Colluding co-delegated MXID** (per ADR-009) | A peer MXID under the same npub that turns hostile. Has Megolm access to all config rooms via §3.9 mutual membership. Can: observe coordination state; attempt to plant lease conflicts during partition windows; race the single-MXID revocation procedure between `effective_at` and observation. Cannot: forge events signed under the persona's epoch key (only the persona's own signing key produces those); evade the §3.9.6 partition-window void-and-requeue rule once the partition heals. Mitigations: §3.9.7 effective_at clamping; embedded Nostr-signed revocation attestations defend against forged peer revocations. |
| **Old-homeserver-during-overlap** (per ADR-015) | The source homeserver `H1` during the 7-day voluntary homeserver-exit window. Retains write access to the old identity room; can attempt to forge state events after the migration. Mitigation: the §3.10.3 migration-pointer-precedence rule ensures the migration announcement in the OLD room is authoritative regardless of subsequent `H1`-side activity; followers' clients log discrepancies between the migration pointer and any later state changes in the OLD room. |
| **Compromised delegation** | Attacker controls a previously-authorized Matrix account. Can publish wrapped events claiming the npub *until revoked*. Cannot retroactively forge older events because each one is Nostr-signed at publication time. |
| **Compromised cold root** | Catastrophic for the persona. Recovery requires §3.5 KERI rotation/recovery from a clean device with sufficient witness support; the KEL preserves persona continuity where possible, but events the attacker published before revocation are valid. |

## Threats and mitigations (initial list)

### Impersonation via friendly homeserver

A homeserver could insert events claiming to be from MXID X.

*Mitigation:* every wrapped event carries an independent Nostr signature;
receivers reject if signature fails or if `nostr.pubkey` is not the
KERI-authoritative epoch key for the persona delegated to the sender
MXID. Bare Matrix events are attributed only when the event's
`heterodyne_persona` (or an unambiguous room context) resolves to an
active delegation for the sender at the event's Matrix timestamp;
otherwise they render as vanilla Matrix.

### Phantom delegation

A homeserver inserts a fake `m.heterodyne.delegation.v1` state event into
an identity room it hosts.

*Mitigation:* delegations are dual-authenticated. The Nostr attestation
must validate against the persona's current epoch key, whose authority
chains to the cold-root npub through the KEL. The Matrix state event's
`sender` must equal the delegation `state_key`, proving the named MXID
self-published it through normal homeserver `/send/state` authorization.
No Matrix cross-signing/MSK signature is required.

### Stale revocation

A compromised key is rotated, but a victim's client hasn't seen the
revocation yet and is still accepting events signed by the revoked key.

*Mitigation:* identity-room state is re-validated on a configurable TTL
and on every Matrix `/sync` cycle. Clients SHOULD display staleness
indicators when verification cache exceeds the configured age. KERI
sequence numbers, witness first-seen ordering, and the cold-root
`kind:31005` identity pointer let verifiers distinguish the current
identity room/KEL from stale rooms served by an attacker.

### Cross-persona linking via metadata

Even when content is encrypted, a homeserver can observe that the same
Matrix device participates in multiple identity rooms.

*Mitigation (incomplete):* personas SHOULD be hosted on different
homeservers and/or used via different Matrix accounts. Per ADR-019,
clients ship embedded Tor and offer opt-in egress-over-Tor (§7.7 of the
spec); when enabled, the homeserver and any on-path observer see only a
Tor entry guard rather than the user's IP, removing the *network-level*
correlator that would otherwise link a single device's connections to
multiple identity rooms. This is now in scope as a mitigation, not
deferred future work. It remains *incomplete*: same-device participation
in multiple rooms is still observable to a homeserver *within* the
encrypted Matrix layer regardless of network path, so Tor egress
addresses the IP/location correlator but not the application-layer
device-reuse correlator. Reducing the latter still relies on separate
accounts/homeservers per persona, and a mixnet-grade defense against
Tor-level traffic analysis remains future work.

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

### Sybil vouching for a hostile key (per ADR-021)

An attacker mints many cheap "friend" identities and floods a persona's
recovery with informal `kind:31008` vouches, hoping to push a key the
persona never authorized over the rotation threshold.

*Mitigation:* informal `kind:31008` vouches are **advisory only** — by
the §3.5.5 / §3.5.3 invariant they are NEVER counted toward the rotation
threshold, so no number of fake friends can move a rotation toward
acceptance. Rotation acceptance rests entirely on declared-witness
weight (or the cold root). Informal vouches only feed a UI confidence
display and *manual* promotion suggestions; promotion into the declared
set is always an explicit user action (clients MUST NOT auto-promote).
The attack therefore has no purchase on acceptance at all. The §3.5.6
witness-hygiene SHOULDs (≥3 declared witnesses, ≥5 for personas with
>1000 mutuals, periodic re-verification) ensure the declared set — the
only thing that *does* gate acceptance — stays live and adequately
sized.

### Hostile mirror homeserver (per ADR-020)

A homeserver hosting a non-primary mirror replica (§3.11) withholds
state, serves stale state, or lies about room contents.

*Mitigation:* the primary is the room named by the cold-root-signed
`kind:31005` / `kind:31007` feed index, and every signed event is
verified by its Nostr signature regardless of which replica served it.
A hostile replica cannot forge persona-signed content, and followers
deduplicate by Nostr event id. The blast radius of any one replica is
bounded to availability, not authenticity — the same posture as the
hostile-homeserver row, applied per replica.

### Friend-cache poisoning (per ADR-021)

A follower caching a persona's identity-room state (§3.12.1) attempts to
serve poisoned or fabricated state to other followers during an outage.

*Mitigation:* the cache content filter admits ONLY events signed by the
persona's own Nostr identity (plus KERI events, which carry their own
signatures/attestations); a cacher cannot inject arbitrary state.
Cache-served state MUST be marked stale and cache-sourced, and the
authoritative re-anchor signal remains the fresh cold-root `kind:31005`
on relays (§3.12.2), which a poisoning cacher cannot forge.

## Out of scope (for now)

- Defenses against compromised user devices (key extraction via OS-level
  malware). The npub holder is assumed to be in control of their device.
  Heterodyne secures its own application surface, not the host OS or
  device. The **cold root** is the relevant in-scope mitigation for the
  application layer: because it is held offline and signs only rare
  identity-anchoring events (§3.5.0), routine app-layer compromise of a
  warm device does not expose it, and recovery from epoch-key loss is
  possible via KERI rotation (§3.5) plus social vouching (§3.12). What
  remains out of scope is an attacker who has fully compromised the OS
  of the device that *holds* the cold root during a ceremony — that is a
  platform-security problem Heterodyne cannot solve from inside its app.
- Tor-level traffic analysis (timing/volume correlation against the Tor
  network itself). As of ADR-019, `.onion` reachability and opt-in
  egress-over-Tor are *in scope* (clients ship embedded Tor, §7.7 of the
  spec) and mitigate the clearnet passive observer and the IP-level
  cross-persona correlator. What remains out of scope is correlation
  performed against the Tor circuit itself: Matrix's traffic pattern is
  fingerprintable, and a global passive adversary observing Tor
  entry/exit can still attempt timing/volume correlation. A mixnet-grade
  defense is future work.
- Quantum-adversary resistance. `secp256k1` is not post-quantum.
  Mitigation strategy will follow Nostr's upstream when it has one.

## Open questions to address before v1.0

The three open questions previously tracked here are now resolved:

1. **Identity rotation × Megolm session keys — RESOLVED.** They are
   independent. Spec §9.4 establishes that KERI epoch rotation changes
   the persona's Nostr signing key but not the Matrix device or its
   Megolm sessions: rotation is invisible to Megolm, no session
   invalidation is required, and the new epoch key co-signs subsequent
   attestations through the same MXIDs. Delegation revocation is a
   verification-layer concern, not a Megolm-session concern.
2. **Warning vs. suppression on verification failure — RESOLVED as
   intentionally loose.** Clients choose contextually how to surface or
   suppress verification-failure signals; the spec deliberately does
   not tighten this into a single normative rule. (Strict mode, §11.7,
   tightens the broadcast-signature subset for clients that opt into the
   high-assurance profile.)
3. **Permanent identity-room homeserver loss — RESOLVED (per ADR-020,
   ADR-021).** A persona running identity-room mirrors (§3.11) survives
   a single-homeserver outage by promoting a replica. When the
   homeserver is permanently gone and no replica remains, the
   involuntary re-anchor procedure (§3.12) applies: the persona
   republishes a cold-root `kind:31005` to relays, and follower-cached
   identity state bridges verification until it propagates. Two-tier
   vouching (declared §3.5 witnesses + capped informal `kind:31008`
   vouchers) re-establishes key continuity.

No open questions remain blocking v1.0 from the items previously listed
here; new ones will be added as the spec matures.
