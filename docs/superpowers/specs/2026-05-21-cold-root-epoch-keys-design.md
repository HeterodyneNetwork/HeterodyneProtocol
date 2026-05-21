# Cold Root + Epoch Keys — design

**Status:** approved for implementation planning
**Date:** 2026-05-21
**Scope:** (A) a standalone NIP for the Nostr ecosystem; (B) consequent
changes to the Heterodyne v0.2 spec.

---

## 1. Summary

Vanilla Nostr conflates identity authority with operational signing: the
single nsec is used both as the long-term identity anchor and as the
day-to-day signing key on phones, browsers, and bunkers. Any leak of that
key burns the identity permanently. This design separates the two:

- The **cold root** keypair is the identity. It is kept offline (USB key
  with a password-encrypted file by default; YubiKey, airgap, or
  encrypted-in-Matrix as alternatives). It signs only lineage attestations
  and revocations.
- **Epoch hot keys**, one per (epoch, device) tuple, do all routine
  signing. They are deterministically derived from the same BIP39 seed via
  a hardened BIP32 path so the seed-holder can re-derive them after data
  loss.
- A signed, append-only lineage stream binds each hot key to the cold
  root. Followers verify the lineage when they encounter a new hot key.
- The cold root is rotated only by one of two mutually exclusive
  pre-declared strategies: `committed` (pre-published commitment to the
  next root, NIP-03 anchored) or `none` (identity loss accepted; only
  self-burn possible). Cross-signed succession is **not** offered because
  it cannot defeat a stealthy compromise: an attacker holding the stolen
  root publishes a competing successor before the legitimate user
  notices, and timestamp anchoring on the post-compromise event loses
  the race.
- For Heterodyne specifically, the Matrix Master Cross-Signing Key (MSK)
  acts as a recovery oracle. Root creation and root rotation are
  ceremonies built on KERI-style inception and rotation events
  co-signed by the cold root and the Matrix MSK, with optional peer
  witnesses. This gives followers a continuity proof when the on-Nostr
  cryptographic chain breaks (the `none` strategy).

The work splits into two independently shippable deliverables.

---

## 2. Deliverables

### A. Standalone NIP

Working title: *"Cold Root + Epoch Keys"*. Submitted to
`nostr-protocol/nips` independent of Heterodyne. Composes with existing
NIPs without modifying them:

- Extends NIP-06 path semantics (does not modify NIP-06).
- Defines new event kinds 1044 (append-only lineage attestation) and
  10044 (replaceable lineage summary).
- Mandates NIP-03 OpenTimestamps anchoring for `genesis_commitment` and
  `root_rotation` events.
- Composes with NIP-07 / NIP-46 / NIP-55 (signer abstraction) without
  normative requirement — those layers see hot keys as ordinary nsecs.
- Cites prior art: deprecated NIP-26 (delegated event signing) as
  ancestor; stalled GitHub issues #116 (root attestation), #103
  (tapscript commitment), #2237 (argon2 hash commitment) as related
  work.

### B. Heterodyne v0.2 spec changes

Changes to `docs/spec/heterodyne.md`:

- §3.5 (identity chain) and §3.5.0 (chain edge cases) **removed**.
  Kind 31002 (`m.heterodyne.successor.v1`) freed.
- §3.5.1 (revocation) **rewritten** as a thin wrapper around the
  NIP's revocation events.
- New §3.5 (renamed: *Epoch keys and lineage*) referencing the NIP.
- New §3.5.2 (*Cold-root backup*) with USB+password-encrypted as the
  recommended default and other options as alternatives.
- New §3.5.3 (*Root creation and recovery — KERI ceremony*).
- New §3.5.4 (*Re-attestation of historical content*).
- §6 / §7 (publishing / discovery) updated with the dual control-plane
  / data-plane subscription model.
- §10 (bridge and client) gains MUST clauses for signer support and
  NIP-03 support.
- §3.0 (kind allocations) updated with new wrapper kinds.

The two deliverables can land independently. Heterodyne references the
NIP by its eventual number (or URL placeholder).

---

## 3. Prior art

We are not the first to propose this. The Nostr community has been
debating cold-root-style key hygiene for 3+ years across at least four
distinct proposals; none reached NIP status. We synthesize them rather
than invent fresh.

| Source | What it is | Status | Relation to this design |
|---|---|---|---|
| NIP-26 | Delegated event signing via per-event token | `unrecommended` | Historical motivation. We replace per-event delegation tokens with hierarchical derivation + lineage events. |
| Issue #116 | Root key attestation listing operational keys with revocation | Open, 49 comments, stalled | Closest sibling. We adopt the "list of hot keys with revocation timestamps" idea but use BIP32 derivation instead of arbitrary key listing, sidestepping the bidirectional-signature debate that wedged the thread. |
| Issue #103 | Tapscript-style commitment chain | Open, 55 comments, stalled | Offered as an alternative concretization of `committed` strategy; not the recommended one. |
| Issue #2237 | Argon2id hash commitment from passphrase | Closed | Offered as another alternative concretization of `committed` strategy. |
| Issue #1959 | Pushback against NIP-26 deprecation | Closed | Confirms there is community demand for cold-root semantics. |
| Issue #1691 | BIP85 derivation path for Nostr | Open | Complementary; could be layered on top for multi-persona under one master. |
| Issue #1774 | Unhardened components in NIP-06 | Open | We address this normatively: epoch subtree is hardened at every level. |

**Why #116 stalled:** the thread was wedged by a long, repetitive
disagreement between the proposer and another contributor over (a)
whether hot keys must sign back (bidirectional) or only the root signs
(unidirectional), and (b) the semantics of "root claims this key" vs
"this key acts on behalf of root". The thread also lacked an
implementation push toward a NIP PR. Our design sidesteps (a) by using
hardened BIP32 derivation, which obviates the question — only the
seed-holder can mint a valid epoch key, so a unilateral root attestation
suffices.

---

## 4. Derivation tree and key roles

### 4.1 Derivation path

```
BIP39 seed
  │
  └── m/44'/1237'/<persona>'/
        ├── 0'/0'                       ← cold root (identity npub)
        └── 1'/<epoch>'/<device>'       ← epoch hot keys
```

Six levels under `m/`, all components **hardened**. Coin type `1237` is
the SLIP-0044 registered Nostr value. Purpose `44'` per BIP44. Persona,
epoch, and device are arbitrary nonnegative integers.

- `<persona>` defaults to 0 (matches NIP-06 default account). Personas
  > 0 are reserved for the persona-index successor (§4.4) and for
  optional multi-persona usage.
- `<epoch>` is a monotonically increasing counter, advanced by the user
  on rotation. Starts at 0.
- `<device>` is a per-device index allocated by the user when adding a
  new device to an epoch. Starts at 0.

### 4.2 Hardening deviation from NIP-06

NIP-06's literal path is `m/44'/1237'/<account>'/0/0` — the last two
levels are **unhardened**. Issue #1774 documents the resulting risk:
exposing the parent xpub + any one private child leaks every sibling
private key. For epoch keys this would be catastrophic — one hot-key
compromise would burn every other device's key.

This design uses hardened derivation at every level of the epoch
subtree (`1'/<epoch>'/<device>'`) and also at the cold-root tail
(`0'/0'`). NIP-06 readers can still find the cold root key at
`m/44'/1237'/0'/0/0` for backward compatibility, but the normative path
for new roots uses the hardened tail.

### 4.3 Key roles

| Role | Where it lives | Signs |
|---|---|---|
| Seed (BIP39 mnemonic) | Offline only | Nothing directly; root of derivation |
| Cold root | `…/<persona>'/0'/0'` | Lineage events (1044, 10044), revocations, KERI inception co-sig |
| Epoch hot key | `…/<persona>'/1'/<epoch>'/<device>'` | All normal events (notes, reactions, etc.) |
| Matrix MSK | Matrix-native, not derived | KERI inception co-sig, KERI rotation co-sig (Heterodyne only) |
| Committed successor | `…/<persona+1>'/0'/0'` (recommended) or external commitment | Becomes the next cold root if `committed` strategy is invoked |

### 4.4 Committed-successor concretization

Two viable variants. The NIP normatively recommends the first.

**Persona-index advance (recommended).** The committed successor is
simply the cold root at the next persona index:
`m/44'/1237'/(<persona>+1)'/0'/0'`. The same seed produces it. At root
creation, R1 publishes a `genesis_commitment` (kind 1044) naming R2 by
pubkey and path; this event is NIP-03 anchored. Rotation reveals R2 by
publishing a `root_rotation` event signed by R2 referencing R1.
Verifiers find the NIP-03-oldest `genesis_commitment` from R1 and
verify that the rotating key matches.

**External commitment (alternative).** Either #103 tapscript style
(`A' = A + hash(A||B')*G`) or #2237 argon2id hash style. The NIP
permits these as alternative concretizations of `committed`; the kind
1044 `genesis_commitment` event carries enough fields to encode them.
Implementations MAY choose; the NIP RECOMMENDS persona-index advance
for simplicity and BIP32 alignment.

---

## 5. NIP wire formats

### 5.1 Kind 10044 — Lineage summary (replaceable, parameterized)

One per persona. `d` tag is the constant string `epochs`. Authoritative
for *current* state only; security-bearing decisions defer to the kind
1044 audit trail.

```
kind: 10044
pubkey: <cold_root_pubkey>
tags:
  ["d", "epochs"]
  ["strategy", "committed" | "none"]
  ["current_epoch", "<n>"]
  ["device", "<epoch>", "<device>", "<pubkey>", "<effective_at>"]   # one per active device
content: ""
sig: <signed by cold_root>
```

### 5.2 Kind 1044 — Lineage attestation (append-only)

One event per change. Tagged by `op`. NIP-03 OpenTimestamps anchoring
is **REQUIRED** for `genesis_commitment`, `root_rotation`,
`device_revoke`, `epoch_revoke`, and `root_revoke`. RECOMMENDED for all
other ops. The `nip03` tag references a kind:1040 event (per NIP-03)
that carries the OTS proof; it does not embed the proof inline.

```
kind: 1044
pubkey: <cold_root_pubkey>          # except root_rotation: signed by NEW root
tags:
  ["op", "<one of: genesis_commitment | epoch_advance | device_add |
            device_revoke | epoch_revoke | root_revoke | root_rotation>"]
  …op-specific tags
content: ""
sig: <signed by cold_root or new_cold_root per op>
```

Op-specific tags. The `["nip03", "<kind_1040_event_id>"]` tag is a
reference to a NIP-03 event carrying the OTS proof, not an embedded
proof.

| op | Required tags |
|---|---|
| `genesis_commitment` | `["commit_pubkey", "<R2_pubkey>"]`, `["commit_path", "m/44'/1237'/<persona+1>'/0'/0'"]`, `["nip03", "<kind_1040_event_id>"]` |
| `epoch_advance` | `["epoch", "<n>"]`, `["prev_epoch", "<n-1>"]`, `["effective_at", "<ts>"]` |
| `device_add` | `["epoch", "<n>"]`, `["device", "<d>"]`, `["pubkey", "<hex>"]`, `["effective_at", "<ts>"]`, optional `["label", "<str>"]` |
| `device_revoke` | `["pubkey", "<hex>"]`, `["revoked_at", "<ts>"]`, `["reason", "<str>"]`, `["nip03", "<kind_1040_event_id>"]` |
| `epoch_revoke` | `["epoch", "<n>"]`, `["revoked_at", "<ts>"]`, `["reason", "<str>"]`, `["nip03", "<kind_1040_event_id>"]` |
| `root_revoke` | `["revoked_at", "<ts>"]`, `["reason", "<str>"]`, `["nip03", "<kind_1040_event_id>"]` — self-burn for `none` |
| `root_rotation` | **Valid only for `committed` strategy.** Signed by **NEW** root R2; `["prior_root", "<R1_pubkey>"]`, `["nip03", "<kind_1040_event_id>"]`. For `none`-strategy roots, no NIP-level rotation event exists; Heterodyne uses its KERI ceremony (§6.6) instead. |

External-commitment variants of `genesis_commitment` use additional
tags: `["commit_hash", "<hex>"]` carries the argon2id digest for #2237
style; `["taproot_commit", "<33-byte hex>"]` carries the tweaked pubkey
`A' = A + hash(A||B')*G` for #103 style. Exact encodings of the
external variants are deferred to the spec text and reference
implementation; the NIP defines the tag names as extension points and
treats the persona-index advance as the only normatively-recommended
form for v1.

### 5.3 Event provenance tags on hot-key events

Every Nostr event signed by an epoch hot key **MUST** carry:

```
["root", "<cold_root_pubkey>"]
["epoch", "<n>"]
["device", "<d>"]
```

These allow relays (via NIP-12 generic tag indexing) and clients to
attribute events to the correct cold root without a per-event lookup.

### 5.4 Backdated `revoked_at`

All revocation events (`device_revoke`, `epoch_revoke`, `root_revoke`)
MUST carry a NIP-03 anchor (per §5.2). The anchor proves *when the
revocation event itself was published*, independent of any `revoked_at`
the event declares.

A revocation MAY set `revoked_at` earlier than the event's `created_at`
(handles "I just realized last Tuesday's leak"). Verifiers MUST honor
`revoked_at` as authoritative for the start of invalidity, **bounded
below** by the earliest NIP-03 anchor proving the cold root was
operating normally at that time. Concretely: a backdated `revoked_at`
MUST NOT precede the NIP-03 anchor of any prior `epoch_advance`,
`device_add`, or other non-revocation lineage event that proves the
cold root was the legitimate signer during the disputed window. This
prevents an attacker holding a stolen root from backdating a revocation
to retroactively invalidate legitimate history.

### 5.4.1 NIP-03 anchor format

Per NIP-03, OTS proofs live in separate kind:1040 events. The
referenced kind:1040 event MUST carry an `["e", "<lineage_event_id>"]`
tag pointing back at the lineage event, and its `content` MUST be the
base64-encoded `.ots` file with at least one Bitcoin attestation (no
pending-only attestations). Clients fetch the kind:1040 event via
standard relay queries; verification is per NIP-03's flow.

---

## 6. Heterodyne integration

### 6.1 Removals and reuses

- §3.5 (identity chain) and §3.5.0 (chain edge cases): removed
  entirely. The diagram, doubly-linked successor/predecessor pair, and
  forked-chain rules go away.
- §3.5.1 revocation: removed in current form, rewritten below.
- Kind 31002 (`m.heterodyne.successor.v1`): freed, **reused** as
  `m.heterodyne.keri_inception.v1` (§6.10).
- Kind 31003 (`m.heterodyne.revoke.v1`): freed, **reused** as
  `m.heterodyne.keri_rotation.v1` (§6.10). Revocation semantics move
  to the NIP's kind 1044 ops, wrapped in
  `m.heterodyne.epoch_attestation.v1` (which embeds NIP kind 1044
  directly without a new Heterodyne kind).

### 6.2 §3 identity model — cold-root MUST

The npub bound in `m.heterodyne.root.v1` MUST be a cold root per the
NIP. Day-to-day Nostr event signing MUST use epoch hot keys.

### 6.3 New §3.5 — Epoch keys and lineage

Thin Matrix wrapper around the NIP. Two new state events in the
identity room:

- `m.heterodyne.epoch_summary.v1` (state_key=`""`) wraps NIP kind
  10044. Content embeds the Nostr-signed attestation per existing
  Heterodyne envelope conventions.
- `m.heterodyne.epoch_attestation.v1` (state_key=`"<op>:<epoch>:<device>"`
  or `"<op>:<n>"` as appropriate) wraps NIP kind 1044. One state event
  per NIP attestation; the state_key form ensures distinct events
  coexist as separate state slots.

Discovery flow update for §3.6: client peeks identity room → reads root
→ reads `epoch_summary` → walks `epoch_attestation` history to verify
lineage and find current devices.

### 6.4 New §3.5.1 — Revocation (rewritten)

Heterodyne wraps the NIP's revocation events (`device_revoke`,
`epoch_revoke`, `root_revoke`) in `epoch_attestation` state events.
Additional Heterodyne-specific behavior:

- Revocation state events MUST persist in the identity room
  indefinitely.
- If the homeserver redacts or ages out a revocation state event,
  Heterodyne clients SHOULD re-publish it when they next have authority
  to do so. State semantics mean the new event supersedes the old slot,
  not appends.
- Revocations MAY be additionally published to one or more Nostr relays
  for cross-protocol visibility.

### 6.5 New §3.5.2 — Cold-root backup

The Heterodyne-recommended default is **a NIP-49 password-encrypted
file on a removable USB device**. Simple, portable, no platform lock-in.

Alternatives offered to users (informational):

- Hardware signer: YubiKey via nostr-keyx-style NIP-07 backend (OpenPGP
  subkey on the YubiKey); NIP-46 bunker on a dedicated device;
  NIP-55 Android signer.
- Airgap paper / steel / offline disk holding the BIP39 mnemonic.
- Encrypted-in-identity-room (normative, MAY): see §6.5.1 below.

Threat models for each option documented inline.

#### 6.5.1 Encrypted-in-identity-room backup (normative format)

If a user opts to store the cold-root backup in the identity room, the
Heterodyne client MUST use the following format:

- Matrix state event type: `m.heterodyne.cold_root_backup.v1`
- Inner Nostr kind: **31006** (Heterodyne-reserved)
- `state_key`: `""` (one backup per persona)
- Content: a NIP-49 password-encrypted blob containing the cold root
  nsec (or the BIP39 mnemonic, at the user's choice). The password is
  user-held, not stored on the homeserver. Heterodyne clients MUST
  prompt for the password at decryption time and MUST NOT cache it
  beyond the user-configured TTL.
- The state event is itself encrypted at rest via MSC4362 encrypted
  state.

Threat profile: defeated only by simultaneous compromise of (a) the
Matrix account credentials sufficient to read the identity room's
encrypted state, AND (b) the user-held backup password.

Clients SHOULD warn users that encrypted-in-identity-room backup is
the *highest-attack-surface* option among the alternatives in §6.5
and SHOULD nudge toward USB or hardware backup unless the user
explicitly opts in.

### 6.6 New §3.5.3 — Root creation and recovery (KERI ceremony)

Two ceremonies, same KERI event shape:

- **Inception** at first root creation. State event
  `m.heterodyne.keri_inception.v1` (kind **31002**). Co-signed by new
  cold root + Matrix MSK — both signatures MUST be present. Peer
  witness signatures MAY be added but are not required at inception
  (no prior identity to vouch for; chicken-and-egg for first users).
  Establishes the binding `(cold_root, Matrix_MSK)` for the user's
  followers.
- **Rotation** at either post-loss recovery (`none` strategy) or at
  committed-successor reveal (`committed` strategy). State event
  `m.heterodyne.keri_rotation.v1` (kind **31003**). Co-signed by new
  cold root + Matrix MSK — both MUST sign. Peer witness signatures
  SHOULD be included, particularly for `none`-strategy rotation where
  no cryptographic chain to the prior root exists; the witness set is
  the primary continuity signal in that case. References prior AID.

Continuity verification logic for followers:

- If `committed` strategy: followers verify the NIP `root_rotation`
  event against the NIP-03-oldest `genesis_commitment` from the prior
  root. Cryptographic chain holds; MSK signature provides additional
  Heterodyne-level reassurance.
- If `none` strategy: the prior cold root cannot sign anything. The
  rotation is supported only by MSK continuity (same MSK signed
  inception and rotation) plus optional peer witnesses. Followers
  decide whether to accept based on the MSK + witness set.

### 6.7 New §3.5.4 — Re-attestation of historical content

After a root rotation, a user MAY republish prior posts using NIP-18
quote semantics, signed by an epoch key under the new root, with a tag
`["original_event", "<event_id>", "<original_root>"]`. The original
event remains valid where the prior root is verifiable; the
re-attestation provides current-identity overlay. No new kind required;
documents the convention only.

### 6.8 §6 / §7 — subscription model

For each followed/friend root, Heterodyne clients subscribe to two
filter sets:

- **Control plane:** `authors=[root_pubkey]` (lineage events,
  revocations, KERI events). For relays indexing NIP-12 generic tags,
  `#root=[root_pubkey]` is equivalent and may be combined with other
  filters.
- **Data plane:** `authors=[<all currently-active hot keys for this
  root>]`. Set updates on every `epoch_advance`, `device_add`, or
  `device_revoke`.

On revocation, the data-plane filter set is immediately pruned; events
from a revoked key with `created_at > revoked_at` (minus a small
clock-skew tolerance, recommended ±5 min) are rejected client-side.

### 6.9 §10 — signer + NIP-03 requirements

- Clients MUST speak ≥1 of NIP-07, NIP-46, NIP-55.
- Clients SHOULD support nostr-keyx-style OS-keystore and YubiKey
  backends via NIP-07.
- Clients MUST support NIP-03 (load-bearing for `genesis_commitment`
  and `root_rotation` verification, and for backdated `revoked_at`
  validation).

### 6.10 §3.0 — kind allocations

Final kind table after this design's changes:

| Kind | Use | Status |
|---|---|---|
| 31000 | Heterodyne: root attestation | unchanged |
| 31001 | Heterodyne: delegation attestation | unchanged |
| **31002** | `m.heterodyne.keri_inception.v1` | **reused** (was successor) |
| **31003** | `m.heterodyne.keri_rotation.v1` | **reused** (was revoke) |
| 31004 | Heterodyne: related-persona attestation | unchanged |
| 31005 | Heterodyne: identity pointer (cross-protocol) | unchanged |
| **31006** | `m.heterodyne.cold_root_backup.v1` (optional) | **new** |
| 31007-31099 | RESERVED for future Heterodyne use | — |
| **10044** | NIP: epoch lineage summary (replaceable) | new — NIP kind |
| **1044** | NIP: epoch lineage attestation (append-only) | new — NIP kind |

The Matrix wrapper events `m.heterodyne.epoch_summary.v1` and
`m.heterodyne.epoch_attestation.v1` do NOT consume Heterodyne-reserved
kinds; they embed the NIP kinds 10044 and 1044 directly via the
existing `nostr_attestation` envelope. This keeps the Heterodyne kind
table and the NIP kind allocations aligned.

---

## 7. Operational flows

Brief sketches; full sequence diagrams come with the spec writing.

1. **First-time follow.** Client walks Matrix profile → identity room
   → root → epoch_summary → epoch_attestation history. Verifies (a)
   root self-attestation, (b) NIP-03 anchor on genesis_commitment, (c)
   every attestation chains from prior state. Subscribes to control
   and data planes.

2. **Epoch advance.** Cold-root device unlocks; signs `epoch_advance`
   plus one `device_add` per new device for the new epoch. NIP-03
   anchoring RECOMMENDED. Old epoch keys remain valid for past events.

3. **Device add (mid-epoch).** Cold root signs single `device_add` for
   the new (epoch, device) slot.

4. **Device revoke.** Cold root signs `device_revoke` with `revoked_at`.
   Followers prune the pubkey from data-plane filter. Sibling devices
   in same epoch unaffected.

5. **Epoch revoke.** Cold root signs `epoch_revoke`. Whole epoch's
   device keys invalidated past `revoked_at`. User is offline until an
   `epoch_advance` is published.

6. **Root rotation (committed strategy).** R2 publishes `root_rotation`
   referencing R1, NIP-03 anchored. Heterodyne wraps in
   `keri_rotation.v1` with new root + Matrix MSK + optional witnesses.
   Followers verify NIP-03-oldest `genesis_commitment` from R1 names
   R2; MSK continuity additionally confirms identity.

7. **Root burn / recovery (none strategy).**
   - If user still holds cold root: publish `root_revoke` (self-burn);
     identity dies; user creates fresh root via new KERI inception.
   - If user lost cold root: only Heterodyne's KERI rotation
     (MSK-signed) recovers continuity. Pure-Nostr followers without
     MSK lookup must re-verify socially.

8. **Re-attestation of historical content.** User publishes NIP-18
   quote events from new-root epoch keys, tagged with
   `["original_event", "<eid>", "<original_root>"]`.

---

## 8. Security model

### 8.1 Threats addressed

| ID | Threat | Mitigation |
|---|---|---|
| T1 | Single operational-key compromise | Burn one (epoch, device) tuple; sibling devices and epochs unaffected |
| T2 | Epoch-wide compromise (shared bunker) | `epoch_revoke`; advance to a fresh epoch with new devices |
| T3 | xpub + private-child sibling leak (issue #1774) | All levels under persona are hardened |
| T4 | Forked-chain attack on root rotation | Cross-signed succession is removed; only `committed` (with NIP-03) is offered |
| T5 | Replaceable kind 10044 overwritten by stolen root | 10044 is non-authoritative; security defers to kind 1044 + NIP-03 |
| T6 | Backdated revocation forgery | `revoked_at` bounded below by cold root's earliest NIP-03 anchor of normal operation |
| T7 | Relay censorship of revocation | Matrix identity room federation + multi-relay propagation + auto-republish |
| T8 | Identity-room homeserver collusion | Nostr-signed attestations inside state events; HS cannot forge cold-root sigs |

### 8.2 Threats NOT addressed

| ID | Threat | Why not |
|---|---|---|
| T9 | Cold-root compromise on `none` strategy | Explicit user choice at root creation; recovery is out-of-band or via Matrix MSK (Heterodyne) |
| T10 | Simultaneous MSK + cold-root compromise | User-controlled storage separation; we recommend separation, can't enforce |
| T11 | BIP39 seed compromise | Total compromise — same as any HD wallet |
| T12 | Pre-image attacks on persona-index commitment | R2's pubkey is exposed at creation; private key remains protected by hardened derivation |

### 8.3 Trust assumptions

- Cold root storage is not simultaneously compromised with Matrix MSK.
- At least one NIP-03 OpenTimestamps anchor reaches a Bitcoin block
  before any compromise.
- Followers can reach at least one honest relay carrying lineage
  events (NIP-65 outbox model + multi-homing).
- Verifiers honor `revoked_at` bounded by NIP-03 anchors per §5.4.

---

## 9. Out of scope / future work

- **Root rotation other than `committed` or `none`.** Cross-signed and
  threshold-signature schemes are explicitly out of scope. Future NIPs
  MAY layer their own mechanisms.
- **BIP85 multi-persona under one master.** Complementary to this NIP;
  see issue #1691.
- **Encrypted DMs across rotation.** Existing NIP-17 / NIP-44 mechanics
  apply unchanged; per-message key derivation is independent of the
  cold-root lineage.
- **Nostr-only KERI inception.** Heterodyne uses KERI as part of its
  identity-room ceremony. A future NIP could specify a pure-Nostr KERI
  binding for non-Heterodyne clients; not in this design.

---

## 10. Resolved design decisions

The following decisions were originally open and have been resolved
inline in §§5–6:

1. **Kind numbers** (§6.10). Final allocations:
   `m.heterodyne.keri_inception.v1` = 31002 (reused);
   `m.heterodyne.keri_rotation.v1` = 31003 (reused);
   `m.heterodyne.cold_root_backup.v1` = 31006 (new). Epoch summary and
   epoch attestation embed NIP kinds 10044 and 1044 directly.
2. **KERI signature requirements** (§6.6). Inception: MSK + new root
   MUST sign; witnesses MAY. Rotation: MSK + new root MUST sign;
   witnesses SHOULD (especially for `none`-strategy).
3. **`nip03` tag format** (§5.2, §5.4.1). Reference, not embed —
   the tag carries a kind:1040 event id per NIP-03.
4. **Revocation NIP-03 requirement** (§5.2, §5.4). All revocation
   events (`device_revoke`, `epoch_revoke`, `root_revoke`) MUST carry
   a NIP-03 anchor.
5. **Cold-root backup in identity room** (§6.5.1). Normative format
   specified: kind 31006, NIP-49-encrypted, state_key=`""`. MAY be
   used; clients SHOULD warn it's the highest-attack-surface option.

---

## 11. Implementation deliverable order

1. NIP draft text + reference vectors (no Heterodyne dependency).
2. Heterodyne §3 / §3.5* rewrites against the NIP.
3. Heterodyne §6 / §7 / §10 normative updates.
4. Test vectors in `docs/spec/vectors/` for each new flow.
5. Reference implementation (per the project README's milestone 2).
