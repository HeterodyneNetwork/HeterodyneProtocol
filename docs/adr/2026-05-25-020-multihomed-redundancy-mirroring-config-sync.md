# ADR-020: Multi-homed redundancy — room mirroring and cross-MXID config sync

**Date:** 2026-05-25
**Status:** Accepted
**Decision makers:** user + multi-LLM council (gemini-3.1-pro, gpt-5.4) via document-mode review

> **Superseded in part (2026-07-31, ADR-037).** Broadcast-room mirroring and
> room-key/private-broadcast body clauses are retired. Cross-MXID config sync,
> generic identity/discussion mirroring, explicit promotion, event-id
> deduplication, and Matrix-session rotation remain accepted.

## Context

Two deferred items in the 0.x spec both reduce to "a persona's
state should survive the loss of any single homeserver":

1. **Cross-MXID config sync** was marked out of scope in §3.8.4: a
   persona with multiple delegated MXIDs has one config room each, and
   persona-scoped state (private mutes, feed preferences) was not
   synchronized across them. But §3.9.1 *already* establishes **mutual
   config-room membership** — every delegated MXID joins every other's
   config room. The substrate exists; only the content-sync rule was
   missing.

2. **Room redundancy** had no story at all. A persona's identity room
   and broadcast rooms each lived on exactly one homeserver; if that
   homeserver vanished, followers lost the canonical room. The only
   related machinery was §3.10 voluntary homeserver-exit, a one-shot
   migration with a 7-day dual-publish overlap — not standing
   redundancy.

These are the same problem viewed twice, so they are decided together.
The governing project constraint is **no new transport and vanilla
homeserver compatibility** (§1.2): redundancy must be built from
Matrix federation and rooms as they already exist, not a new
replication protocol. The **no-unnecessary-broadcast** rule also
applies — coordination/sync state stays in the encrypted config rooms,
never the identity room or relays.

## Decision

**Persona state is made redundant across the persona's own
homeservers by standing full-replica room mirroring, and persona
config is synchronized across the already-mutually-joined config
rooms.** Voluntary homeserver-exit (§3.10) is reframed as the
mirror-promotion special case of this model rather than a separate
mechanism.

- **Cross-MXID config sync.** `persona_config.v1`, `key_backup.v1`,
  and `user_prefs.v1` synchronize across the persona's
  mutually-joined config rooms (§3.9.1). `device_inventory.v1` stays
  per-room (it is inherently per-room bookkeeping). Sync rides
  existing Matrix state replication; no new transport.

- **Full-replica mirroring.** A persona MAY maintain parallel replicas
  of both the **identity room** and its **broadcast rooms**
  (`public_broadcast`, `private_broadcast`) across multiple homeservers
  it controls. One replica is the **primary** (the room named by the
  cold-root-signed `kind:31005` pointer and the `kind:31007` feed
  index); the others are warm replicas tied together by a new
  identity-room state event. On primary-homeserver failure, the persona
  **promotes** a replica by republishing `kind:31005` to point at it.

- **Private content stays relay-borne.** Mirroring does not duplicate
  private post *bodies* into each Matrix room: private broadcast posts
  remain room-key-wrapped on relays (§6.10), and the mirror rooms carry
  the Heterodyne state, the follower keyring (Megolm session), and bare
  reactions/replies. The per-mirror cost is therefore re-keying and
  event re-publication on re-key, not N copies of every post.

- **Re-key on removal, not on join.** A mirrored private room SHOULD
  rotate its Megolm/room key only when a member is **removed**, not
  when one joins — joiners receive the current session forward. This
  preserves forward secrecy against departed members while avoiding a
  re-key storm as followers and mirror replicas come online.

- **Migration folds into mirroring.** Voluntary homeserver-exit becomes
  "promote a replica on the target homeserver to primary and republish
  `kind:31005`." §3.10's standalone dual-publish overlap is retained
  only as the underlying operation / the path for personas not running
  mirrors.

## Requirements (RFC 2119)

- A conforming client SHOULD synchronize `m.heterodyne.persona_config.v1`,
  `m.heterodyne.key_backup.v1`, and `m.heterodyne.user_prefs.v1` across
  all of a persona's mutually-joined config rooms (§3.9.1).
  `m.heterodyne.device_inventory.v1` MUST NOT be synchronized (it is
  per-room state). Sync MUST use ordinary Matrix state replication and
  MUST NOT introduce any homeserver-side component.
- Conflicting synced config across config rooms MUST be resolved by the
  same rule as §3.9 active-room reconciliation: the write with the
  greatest `origin_server_ts` wins, and clients SHOULD surface a sync
  conflict indicator on rapid concurrent writes.
- Synchronizing `m.heterodyne.key_backup.v1` widens the at-rest
  footprint of the wrapped `nsec`; a client MUST keep the backup wrapped
  under the user-controlled secret in every replica (the config-room
  E2EE is not sufficient alone) and SHOULD let the user opt the nsec
  backup out of sync.
- A conforming client MAY maintain full-replica mirrors of a persona's
  identity room and broadcast rooms across multiple homeservers the
  persona controls. When it does, it MUST publish an
  `m.heterodyne.mirror_group.v1` state event in the identity room
  enumerating the replica rooms and naming the current primary.
- The primary replica MUST be the room referenced by the persona's
  current `kind:31005` identity pointer and `kind:31007` feed index.
  Followers MUST treat the primary as canonical and MUST deduplicate
  content observed across replicas by Nostr event `id`.
- Mirroring MUST NOT duplicate private (E2EE) post bodies into multiple
  Matrix rooms; private broadcast content MUST remain room-key-wrapped
  on relays per §6.10. Mirror replicas carry Heterodyne state, the
  Megolm follower keyring, and bare in-room traffic only.
- A mirrored private room SHOULD rotate its Megolm/room key on member
  **removal** and SHOULD NOT rotate it on member **join**, sharing the
  current session forward to joiners, where the client's Megolm
  implementation supports forward session sharing.
- Promotion of a replica to primary MUST be performed by republishing a
  cold-root-signed `kind:31005` pointing at the new primary; clients
  MUST warn the user that promotion unseals the cold root (as with §3.10
  migration) and SHOULD recommend re-securing it afterward.
- Voluntary homeserver-exit (§3.10) MUST be expressible as mirror
  promotion when the persona runs mirrors; the §3.10 dual-publish
  overlap remains valid for personas not running mirrors and MUST NOT be
  removed.
- All redundancy and sync state MUST stay within the persona's own
  config/identity rooms and replicas; no coordination state may be
  added to relays or broadcast to non-members (no-unnecessary-broadcast,
  §3.9).

## Consequences

- A persona surviving any single homeserver outage no longer depends on
  the §3.10 one-shot migration; a standing replica is promoted instead.
  This subsumes voluntary migration under one model.
- Cross-MXID sync resolves the §3.8.4 deferral with zero new wire
  mechanism by reusing the §3.9.1 mutual-membership substrate.
- Syncing the wrapped nsec to every config room trades a wider at-rest
  blast radius for recoverability; the opt-out and the
  wrapped-everywhere requirement bound the risk.
- Identity-room mirroring makes the §3.12 friend-cache / cold-root
  re-anchor (ADR-021) a *deep* fallback — reached only when every
  persona-run replica is also gone — rather than the first line of
  defense.
- The `m.heterodyne.mirror_group.v1` state event and the
  promotion-republishes-`kind:31005` rule add a new lifecycle that the
  conformance vectors (§14) must cover; mirroring remains OPTIONAL and
  baseline conformance does not require it.
- Hostile-mirror-homeserver and mirror-consistency threats are added to
  the threat model: a replica's homeserver can withhold or lie about
  state, mitigated by the cold-root `kind:31005` precedence rule and
  per-event Nostr signatures (followers verify content independent of
  which replica served it).
