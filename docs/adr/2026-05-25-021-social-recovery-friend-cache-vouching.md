# ADR-021: Social recovery — friend-caching, two-tier vouching, and involuntary re-anchor

**Date:** 2026-05-25
**Status:** Accepted
**Decision makers:** user + multi-LLM council (gemini-3.1-pro, gpt-5.4) via document-mode review

## Context

Threat-model open question #3 asked how a persona recovers when the
homeserver hosting its identity room goes **permanently** offline.
§3.10 only covers *voluntary* exit (a planned migration with a 7-day
overlap); §3.7 "identity room unreachable" only says cached state MAY
be used with a staleness indicator. Neither answers the involuntary
case, where there is no overlap window and no way to post a migration
pointer into the dead room.

Heterodyne already has the cryptographic primitive needed for social
recovery: §3.5 KERI inception/rotation events carry a **witness set**
with per-witness weights and a **threshold**, and `none`-strategy
rotation already relies on witness attestations for continuity when the
cold root is lost. What was missing was (a) the social process that
keeps a persona verifiable and recoverable across a homeserver death,
and (b) a way for ordinary friends — not just formally declared
witnesses — to contribute social-trust signal without becoming a sybil
vector.

The cold root is the backstop for app-layer key loss, but it cannot
defend against OS/device compromise — Heterodyne secures its own
application surface, not the platform. Recovery therefore leans on the
social graph as an independent axis from the cold-root chain.

## Decision

**Followers cache a persona's identity-room state; a two-tier vouching
model lets both declared KERI witnesses and informal friends attest a
recovery; and involuntary re-anchor is performed by republishing a
cold-root `kind:31005` to relays, with the friend-cache as the trust
bridge and deep fallback.**

- **Three-tier caching duty.** Followers MAY cache the persona's
  identity-room state; mutuals SHOULD; declared §3.5 witnesses MUST.
  The cache retains state for at least 30 days and holds **only**
  owner-NOSTR-signed feed/identity content **plus** KERI events
  (`kind:31002`/`31003`) — never arbitrary other room content. Its
  purpose is dual: keep verifying / re-serving the persona while the
  homeserver is down, and seed/attest the re-published identity room
  after re-anchor.

- **Declared witnesses (authoritative tier).** The friends who cache
  and vouch in a recovery are, by default, the persona's declared §3.5
  witnesses. Their signatures on the new epoch/cold key are ordinary
  KERI witness attestations counted by the existing weight/threshold
  verifier (§3.5.3). No parallel trust layer for this tier.

- **Informal vouchers (advisory tier).** Any friend MAY publish a
  signed "social vouch" for a persona's new key at a given sequence
  (a new Heterodyne-reserved `kind:31008`). Each informal vouch carries
  a small fractional weight (RECOMMENDED ≤ 1% of the default declared
  witness weight). Clients MAY surface aggregate informal vouching and
  MAY *suggest* the user promote an informal voucher into the declared
  set (the intended web-of-trust snowball) — but **promotion is always
  a manual user action**, and informal weight alone can never satisfy a
  rotation threshold.

- **Involuntary re-anchor.** When the identity-room homeserver is
  permanently gone, the persona signs a fresh `kind:31005` identity
  pointer **with the cold root** and publishes it to Nostr relays;
  followers re-resolve by `authors:[npub]` independent of the dead
  homeserver (§11.3 / §3.10.3 precedence). The friend-cache bridges
  verification until the new pointer propagates and is the fallback
  source if relays also lack it. This is the *deep* fallback beneath
  ADR-020 identity-room mirroring — reached only when every persona-run
  replica is also gone.

- **Out-of-band identity verification stays deferred.** How a friend
  satisfies themselves that the recovering party is genuinely the
  persona owner (the actual human-trust step before they sign) is
  deliberately left outside the protocol, so those channels cannot be
  captured or standardized into a single attackable surface.

## Requirements (RFC 2119)

- A conforming client MAY cache a followed persona's identity-room
  state; for personas the user mutually follows it SHOULD; for personas
  for which the user is a declared §3.5 witness it MUST.
- A cache MUST retain the state for at least 30 days and MUST store
  ONLY (a) content signed by the persona's own Nostr identity that is
  feed- or identity-related, and (b) KERI events (`kind:31002`,
  `kind:31003`) appearing in the room. A client MUST NOT cache other
  room content, and MUST NOT treat events not signed by the persona's
  Nostr identity as cacheable identity state (KERI events are the sole
  exception, since they may legitimately be signed by a prior epoch key
  or carry witness attestations).
- A persona MAY enlist informal vouchers in addition to declared
  witnesses. An informal vouch MUST be a signed `kind:31008` event
  naming the persona npub, the target key, and the KERI sequence number
  it vouches for.
- Informal vouch weight is **supplemental**: each vouch's contribution
  MUST be capped (RECOMMENDED ≤ 1% of the default declared-witness
  weight), and informal weight MAY help a rotation that already carries
  at least one valid declared-witness signature cross the threshold. But
  acceptance MUST always require at least one declared-witness signature
  (or, for `committed` strategy, the cold root); the **total** informal
  contribution MUST NOT reach the threshold on its own; and a rotation
  backed only by informal vouches MUST NOT be accepted. (Verifier
  invariant in §3.5.3: informal weight is counted only once a declared
  signature is present, and capping limits it to a fractional remainder.)
- A client SHOULD steward the declared witness set (§3.5.6): it SHOULD
  continually nudge the user to designate witnesses until the persona
  has at least 3 (recurring when friends/mutuals are added, not
  permanently dismissable below 3); SHOULD recommend at least 5 for a
  persona with more than 1000 mutuals; and SHOULD periodically
  (RECOMMENDED every 1–6 months) re-verify that declared witnesses are
  still valid and reachable, surfacing any stale/invalid witness for
  replacement.
- A client MAY suggest promoting an informal voucher into the declared
  witness set but MUST NOT promote automatically; promotion MUST be an
  explicit user action.
- For involuntary re-anchor, the persona MUST republish a
  cold-root-signed `kind:31005` pointing at the new identity room and
  publish it to the persona's Nostr write relays. Followers MUST treat
  that `kind:31005` as the authoritative discovery path and MUST log any
  disagreement with cached state for security review.
- A client serving cached identity state to other followers during an
  outage MUST mark it as cache-sourced and stale, and MUST NOT present
  it as live homeserver state.
- The means by which a voucher verifies the recovering party's identity
  out-of-band is explicitly out of scope and MUST NOT be standardized by
  this spec version.

## Consequences

- Open question #3 is resolved: a persona survives permanent
  homeserver loss via cold-root `kind:31005` re-anchor, with the social
  graph providing continuity of trust across the gap.
- The two-tier model gives ordinary followers a real (if small) voice
  in recovery and a growth path into the witness set, while the hard
  cap + manual-promotion rule keeps informal vouching from becoming a
  sybil takeover path. This trade is surfaced as a threat-model entry.
- A new reserved kind (`kind:31008`, social vouch) is allocated from the
  31008–31099 reserved range and added to the §3 kind table.
- The content-filtered cache (owner-signed feed/identity + KERI only)
  bounds friend-cache poisoning: a malicious cacher cannot inject
  arbitrary content because non-persona-signed events are not cacheable
  identity state.
- Caching duty scales with trust (followers MAY → mutuals SHOULD →
  witnesses MUST), which is why identity rooms are kept deliberately
  small (the 30-day, content-filtered cache stays cheap to hold).
- Social recovery is OPTIONAL infrastructure layered on the existing
  §3.5 witness machinery; baseline conformance does not require a client
  to act as a cacher or voucher, but it MUST honor the informal-weight
  cap when verifying rotations that present `kind:31008` vouches.
