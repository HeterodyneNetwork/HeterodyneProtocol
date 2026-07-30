# Heterodyne Social Protocol Specification

Document ID: `social`<br>
Version: `social/0.5.0`<br>
Registry revision: `3`

Normative dependencies:

- `heterodyne:core/0.5.0#core-conformance`
- `heterodyne:comms/0.5.0#comms-conformance`

This document prepares Social's first 0.5.0 release, descended from the
Heterodyne 0.4.x monolith. It is current normative authority at this repository
path but remains unreleased pending explicit release approval. It is not a
synchronized family version. While Social is
0.x, a
conformance claim MUST pin the exact Social, Core, and Comms versions; any 0.x
release MAY break an earlier one. The key words MUST, MUST NOT, REQUIRED,
SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, NOT RECOMMENDED, MAY, and
OPTIONAL are to be interpreted as described by BCP 14 when, and only when,
they appear in all capitals.

Permanent anchors use the literal `social-` prefix and lowercase ASCII
kebab-case. Generated heading IDs are not stable protocol references.

<a id="social-scope"></a>
## 1. Scope and conformance features

<!-- Monolith provenance: §3.3.2, §3.8.1-§3.8.5, §3.9.1-§3.9.7,
§3.10, §3.11.2-§3.11.5, §3.12 social bindings, §4.2-§4.5 Matrix path,
§5.1/§5.4-§5.6, §6.5-§6.8 social policy, §7.3-§7.6, §8,
§9.1.1-§9.4/§9.6 Matrix path, §10.3-§10.4 Matrix path, §11.1/§11.4-§11.7. -->

Social defines following, replies, reactions, threading, social discovery,
cross-persona advertisements, reply inboxes, feed presentation, community and
organization presentation, moderation, personal and community lists,
web-of-trust policy, starter packs, social recovery bindings, and the optional
ATProto attached outbox. It also defines the complete OPTIONAL Matrix feature:
MXID delegation and coordination, Matrix envelopes, discussion rooms,
Megolm/MLS, encrypted configuration rooms, homeserver exit, personal headless
bridging, homeserver requirements, and vanilla-Matrix fallback rendering.

The following conformance claims are distinct:

- **`Social`** requires every non-Matrix section of this document and the
  exact dependency versions above. A Matrix-free implementation can be fully Social-conformant.
  Following, discovery, moderation, lists, recovery
  binding, and async interaction are complete without Matrix.
- **`Social+Matrix`** requires `Social` plus the complete Matrix feature in
  §§9-12. An implementation MUST NOT claim `Social+Matrix` by implementing
  only selected Matrix carriers.

None of these Matrix-free Social mechanisms require Matrix. Matrix is an
optional feature inside Social, not an identity, publishing, discovery,
moderation, privacy, or recovery prerequisite.

<a id="social-interactions"></a>
## 2. Replies, reactions, threading, and mixed-tier fan-out

<!-- Monolith provenance: §4.4, §6.5-§6.6, §6.8-§6.8.1. -->

Because a persona's repository is writable only by its authorized delegates,
a replier MUST NOT require write access to another persona's repository.
Replies and reactions use the Nostr outbox model:

- A reply is a NIP-10 event and a reaction is a NIP-25 `kind:7` event written
  to the replier's own Comms outbox. It carries the standard `e`/`p` references
  to the target id and author and is published under
  `heterodyne:comms/0.5.0#comms-publishing`.
- Thread assembly is scatter-gather over repliers' repo relays and ordinary
  relays. A client MUST locally verify every event through
  `heterodyne:comms/0.5.0#comms-envelope` and MUST deduplicate by event id.
- A full node MAY materialize `xyz.heterodyne.thread` as a Radicle
  Collaborative Object, but a client MUST treat it only as an optimization.
  The verified scatter-gathered events remain authoritative.
- A replier MAY index its reply in its own feed. By default replies and
  reactions are non-indexed and render only in context. An explicit signed
  `['heterodyne_index','true']` overrides the default; `false` excludes an
  otherwise indexed event.

The default feed classifications are: kinds `1`, `6`, `16`, `1063`, `30023`,
and `30402` indexed; kinds `0`, `3`, `5`, `7`, `8`, `17`, `1984`, `4550`,
`9734`, `9735`, `10000-10999`, `30000-30099`, and `31000-31099` non-indexed.
Kind `30024` is a non-indexed draft. Unknown persistent addressable content
SHOULD default indexed; other unknown kinds SHOULD default non-indexed.

<a id="social-mixed-tier-fanout"></a>
### 2.1 Mixed-tier fan-out and reply inboxes

A Social UI MAY compose one intent across multiple Comms destinations, but it
MUST preserve `heterodyne:comms/0.5.0#comms-privacy-tiers`: Tier 2 plaintext
MUST NOT reach a public relay, and Tier 3 MUST remain ciphertext at every
destination. A client SHOULD warn before a user expands a Tier 2, Tier 3, or
private-discussion intent to a public destination. The warning never permits
plaintext leakage.

An outbox advertisement MAY contain a reply inbox: a closed set of ordinary
relay, repo-relay, and, under Social+Matrix, Matrix-room hints where the persona
prefers to observe replies and mentions. A replier SHOULD add these reachable
destinations to the normal destination set; the reply still belongs to the
replier's own outbox, and an inbox never grants write authority over the
parent's repository.

Matrix-free interaction is intentionally asynchronous. A client MUST degrade
gracefully to outbox replies/reactions and MUST NOT block the user waiting for
real-time push from Radicle's announce-then-fetch substrate.

<a id="social-discovery"></a>
## 3. Following and social discovery

<!-- Monolith provenance: §7.3-§7.6 and §11.4; lower-layer discovery split by
ADR-033 requirements 9 and 11. -->

Social discovery starts only after Core has resolved npub to RID to serving
node and Comms has located the generic feed/outbox. A follower MUST:

1. resolve the target npub through
   `heterodyne:core/0.5.0#core-identity-discovery`;
2. read and verify the target's public Comms `kind:31007` indexes and select
   topic feeds;
3. for Tier 2, establish access through the repository allow list; for Tier 3,
   possess the current audience key and use the in-audience descriptor;
4. after entering an audience, read its descriptor for deeper feeds and repeat
   transitively; and
5. cache discoveries with a TTL, revalidate on a newer verified identity
   pointer, and discard expired node advertisements.

Transitive discovery MUST NOT disclose an inner feed before the reader holds
the outer audience's access capability. A search result, starter pack, graph
snapshot, or recommendation is never identity authority: every npub MUST walk
the same Core and Comms resolution path before subscription.

<a id="social-following"></a>
### 3.1 Following semantics and private state

Following is a set of feed subscriptions, not one global server-side edge:

- following one public topic subscribes to that topic's index;
- following all public topics subscribes to every selected public index;
- private following requires Tier 2 allow-list access or Tier 3 audience-key
  membership; and
- vanilla-Nostr following subscribes through the target's NIP-65 write relays.

A client that follows a public feed SHOULD offer to opt into seeding its
Radicle repository. Seeding remains an explicit user choice and MUST NOT be
inferred from popularity or from following alone.

A client MAY publish a NIP-02 `kind:3` follow list for vanilla interop, but
MUST NOT require a public follow list. Private follows, feed preferences,
followed-repository locators, private mutes, and UI preferences are
Social-owned records. They MUST be encrypted at rest in the config-repository
profile of `heterodyne:comms/0.5.0#comms-config-repository` or retained in
local encrypted storage. A followed-repositories record stored through the
Core keys-repository protection mechanism remains a Social payload; storage
location does not transfer semantic ownership.

A Heterodyne user MAY follow a vanilla Nostr-only npub. The client verifies
that user's Nostr signature directly, subscribes to their NIP-65 relays, and
MUST present the absence of Heterodyne KEL/delegation and private-audience
features as reduced guarantees. If it offers DMs, it uses the Comms NIP-17
fallback and labels the lack of Double Ratchet forward secrecy.

<a id="social-cross-persona"></a>
### 3.2 Cross-persona advertisements

`kind:31004` is the Social `related_persona` attestation. A relationship is
valid only when two distinct personas A and B publish a matching pair of
attestations. A's `other_npub` MUST be B's cold-root npub and B's
`other_npub` MUST be A's. Each event carries:

```text
['d','<relation>:<other_npub_hex>']
['heterodyne','related_persona']
['other_npub','<other_npub_hex>']
['relation','same_holder|endorses|endorsed_by|linked']
['cold_root','<signing persona cold-root hex>']
['kel_head','<accepted KEL event id>','<seq>']
['spec_version','social/0.5.0']
```

Both signatures and both personas' Core key authority MUST verify. A
single-signed relationship MUST be rejected. The `d`, `other_npub`, and
opposite-party values MUST match exactly. `same_holder` and `linked` are
symmetric: both events MUST use the same relation. `endorses` and
`endorsed_by` are the only inverse pair. The events MUST have independent
signatures, signing epoch keys, cold roots, and accepted `kel_head` proofs.
An OPTIONAL `['scope','<value>']` tag is valid only when it is either absent
from both events or occurs exactly once with the same value in both. A
relationship MAY be advertised
publicly or inside a Comms audience, but a client MUST NOT infer relationships
from co-hosting, timing, caches, or any signal other than an explicit valid
pair.

<!-- fixture:related-persona-pair -->
```json
{
  "left": {
    "pubkey": "1b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
    "created_at": 1710000000,
    "kind": 31004,
    "tags": [["d","endorses:4d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766"],["heterodyne","related_persona"],["other_npub","4d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766"],["relation","endorses"],["scope","professional"],["cold_root","1b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"],["kel_head","3333333333333333333333333333333333333333333333333333333333333333","0"],["spec_version","social/0.5.0"]],
    "content": "",
    "id": "89a6a1bf0345535482d296e6910b5115a623dbafe8b9cdd5011af28f686eb45d",
    "sig": "7ff8bd7d316fd67820547ed4d92c60a556ed1fd089afd6aafe30190c2fe9812e34f81b3bf8200eb1437e3ccdcc74bfa874d9014d6cd924efb6ad1072dfd1a3ff"
  },
  "right": {
    "pubkey": "4d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766",
    "created_at": 1710000001,
    "kind": 31004,
    "tags": [["d","endorsed_by:1b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"],["heterodyne","related_persona"],["other_npub","1b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"],["relation","endorsed_by"],["scope","professional"],["cold_root","4d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766"],["kel_head","4444444444444444444444444444444444444444444444444444444444444444","0"],["spec_version","social/0.5.0"]],
    "content": "",
    "id": "5781bb1481f0872b2f30cb814504ff2d88a6f3e7698ef5d282efd408181fa135",
    "sig": "dff1363b0c75c624a849bea8251eb8404fe1cc0972aa7e68663737351dcaea6138d146eee98ce3bdefbe20de8765d0d017596910f96128c451cf9690e7d8a1b0"
  },
  "kel_authority": {
    "left": {"cold_root":"1b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f","accepted_head":"3333333333333333333333333333333333333333333333333333333333333333","authorized_epoch_key":"1b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"},
    "right": {"cold_root":"4d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766","accepted_head":"4444444444444444444444444444444444444444444444444444444444444444","authorized_epoch_key":"4d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766"}
  }
}
```

The fixture's `kel_authority` object is test metadata, not part of either
Nostr event. It records the accepted Core KEL head and authorized epoch key
used to verify each event independently; both example personas are at their
inception epoch, so each authorized epoch key equals its cold root.

<a id="social-discovery-extensions"></a>
### 3.3 Search, starter packs, and graph sources

NIP-50 relay-side search is OPTIONAL. A returned npub MUST be independently
resolved. Clients SHOULD recognize NIP-51 `kind:39089` starter packs and MUST
resolve every listed npub before following it. Algorithmic feed/DVM behavior
is outside this release's conformance requirements.

The Social graph MUST NOT depend on a centralized follow-graph oracle. A
client MAY bootstrap from a snapshot, but it MUST mark the snapshot as a cache,
replace it with live verified lists, and MUST NOT allow it to override the
user's own follows or mutes.

<a id="social-recovery-binding"></a>
## 4. Social binding of Core recovery roles

<!-- Monolith provenance: §3.12.1-§3.12.4; mechanism recast in Core by
ADR-033 requirement 13. -->

Core defines recovery peers, declared witnesses, cached identity material,
and cold-root re-anchor at `heterodyne:core/0.5.0#core-recovery`. Social MAY
select recovery peers from follows, mutual follows, friends, and, under
Social+Matrix, a Matrix identity-room cache:

- any follower MAY cache permitted identity material;
- a mutual follow SHOULD cache it; and
- a declared Core witness MUST retain the material required by the Core
  recovery profile for at least 30 days.

<!-- fixture:social-recovery-cache-duties -->
```json
{"follower":"may","mutual-follow":"should","declared-witness":"must"}
```

Only persona-signed identity/feed material and valid KEL events may enter this
cache. A serving peer MUST mark cached data stale and cache-sourced. Social
relationships and Matrix identity-room cache entries are advisory availability
bindings and MUST NOT replace the cold-root re-anchor, accepted KEL, witness
threshold, or verification rules in Core. Informal `kind:31008` social vouches
are advisory only and MUST NOT count toward a Core rotation threshold.

Human out-of-band assurance before vouching is deliberately unspecified. A
voucher MAY use any channel; this document defines no single capturable proof.

<a id="social-informal-vouch"></a>
### 4.1 Informal social vouch (`kind:31008`)

An informal vouch has this Social-owned addressable shape:

```json
{
  "pubkey": "<voucher current epoch key>",
  "created_at": 0,
  "kind": 31008,
  "tags": [
    ["d", "<persona cold-root>:<s>:<vouched_key>"],
    ["heterodyne", "social_vouch"],
    ["p", "<persona cold-root>"],
    ["vouched_key", "<new epoch or cold key hex>"],
    ["s", "<KEL sequence>"],
    ["kel_head", "<voucher accepted KEL event id>", "<seq>"],
    ["spec_version", "social/0.5.0"]
  ],
  "content": "<optional free-text note>",
  "sig": "<BIP-340 signature by voucher epoch key>"
}
```

The `d`, `p`, `s`, and `vouched_key` values MUST agree exactly, and the named
sequence/key MUST match the rotation being discussed. The voucher's signature,
KEL authority, `kel_head`, and Social stamp MUST verify. A `did:key`-only peer
participates through Core's declared-witness mechanism, not this Nostr event.
No number of informal vouches can satisfy a Core threshold. A client MAY show
or rank them and suggest a declared-witness promotion, but promotion MUST be an
explicit user action and MUST NOT influence the Core accept/reject verdict.

<a id="social-feed-presentation"></a>
## 5. Feed and organization presentation

<!-- Monolith provenance: §5.6, §6.7.0/§6.7.6, §6.8-§6.8.1, §7.1-§7.2;
Comms base ownership retained by ADR-033 requirements 7, 11, and 12. -->

Comms owns feed storage, ordering, paging, retrieval, and threshold
authorization. Social turns those verified inputs into topic subscriptions,
curated views, community pages, reply counters, moderation views, and
organization presentation. A Social renderer MUST NOT show an org post or
index as canonical until it passes
`heterodyne:comms/0.5.0#comms-org-authorization`.

A persona MAY operate multiple topic feeds and multiple audience feeds. A
client SHOULD support topic-selective subscription and MAY present a union as
"all topics." Feed labels, topic tags, pinning, intentional omissions, and
nonchronological ordering are presentation instructions from the verified
Comms index; relay presence alone MUST NOT insert an unindexed event into a
persona's curated feed.

<a id="social-org-feed-profile"></a>
### 5.1 Registered Social org-feed profile

Registry revision 3 defines the stamping profile
`heterodyne-social-org-feed-v1` on the Comms-owned `kind:31007`, with immutable
discriminator `content.profile=heterodyne.social.org-feed.v1`. An event opting
into this profile MUST otherwise validate the complete Comms feed-index schema.
The immutable profile permits it only in Tier 1 and Tier 2; Tier 3 use and
ciphertext are forbidden. It replaces the ordinary Comms empty content with
exactly this canonical compact JSON string, including member order and with no
unknown members:

```json
{
  "profile": "heterodyne.social.org-feed.v1",
  "spec_version": "social/0.5.0"
}
```

Because the profile is stamping, the Social stamp is the event's sole owner
stamp and occurs only in `content`; the event MUST NOT carry either a Comms or
Social version tag. All Comms tags, paging, thresholds, page-size, publication,
retrieval, signature, and KEL requirements remain in force. It MUST NOT carry
`heterodyne_wrap` or `key_id`. A Comms `kind:31007` without the exact
discriminator remains a Comms event and MUST NOT be interpreted as this Social
profile.

<!-- fixture:social-org-feed-index -->
```json
{
  "pubkey": "1111111111111111111111111111111111111111111111111111111111111111",
  "created_at": 1710000000,
  "kind": 31007,
  "tags": [["d","org-news:page-2"],["heterodyne","feed_index"],["cold_root","2222222222222222222222222222222222222222222222222222222222222222"],["rid","rad:zExample"],["feed_label","Org news"],["e","3333333333333333333333333333333333333333333333333333333333333333","wss://relay.example"],["previous_index","4444444444444444444444444444444444444444444444444444444444444444"],["prev_page_hash","5555555555555555555555555555555555555555555555555555555555555555"],["kel_head","6666666666666666666666666666666666666666666666666666666666666666","7"]],
  "content": "{\"profile\":\"heterodyne.social.org-feed.v1\",\"spec_version\":\"social/0.5.0\"}",
  "sig": "77777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777"
}
```

The profile controls only org/community/editorial presentation. It MUST NOT
weaken the requirement that both the org post and index be reachable from the
delegate-threshold-approved canonical feed branch. The optional per-ref
`xyz.radicle.crefs` refinement MAY further scope editorial refs, but baseline
canonicity MUST NOT depend on it.

<a id="social-matrix-outbox-presentation"></a>
### 5.2 Optional Matrix outbox presentation

<!-- Monolith provenance: §7.1-§7.2 Matrix carrier forms. -->

Under Social+Matrix, an identity room MAY contain at most one unencrypted
`m.heterodyne.outbox.public.v1` with `spec_version: social/0.5.0`. It MAY list
public discussion rooms, topic/feed presentation, NIP-65 read/write relays, an
optional Matrix Space, and a reply inbox. It is a human-curated mirror only;
Core identity and Comms outbox discovery MUST remain complete without it.
Room references MUST accept both structured `{room_id,via}` and `matrix:` URI
forms.

An audience descriptor MAY additionally appear as encrypted
`m.heterodyne.outbox.scoped.v1`, keyed by advertising persona, inside an E2EE
`private_discussion`. The descriptor MUST also remain available through the
applicable Comms Tier 2 or Tier 3 carrier and MUST NOT exist only in Matrix.
The Matrix form MUST NOT expose Tier 3 RID, feed address, relay hint, topic, or
membership data outside encrypted state. Membership or key possession gates
the descriptor; it never grants repository authority.

<a id="social-moderation"></a>
## 6. Moderation and editorial gating

<!-- Monolith provenance: §8.0-§8.4 and §8.7-§8.9. -->

Social defines two independent editorial-gating mechanisms:

1. **NIP-72 approval mode.** A moderator publishes a `kind:4550` approval;
   authorized, anchored approvals determine the curated view.
2. **Radicle editorial mode.** A post and its index are approved exactly when
   both are reachable from the delegate-threshold-approved canonical feed
   branch.

A community MAY use either or both. A client MUST NOT treat one as proof of
the other. Membership is a separate axis: repository `visibility.allow`
controls replication/read access, Core delegates control repo authority, and
Matrix membership controls only an optional Matrix room. An unapproved post
may remain visible in a raw relay/repository/room view while being absent from
the curated view.

<a id="social-nip72-submission"></a>
### 6.1 NIP-72 contribution and declaration

A NIP-72 candidate MUST include before signing:

```text
['a','34550:<community-pubkey-hex>:<community-d-tag>']
```

The contributor MUST publish to its own NIP-65 write relays and SHOULD also
publish to the current moderators' write relays. A
`['client','heterodyne']` tag is
OPTIONAL and MUST NOT be used to exclude vanilla submissions. A contributor
SHOULD poll or subscribe to moderator indexes. Polling MUST use five-minute
intervals for the first 30 minutes, then MAY use exponential backoff of 5, 10,
30, then 60 minutes. It MUST stop on approval or when the seven-day
implicit-rejection window expires. If no approval appears within seven days of candidate
`created_at`, conforming clients MUST treat the candidate as implicitly
rejected, MUST surface exactly "post not approved within 7-day window", and
offer abandon, edited republication with a new id, or intentional unchanged
republication. This release defines no explicit moderator-rejection event;
silence is rejection. After three consecutive posts are implicitly rejected
from one community, the client SHOULD warn that "the community may not be
accepting your submissions." This is advisory UX, not enforcement.

Every moderated community MUST publish a NIP-72 `kind:34550` addressable
community definition on the Core/Comms backends. It lists each moderator's
permanent cold-root npub as:

```text
['p','<moderator cold-root npub>','<relay hint>','moderator']
```

and MAY carry `['approvals_required','<positive integer>']`; absence means 1.
A repo-hosted community MUST commit every declaration revision to the
delegate-threshold canonical history.

<a id="social-nip72-approval"></a>
### 6.2 Approval verification and anchors

A moderator approval is an upstream NIP-72 `kind:4550`: its `content`
stringifies the approved post and its tags identify the post, author, and
community. It remains an unstamped upstream event. For each candidate, a
Social client MUST:

1. resolve the community declaration and `approvals_required`;
2. fetch each moderator's current `kind:31007` approval index;
3. fetch each referenced `kind:4550`, the approved post, and applicable
   deletion requests;
4. verify exact NIP-01 bytes, the BIP-340 signature, moderator cold-root
   mapping through the KEL at approval `created_at`, index inclusion, and the
   required historical anchor; and
5. surface the candidate only when distinct live approvals meet the threshold.

An approval counts only with the anchor required by its hosting mode:

- **Repo anchor:** its introducing commit is reachable from canonical history;
  the moderator set is the newest `kind:34550` revision in that commit's
  ancestor history.
- **Matrix anchor:** an `m.heterodyne.approval.v1` timeline event references
  both ids; the moderator set is Matrix state at that anchor, and the anchor
  sender MUST resolve to the same moderator persona.
- **Relay-only fallback:** the newest declaration with `created_at` not after
  the approval is used. A client MUST label this reduced assurance because a
  removed moderator can backdate.

An approval required to have a repo or Matrix anchor but lacking it MUST NOT
count. An approval omitted from the moderator's current index is off-index and
MUST NOT count in the Heterodyne curated view even if a vanilla NIP-72 client
uses it.

<!-- fixture:social-approval-anchor-evidence -->
```json
{"indexed":true,"signatureValid":true,"moderatorAuthorizedAtAnchor":true,"requiredAnchorPresent":true,"deleted":false}
```

The moderator set is evaluated at the anchor, not verification time. Later
removal does not invalidate an earlier approval. A KERI compromise cutoff
MUST invalidate approvals signed after the cutoff. Invalidating an otherwise
historical approval requires a per-approval NIP-09 `kind:5` deletion request
and an updated moderator index.

<a id="social-moderator-matrix-carrier"></a>
### 6.3 Optional Matrix moderator carrier

Under Social+Matrix, a moderated `public_discussion` room carries exactly one
`m.heterodyne.moderators.v1` state event with empty state key:

```json
{
  "type": "m.heterodyne.moderators.v1",
  "state_key": "",
  "content": {
    "spec_version": "social/0.5.0",
    "approvals_required": 1,
    "moderators": [{
      "mxid": "@alice:example.org",
      "npub": "<cold-root hex>",
      "powers": ["approve"],
      "appointed_at": 0
    }]
  }
}
```

`approvals_required` MUST be a positive integer. A moderator entry's npub is
the cold root, while approval signatures use the KEL-authoritative epoch key.
Only `approve` is defined in this release. A community carrying both the
NIP-72 and Matrix declarations SHOULD keep them consistent; the required
anchor determines which historical declaration is authoritative for a given
approval.

The Matrix anchor form is:

```json
{
  "type": "m.heterodyne.approval.v1",
  "content": {
    "spec_version": "social/0.5.0",
    "approval_event_id": "<kind:4550 id>",
    "approved_post_id": "<post id>"
  }
}
```

<a id="social-revocation"></a>
### 6.4 Approval withdrawal and deletion

Silence is rejection; this release defines no explicit rejection event. To
withdraw an approval, its author MUST publish a NIP-09 `kind:5` deletion
request targeting its own `kind:4550` and MUST publish an updated approval
index omitting it. A client MUST validate that the deletion and target authors
match before hiding or discounting the approval. Matrix redaction MUST NOT be
treated as cross-protocol approval withdrawal. Deletion signals intent and
MUST NOT be represented as erasure.

<a id="social-radicle-editorial"></a>
### 6.5 Radicle editorial-gating mode

For a Radicle-mode community, a client MUST treat a post as editorially
approved if and only if both the post and the `kind:31007` that references it
are reachable from the delegate-threshold-approved canonical feed branch. A
lone epoch-key signature observed only on an ordinary relay MUST NOT bypass
that threshold. A client MUST NOT require `kind:4550` in this mode. Conversely,
it MUST NOT impose branch reachability on a NIP-72-mode view.

Post-hoc removal uses `kind:5` plus a new canonical index omitting the post.
Immutable git history means this changes the live view but does not erase the
old bytes. `xyz.radicle.crefs` MAY refine per-ref authority; the baseline MUST
remain evaluable without it.

<a id="social-labels"></a>
### 6.6 Reports and labels

Clients MAY consume NIP-56 `kind:1984` reports. They are RECOMMENDED to emit
and consume NIP-32 `kind:1985` labels. A label event MUST target at least one
event, pubkey, address, relay, or topic through an upstream `e`, `p`, `a`, `r`,
or `t` tag. When it uses an `L` namespace, each `l` tag MUST mark a matching
namespace. Labels are advisory: they MAY influence local warnings/ranking but
MUST NOT constitute either editorial approval mechanism.

<a id="social-agent-policy-receipts"></a>
### 6.7 Agent-policy receipts and corrections

Registry revision 3 defines the stamping
`heterodyne-social-agent-policy-receipt-v1` profile on NIP-32 `kind:1985`.
A receipt MUST have exactly:

```text
["L", "network.heterodyne.agent-policy"]
["l", "agent-attribution-missing" |
      "agent-attribution-falsified" |
      "agent-publication-bypass", "network.heterodyne.agent-policy"]
["e", "<offending-event-id>", "<optional relay hint>"]
["p", "<offending device-publishing-key>", "<optional relay hint>"]
```

It MUST target exactly one event and exactly its signing device key. Its
content MUST validate against
`docs/spec/schemas/social/agent-policy-receipt-v1.schema.json`, whose closed
Social JSON binds profile/version, offending event, device key, resolved
cold-root persona, reason, observation time, evidence references or digests,
explanation, and remediation `rotate-device-key`. It MUST NOT expose a token,
secret, private claim, raw sender proof, or protected audit record.

A valid receipt publicly informs. It does not mute, hide, establish editorial
authority, or prove a private token failure by itself. A recipient MUST verify
the event signature, exact tag/body binding, offending event signature,
device-to-role delegation, and point-in-time persona resolution before showing
it as verified.

A false-positive correction is a signed `kind:1985` receipt from the correcting
policy authority with `L` namespace `network.heterodyne.agent-policy`,
`l` value `correction`, one `e` tag naming the original receipt, and one `p`
tag naming the device key. Its content MUST validate against
`docs/spec/schemas/social/agent-policy-correction-v1.schema.json`. A correction
does not restore visibility until the current canonical policy list also
removes the original binding.

<a id="social-lists"></a>
## 7. Personal lists, community policy, and web of trust

<!-- Monolith provenance: §3.8 private Social payloads and §8.5-§8.6/§8.10;
NIP-51 ownership corrected by ADR-033 requirement 9. -->

NIP-51 is an adopted upstream Social profile, not a Core or Comms construct.
Public NIP-51 items are tags. Private items are tag-shaped arrays encoded as a
JSON array, NIP-44-encrypted to self, and stored in `content`. New private
items MUST use NIP-44; legacy NIP-04 read-back MAY be detected by its `iv`
field. A client SHOULD preserve list order when appending.

<a id="social-mute-profile"></a>
### 7.1 Registered Social mute-list profile

Registry revision 3 defines `heterodyne-social-mute-list-v1` on upstream
replaceable `kind:10000`, with immutable discriminator
`tag:heterodyne=social-mute-list-v1`. A Social-profiled mute list MUST carry
exactly one of each profile tag:

```json
["heterodyne", "social-mute-list-v1"]
["spec_version", "social/0.5.0"]
```

The profile is stamping, so `social/0.5.0` is its sole owner stamp. Public
mute entries use upstream `p`, `t`, `word`, and `e` tags. Private entries keep
the upstream NIP-51 encrypted-content shape; the profile MUST NOT change that
shape. A client MUST verify the signer through Core and re-encrypt private
items under the new authoritative epoch key on the next list write after
rotation.

A plain upstream NIP-51 event without the exact Social discriminator MUST remain unstamped.
It is an interoperability input and MUST NOT be legacy-
inferred, stamped during ingestion, or represented as this Social profile.

<a id="social-agent-policy-list"></a>
### 7.2 Subscriber-local agent policy

Registry revision 3 defines the stamping
`heterodyne-social-agent-policy-list-v1` profile on NIP-51 replaceable
`kind:10000`, with the exact profile tags:

```text
["heterodyne", "social-agent-policy-list-v1"]
["spec_version", "social/0.5.0"]
```

For each adopted receipt, the list contains one upstream
`["p","<device-key>"]` mute, one `["e","<receipt-id>"]` reference, and one
closed binding:

```text
["agent_violation", "<device-key>", "<receipt-id>", "<reason-code>"]
```

The client MUST verify the receipt, exact `p`/`e`/`agent_violation` binding,
policy persona, current replaceable event, and canonical repository history
before the entry can affect visibility. A relay-only list candidate or
unmerged Radicle PR has no policy effect.

Only an explicitly subscribed policy list affects a client. An unsubscribed
receipt or list remains visible information and MUST NOT silently change
ranking or visibility. A reference client MAY ship a visible global
moderator-persona subscription enabled by default, but MUST identify that
source for each filtering decision and let the user inspect, disable, or
replace it. No moderator, registry entry, default client, repository, or relay
has global power.

Enforcement mutes exactly the listed device-publishing key. It MUST NOT mute
the persona, epoch key, human devices, hosting NID, or other agent-role keys.
Remediation replaces the offending role key at the same `agent:<role-id>`
address and finalizes that Core/Comms delegation. The old key MAY remain muted
indefinitely; the replacement key is evaluated independently. Epoch-key
rotation is neither required nor permitted as a substitute for the
device-scoped remediation.

Correction requires both a valid signed correction receipt and a current
canonical list revision removing the original binding. Either one alone leaves
the current subscribed mute unchanged.

<a id="social-sets"></a>
### 7.3 Sets and private configuration

Social supports upstream NIP-51 standard lists and addressable sets, including
follow sets `30000`, relay sets `30002`, bookmark sets `30003`, kind-mute sets
`30007` (whose `d` is the kind string), interest sets `30015`, and starter
packs `39089`. Sets MAY use upstream `title`, `image`, and `description` tags.
They remain unstamped unless a registry profile explicitly opts them in.

Every ordinary Social NIP-51 list or set uses a public dual-backend carrier:
it MUST be publishable to and served from both the persona's ordinary relays
and its repo relay. The repo relay MUST accept conforming NIP-51 events for a
repository it serves. Upstream private items remain NIP-44-encrypted to self
inside that same publishable event; ciphertext does not make the event or its
metadata private. This dual-backend rule MUST NOT imply Tier 2 delivery or a
private-repository allow list.

The persona SHOULD also commit each current list revision to its persona
repository. A reader MUST prefer the newest
verifiable replaceable/addressable revision and SHOULD detect an older relay
revision when canonical repo history proves a newer one. Data whose existence
or size must not be exposed even as ciphertext SHOULD be stored as a
Social-owned private payload in the encrypted config repository instead of a
NIP-51 event.

<a id="social-community-policy"></a>
### 7.4 Community policy lists

A policy persona MAY publish community block/allow policy using `kind:10000`,
`kind:30007`, and `kind:30000`. A community adopts it through `a` tags for
sets or `['p','<policy npub>','<relay hint>','policy']` in `kind:34550`.
Clients computing that community's view SHOULD apply adopted sources after
verifying their signatures and current KEL authority. A follower MAY subscribe
to additional policy personas independently.

Under Social+Matrix, a room MAY additionally use Matrix policy rooms and
`m.policy.rule.user`, `m.policy.rule.server`, and `m.policy.rule.room`.
Matrix-server policy has no Nostr equivalent and MUST NOT alter the verified
NIP-72 or Radicle editorial record.

<a id="social-admission-policy"></a>
### 7.5 Web-of-trust and the Comms acceptance hook

Social implements mute and web-of-trust admission only through
`heterodyne:comms/0.5.0#comms-acceptance-hook`. Authentication and all Comms
cryptographic checks run first. An explicit user decision is an input to a
fresh Comms hook evaluation, not a Social override: the client MUST first
recompute the Comms-native outcome with that locally authenticated decision,
then apply Social policy. Social MAY only preserve or tighten that recomputed
outcome using the user's mutes, follows, reply relationship, trust distance,
overmuted ratio, and explicitly accepted contacts. It MUST NOT bypass a
cryptographic check or loosen admission. Specifically, it may change
`accept` to `hold-as-message-request` or `reject`, and may change
`hold-as-message-request` to `reject`; `reject` is absorbing. No-op transitions
are allowed. It MUST NOT change `hold-as-message-request` to `accept` or
change `reject` to either other outcome.

<!-- fixture:social-acceptance-lattice -->
```json
{"accept":["accept","hold-as-message-request","reject"],"hold-as-message-request":["hold-as-message-request","reject"],"reject":["reject"]}
```

Before acceptance, `hold-as-message-request` emits no receipt, typing signal,
read marker, or other sender-observable response. A Social policy MUST preserve
that no-receipt rule. Muting a sender maps an otherwise acceptable ordinary DM
to `reject` or `hold-as-message-request`; it never authenticates a sender.

Web-of-trust ranking is local policy, not canonicality. A graph MAY be built
from verified `kind:3` follows, public Social mute profiles, and weighted
NIP-32 labels. It MUST NOT change whether a post is signed, indexed,
NIP-72-approved, or Radicle-editorially approved.

<a id="social-atproto"></a>
## 8. Optional ATProto attached outbox

<!-- Monolith provenance: §11.6.1-§11.6.9. -->

ATProto is an OPTIONAL decorative public outbox and witness surface. It is not
the persona identity, a required transport, or recovery authority. The npub,
accepted KEL, Core identity pointer, and Comms feed remain authoritative.
Private or audience-gated content MUST NOT mirror to ATProto. An ATProto
failure MUST NOT fail or roll back canonical Heterodyne publication.

<a id="social-atproto-resolution"></a>
### 8.1 DID resolution and SSRF protection

Implementations SHOULD support `did:web`; they MAY support `did:plc` but MUST
disclose its centralized directory. `did:key` may be a Core witness but has no
PDS service endpoint and MUST NOT be treated as an ATProto attached identity.

Every DID/PDS HTTPS request MUST reject RFC 1918, loopback, link-local,
wildcard, and otherwise non-public resolved addresses. A non-443 port MUST be
rejected unless the user explicitly allow-lists that host and port. At most
three redirects are RECOMMENDED, and every redirect MUST be independently
re-resolved and revalidated. A client MUST NOT follow a public-to-private or
443-to-unapproved-port redirect. It SHOULD warn when a DID's PDS endpoint
changes from the cached value.

<a id="social-atproto-binding"></a>
### 8.2 Bidirectional binding

The DID-side record MUST use ATProto collection
`social.heterodyne.identityLink` with record key `self`. Its `value` and the
Social-owned `kind:31009` `atproto_link` event's content cover the same
canonical compact JSON object:

```json
{"spec_version":"social/0.5.0","did":"<DID>","did_signing_key_id":"<key id>","npub":"<cold-root hex>","rid":"<canonical RID>","established_at":0}
```

`rid` is omitted only if no RID exists. Matrix identifiers MUST NOT appear in
the signed payload. The Nostr attestation MUST be signed by the currently
authoritative epoch key and include exactly one each of `d=<DID>`,
`heterodyne=atproto_link`, `cold_root=<npub>`, `did=<DID>`, `kel_head`, and
use the canonical payload above as its JSON `content`. The in-content
`spec_version` is the event's Social stamp; a duplicate version tag MUST NOT
be added. The DID signature MUST verify under the resolved key over SHA-256 of
the canonical payload. Both signatures MUST verify; a one-sided claim MUST be
rejected.

The executable fixture below uses a deterministic Ed25519 DID key. Its PDS
proof records `algorithm`, the resolved raw `public_key`, the lowercase-hex
SHA-256 `signed_payload_hash` of the exact compact payload bytes, and the
lowercase-hex signature over that 32-byte hash. Those proof members are outside
the PDS record `value`; the value remains byte-identical to the Nostr content.
A verifier MUST recompute the hash, require the resolved DID key and algorithm,
and cryptographically verify the proof rather than treating the fields as
non-empty markers.

Verification MUST begin from the PDS record and proceed through every binding:
resolve the DID and verify its named signing key and record signature; read the
payload's cold-root npub; verify that npub's current Core `kind:31005`; follow
its canonical RID and KEL; locate the current Social `kind:31009`; verify its
Nostr id, epoch-key signature, KEL authority, tags, and byte-exact payload; and
finally require the two payloads to be identical. No Matrix service is needed
for this procedure.

Under Social+Matrix, the binding MAY be mirrored in
`m.heterodyne.atproto_link.v1` with state key equal to the DID. Its sender MUST
equal `content.mxid`, and that MXID MUST have a current delegation for the
payload npub. The mirror MAY carry a Matrix identity-room locator, but it MUST
embed the byte-exact signed payload and both proof locators; it MUST NOT modify
the signed payload or become authoritative.

<!-- fixture:atproto-identity-link -->
```json
{
  "nostr_event": {
    "pubkey": "531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337",
    "created_at": 1710000000,
    "kind": 31009,
    "tags": [["d","did:web:alice.example"],["heterodyne","atproto_link"],["cold_root","531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337"],["did","did:web:alice.example"],["kel_head","5555555555555555555555555555555555555555555555555555555555555555","0"]],
    "content": "{\"spec_version\":\"social/0.5.0\",\"did\":\"did:web:alice.example\",\"did_signing_key_id\":\"did:web:alice.example#atproto\",\"npub\":\"531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337\",\"rid\":\"rad:zAlice\",\"established_at\":1710000000}",
    "id": "cd41c76501b0b7145c8dd115503473553e0e8a31c8e5849822aa7c87d19c6bf6",
    "sig": "a63775bd44e0b09a9400ed900aa13cdae9b239237056fe9b2bc87b24297af117d562a61f80a5d522680fc8d683b6ffa1f3d5e963a7c99635bdf0385ea80b03d5"
  },
  "pds_record": {
    "collection": "social.heterodyne.identityLink",
    "rkey": "self",
    "value": {"spec_version":"social/0.5.0","did":"did:web:alice.example","did_signing_key_id":"did:web:alice.example#atproto","npub":"531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337","rid":"rad:zAlice","established_at":1710000000},
    "algorithm": "Ed25519",
    "public_key": "ca93ac1705187071d67b83c7ff0efe8108e8ec4530575d7726879333dbdabe7c",
    "signed_payload_hash": "6adf242345b2ac833ec54689e1eb6607d84897a5a116ef00df447646c5c541a0",
    "signature": "83a5f27554ae5dcd20552e19894c6d0c87d5a0efc91b423d88cb6ded67d1763c20013b7dec15aea8e8bf577c3dccab4749227756441a608d20d979c2ddc1570b"
  },
  "matrix_mirror": {
    "type": "m.heterodyne.atproto_link.v1",
    "state_key": "did:web:alice.example",
    "sender": "@alice:matrix.example",
    "content": {"spec_version":"social/0.5.0","mxid":"@alice:matrix.example","did":"did:web:alice.example","did_signing_key_id":"did:web:alice.example#atproto","atproto_record_uri":"at://did:web:alice.example/social.heterodyne.identityLink/self","nostr_event_id":"cd41c76501b0b7145c8dd115503473553e0e8a31c8e5849822aa7c87d19c6bf6","binding_payload":"{\"spec_version\":\"social/0.5.0\",\"did\":\"did:web:alice.example\",\"did_signing_key_id\":\"did:web:alice.example#atproto\",\"npub\":\"531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337\",\"rid\":\"rad:zAlice\",\"established_at\":1710000000}","atproto_attestation":{"alg":"Ed25519","public_key":"ca93ac1705187071d67b83c7ff0efe8108e8ec4530575d7726879333dbdabe7c","sig":"83a5f27554ae5dcd20552e19894c6d0c87d5a0efc91b423d88cb6ded67d1763c20013b7dec15aea8e8bf577c3dccab4749227756441a608d20d979c2ddc1570b","signed_payload_hash":"6adf242345b2ac833ec54689e1eb6607d84897a5a116ef00df447646c5c541a0"},"established_at":1710000000,"revoked_at":null}
  }
}
```

Either identity may revoke unilaterally. The persona publishes an
epoch-key-signed `kind:31009` with `heterodyne=atproto_link_revocation`,
`d=<DID>`, `did`, `cold_root`, and `kel_head`; the closed ordered content has
`spec_version`, `record_type=atproto_link_revocation`, `did`, `npub`,
`binding_hash` (SHA-256 of the binding payload), and integer `revoked_at`. The
DID owner publishes the same revocation value, signed by the current DID key,
to `social.heterodyne.identityLink/self`. Either independently verified
revocation supersedes the binding at `revoked_at`; establishing a link still
requires both signatures.

Under Social+Matrix a revocation MAY be mirrored by updating the same
`m.heterodyne.atproto_link.v1` DID state with non-null `revoked_at`. The sender
MUST equal `content.mxid` and be currently delegated for the binding npub; the
mirror MUST identify the verified Nostr event or ATProto record that caused
the revocation and is never authoritative by itself.

<!-- fixture:atproto-link-revocations -->
```json
{
  "nostr": {
    "pubkey": "531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337",
    "created_at": 1710000100,
    "kind": 31009,
    "tags": [["d","did:web:alice.example"],["heterodyne","atproto_link_revocation"],["did","did:web:alice.example"],["cold_root","531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337"],["kel_head","5555555555555555555555555555555555555555555555555555555555555555","0"]],
    "content": "{\"spec_version\":\"social/0.5.0\",\"record_type\":\"atproto_link_revocation\",\"did\":\"did:web:alice.example\",\"npub\":\"531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337\",\"binding_hash\":\"6adf242345b2ac833ec54689e1eb6607d84897a5a116ef00df447646c5c541a0\",\"revoked_at\":1710000100}",
    "sig": "66666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666"
  },
  "atproto": {
    "collection": "social.heterodyne.identityLink",
    "rkey": "self",
    "value": {"spec_version":"social/0.5.0","record_type":"atproto_link_revocation","did":"did:web:alice.example","npub":"531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337","binding_hash":"6adf242345b2ac833ec54689e1eb6607d84897a5a116ef00df447646c5c541a0","revoked_at":1710000100},
    "signature": "did-revocation-signature-base64url"
  },
  "matrix": {
    "type": "m.heterodyne.atproto_link.v1",
    "state_key": "did:web:alice.example",
    "sender": "@alice:matrix.example",
    "content": {"spec_version":"social/0.5.0","mxid":"@alice:matrix.example","did":"did:web:alice.example","npub":"531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337","binding_hash":"6adf242345b2ac833ec54689e1eb6607d84897a5a116ef00df447646c5c541a0","revocation_source":"nostr","revoked_at":1710000100,"nostr_revocation_event_id":"7777777777777777777777777777777777777777777777777777777777777777"}
  }
}
```

Successful DID, PDS, binding, and revocation verification SHOULD be cached for
at most one hour. A changed `kind:31005`, KEL head, DID document, PDS record,
or observed revocation MUST invalidate the relevant cache immediately. Any
signature or binding failure MUST invalidate the cached success rather than
extending its TTL.

<a id="social-atproto-mirror"></a>
### 8.3 Mirror publication and witnessing

Mirroring defaults off. An explicit configuration MUST allow-list source
public feeds, Nostr kinds, and either `truncate_with_link` or `full_or_skip`.
Only Tier 1 public material may mirror. The client first completes canonical
Comms publication and index update, then best-effort publishes the adapted PDS
record with a canonical Nostr event-id reference. It SHOULD avoid aggressive
retry.

A verified DID key MAY sign a Core KERI ceremony as an additive witness. It
MUST NOT satisfy a controller-signature requirement or replace the declared
Core witness threshold. A verifier MAY ignore it without losing Social
conformance. A displayed ATProto handle MUST remain marked unverified until
both halves of the binding verify.

<a id="social-matrix-identity"></a>
## 9. Optional Matrix identity and MXID delegation

<!-- Monolith provenance: §3.2 Matrix path, §3.3.2-§3.3.3, §3.6 Matrix path. -->

Sections 9-12 are one OPTIONAL feature. A Social-only implementation omits
them completely and remains fully conformant.

<a id="social-identity-room"></a>
### 9.1 Identity room and root mirror

The Matrix identity room is an optional, intentionally peekable container. It
SHOULD contain `m.heterodyne.room_kind.v1` with `identity_room`, one
`m.heterodyne.root.v1`, zero or more delegation and KEL mirrors, and at most
one public-outbox mirror. Audience-restricted state MUST NOT be placed there.
The current verified Core identity pointer is authoritative over any cached
room id, and a verifier MUST discard an older container pointer.

The root mirror wraps Core `kind:31000`. Its Matrix content carries
`spec_version: social/0.5.0`; the embedded empty-content Nostr event carries
the Core stamp `core/0.5.0`, empty `d`, `heterodyne=root`, the exact bare room
id in `matrix_room`, `cold_root`, and exactly one `kel_head`. A verifier MUST
hash exact `nip01_raw`, verify BIP-340 and current epoch authority, require the
cold root to equal the persona npub, and require `created_at` within a strict
plus-or-minus five-minute window at verification. The freshness window applies
only to this root mirror and MUST NOT be copied to delegations, KEL events,
indexes, or posts. Conflicting resolved roots with different cold-root npubs
make the room invalid for delegation verification.

An MXID may locate the room through ordinary Matrix profile/discovery data,
but a verifier MUST corroborate it against the latest valid Core identity
pointer before trusting any mirrored state. If Matrix profile or room-mirror
lookup fails, the verifier MUST fall back to the persona's current cold-root
`kind:31005` identity pointer rather than treating the persona as unresolved.

<a id="social-mxid-delegation"></a>
### 9.2 MXID delegation

An MXID delegation uses the Core-owned `kind:31001` base schema embedded in
an `m.heterodyne.delegation.v1` identity-room state event. The embedded event
MUST be epoch-key signed, carry exactly one `kel_head`, use
`d=mxid:<exact MXID>`, `heterodyne=delegation`, `matrix_mxid=<exact MXID>`,
`cold_root=<npub>`, `valid_until`, and the Core base-schema stamp
`core/0.5.0`. Social does not override that wire owner.

An MXID delegation is active if and only if:

1. the embedded NIP-01 bytes, id, epoch-key signature, Core KEL authority,
   compromise window, `kel_head`, and key-material finality all verify;
2. the Matrix state sender exactly equals its MXID state key, proving
   self-publication through Matrix state authorization;
3. `matrix_mxid` and `d` exactly bind that same state key;
4. `valid_until` is empty or a valid future decimal Unix time, with only a
   declared bounded clock allowance;
5. no effective `m.heterodyne.delegation_revoked.v1` exists; and
6. the epoch remains authoritative at the evaluation time.

Thus MXID delegation requires both the persona epoch-key proof and MXID
self-publication. A homeserver cannot forge the persona proof. Relay- or
room-only key material is provisional under Core; a `deny-until-repo` client
MUST NOT honor it before canonical repo inclusion.

A Matrix identity room is an optional discovery/cache surface. Its root,
delegation, KEL, outbox, and ATProto state MUST NOT override the accepted KEL,
the cold-root `kind:31005`, or Core repository authority.

<a id="social-matrix-coordination"></a>
## 10. Optional Matrix coordination, configuration, and exit

<!-- Monolith provenance: §3.8.1-§3.8.5, §3.9.1-§3.9.7,
§3.10.1-§3.10.6, §3.11.2-§3.11.5. -->

<a id="social-config-room"></a>
### 10.1 Encrypted config room and Social mirrors

Each delegated MXID that uses this feature has one invite-only
`config_room`. It MUST use room version 11, Megolm or the migrated MLS
algorithm, guest access forbidden, history visibility shared, and only
currently delegated MXIDs of the same persona as members. Every event,
including every state event, MUST be encrypted client-side. The Matrix profile
SHOULD advertise the room by a `matrix:` URI in
`m.heterodyne.config_room`.

The room MAY mirror these Social-owned records:

- `m.heterodyne.user_prefs.v1`: UI, notification, language, feed-density, and
  bare-message display preferences;
- `m.heterodyne.persona_config.v1`, keyed by npub: private mutes, feed
  preferences, subscribed outboxes, default audience, followed-repository
  state, and identity-room cache;
- `m.heterodyne.key_backup.v1`: an additional wrapped-nsec backup; and
- `m.heterodyne.device_inventory.v1`: per-room bookkeeping only.

Every content object MUST carry `spec_version: social/0.5.0`. Unknown fields
in preference records MUST be tolerated. The authoritative non-Matrix records
remain the Social list/private payloads stored through Core/Comms; Matrix is a
mirror. `key_backup` MUST remain wrapped under a user-controlled secret with a
memory-hard KDF even inside E2EE, and clients SHOULD allow it to be excluded
from cross-MXID synchronization. Matrix-native cross-signing, Megolm session
backup, and recovery keys remain standard Matrix responsibilities.

Mutually delegated MXIDs SHOULD synchronize user preferences, persona config,
and the wrapped backup through ordinary encrypted Matrix state replication.
They MUST NOT synchronize device inventory. A higher explicit monotonic
`revision` wins; equal/absent revisions fall back to `origin_server_ts`, then
lexicographically smallest event id. Config state MUST NOT be placed in the
identity room or broadcast to relays. Unreachable config state falls back to
safe defaults with a visible warning.

<a id="social-active-room-election"></a>
### 10.2 Active-room election, publish lease, and failover

Every delegated MXID MUST create its config room on first publish and invite
all other delegated MXIDs, sharing history. Existing rooms MUST invite a newly
observed delegated MXID within 60 seconds. Transient asymmetric membership
MUST NOT stop convergence.

`m.heterodyne.active_config_room.v1` has empty state key and exactly
`active_room_id`, `active_room_homeserver`, integer `elected_at`, and UUIDv4
`election_id`. It MUST be written into every config room. Receivers choose
greatest `elected_at`, then lexicographically smallest `election_id`. The room
with the earliest observed create timestamp is bootstrap-active, and even a
single-MXID persona MUST publish the pointer.

`m.heterodyne.publish_lease.v1` lives only in the active room and contains
`holder_mxid`, `expires_at`, and fresh UUIDv4 `lease_id`. A device MUST acquire
it before signing a publishable event. TTL is 60 seconds and renewal at 30
seconds is RECOMMENDED. Concurrent writes use Matrix state ordering.

A nonactive device MAY elect another room when the active delegation is
revoked, sync receives 5xx/unreachable errors for more than 30 seconds, or the
room is tombstoned. It MUST create a fresh lease after election. A readable
room that remains unwritable for five cumulative minutes across three retry
windows MUST receive an active-room
`m.heterodyne.config_room_tombstone.v1`; it is ineligible until `expires_at`
(default one hour), except when every alternative is unavailable.

During a federation partition, losing-room leases become void after election
converges. Events signed under them MUST be requeued and republished using the
same Nostr event id as the Matrix transaction id; readers deduplicate by id.

<a id="social-mxid-revocation"></a>
### 10.3 Single-MXID revocation

Selective revocation requires both a NIP-09 `kind:5` targeting the embedded
delegation and `m.heterodyne.delegation_revoked.v1` in the identity room. The
state embeds an epoch-key-signed revocation binding `revoked_mxid`,
`effective_at`, the deleted delegation id, and optional reason. `effective_at`
MUST be no earlier than attestation `created_at`; a verifier MUST clamp it to
at least observation time plus its declared clock-skew policy, reject unsigned
or mismatched records, and distrust Matrix events at or after the effective
time.

Other delegated MXIDs MUST remove the revoked MXID from their config rooms
within 60 seconds. If it held the lease, a remaining device MUST trigger
failover. A later KEL rotation deactivates every delegation signed by the old
epoch independently of this selective process. Affected private-discussion
rooms SHOULD rotate Megolm sessions to exclude extracted old keys.

<a id="social-homeserver-exit"></a>
### 10.4 Voluntary homeserver exit

Voluntary identity-room exit preserves the same npub and KEL. In order, the
persona MUST create a room-version-11 identity room at the target; republish
current root/delegation/KEL/outbox state; publish a fresh cold-root-signed
`kind:31005` with the new Matrix locator while retaining the same RID; publish
`m.heterodyne.identity_room_migrated.v1` in the old room; and dual-publish
state for a RECOMMENDED seven-day cache-expiry overlap before retiring the old
room. The UI MUST warn that updating the Matrix locator requires the rare
cold-root signing operation and SHOULD prompt immediate resecuring.

A follower MUST verify the new locator against the cold-root pointer, switch
lookups after `migrated_at`, and log disagreement; the cold-root pointer wins.
Config-room movement uses the election machinery above. Private room history
and Megolm sessions do not migrate automatically: users MUST recreate rooms,
reinvite members, and receive a warning. A KEL rotation MAY coincide with
exit, but the rotation MUST be published into both identity rooms during the
overlap. Before retiring an MXID during exit, the client SHOULD tombstone that
MXID's config room through `m.heterodyne.config_room_tombstone.v1`, elect a
surviving room, and only then revoke or retire the MXID.

<a id="social-matrix-mirroring"></a>
### 10.5 Matrix room mirroring and promotion

A Social+Matrix persona MAY maintain warm identity/discussion-room replicas.
`m.heterodyne.mirror_group.v1` is keyed by the logical family and records room
kind, primary, replica ids, optional feed-index address, and update time. It
MUST be copied into every identity replica so discovery is not circular.
Identity primary MUST match the current cold-root pointer; a feed primary MUST
match the verified feed descriptor. Followers MUST deduplicate replicas by
Nostr event id and MAY read standby replicas with stale-cache handling.

Private post bodies MUST NOT be duplicated into room replicas; only Matrix
state/session material and room-local interaction may mirror. Removal SHOULD
rotate the room session; join SHOULD preserve the current session when the
Matrix SDK permits. Promotion is explicit: choose a healthy replica, republish
the authoritative pointer/index, update the mirror group, and warn if identity
promotion unseals the cold root. It MUST NOT be automatic.

<a id="social-matrix-envelopes"></a>
## 11. Optional Matrix envelopes and discussion rooms

<!-- Monolith provenance: §4.1-§4.5 Matrix entry point, §5.1/§5.4-§5.5,
§6.5/§6.8 Matrix interaction. -->

Matrix timeline traffic has two envelope forms. A wrapped
`m.heterodyne.note.v1` embeds a complete Nostr event plus exact `nip01_raw`;
a bare `m.room.message` or `m.reaction` uses normal Matrix rendering and MAY
carry an authenticity badge. Neither changes the Comms event or Core identity
rules.

<a id="social-wrapped-envelope"></a>
### 11.1 Wrapped envelope

```json
{
  "type": "m.heterodyne.note.v1",
  "content": {
    "spec_version": "social/0.5.0",
    "nip01_raw": "[0,\"<epoch key>\",0,1,[],\"hello\"]",
    "nostr": {
      "id": "<sha256>", "pubkey": "<epoch key>", "created_at": 0,
      "kind": 1, "tags": [], "content": "hello", "sig": "<BIP-340>"
    },
    "fallback": {"msgtype": "m.text", "body": "hello"}
  }
}
```

The receiver MUST hash `nip01_raw`, compare the id and every parsed field,
verify BIP-340, verify Core KEL authority and finality, and verify an active
MXID delegation at the embedded event's `created_at`. Any mismatch is
rejection. The embedded event MUST be byte-identical to the event that could
be sent over an ordinary relay. `fallback` is OPTIONAL but RECOMMENDED for
kind 1; a Social+Matrix client MUST render verified Nostr data, not trust the
fallback.

<a id="social-bare-envelope"></a>
### 11.2 Bare envelope and attribution

A bare event is a normal `m.room.message` or `m.reaction`. It is attributable
through MXID delegation but has no transferable Nostr proof. It SHOULD contain
`heterodyne_persona`; that selector is REQUIRED when the MXID has more than one
possible persona and the room context does not select exactly one.

A bare message MAY carry `heterodyne_nostr_sig`, an upstream Nostr proof whose
content equals the Matrix body byte-for-byte after Unicode NFC normalization.
A receiver MUST verify the embedded event and selected persona. Success earns
an authenticated indicator. Failure MUST retain the vanilla body with an
explicit invalid-signature warning. A later delegation revocation MUST NOT
retroactively de-attribute an event valid at its own DAG position.

Unknown Heterodyne Matrix event types MUST render as a safe placeholder. A
receiver first applies Matrix SDK integrity, then branches on wrapped or bare,
then applies exact Nostr/Core checks. It MUST NOT infer a verified identity
from the Matrix sender alone.

<a id="social-discussion-rooms"></a>
### 11.3 Room kinds

Every managed Matrix room MUST have empty-state-key
`m.heterodyne.room_kind.v1` with `spec_version: social/0.5.0`, a current kind,
and optional namespaced topics. New rooms use exactly `identity_room`,
`config_room`, `public_discussion`, or `private_discussion`. The
pre-0.4/v0.3-era kinds
MAY be mapped for read-back with a visible legacy marker, but MUST NOT be
produced.

`public_discussion` is an intentionally unencrypted many-party room. It MUST
use Matrix room version 11, have no encryption state, use `world_readable` or
`shared` history, and set guest access explicitly. Bare messages are default.
A moderator carrier turns it into a Matrix-hosted NIP-72 community. Its power
levels SHOULD use users/events default 0, state default 50 or 100, moderators
50, and owner 100.

`private_discussion` is invite/restricted E2EE for groups or the optional
Matrix two-party surface. It MUST use room version 11,
`m.megolm.v1.aes-sha2` until migrated to MLS, `shared` or `invited` history,
guest access forbidden, and invite or restricted join rules. Every event,
including state, MUST be encrypted. Bare messages are default and remain
attributable; the protocol claims pseudonymity, not deniability.
Its power levels SHOULD use users/events default 0, state default 50 or 100,
and owner 100. A client SHOULD warn before inviting a user whose clients have
not demonstrated Heterodyne Matrix support; this is not a hard rejection.

A Social client SHOULD support these room kinds for real-time communication.
A Matrix-free client instead uses complete async Social interaction and does
not lose Social conformance.

<a id="social-matrix-encryption"></a>
## 12. Optional Matrix encryption, bridge, and interoperability

<!-- Monolith provenance: §9.1.1-§9.4, §9.6 Matrix mirror, §10.3-§10.4,
§11.1/§11.5. -->

<a id="social-encrypted-state"></a>
### 12.1 Encrypted state and downgrade resistance

In a `private_discussion` or `config_room`, every timeline and state event MUST
be end-to-end encrypted. Heterodyne state content is encrypted client-side and
sent through the standard Matrix state endpoint as opaque JSON; a homeserver
needs no custom support. A plaintext `m.heterodyne.*` state event in either
room is a state downgrade attack: it MUST be invalid, MUST NOT participate in
authoritative Social state, SHOULD be security-logged, and MUST NOT be shown
without a prominent potentially-forged warning naming the sender.

Removing an MXID SHOULD start a fresh Megolm session for remaining members.
KERI epoch rotation alone does not require Megolm rotation because the Matrix
device/session membership is unchanged.

Every Heterodyne E2EE Matrix room MUST declare its logical encryption version
with empty-state-key `m.heterodyne.encryption_version.v1`. Its initial closed
content schema is `spec_version`, `algorithm: "megolm"`, `migrated_from:
null`, and `migrated_at: null`, in that order:

<!-- fixture:matrix-encryption-megolm -->
```json
{
  "type": "m.heterodyne.encryption_version.v1",
  "state_key": "",
  "sender": "@alice:matrix.example",
  "origin_server_ts": 1710000000000,
  "content": {"spec_version":"social/0.5.0","algorithm":"megolm","migrated_from":null,"migrated_at":null}
}
```

If that state is absent but `m.room.encryption.algorithm` is
`m.megolm.v1.aes-sha2`, a client MUST infer the exact baseline state above and
SHOULD publish it on its next send to the room. A conflicting downgrade or an
unknown logical algorithm MUST NOT be silently inferred as Megolm.

<a id="social-megolm-mls"></a>
### 12.2 Megolm-to-MLS migration

Baseline Social+Matrix capability MUST advertise Megolm. A client claiming
MLS MUST advertise it. The encrypted, scoped Matrix carrier is
`m.heterodyne.capabilities.v1`, state-keyed by its publishing MXID; the sender
MUST equal that state key. Its content MUST begin with the mandatory
`heterodyne:core/0.5.0#core-capabilities` bootstrap object. Core support,
descriptor, bootstrap version, registry revision, supported document set,
required features, and strict profiles are mandatory. Social+Matrix adds only
safely ignorable extension members after that bootstrap. An extension MUST NOT
replace, rename, or reinterpret any Core bootstrap member.

The carrier MUST be published on the first Heterodyne interaction in a shared
private room, updated when the advertised set changes, and omitted from a
public identity room unless the user opts in. The migration gate reads the
extension members `encryption_algorithms_supported` and `advertised_at`; it
still MUST reject an advertisement whose Core bootstrap is invalid.

<!-- fixture:matrix-mls-capabilities -->
```json
{
  "type": "m.heterodyne.capabilities.v1",
  "state_key": "@alice:matrix.example",
  "sender": "@alice:matrix.example",
  "origin_server_ts": 1710000000000,
  "content": {"descriptor":"heterodyne-capabilities-v1","bootstrap_version":"core/0.5.0","registry_revision":2,"supported_versions":{"core":["core/0.5.0"],"comms":["comms/0.5.0"],"control":[],"social":["social/0.5.0"]},"required_features":["core.identity.v1","core.repo-relay-client.v1","core.embedded-tor.v1"],"strict_profiles":[],"backends":["nostr_relay","repo_relay"],"node_roles":["light"],"matrix":true,"event_types":["m.heterodyne.encryption_version.v1","m.heterodyne.migration_intent.v1","m.heterodyne.migration_ack.v1","m.heterodyne.migration_abort.v1"],"nostr_kinds":[31004,31009],"encryption_algorithms_supported":["megolm","mls"],"advertised_at":1710000000}
}
```

Migration MUST NOT begin until every current joined member has a most-recent,
signature- and delegation-verified capability advertisement no more than 30
days old that includes `mls`. The initiator MUST be the currently delegated
moderator with the highest Matrix power level; a tie selects the
lexicographically smallest persona npub. The selected initiator's sending MXID
and npub MUST match the intent.

The initiator publishes encrypted state
`m.heterodyne.migration_intent.v1`, state-keyed by a UUIDv4 `intent_id`, under
the current Megolm session. Its closed ordered content is:

<!-- fixture:matrix-mls-intent -->
```json
{
  "type": "m.heterodyne.migration_intent.v1",
  "state_key": "123e4567-e89b-42d3-a456-426614174000",
  "sender": "@alice:matrix.example",
  "origin_server_ts": 1710000000000,
  "content": {"spec_version":"social/0.5.0","target_algorithm":"mls","drain_window_seconds":60,"intent_id":"123e4567-e89b-42d3-a456-426614174000","initiator_mxid":"@alice:matrix.example","initiator_npub":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
}
```

Every current member MUST ACK within the 60-second drain window. An ACK is
encrypted `m.heterodyne.migration_ack.v1` state with key
`<intent_id>:<member_npub>`; its sender MUST be a joined MXID currently
delegated for `member_npub`, and `acked_at` MUST fall within the window:

<!-- fixture:matrix-mls-ack -->
```json
{
  "type": "m.heterodyne.migration_ack.v1",
  "state_key": "123e4567-e89b-42d3-a456-426614174000:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "sender": "@bob:matrix.example",
  "origin_server_ts": 1710000030000,
  "content": {"spec_version":"social/0.5.0","intent_id":"123e4567-e89b-42d3-a456-426614174000","member_npub":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","acked_at":1710000030}
}
```

Members SHOULD NOT originate new timeline traffic during drain; in-flight
Megolm events created before the intent may complete. At expiry, any missing or
invalid ACK requires the initiator to publish encrypted
`m.heterodyne.migration_abort.v1`, state-keyed by the intent id, with the exact
missing npubs. The room remains on Megolm, and no retry may begin for 24 hours:

<!-- fixture:matrix-mls-abort -->
```json
{
  "type": "m.heterodyne.migration_abort.v1",
  "state_key": "123e4567-e89b-42d3-a456-426614174000",
  "sender": "@alice:matrix.example",
  "origin_server_ts": 1710000060000,
  "content": {"spec_version":"social/0.5.0","intent_id":"123e4567-e89b-42d3-a456-426614174000","reason":"missing_acks","missing_npubs":["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],"aborted_at":1710000060}
}
```

With all ACKs, the initiator MUST publish the flip as empty-state-key
`m.heterodyne.encryption_version.v1`, itself encrypted under the last Megolm
session. `migrated_at` is integer Unix seconds and MUST correspond to the
event's Matrix `origin_server_ts` in milliseconds:

<!-- fixture:matrix-mls-flip -->
```json
{
  "type": "m.heterodyne.encryption_version.v1",
  "state_key": "",
  "sender": "@alice:matrix.example",
  "origin_server_ts": 1710000060000,
  "content": {"spec_version":"social/0.5.0","algorithm":"mls","migrated_from":"megolm","migrated_at":1710000060,"intent_id":"123e4567-e89b-42d3-a456-426614174000"}
}
```

The flip is receiver-verifiable, not atomic. Events with
`origin_server_ts` at or before the flip are Megolm; later events are MLS,
subject only to the tail exception below. An offline sender MUST reread current
encryption state before publish and re-encrypt queued plaintext with fresh MLS
state, reusing the original Nostr id as Matrix transaction id. It MUST NOT send
queued Megolm ciphertext. A sender without MLS MUST fail the queued send
visibly. If the same event was already published through a Comms backend while
the member was offline, Matrix-side re-encryption still proceeds and the Comms
asymmetric-delivery and deduplication rules remain applicable.

A receiver that has observed the flip may accept a lagging Megolm event only
when all three conditions hold: its `origin_server_ts` is no more than 60
seconds after the flip; it references a Megolm session key the receiver
obtained before the flip; and its sender MXID was joined at the flip according
to pre-flip `m.room.member` state. Missing provenance or membership is
rejection. After the 60-second tail, every Megolm event MUST be rejected.

The first MLS commit SHOULD carry the Megolm session export, encrypted as
opaque `app_data.megolm_session_export`, for pre-flip history continuity. A
non-MLS client encountering the flip MUST stop accepting new room traffic,
retain readable pre-flip and valid-tail history, and display an MLS-upgrade
warning. MLS-to-Megolm rollback is FORBIDDEN in this release. An abort or
expired intent never changes the algorithm; repeated aborts SHOULD warn
moderators that members are not upgrading.

<a id="social-headless-bridge"></a>
### 12.3 Client-side bridge and homeserver boundary

A personal headless bridge MAY maintain Matrix presence, mirror public Social
content to configured destinations, and host archive endpoints. It is a
normal user-controlled client inside the user's trust boundary. Cross-protocol
Social bridging MUST run only on user-controlled clients; it MUST NOT require
a relay-side or homeserver-side bridge that receives protected plaintext.

A vanilla Matrix homeserver is sufficient. A homeserver MUST NOT be expected
to parse Heterodyne content, verify npubs/KELs, enforce Social policy, or see
E2EE plaintext. It MAY reject traffic under its ordinary policy. Users respond
by moving accounts/rooms through the exit procedures rather than requiring a
server extension.

<a id="social-vanilla-matrix"></a>
### 12.4 Vanilla Matrix and fallback rendering

A vanilla Matrix client sees `public_discussion` as an ordinary unencrypted
room and `private_discussion` as an ordinary Megolm/MLS room when it supports
the selected algorithm. It renders bare messages and ignores unknown Social
fields. It cannot interpret encrypted Heterodyne state or wrapped-only events.

A wrapped kind-1 event SHOULD contain an `m.text` fallback; kind 30023 MAY use
an excerpt; nontext events SHOULD omit misleading fallback. Before sending an
event invisible to known vanilla members, a Social+Matrix client SHOULD warn
the user. A Social client encountering a bare message MUST render it with an
unauthenticated-message indicator and SHOULD offer `never`, `unsigned_only`,
and `per_room` display policies. A room cannot enforce wrapped admission;
moderation may omit or remove an event from a curated view but MUST NOT claim
that the Matrix wire rejected it.

<a id="social-security"></a>
## 13. Security invariants

<!-- Monolith provenance: §9 Social/Matrix portions and §13 mixed invariants;
namespaced by ADR-033. -->

Registry revision 3 binds these exact Social invariants:

- **SOCIAL-I-MATRIX-E2EE:** Private Matrix discussion and configuration content, including protected state, remains end-to-end encrypted and downgrade-resistant from the homeserver.
- **SOCIAL-I-MXID-DELEGATION-DUAL-PROOF:** A Matrix MXID delegation requires both the persona epoch-key signature and successful MXID self-publication through Matrix state authorization.
- **SOCIAL-I-PRIVATE-STATE-AT-REST:** Private mute, feed-preference, followed-repository, and other Social state are encrypted at rest using the owning Social or bound Comms profile.
- **SOCIAL-I-CLIENT-SIDE-MATRIX-BRIDGE:** Matrix and cross-protocol Social bridging runs on user-controlled clients; no homeserver or relay bridge receives protected plaintext.
- **SOCIAL-I-NO-CENTRAL-SOCIAL-GRAPH:** Following, transitive discovery, and social-graph evaluation do not depend on a centralized follow-graph oracle.
- **SOCIAL-I-AGENT-POLICY-LOCAL:** Agent-policy receipts inform publicly, but only an explicitly subscribed and verified current policy list changes a client's local visibility.
- **SOCIAL-I-AGENT-REMEDIATION-SCOPED:** Agent-policy enforcement and remediation target only the offending role device key; replacement at the same role address never requires epoch-key rotation.

The mechanism boundaries MUST remain honest. Tier 2 and Tier 3 guarantees
come from Comms, not Matrix. A Matrix private room uses its Megolm/MLS session;
a bare Matrix event is attributed but not a transferable Nostr proof. Social
ranking is advisory and never identity or editorial authority. ATProto is an
attached public outbox and optional witness, never persona authority.

<a id="social-strict-profiles"></a>
### 13.1 Social strict profiles

The Matrix-free Social strict profile composes the Core, Comms, and applicable
Social invariant sets. Matrix-only invariants are not applicable until Matrix
is advertised, so they are added by the separate Social+Matrix profile.

<!-- fixture:social-strict-profile -->
```json
{
  "profile_id": "heterodyne-social-strict-v1",
  "conformance_class": "Social",
  "state": "active",
  "requires_profiles": [
    "heterodyne-core-strict-v1",
    "heterodyne-comms-strict-v1"
  ],
  "required_invariants": [
    "CORE-I-IDENTITY-INTEGRITY",
    "CORE-I-NID-DELEGATION-DUAL-PROOF",
    "CORE-I-VERIFY-BEFORE-USE",
    "CORE-I-NO-CENTRAL-IDENTITY-DIRECTORY",
    "CORE-I-KEY-MATERIAL-AT-REST",
    "COMMS-I-TIER3-BLIND-CARRIER",
    "COMMS-I-TIER2-HONESTY",
    "COMMS-I-CONFIG-AT-REST",
    "COMMS-I-CLIENT-SIDE-DELIVERY",
    "COMMS-I-NO-CENTRAL-DELIVERY-DIRECTORY",
    "COMMS-I-CLAIM-AUTHENTICITY",
    "COMMS-I-CLAIM-ATTENUATION",
    "COMMS-I-CLAIM-REPOSITORY-AUTHORITY",
    "COMMS-I-CLAIM-REVOCATION",
    "COMMS-I-LEDGER-CONFINEMENT",
    "COMMS-I-ISSUER-KEY-CONFINEMENT",
    "COMMS-I-MINT-FRESHNESS",
    "COMMS-I-ISSUER-CONTINUITY",
    "COMMS-I-CLAIM-RELEASE",
    "COMMS-I-JWT-TYPE-AUDIENCE",
    "COMMS-I-STATUS-INTEGRITY",
    "SOCIAL-I-PRIVATE-STATE-AT-REST",
    "SOCIAL-I-NO-CENTRAL-SOCIAL-GRAPH"
  ]
}
```

This profile additionally requires a valid signed event to pass baseline
verification before Social policy, observation of a valid `kind:5` deletion
within 30 seconds on an active source, and a visible warning when a previously
met strict requirement becomes unmet. It does not require Matrix.

`heterodyne-social-matrix-strict-v1` has the exact conformance class
`Social+Matrix`. It composes the Matrix-free Social strict profile and adds all
Matrix-specific Social invariants and obligations:

<!-- fixture:social-matrix-strict-profile -->
```json
{
  "profile_id": "heterodyne-social-matrix-strict-v1",
  "conformance_class": "Social+Matrix",
  "state": "active",
  "requires_profiles": ["heterodyne-social-strict-v1"],
  "required_invariants": [
    "CORE-I-IDENTITY-INTEGRITY",
    "CORE-I-NID-DELEGATION-DUAL-PROOF",
    "CORE-I-VERIFY-BEFORE-USE",
    "CORE-I-NO-CENTRAL-IDENTITY-DIRECTORY",
    "CORE-I-KEY-MATERIAL-AT-REST",
    "COMMS-I-TIER3-BLIND-CARRIER",
    "COMMS-I-TIER2-HONESTY",
    "COMMS-I-CONFIG-AT-REST",
    "COMMS-I-CLIENT-SIDE-DELIVERY",
    "COMMS-I-NO-CENTRAL-DELIVERY-DIRECTORY",
    "COMMS-I-CLAIM-AUTHENTICITY",
    "COMMS-I-CLAIM-ATTENUATION",
    "COMMS-I-CLAIM-REPOSITORY-AUTHORITY",
    "COMMS-I-CLAIM-REVOCATION",
    "COMMS-I-LEDGER-CONFINEMENT",
    "COMMS-I-ISSUER-KEY-CONFINEMENT",
    "COMMS-I-MINT-FRESHNESS",
    "COMMS-I-ISSUER-CONTINUITY",
    "COMMS-I-CLAIM-RELEASE",
    "COMMS-I-JWT-TYPE-AUDIENCE",
    "COMMS-I-STATUS-INTEGRITY",
    "SOCIAL-I-PRIVATE-STATE-AT-REST",
    "SOCIAL-I-NO-CENTRAL-SOCIAL-GRAPH",
    "SOCIAL-I-MATRIX-E2EE",
    "SOCIAL-I-MXID-DELEGATION-DUAL-PROOF",
    "SOCIAL-I-CLIENT-SIDE-MATRIX-BRIDGE"
  ],
  "matrix_obligations": [
    "encrypted-private-content-and-state",
    "mxid-dual-proof",
    "downgrade-warning",
    "bare-message-visibility"
  ]
}
```

The Matrix profile requires private content and protected state encryption,
MXID dual proof, a visible downgrade warning, and rendering of a valid bare
message with its unauthenticated indicator rather than hiding it solely for
being bare. Capability advertisements MUST include every prerequisite profile
actually met and MUST omit either Social profile when any corresponding
invariant, obligation, feature, or vector is unmet.

The revision-3 agent-policy invariants require new profile IDs. Both v1
declarations above remain unchanged.

<!-- fixture:social-strict-profile-v2 -->
```json
{
  "profile_id": "heterodyne-social-strict-v2",
  "conformance_class": "Social",
  "state": "active",
  "requires_profiles": ["heterodyne-comms-strict-v2"],
  "required_invariants": [
    "CORE-I-IDENTITY-INTEGRITY",
    "CORE-I-NID-DELEGATION-DUAL-PROOF",
    "CORE-I-VERIFY-BEFORE-USE",
    "CORE-I-NO-CENTRAL-IDENTITY-DIRECTORY",
    "CORE-I-KEY-MATERIAL-AT-REST",
    "COMMS-I-TIER3-BLIND-CARRIER",
    "COMMS-I-TIER2-HONESTY",
    "COMMS-I-CONFIG-AT-REST",
    "COMMS-I-CLIENT-SIDE-DELIVERY",
    "COMMS-I-NO-CENTRAL-DELIVERY-DIRECTORY",
    "COMMS-I-CLAIM-AUTHENTICITY",
    "COMMS-I-CLAIM-ATTENUATION",
    "COMMS-I-CLAIM-REPOSITORY-AUTHORITY",
    "COMMS-I-CLAIM-REVOCATION",
    "COMMS-I-LEDGER-CONFINEMENT",
    "COMMS-I-ISSUER-KEY-CONFINEMENT",
    "COMMS-I-MINT-FRESHNESS",
    "COMMS-I-ISSUER-CONTINUITY",
    "COMMS-I-CLAIM-RELEASE",
    "COMMS-I-JWT-TYPE-AUDIENCE",
    "COMMS-I-STATUS-INTEGRITY",
    "COMMS-I-PUBLIC-READER-TIER1-ONLY",
    "COMMS-I-AGENT-ROLE-BINDING",
    "COMMS-I-AGENT-ATTRIBUTION",
    "COMMS-I-WORKLOAD-TOKEN-CONFINEMENT",
    "SOCIAL-I-PRIVATE-STATE-AT-REST",
    "SOCIAL-I-NO-CENTRAL-SOCIAL-GRAPH",
    "SOCIAL-I-AGENT-POLICY-LOCAL",
    "SOCIAL-I-AGENT-REMEDIATION-SCOPED"
  ]
}
```

`heterodyne-social-strict-v2` inherits the v1 operational obligations and
additionally requires exact receipt/list binding, subscribed-policy
transparency, and device-key-scoped remediation.

<!-- fixture:social-matrix-strict-profile-v2 -->
```json
{
  "profile_id": "heterodyne-social-matrix-strict-v2",
  "conformance_class": "Social+Matrix",
  "state": "active",
  "requires_profiles": ["heterodyne-social-strict-v2"],
  "required_invariants": [
    "CORE-I-IDENTITY-INTEGRITY",
    "CORE-I-NID-DELEGATION-DUAL-PROOF",
    "CORE-I-VERIFY-BEFORE-USE",
    "CORE-I-NO-CENTRAL-IDENTITY-DIRECTORY",
    "CORE-I-KEY-MATERIAL-AT-REST",
    "COMMS-I-TIER3-BLIND-CARRIER",
    "COMMS-I-TIER2-HONESTY",
    "COMMS-I-CONFIG-AT-REST",
    "COMMS-I-CLIENT-SIDE-DELIVERY",
    "COMMS-I-NO-CENTRAL-DELIVERY-DIRECTORY",
    "COMMS-I-CLAIM-AUTHENTICITY",
    "COMMS-I-CLAIM-ATTENUATION",
    "COMMS-I-CLAIM-REPOSITORY-AUTHORITY",
    "COMMS-I-CLAIM-REVOCATION",
    "COMMS-I-LEDGER-CONFINEMENT",
    "COMMS-I-ISSUER-KEY-CONFINEMENT",
    "COMMS-I-MINT-FRESHNESS",
    "COMMS-I-ISSUER-CONTINUITY",
    "COMMS-I-CLAIM-RELEASE",
    "COMMS-I-JWT-TYPE-AUDIENCE",
    "COMMS-I-STATUS-INTEGRITY",
    "COMMS-I-PUBLIC-READER-TIER1-ONLY",
    "COMMS-I-AGENT-ROLE-BINDING",
    "COMMS-I-AGENT-ATTRIBUTION",
    "COMMS-I-WORKLOAD-TOKEN-CONFINEMENT",
    "SOCIAL-I-PRIVATE-STATE-AT-REST",
    "SOCIAL-I-NO-CENTRAL-SOCIAL-GRAPH",
    "SOCIAL-I-AGENT-POLICY-LOCAL",
    "SOCIAL-I-AGENT-REMEDIATION-SCOPED",
    "SOCIAL-I-MATRIX-E2EE",
    "SOCIAL-I-MXID-DELEGATION-DUAL-PROOF",
    "SOCIAL-I-CLIENT-SIDE-MATRIX-BRIDGE"
  ],
  "matrix_obligations": [
    "encrypted-private-content-and-state",
    "mxid-dual-proof",
    "downgrade-warning",
    "bare-message-visibility"
  ]
}
```

<a id="social-conformance"></a>
## 14. Conformance

<!-- Monolith provenance: §11.7 Social policy and §14; family claims split by
ADR-033 requirements 30-34. -->

A `Social` report MUST name `social/0.5.0`, pin `core/0.5.0` and
`comms/0.5.0`, pin registry revision 3 or its immutable digest, enumerate
supported features and strict profiles, and implement §§1-8 and §13. It MUST
include async replies/reactions, following and transitive discovery,
cross-persona advertisements, reply inboxes, mixed-tier Social fan-out,
moderation, NIP-51 Social profiles, community policy, Social recovery binding,
feed/org presentation, ATProto behavior when advertised, the acceptance-hook
policy, subscriber-local agent-policy moderation when
`social.agent-policy-moderation.v1` is advertised, and all non-Matrix Social
invariants.

A `Social+Matrix` report MUST include a complete `Social` claim and every
Matrix requirement in §§9-12: MXID delegation, election/leases/failover,
config-room behavior, exit and mirroring, wrapped/bare verification, both room
kinds, Megolm baseline, downgrade resistance, MLS migration when advertised,
client-side bridge boundary, homeserver independence, and fallback rendering.
A partial Matrix implementation MUST list gaps and MUST NOT claim
`Social+Matrix`.

A Social conformance report that claims a strict profile MUST reproduce its
exact membership, prerequisite results, applicable strict-vector results, and
any Matrix obligations. It MUST use the conformance class stated in the
profile fixture and MUST NOT collapse `Social` and `Social+Matrix`.

Wire conformance is byte-exact. Existing signed 0.4 events MUST NOT be
restamped. Plain upstream NIP-51 and NIP-72 events remain unstamped; only the
exact immutable Social profiles opt into a Social stamp. A changed wire
behavior requires a new immutable vector id. Unsupported Social versions or
profiles MUST be rejected or explicitly degraded under Core's version rules,
never silently interpreted as this release.
