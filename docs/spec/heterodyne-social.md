# Heterodyne Social Protocol Specification

Document ID: `social`

Social is a section of the Heterodyne specification and is governed by
`heterodyne:0.5.0#core-document-conventions`, which fixes the family version,
the registry pin, release status, BCP 14 usage, and the anchor and reference
forms.

<a id="social-scope"></a>
## 1. Scope and conformance features


Social defines following, replies, reactions, threading, social discovery,
cross-persona advertisements, reply inboxes, feed presentation, community and
organization presentation, moderation, personal and community lists,
web-of-trust policy, starter packs, social recovery bindings, and the optional
ATProto attached outbox. Social owns public and audience publishing, durable
feed assets, stable links, citations, public community presentation,
moderation, and discovery. Private conversation and group-scoped content use
Marmot under Comms.

There is one `Social` conformance class. It requires the exact dependency
versions above and every applicable section of this document.

<a id="social-interactions"></a>
## 2. Replies, reactions, threading, and mixed-tier fan-out


Because a persona's repository is writable only by its authorized delegates,
a replier MUST NOT require write access to another persona's repository.
Replies and reactions use the Nostr outbox model:

- A reply is a NIP-10 event and a reaction is a NIP-25 `kind:7` event written
  to the replier's own Comms outbox. It carries the standard `e`/`p` references
  to the target id and author and is published under
  `heterodyne:0.5.0#comms-publishing`.
- Thread assembly is scatter-gather over repliers' repo relays and ordinary
  relays. A client MUST locally verify every event through
  `heterodyne:0.5.0#comms-envelope` and MUST deduplicate by event id.
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

A private reply or reaction MUST use a Marmot conversation under
`heterodyne:0.5.0#comms-marmot`. If no suitable two-member group exists,
it uses the persona-inbox bootstrap at
`heterodyne:0.5.0#comms-marmot-persona-inbox`. The Marmot application
event MAY reference the stable Social asset ID, but the private response is
not added to the public Social outbox unless the user separately publishes it.

<a id="social-mixed-tier-fanout"></a>
### 2.1 Mixed-tier fan-out and reply inboxes

A Social UI MAY compose one intent across multiple Comms destinations, but it
MUST preserve `heterodyne:0.5.0#comms-privacy-tiers`: Tier 2 plaintext
MUST NOT reach a public relay, and Tier 3 MUST remain ciphertext at every
destination. A client SHOULD warn before a user expands a Tier 2, Tier 3, or
private-discussion intent to a public destination. The warning never permits
plaintext leakage.

An outbox advertisement MAY contain ordinary-relay, repo-relay, and Marmot
persona-inbox hints where the persona prefers to observe replies and mentions.
A replier SHOULD add reachable public destinations to the normal destination
set. A private response uses the Marmot hint and remains in its two-member
group. An inbox never grants write authority over the parent's canonical
repository.

Public interaction is intentionally asynchronous. A client MUST degrade
gracefully to outbox replies and reactions and MUST NOT block the user waiting
for real-time push.

<a id="social-discovery"></a>
## 3. Following and social discovery


Social discovery starts only after Core has resolved npub to RID to serving
node and Comms has located the generic feed/outbox. A follower MUST:

1. resolve the target npub through
   `heterodyne:0.5.0#core-identity-discovery`;
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
profile of `heterodyne:0.5.0#comms-config-repository` or retained in
local encrypted storage. A followed-repositories record stored through the
Core keys-repository protection mechanism remains a Social payload; storage
location does not transfer semantic ownership.

A conforming client MUST support a vanilla Nostr-only author as a first-class
follow target. It verifies each event's NIP-01 signature, subscribes through
the author's current NIP-65 write-relay list, and MUST present the author as an
external identity with no Heterodyne KEL, delegation, or private-audience
guarantees. Following an external identity does not imply that it has a
compatible Marmot account or can receive a Heterodyne private conversation.

An unstamped `kind:0` or `kind:1` without `kel_head` remains ordinary upstream
Nostr even when its prose claims that an account moved. A client MAY render
that claim as an advisory, reduced-assurance breadcrumb, but it MUST NOT infer
either registered rotation-breadcrumb producer profile, project KEL
continuity, or use the event as persona authority. Following, refollowing, or
switching to a claimed successor requires an explicit user action; a client
MUST NOT change a follow automatically. Compromise-driven rotations have no
trustworthy old-key breadcrumb, and a later compromise of a retired key can
overwrite replaceable `kind:0` or publish a competing note, so the UI MUST NOT
describe breadcrumb continuity as secure or compromise-resistant.

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
['spec_version','heterodyne/0.5.0']
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

This exact dual-signed pair is the higher-layer explicit-relationship
exception permitted by Core. Before producing `same_holder`, a client MUST
obtain explicit confirmation after warning that the two persona histories
become permanently and externally linkable. Later deletion of either
relationship event cannot erase prior observations or copies.

<!-- fixture:related-persona-pair -->
```json
{
  "left": {
    "pubkey": "1b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
    "created_at": 1710000000,
    "kind": 31004,
    "tags": [["d","endorses:4d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766"],["heterodyne","related_persona"],["other_npub","4d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766"],["relation","endorses"],["scope","professional"],["cold_root","1b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"],["kel_head","3333333333333333333333333333333333333333333333333333333333333333","0"],["spec_version","heterodyne/0.5.0"]],
    "content": "",
    "id": "89a6a1bf0345535482d296e6910b5115a623dbafe8b9cdd5011af28f686eb45d",
    "sig": "7ff8bd7d316fd67820547ed4d92c60a556ed1fd089afd6aafe30190c2fe9812e34f81b3bf8200eb1437e3ccdcc74bfa874d9014d6cd924efb6ad1072dfd1a3ff"
  },
  "right": {
    "pubkey": "4d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766",
    "created_at": 1710000001,
    "kind": 31004,
    "tags": [["d","endorsed_by:1b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"],["heterodyne","related_persona"],["other_npub","1b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"],["relation","endorsed_by"],["scope","professional"],["cold_root","4d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766"],["kel_head","4444444444444444444444444444444444444444444444444444444444444444","0"],["spec_version","heterodyne/0.5.0"]],
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


Core defines recovery peers, declared witnesses, cached identity material,
and cold-root re-anchor at `heterodyne:0.5.0#core-recovery`. Social MAY
select recovery peers from follows, mutual follows, and friends:

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
relationships are advisory availability bindings and MUST NOT replace the
cold-root re-anchor, accepted KEL, witness
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
    ["spec_version", "heterodyne/0.5.0"]
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


Comms owns feed storage, ordering, paging, retrieval, and threshold
authorization. Social turns those verified inputs into topic subscriptions,
curated views, community pages, reply counters, moderation views, and
organization presentation. A Social renderer MUST NOT show an org post or
index as canonical until it passes
`heterodyne:0.5.0#comms-org-authorization`.

A persona MAY operate multiple topic feeds and multiple audience feeds. A
client SHOULD support topic-selective subscription and MAY present a union as
"all topics." Feed labels, topic tags, pinning, intentional omissions, and
nonchronological ordering are presentation instructions from the verified
Comms index; relay presence alone MUST NOT insert an unindexed event into a
persona's curated feed.

<a id="social-org-feed-profile"></a>
### 5.1 Registered Social org-feed profile

The registry defines the stamping profile
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
  "spec_version": "heterodyne/0.5.0"
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
  "content": "{\"profile\":\"heterodyne.social.org-feed.v1\",\"spec_version\":\"heterodyne/0.5.0\"}",
  "sig": "77777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777"
}
```

The profile controls only org/community/editorial presentation. It MUST NOT
weaken the requirement that both the org post and index be reachable from the
delegate-threshold-approved canonical feed branch. Any `xyz.radicle.crefs` refinement of editorial refs
is bounded by `heterodyne:0.5.0#core-threshold-authority`.

<a id="social-moderation"></a>
## 6. Moderation and editorial gating


Social defines two independent editorial-gating mechanisms:

1. **NIP-72 approval mode.** A moderator publishes a `kind:4550` approval;
   authorized, anchored approvals determine the curated view.
2. **Radicle editorial mode.** A post and its index are approved exactly when
   both are reachable from the delegate-threshold-approved canonical feed
   branch.

A community MAY use either or both. A client MUST NOT treat one as proof of
the other. Membership is a separate axis: repository `visibility.allow`
controls replication/read access and Core delegates control repo authority.
An unapproved post may remain visible in a raw relay or repository view while
being absent from the curated view.

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
implicit-rejection window expires. If no approval appears within seven days
(604800 seconds) of candidate `created_at`, conforming clients MUST treat the
candidate as implicitly rejected and surface a localizable structured outcome
with class `moderation-approval-window-expired`, candidate, approval and
community identifiers, submission identity, attempt/deadline/last-attempt
timestamps, retry state, terminal cause, and allowed actions: abandon, edited
republication with a new id, or intentional unchanged republication. This
release defines no explicit moderator-rejection event; silence is rejection.
After three consecutive implicit rejections from one community, the client
SHOULD surface a structured advisory with class
`moderation-repeated-implicit-rejection`. English renderings such as “post not
approved within 7-day window” are examples, not normative strings.

Every moderated community MUST publish a NIP-72 `kind:34550` addressable
community definition on the Core/Comms backends. It lists each moderator's
permanent cold root as a wire key per
`heterodyne:0.5.0#core-wire-keys`:

```text
['p','<moderator cold-root 64-lowercase-hex>','<relay hint>','moderator']
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
- **Relay-only fallback:** the newest declaration with `created_at` not after
  the approval is used. A client MUST label this reduced assurance because a
  removed moderator can backdate.

An approval required to have a repo anchor but lacking it MUST NOT count. An
approval omitted from the moderator's current index is off-index and
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

<a id="social-revocation"></a>
### 6.3 Approval withdrawal and deletion

Silence is rejection; this release defines no explicit rejection event. To
withdraw an approval, its author MUST publish a NIP-09 `kind:5` deletion
request targeting its own `kind:4550` and MUST publish an updated approval
index omitting it. A client MUST validate that the deletion and target authors
match before hiding or discounting the approval. Deletion signals intent and
MUST NOT be represented as erasure.

<a id="social-radicle-editorial"></a>
### 6.4 Radicle editorial-gating mode

For a Radicle-mode community, a client MUST treat a post as editorially
approved if and only if both the post and the `kind:31007` that references it
are reachable from the delegate-threshold-approved canonical feed branch. A
lone epoch-key signature observed only on an ordinary relay MUST NOT bypass
that threshold. A client MUST NOT require `kind:4550` in this mode. Conversely,
it MUST NOT impose branch reachability on a NIP-72-mode view.

Post-hoc removal uses `kind:5` plus a new canonical index omitting the post.
It changes the live view only, under `heterodyne:0.5.0#core-non-erasure`.

<a id="social-labels"></a>
### 6.5 Reports and labels

Clients MAY consume NIP-56 `kind:1984` reports. They are RECOMMENDED to emit
and consume NIP-32 `kind:1985` labels. A label event MUST target at least one
event, pubkey, address, relay, or topic through an upstream `e`, `p`, `a`, `r`,
or `t` tag. When it uses an `L` namespace, each `l` tag MUST mark a matching
namespace. Labels are advisory: they MAY influence local warnings/ranking but
MUST NOT constitute either editorial approval mechanism.

<a id="social-agent-policy-receipts"></a>
### 6.6 Agent-policy receipts and corrections

The registry defines the stamping
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


NIP-51 is an adopted upstream Social profile, not a Core or Comms construct.
Public NIP-51 items are tags. Private items are tag-shaped arrays encoded as a
JSON array, NIP-44-encrypted to self, and stored in `content`. New private
items MUST use NIP-44; legacy NIP-04 read-back MAY be detected by its `iv`
field. A client SHOULD preserve list order when appending.

<a id="social-mute-profile"></a>
### 7.1 Registered Social mute-list profile

The registry defines `heterodyne-social-mute-list-v1` on upstream
replaceable `kind:10000`, with immutable discriminator
`tag:heterodyne=social-mute-list-v1`. A Social-profiled mute list MUST carry
exactly one of each profile tag:

```json
["heterodyne", "social-mute-list-v1"]
["spec_version", "heterodyne/0.5.0"]
```

The profile is stamping, so `heterodyne/0.5.0` is its sole owner stamp. Public
mute entries use upstream `p`, `t`, `word`, and `e` tags. Private entries keep
the upstream NIP-51 encrypted-content shape; the profile MUST NOT change that
shape. A client MUST verify the signer through Core and re-encrypt private
items under the new authoritative epoch key on the next list write after
rotation.

A plain upstream NIP-51 event without the exact Social discriminator MUST
remain unstamped. It is an interoperability input and MUST NOT be stamped
during ingestion or represented as this Social profile.

<a id="social-agent-policy-list"></a>
### 7.2 Subscriber-local agent policy

The registry defines the stamping
`heterodyne-social-agent-policy-list-v1` profile on NIP-51 replaceable
`kind:10000`, with the exact profile tags:

```text
["heterodyne", "social-agent-policy-list-v1"]
["spec_version", "heterodyne/0.5.0"]
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
sets or `['p','<policy cold-root 64-lowercase-hex>','<relay hint>','policy']`
in `kind:34550`.
Clients computing that community's view SHOULD apply adopted sources after
verifying their signatures and current KEL authority. A follower MAY subscribe
to additional policy personas independently.

<a id="social-admission-policy"></a>
### 7.5 Web-of-trust and the Comms acceptance hook

Social implements mute and web-of-trust admission only through
`heterodyne:0.5.0#comms-acceptance-hook`. Authentication and all Comms
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

Before acceptance, `hold-as-message-request` emits no receipt, retry hint,
typing signal, read marker, presence update, or other sender-observable
response. A Social policy MUST preserve that no-signal rule. Muting or
blocking a sender maps an otherwise acceptable ordinary Marmot conversation
to `reject`; it never authenticates a sender. This lattice applies only to
the Comms ordinary-conversation hook. It does not consume or alter a Control
group admission result.

Web-of-trust ranking is local policy, not canonicality. A graph MAY be built
from verified `kind:3` follows, public Social mute profiles, and weighted
NIP-32 labels. It MUST NOT change whether a post is signed, indexed,
NIP-72-approved, or Radicle-editorially approved.

<a id="social-atproto"></a>
## 8. Optional ATProto attached outbox


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
wildcard, and otherwise non-public resolved addresses. The client MUST
explicitly resolve a non-empty set and reject the entire hop if any answer is
non-public. It MUST choose one validated public address and connect directly
to that address without allowing the HTTP stack to resolve the hostname a
second time. The established peer address MUST equal the selected address
after canonical IP normalization.

TLS SNI, certificate-name verification, and HTTP `Host`/`:authority` MUST use
the original requested hostname, never the selected IP. A non-443 port MUST be
rejected unless the user explicitly allow-lists that host and port. Automatic
redirect following MUST be disabled. At most three redirects are
RECOMMENDED; each target is returned to the resolver and independently
re-resolved, selected, dial-pinned, peer-inspected, and host-verified. A client
MUST NOT follow a public-to-private or 443-to-unapproved-port redirect. If its
runtime cannot both bind the selected address and inspect the established
peer, it MUST report this feature unavailable and MUST NOT claim ATProto
resolver conformance. It SHOULD warn when a DID's PDS endpoint changes from
the cached value.

<a id="social-atproto-binding"></a>
### 8.2 Bidirectional binding

The DID-side record MUST use ATProto collection
`social.heterodyne.identityLink` with record key `self`. Its `value` and the
Social-owned `kind:31009` `atproto_link` event's content cover the same
canonical compact JSON object:

```json
{"spec_version":"heterodyne/0.5.0","did":"<DID>","did_signing_key_id":"<key id>","npub":"<cold-root hex>","rid":"<canonical RID>","established_at":0}
```

`rid` is omitted only if no RID exists. Transport-specific account
identifiers MUST NOT appear in the signed payload. The Nostr attestation MUST
be signed by the currently
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
finally require the two payloads to be identical.

<!-- fixture:atproto-identity-link -->
```json
{
  "nostr_event": {
    "pubkey": "531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337",
    "created_at": 1710000000,
    "kind": 31009,
    "tags": [["d","did:web:alice.example"],["heterodyne","atproto_link"],["cold_root","531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337"],["did","did:web:alice.example"],["kel_head","5555555555555555555555555555555555555555555555555555555555555555","0"]],
    "content": "{\"spec_version\":\"heterodyne/0.5.0\",\"did\":\"did:web:alice.example\",\"did_signing_key_id\":\"did:web:alice.example#atproto\",\"npub\":\"531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337\",\"rid\":\"rad:zAlice\",\"established_at\":1710000000}",
    "id": "cd41c76501b0b7145c8dd115503473553e0e8a31c8e5849822aa7c87d19c6bf6",
    "sig": "a63775bd44e0b09a9400ed900aa13cdae9b239237056fe9b2bc87b24297af117d562a61f80a5d522680fc8d683b6ffa1f3d5e963a7c99635bdf0385ea80b03d5"
  },
  "pds_record": {
    "collection": "social.heterodyne.identityLink",
    "rkey": "self",
    "value": {"spec_version":"heterodyne/0.5.0","did":"did:web:alice.example","did_signing_key_id":"did:web:alice.example#atproto","npub":"531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337","rid":"rad:zAlice","established_at":1710000000},
    "algorithm": "Ed25519",
    "public_key": "ca93ac1705187071d67b83c7ff0efe8108e8ec4530575d7726879333dbdabe7c",
    "signed_payload_hash": "6adf242345b2ac833ec54689e1eb6607d84897a5a116ef00df447646c5c541a0",
    "signature": "83a5f27554ae5dcd20552e19894c6d0c87d5a0efc91b423d88cb6ded67d1763c20013b7dec15aea8e8bf577c3dccab4749227756441a608d20d979c2ddc1570b"
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

<!-- fixture:atproto-link-revocations -->
```json
{
  "nostr": {
    "pubkey": "531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337",
    "created_at": 1710000100,
    "kind": 31009,
    "tags": [["d","did:web:alice.example"],["heterodyne","atproto_link_revocation"],["did","did:web:alice.example"],["cold_root","531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337"],["kel_head","5555555555555555555555555555555555555555555555555555555555555555","0"]],
    "content": "{\"spec_version\":\"heterodyne/0.5.0\",\"record_type\":\"atproto_link_revocation\",\"did\":\"did:web:alice.example\",\"npub\":\"531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337\",\"binding_hash\":\"6adf242345b2ac833ec54689e1eb6607d84897a5a116ef00df447646c5c541a0\",\"revoked_at\":1710000100}",
    "sig": "66666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666"
  },
  "atproto": {
    "collection": "social.heterodyne.identityLink",
    "rkey": "self",
    "value": {"spec_version":"heterodyne/0.5.0","record_type":"atproto_link_revocation","did":"did:web:alice.example","npub":"531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337","binding_hash":"6adf242345b2ac833ec54689e1eb6607d84897a5a116ef00df447646c5c541a0","revoked_at":1710000100},
    "signature": "did-revocation-signature-base64url"
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

<a id="social-security"></a>
## 9. Security invariants


The registry binds these exact Social invariants:

- **SOCIAL-I-PRIVATE-STATE-AT-REST:** Private mute, feed-preference, followed-repository, and other Social state are encrypted at rest using the owning Social or bound Comms profile.
- **SOCIAL-I-NO-CENTRAL-SOCIAL-GRAPH:** Following, transitive discovery, and social-graph evaluation do not depend on a centralized follow-graph oracle.
- **SOCIAL-I-AGENT-POLICY-LOCAL:** Agent-policy receipts inform publicly, but only an explicitly subscribed and verified current policy list changes a client's local visibility.
- **SOCIAL-I-AGENT-REMEDIATION-SCOPED:** Agent-policy enforcement and remediation target only the offending role device key; replacement at the same role address never requires epoch-key rotation.

The mechanism boundaries MUST remain honest. Tier 2, Tier 3, Marmot
conversation, and Radicle persona-inbox guarantees come from Comms. Social
ranking is advisory and never identity or editorial authority. ATProto is an
attached public outbox and optional witness, never persona authority.

<a id="social-strict-profiles"></a>
### 9.1 Social strict profiles

The Social strict profile composes the Core, Comms, and applicable Social
invariant sets.

<!-- fixture:social-strict-profile -->
```json
{
  "profile_id": "heterodyne-social-strict-v1",
  "conformance_class": "Social",
  "state": "active",
  "requires_profiles": [
    "heterodyne-comms-strict-v1"
  ],
  "adds_invariants": [
    "SOCIAL-I-PRIVATE-STATE-AT-REST",
    "SOCIAL-I-NO-CENTRAL-SOCIAL-GRAPH",
    "SOCIAL-I-AGENT-POLICY-LOCAL",
    "SOCIAL-I-AGENT-REMEDIATION-SCOPED"
  ]
}
```

Beyond its inherited obligations this profile requires a valid signed event to
pass baseline verification before Social policy is applied; initiation of
subscription or polling for a valid `kind:5` deletion within 30 seconds on an
active source, with retry and availability evidence until a terminal
condition; exact receipt/list binding; subscribed-policy transparency;
device-key-scoped remediation; and a visible warning when a previously met
strict requirement becomes unmet. A carrier partition does not itself make an
otherwise conforming consumer nonconformant.

<a id="social-conformance"></a>
## 10. Conformance


A `Social` report follows the family requirements in
`heterodyne:0.5.0#core-conformance`, claims Core+Comms+Social, and implements
§§1-9. It MUST
include async replies/reactions, following and transitive discovery,
cross-persona advertisements, reply inboxes, mixed-tier Social fan-out,
moderation, NIP-51 Social profiles, community policy, Social recovery binding,
feed/org presentation, ATProto behavior when advertised, the acceptance-hook
policy, subscriber-local agent-policy moderation when
`social.agent-policy-moderation.v1` is advertised, and all registered Social
invariants.

Social presentation of persona name, avatar, biography, website, or NIP-05
MUST begin from the canonical Core persona-profile record. The delegated
`kind:0` mirror provides vanilla interoperability, but a competing relay event
or repointed NIP-05 MUST NOT replace canonical repository state.

Optional lower-layer profiles are claimed only when their owning documents'
requirements and vectors are satisfied.

Report contents, byte-exact wire conformance, vector-ID immutability, and
unknown-version handling are family-wide rules stated once by
`heterodyne:0.5.0#core-conformance` and `heterodyne:0.5.0#core-versioning`.
Social adds one stamping rule: plain upstream NIP-51 and NIP-72 events remain
unstamped, and only the exact immutable Social profiles opt into a Social
stamp.
