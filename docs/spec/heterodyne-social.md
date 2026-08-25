# Heterodyne Social Protocol Specification

Document ID: `social`

Social is a section of the Heterodyne specification and is governed by
[`heterodyne:0.5.0#core-document-conventions`](heterodyne-core.md#core-document-conventions), which fixes the family version,
the registry pin, release status, BCP 14 usage, and the anchor and reference
forms.

<a id="social-scope"></a>
## 1. Scope and conformance features


Social defines following, replies, reactions, threading, social discovery,
cross-persona advertisements, reply inboxes, feed presentation, community and
organization presentation, moderation, personal and community lists,
web-of-trust policy, starter packs, optional Assurance-informed continuity
vouches, and the optional ATProto attached outbox. Social applies these
behaviors to ordinary Nostr events. It does not redefine NIP-01 authorship,
addresses, filters, or replaceable-event selection. Private conversation and
group-scoped content use Marmot under Comms.

There is one `Social` conformance class. It follows the Core-defined layering
closure and requires every claimed document to use the same family version,
plus every applicable section of this document.

<a id="social-interactions"></a>
## 2. Replies, reactions, threading, and mixed-tier fan-out


Replies and reactions use the ordinary Nostr outbox model:

- A reply is a NIP-10 event and a reaction is a NIP-25 `kind:7` event written
  to the replier's own Comms outbox. It carries the standard `e`/`p` references
  to the target id and author and is published under
  [`heterodyne:0.5.0#comms-publishing`](heterodyne-comms.md#comms-publishing).
- Thread assembly is scatter-gather over the authors' NIP-65 relays and any
  repository-published relay hints. A client MUST locally verify every event
  through [`heterodyne:0.5.0#comms-envelope`](heterodyne-comms.md#comms-envelope) and MUST deduplicate by event id.
- A full node MAY materialize `xyz.heterodyne.thread` as a Radicle
  Collaborative Object, but a client MUST treat it only as an optimization.
  The verified scatter-gathered events remain authoritative.
- The event's `pubkey` is its author. A cold root, KEL head, feed index,
  repository writer, moderator, or agent association MUST NOT substitute a
  different author. A valid bare Nostr key with no Assurance state is a
  first-class Social author.

Feed inclusion, reply collapsing, reaction display, and ranking are local
presentation decisions over valid events. They do not add an authorship or
validity rule to NIP-10, NIP-25, or NIP-01.

A private reply or reaction MUST use a Marmot conversation under
[`heterodyne:0.5.0#comms-marmot`](heterodyne-comms.md#comms-marmot). If no suitable two-member group exists,
it uses the persona-inbox bootstrap at
[`heterodyne:0.5.0#comms-marmot-persona-inbox`](heterodyne-comms.md#comms-marmot-persona-inbox). The Marmot application
event MAY reference the stable Social asset ID, but the private response is
not added to the public Social outbox unless the user separately publishes it.

<a id="social-mixed-tier-fanout"></a>
### 2.1 Mixed-tier fan-out and reply inboxes

A Social UI MAY compose one intent across multiple Comms destinations, but it
MUST preserve [`heterodyne:0.5.0#comms-privacy-tiers`](heterodyne-comms.md#comms-privacy-tiers): Tier 2 plaintext
MUST NOT reach a public relay, and Tier 3 MUST remain ciphertext at every
destination. A client SHOULD warn before a user expands a Tier 2, Tier 3, or
private-discussion intent to a public destination. The warning never permits
plaintext leakage.

An outbox advertisement MAY contain ordinary-relay, repo-relay, and Marmot
persona-inbox hints where the persona prefers to observe replies and mentions.
A replier SHOULD add reachable public destinations to the normal destination
set. A private response uses the Marmot hint and remains in its two-member
group. An inbox never grants write authority over the parent's repository or
changes source-neutral event selection.

Public interaction is intentionally asynchronous. A client MUST degrade
gracefully to outbox replies and reactions and MUST NOT block the user waiting
for real-time push.

<a id="social-discovery"></a>
## 3. Following and social discovery


Social discovery starts from an active npub, whether supplied directly or
resolved through NIP-05. A follower MUST:

1. resolve the target npub through
   [`heterodyne:0.5.0#core-identity-discovery`](heterodyne-core.md#core-identity-discovery);
2. retrieve the target's standard NIP-65 `kind:10002` relay list and query its
   write relays plus any repository-published relay hints with NIP-01 filters;
3. union valid exact events from all reachable carriers, deduplicate by event
   id, and use NIP-01 replaceable selection where applicable;
4. for Tier 2, establish access through the repository allow list; for Tier 3,
   possess the current audience key and use the in-audience descriptor;
5. after entering an audience, read its descriptor for deeper feeds and repeat
   transitively; and
6. cache transport hints with a TTL and revalidate on a newer valid kind `0`
   or kind `10002`.

Repository bytes are the canonical event bytes when available, but repository
carriage has no selection priority. A newer valid relay event wins immediately
and remains usable while repository ingestion catches up. If a repository is
unavailable, ordinary relay state remains valid. Publishing clients refresh
kind `0` and kind `10002` at least every seven days; exceeding that interval
produces a visible warning and MUST NOT invalidate the latest valid state.

Transitive discovery MUST NOT disclose an inner feed before the reader holds
the outer audience's access capability. A search result, starter pack, graph
snapshot, or recommendation is never identity authority: every npub MUST walk
the same Core and Comms resolution path before subscription.

<a id="social-following"></a>
### 3.1 Following semantics and private state

Following is a set of feed subscriptions, not one global server-side edge:

- following a public author subscribes to its NIP-65 write relays with
  ordinary NIP-01 filters;
- topic selection is a local filter over that author's valid events;
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
profile of [`heterodyne:0.5.0#comms-config-repository`](heterodyne-comms.md#comms-config-repository) or retained in
local encrypted storage. A followed-repositories record stored through the
Core keys-repository protection mechanism remains a Social payload; storage
location does not transfer semantic ownership.

A conforming client MUST support every valid vanilla Nostr author as a
first-class follow target. Absence of Heterodyne metadata or Assurance is not
an external, incomplete, downgraded, or invalid identity state. Following an
author does not by itself imply private-audience access or Marmot reachability.

An ordinary `kind:0` or `kind:1` may contain a human-readable succession
breadcrumb. It remains advisory. A client MUST NOT change a follow
automatically or alias the old and new authors. Optional Assurance can add
verified continuity evidence, but only when the user requests that separate
claim; it never changes the validity or authorship of either event.

<a id="social-cross-persona"></a>
### 3.2 Cross-persona advertisements

`kind:31004` is the Social `related_persona` attestation. A relationship is
valid only when two distinct personas A and B publish a matching pair of
attestations. A's `other_npub` MUST be B's active npub and B's `other_npub`
MUST be A's active npub. Each event carries:

```text
['d','<relation>:<other_npub_hex>']
['heterodyne','related_persona']
['other_npub','<other_npub_hex>']
['relation','same_holder|endorses|endorsed_by|linked']
['spec_version','heterodyne/0.5.0']
```

Both NIP-01 event ids and signatures MUST verify, and each event's `pubkey`
MUST equal the active author identified by the opposite attestation. A
single-signed relationship MUST be rejected. The `d`, `other_npub`, and
opposite-party values MUST match exactly. `same_holder` and `linked` are
symmetric: both events MUST use the same relation. `endorses` and
`endorsed_by` are the only inverse pair. The events MUST have independent
signatures from their actual authors. Neither author requires Assurance.
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
    "tags": [["d","endorses:4d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766"],["heterodyne","related_persona"],["other_npub","4d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766"],["relation","endorses"],["scope","professional"],["spec_version","heterodyne/0.5.0"]],
    "content": "",
    "id": "8c63243f98958be655db1f24298e4c0053e77174f354b0603e7687e5f99e9a8e",
    "sig": "c926b803104698e5bd6a1e3294c418cc3d6367dc7b3b0cc7aad7cc14f97ecd21fdb412ec867dc4e64e3cfdd3ca0deb1a6f964b3fff2b1d8d70d85433e1710785"
  },
  "right": {
    "pubkey": "4d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766",
    "created_at": 1710000001,
    "kind": 31004,
    "tags": [["d","endorsed_by:1b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"],["heterodyne","related_persona"],["other_npub","1b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"],["relation","endorsed_by"],["scope","professional"],["spec_version","heterodyne/0.5.0"]],
    "content": "",
    "id": "bd75843f083ad87e979b9f8de0c267b0a9ea82ad6b2d8d3377b06450308dcbc8",
    "sig": "5c3a3dac8f9344796a746943d3c58d0b33cbfda22fa6db2e5c4208210ffd4e5ec383cc2370eaced191811e9dd15f12df95099278b026dde65a98dcc3e2b82362"
  }
}
```

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
## 4. Optional Assurance continuity vouches


Ordinary Social behavior does not require recovery roles, continuity proofs,
or cached authority state. A follower MAY cache exact signed Nostr events and
MAY publish an advisory vouch about a claimed key transition. Such a vouch is
not identity authority and never changes an event's NIP-01 author.

When the subject has explicitly attached optional Assurance, an Assurance
verifier MAY consume a Social vouch as extra evidence under that document's
rules. Social itself does not make a succession or recovery decision. Absence,
invalidity, or staleness of a vouch or Assurance state MUST NOT invalidate an
otherwise valid Social event or prevent an unassured persona from using any
ordinary Social feature.

<!-- fixture:social-recovery-cache-duties -->
```json
{"ordinary_event_cache":"may","continuity_vouch":"advisory","assurance_required_for_baseline":false}
```

Human out-of-band assurance before vouching is deliberately unspecified. A
voucher MAY use any channel; this document defines no single capturable proof.

<a id="social-informal-vouch"></a>
### 4.1 Informal social vouch (`kind:31008`)

An informal vouch has this Social-owned addressable shape:

```json
{
  "pubkey": "<voucher active Nostr key>",
  "created_at": 0,
  "kind": 31008,
  "tags": [
    ["d", "<subject-active-key>:<claimed-successor-key>"],
    ["heterodyne", "social_vouch"],
    ["p", "<subject-active-key>"],
    ["vouched_key", "<claimed-successor-key>"],
    ["spec_version", "heterodyne/0.5.0"]
  ],
  "content": "<optional free-text note>",
  "sig": "<BIP-340 signature by voucher active key>"
}
```

The `d`, `p`, and `vouched_key` values MUST agree exactly. The voucher's
NIP-01 event id, signature, and Social stamp MUST verify, and its `pubkey` is
the voucher's only author. No number of informal vouches can alias authors,
move follows, or satisfy an Assurance threshold. A client MAY show or rank
them, but any continuity decision is an explicit optional Assurance claim.

<a id="social-feed-presentation"></a>
## 5. Feed and organization presentation


Social turns valid ordinary Nostr inputs into topic subscriptions, curated
views, community pages, reply counters, moderation views, and organization
presentation. Clients discover public events through the author's NIP-65
write relays and repository-published relay hints. They union valid exact
events and use NIP-01 selection. A repository is a durable source and
reconciliation target, not a source-priority override.

A persona MAY use standard topic tags, NIP-51 sets, and NIP-72 communities.
Pinning, intentional omission, and nonchronological ordering are local or
explicitly subscribed presentation policy. They do not make a signed event
invalid or change its author.

<a id="social-organization-personas"></a>
### 5.1 Organization personas

An organization has the same wire identity as a human persona: one active
Nostr key, one ordinary kind `0` profile, and one NIP-65 kind `10002` relay
list. There is no separate organization-feed identity or live Social profile
on kind `31007`.

An organization post is an ordinary event signed by the organization active
key. An authorized agent or human persona MAY instead sign with its own key
only when the event carries the mandatory Comms automation attribution or the
organization's explicit public-byline profile for that path. In every case the
event `pubkey` is the actual author. Association with the organization affects
presentation and audit; it MUST NOT rewrite the author, signature, address, or
replaceable namespace. Private delegate authority remains a Workspace concern.

<a id="social-moderation"></a>
## 6. Moderation and editorial gating


Social adopts ordinary NIP-72 communities and approvals. A moderator's valid
`kind:4550` event is authored by its own `pubkey`; community metadata cannot
replace that author. Labels, repository inclusion, relay acceptance, and
subscriber policy MAY affect a curated presentation but MUST NOT create a
NIP-72 approval or invalidate the underlying signed event. Membership and
repository replication remain separate axes.

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
SHOULD poll or subscribe to the moderators' NIP-65 write relays. Polling MUST use five-minute
intervals for the first 30 minutes, then MAY use exponential backoff of 5, 10,
30, then 60 minutes. It MUST stop on approval or when the seven-day
implicit-rejection window expires. If no approval appears within seven days
(604800 seconds) of candidate `created_at`, conforming clients MUST treat the
candidate as implicitly rejected and surface a
[`heterodyne:0.5.0#core-structured-outcome`](heterodyne-core.md#core-structured-outcome)
with `outcome_class` `moderation-approval-window-expired`, a `subject` binding
the candidate, approval, and community identifiers and the submission
identity, and `allowed_actions` of `abandon`, `edited-republication` with a
new id, and `unchanged-republication`. This
release defines no explicit moderator-rejection event; silence is rejection.
After three consecutive implicit rejections from one community, the client
SHOULD surface a second such outcome with `outcome_class`
`moderation-repeated-implicit-rejection`. English renderings such as “post not
approved within 7-day window” are examples, not normative strings.

Every moderated community MUST publish a NIP-72 `kind:34550` addressable
community definition through ordinary relays and any repository relay. It
lists each moderator's active Nostr public key:

```text
['p','<moderator-active-key 64-lowercase-hex>','<relay hint>','moderator']
```

and MAY carry `['approvals_required','<positive integer>']`; absence means 1.
A repo-hosted community SHOULD preserve every exact declaration event for
durability. The same event remains usable when available only from an
ordinary relay.

<a id="social-nip72-approval"></a>
### 6.2 Approval verification and anchors

A moderator approval is an upstream NIP-72 `kind:4550`: its `content`
stringifies the approved post and its tags identify the post, author, and
community. It remains an unstamped upstream event. For each candidate, a
Social client MUST:

1. resolve the current valid `kind:34550` community declaration with ordinary
   NIP-01 addressable-event selection;
2. query each declared moderator's NIP-65 write relays and any
   repository-published relay hints;
3. fetch each `kind:4550`, the approved post, and applicable
   deletion requests;
4. verify every NIP-01 event id and BIP-340 signature and require each
   approval author to be a moderator active key declared for that community;
   and
5. surface the candidate only when distinct live approvals meet the threshold.

For an approval-time view, select among valid declaration events whose
`created_at` is not after the approval: greatest `created_at`, then lowest
event id. Carrier does not enter the comparison. Optional Assurance may add
continuity evidence for a moderator that later changes active key, but it is
not required to validate an approval by the key that actually signed it.

<!-- fixture:social-approval-anchor-evidence -->
```json
{"signature_valid":true,"moderator_declared_at_event_time":true,"carrier":"relay-or-repository","deleted":false}
```

Later removal of a moderator does not rewrite an earlier approval. An optional
Assurance compromise claim may cause a client explicitly evaluating that
claim to warn about affected history; it MUST NOT change baseline NIP-01
validity. Withdrawing a live approval uses NIP-09 as described below.

<a id="social-revocation"></a>
### 6.3 Approval withdrawal and deletion

Silence is rejection; this release defines no explicit rejection event. To
withdraw an approval, its author MUST publish a NIP-09 `kind:5` deletion
request targeting its own `kind:4550`. A client MUST validate that the deletion and target authors
match before hiding or discounting the approval. Deletion signals intent and
MUST NOT be represented as erasure.

<a id="social-radicle-editorial"></a>
### 6.4 Repository-backed editorial views

A community MAY offer a repository-backed curated view containing exact
signed Nostr events. Repository inclusion is a subscriber-local presentation
signal and storage fact. It MUST NOT replace a NIP-72 `kind:4550`, confer
moderator authority on a writer NID, or make a relay-only event invalid.
Post-hoc removal from that view changes only the view and never claims erasure,
under [`heterodyne:0.5.0#core-non-erasure`](heterodyne-core.md#core-non-erasure).

<a id="social-labels"></a>
### 6.5 Reports and labels

Clients MAY consume NIP-56 `kind:1984` reports. They are RECOMMENDED to emit
and consume NIP-32 `kind:1985` labels. A label event MUST target at least one
event, pubkey, address, relay, or topic through an upstream `e`, `p`, `a`, `r`,
or `t` tag. When it uses an `L` namespace, each `l` tag MUST mark a matching
namespace. Labels are advisory: they MAY influence local warnings/ranking but
MUST NOT change event authorship or constitute NIP-72 approval.

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
["p", "<offending-event-author>", "<optional relay hint>"]
```

It MUST target exactly one event and its actual signing `pubkey`. Its
content MUST validate against
`docs/spec/schemas/social/agent-policy-receipt-v1.schema.json`, whose closed
Social JSON binds profile/version, offending event id and author, the verified
Comms agent association or explicit null, policy id/version, advisory decision,
reason, observation time, evidence references or digests, explanation, and
bounded remediation. It carries no root, KEL, or epoch authority. It MUST NOT
expose a token, secret, private claim, raw sender proof, or protected audit
record.

A valid receipt publicly informs. It does not mute, hide, establish editorial
authority, or prove a private token failure by itself. A recipient MUST verify
the receipt signature, exact tag/body binding, offending event signature and
author, and the Comms association evidence before showing it as verified. A
moderator or associated persona MUST NOT be displayed as the event author
unless that key actually produced the event signature.

A false-positive correction is a signed `kind:1985` receipt from the correcting
policy authority with `L` namespace `network.heterodyne.agent-policy`,
`l` value `correction`, one `e` tag naming the original receipt, and one `p`
tag naming the same event author. Its content MUST validate against
`docs/spec/schemas/social/agent-policy-correction-v1.schema.json`. A correction
MUST bind the original receipt id, offending event id and author, verified
agent association, same policy id/version, retraction decision, correction
evidence, time, and explanation. It does not restore visibility until the
source-neutrally selected current policy list also removes the original
binding.

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
items to the current active key on the next list write after a user-approved
key transition. Optional Assurance continuity does not change NIP-51
authorship or replacement.

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
`["p","<event-author>"]` mute, one `["e","<receipt-id>"]` reference, and one
closed binding:

```text
["agent_violation", "<event-author>", "<receipt-id>", "<reason-code>"]
```

The client MUST verify the receipt, exact `p`/`e`/`agent_violation` binding,
policy author, and the current replaceable event before the entry can affect
visibility. Current state is selected from the union of valid relay and
authorized-repository candidates by greatest `created_at`, then lowest event
id. A relay-only candidate may therefore be current; carrier location does
not grant or remove policy effect. An unauthorized Radicle ref is not a Core
repository candidate.

Only an explicitly subscribed policy list affects a client. An unsubscribed
receipt or list remains visible information and MUST NOT silently change
ranking or visibility. A reference client MAY ship a visible global
moderator-persona subscription enabled by default, but MUST identify that
source for each filtering decision and let the user inspect, disable, or
replace it. No moderator, registry entry, default client, repository, or relay
has global power.

Enforcement mutes exactly the listed event author. It MUST NOT mute an
associated persona, organization, moderator, hosting NID, or different agent
key. A receipt MAY recommend correcting attribution or replacing that signing
key, but Social policy is advisory and cannot require a persona or Assurance
rotation. A replacement author is evaluated independently.

Correction requires both a valid signed correction receipt and a current
source-neutrally selected list revision removing the original binding. Either
one alone leaves the current subscribed mute unchanged.

<a id="social-sets"></a>
### 7.3 Sets and private configuration

Social supports upstream NIP-51 standard lists and addressable sets, including
follow sets `30000`, relay sets `30002`, bookmark sets `30003`, kind-mute sets
`30007` (whose `d` is the kind string), interest sets `30015`, and starter
packs `39089`. Sets MAY use upstream `title`, `image`, and `description` tags.
They remain unstamped unless a registry profile explicitly opts them in.

Every ordinary Social NIP-51 list or set is a standard signed event publishable
to the persona's NIP-65 write relays. A repository or repository-backed relay
MAY store and serve the exact same event. Upstream private items remain NIP-44-encrypted to self
inside that same publishable event; ciphertext does not make the event or its
metadata private. Repository carriage MUST NOT imply Tier 2 delivery or a
private-repository allow list.

The persona SHOULD also commit each current list revision to its persona
repository. A reader MUST select the newest valid replaceable/addressable
revision across relay and repository candidates without carrier priority and
SHOULD warn when a reachable carrier is missing the selected event. Data whose existence
or size must not be exposed even as ciphertext SHOULD be stored as a
Social-owned private payload in the encrypted config repository instead of a
NIP-51 event.

<a id="social-community-policy"></a>
### 7.4 Community policy lists

A policy persona MAY publish community block/allow policy using `kind:10000`,
`kind:30007`, and `kind:30000`. A community adopts it through `a` tags for
sets or `['p','<policy-active-key 64-lowercase-hex>','<relay hint>','policy']`
in `kind:34550`.
Clients computing that community's view SHOULD apply adopted sources after
verifying their NIP-01 signatures and selecting current replaceable state. An
unassured policy key is complete. Optional Assurance may add continuity
evidence without becoming an enforcement prerequisite. A follower MAY
subscribe to additional policy personas independently.

<a id="social-admission-policy"></a>
### 7.5 Web-of-trust and the Comms acceptance hook

Social implements mute and web-of-trust admission only through
[`heterodyne:0.5.0#comms-acceptance-hook`](heterodyne-comms.md#comms-acceptance-hook). Authentication and all Comms
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

A Social policy MUST preserve the no-signal rule that
[`heterodyne:0.5.0#comms-ordinary-conversation-admission`](heterodyne-comms.md#comms-ordinary-conversation-admission)
places on `hold-as-message-request`. Muting or
blocking a sender maps an otherwise acceptable ordinary Marmot conversation
to `reject`; it never authenticates a sender. This lattice applies only to
the Comms ordinary-conversation hook. It does not consume or alter a Control
group admission result.

Web-of-trust ranking is local policy, not canonicality. A graph MAY be built
from verified `kind:3` follows, public Social mute profiles, and weighted
NIP-32 labels. It MUST NOT change whether a post is signed, authored, selected
under NIP-01, or NIP-72-approved.

<a id="social-atproto"></a>
## 8. Optional ATProto attached outbox


ATProto is an OPTIONAL decorative public outbox and witness surface. It is not
the persona identity, a required transport, or recovery authority. The current
active npub and its valid Nostr events remain authoritative. Optional
Assurance continuity is extra evidence only.
Private or audience-gated content MUST NOT mirror to ATProto. An ATProto
failure MUST NOT fail or roll back ordinary Heterodyne publication.

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
{"spec_version":"heterodyne/0.5.0","did":"<DID>","did_signing_key_id":"<key id>","npub":"<active Nostr key hex>","rid":"<canonical RID>","established_at":0}
```

`rid` is omitted only if no RID exists. Transport-specific account
identifiers MUST NOT appear in the signed payload. The Nostr attestation MUST
be signed by the current active key named by `npub` and include exactly one
each of `d=<DID>`, `heterodyne=atproto_link`, `npub=<active-key>`, and
`did=<DID>`, and use the canonical payload above as its JSON `content`. The in-content
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
payload's active npub; locate Social `kind:31009` candidates through that
author's NIP-65 relays and repository relay hints; apply ordinary NIP-01
addressable-event selection; verify the selected event id, active-key
signature, tags, and byte-exact payload; and finally require the two payloads
to be identical. Optional Assurance continuity may be displayed separately.

<!-- fixture:atproto-identity-link -->
```json
{
  "nostr_event": {
    "pubkey": "531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337",
    "created_at": 1710000000,
    "kind": 31009,
    "tags": [["d","did:web:alice.example"],["heterodyne","atproto_link"],["npub","531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337"],["did","did:web:alice.example"]],
    "content": "{\"spec_version\":\"heterodyne/0.5.0\",\"did\":\"did:web:alice.example\",\"did_signing_key_id\":\"did:web:alice.example#atproto\",\"npub\":\"531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337\",\"rid\":\"rad:zAlice\",\"established_at\":1710000000}",
    "id": "238811dae009972d744370a179ab105e59e366a6ad45f0166740a5cdb45dc45e",
    "sig": "a26c1b3a4afffa9f140ab54369b470a5df7e0973eb09934b4c169f57e55384a992a8cb00a2192ee2adc5a82a7976077dedabc8bbc5fd5d67c36215a899fcafc5"
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
active-key-signed `kind:31009` with `heterodyne=atproto_link_revocation`,
`d=<DID>`, `did`, and `npub`; the closed ordered content has
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
    "tags": [["d","did:web:alice.example"],["heterodyne","atproto_link_revocation"],["did","did:web:alice.example"],["npub","531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337"]],
    "content": "{\"spec_version\":\"heterodyne/0.5.0\",\"record_type\":\"atproto_link_revocation\",\"did\":\"did:web:alice.example\",\"npub\":\"531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337\",\"binding_hash\":\"6adf242345b2ac833ec54689e1eb6607d84897a5a116ef00df447646c5c541a0\",\"revoked_at\":1710000100}",
    "id": "8cc56e87c621bdbfc9d7db52932e26db4e7a3007b02b02a85abefd9541c192ab",
    "sig": "6d5b603bfa816c846ba6958e8262cb48ba7a31f0692fa046dfe19b1d8fb731b3a0da9479c0969863cd6cc786882059d0199925859cad755144288b8efe9ea582"
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
at most one hour. A newer selected kind `0`, kind `10002`, or kind `31009`, a
changed DID document or PDS record, or an observed revocation MUST invalidate
the relevant cache immediately. Any
signature or binding failure MUST invalidate the cached success rather than
extending its TTL.

<a id="social-atproto-mirror"></a>
### 8.3 Mirror publication and witnessing

Mirroring defaults off. An explicit configuration MUST allow-list source
public feeds, Nostr kinds, and either `truncate_with_link` or `full_or_skip`.
Only Tier 1 public material may mirror. The client first completes ordinary
Comms publication to at least one intended destination, then best-effort publishes the adapted PDS
record with a canonical Nostr event-id reference. It SHOULD avoid aggressive
retry.

A verified DID key MAY serve as extra evidence in an optional Assurance
workflow. It MUST NOT replace an active-key signature or become a baseline
Social requirement. A verifier MAY ignore it without losing Social
conformance. A displayed ATProto handle MUST remain marked unverified until
both halves of the binding verify.

<a id="social-security"></a>
## 9. Security invariants


The registry binds these exact Social invariants. An entry the registry binds to a feature is owed only by an implementation
claiming that feature, under
[`heterodyne:0.5.0#core-invariant-scope`](heterodyne-core.md#core-invariant-scope).
The list below is descriptive:

- **SOCIAL-I-PRIVATE-STATE-AT-REST:** Private mute, feed-preference, followed-repository, and other Social state are encrypted at rest using the owning Social or bound Comms profile.
- **SOCIAL-I-NO-CENTRAL-SOCIAL-GRAPH:** Following, transitive discovery, and social-graph evaluation do not depend on a centralized follow-graph oracle.
- **SOCIAL-I-NIP01-AUTHORSHIP:** Every ordinary Social event is authored by the public key that actually produced its valid NIP-01 signature; no persona, agent, moderator, repository, relay, KEL, or feed metadata can substitute another author.
- **SOCIAL-I-SOURCE-NEUTRAL-SELECTION:** Social state unions valid exact events from relays and repositories and applies NIP-01 replaceable selection without carrier priority; seven-day refresh age is warning-only.
- **SOCIAL-I-AGENT-POLICY-LOCAL:** Agent-policy receipts inform publicly, but only an explicitly subscribed and verified current policy list changes a client's local visibility.
- **SOCIAL-I-AGENT-AUTHORSHIP-EXACT:** Agent-policy receipts, corrections, and subscriber-local enforcement bind the actual signed event author and verified Comms agent association; no moderator or associated agent becomes an event author without producing that event's signature.

The mechanism boundaries MUST remain honest. Tier 2, Tier 3, Marmot
conversation, and Radicle persona-inbox guarantees come from Comms. Social
ranking is advisory and never identity or editorial authority. ATProto is an
attached public outbox and optional witness, never persona authority.

<a id="social-strict-profiles"></a>
### 9.1 Social strict profiles

The Social strict profile composes the Core and Comms strict closures and adds
the baseline Social invariants. The agent-policy invariants are bound to
`social.agent-policy-moderation.v1` and are owed under
[`heterodyne:0.5.0#core-invariant-scope`](heterodyne-core.md#core-invariant-scope) whenever that
feature is claimed, so the profile does not restate them.

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
    "SOCIAL-I-NIP01-AUTHORSHIP",
    "SOCIAL-I-SOURCE-NEUTRAL-SELECTION"
  ]
}
```

Beyond its inherited obligations this profile requires a valid signed event to
pass baseline verification before Social policy is applied; initiation of
subscription or polling for a valid `kind:5` deletion within 30 seconds on an
active source, with retry and availability evidence until a terminal
condition; exact receipt/list binding; subscribed-policy transparency;
actual-author-scoped moderation; source-neutral replaceable selection; and a
visible warning when a previously met strict requirement becomes unmet. A carrier partition does not itself make an
otherwise conforming consumer nonconformant.

<a id="social-conformance"></a>
## 10. Conformance


A `Social` report follows the family requirements in
[`heterodyne:0.5.0#core-conformance`](heterodyne-core.md#core-conformance), claims Core+Comms+Social, and implements
§§1-9. It MUST
include async replies/reactions, following and transitive discovery,
cross-persona advertisements, reply inboxes, mixed-tier Social fan-out,
moderation, NIP-51 Social profiles, community policy,
source-neutral feed and organization presentation, optional Assurance-only
continuity vouches, ATProto behavior when advertised, the acceptance-hook
policy, subscriber-local agent-policy moderation when
`social.agent-policy-moderation.v1` is advertised, and every Social invariant
its claim scopes in under
[`heterodyne:0.5.0#core-invariant-scope`](heterodyne-core.md#core-invariant-scope).

Social presentation of persona name, avatar, biography, website, or NIP-05
MUST begin from the current valid kind `0` event selected across relay and
repository candidates under NIP-01. The repository is a durable source, not a
selection override. NIP-05 maps to the active key and does not supersede event
signatures.

Optional lower-layer profiles are claimed only when their owning documents'
requirements are satisfied. Assurance is optional and is never included in
the baseline Social dependency closure.

Report contents, byte-exact wire conformance, vector-ID immutability, and
unknown-version handling are family-wide rules stated once by
[`heterodyne:0.5.0#core-conformance`](heterodyne-core.md#core-conformance) and [`heterodyne:0.5.0#core-versioning`](heterodyne-core.md#core-versioning).
Social adds one stamping rule: plain upstream NIP-51 and NIP-72 events remain
unstamped, and only the exact immutable Social profiles opt into a Social
stamp.
