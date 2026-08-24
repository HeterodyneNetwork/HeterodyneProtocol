# Nostr-First Heterodyne Interoperability Design

**Status:** Approved for implementation planning

**Date:** 2026-08-24

**Scope:** Protocol-family redesign before 1.0; conformance vectors remain a
frozen historical snapshot until a later reconciliation point.

## 1. Summary

Heterodyne becomes a Nostr- and Marmot-native protocol with optional
Heterodyne capabilities, rather than a parallel identity system bridged to
Nostr.

One active Nostr public key is the current network identity of every human or
organizational persona. It is also that persona's Marmot account identity.
Ordinary profiles, relay lists, notes, lists, social events, KeyPackages, and
Marmot account proofs use that key and standard Nostr or Marmot formats.

Cold roots, succession authorities, KERI pre-rotation, witnesses, thresholds,
and epoch keys move into an optional Assurance specification. An existing
Nostr key can attach that layer later without changing its npub or historical
events. A key with no cold root or KERI state is a complete, first-class
Heterodyne persona.

Public discovery uses standard kind `0`, NIP-05, and NIP-65 kind `10002`.
Required Heterodyne identity pointers and public feed indexes are retired.
Public content is signed once and sent unchanged to ordinary relays and any
Radicle-backed NIP-01 repo relay.

Persona- and group-owned Radicle event repositories store exact Nostr events.
Full nodes may offload repository availability and public or private relay
service to explicitly trusted seed nodes. A seed writes only its own
authorized Radicle ref and does not gain persona, repository-owner, or group
authority.

## 2. Goals

The design has these goals:

1. An unmodified Nostr client can use the same active key, profile, NIP-05
   identifier, relay list, public events, and social graph as a Heterodyne
   client.
2. An unmodified Marmot client can use the active Nostr key as the account
   identity and participate through standard Marmot operations.
3. Heterodyne extensions remain ignorable by vanilla clients and never alter
   NIP-01 signature or addressing semantics.
4. Existing Nostr users can adopt Heterodyne without rotating their key.
5. Optional cold-root and KERI assurance can be attached without becoming a
   prerequisite for identity or communication.
6. One full node can safely manage several isolated human, organization, and
   agent personas.
7. Agents are ordinary Nostr authors when they use agent keys, and all
   agent-originated publications remain visibly automated to Heterodyne
   clients even when a persona key signs them.
8. Radicle provides durable, replicated Nostr event storage without becoming
   an alternate authorship system.
9. Trusted seed nodes can provide public and group-private NIP-01 relay service
   without holding persona keys, repository ownership, or MLS plaintext.

## 3. Non-goals

This redesign does not make vanilla clients understand Heterodyne succession,
automation labels, repository trust, or KERI assurance. It makes those
features non-interfering extensions.

It does not preserve the pre-1.0 cold-root-as-persona model. It does not alias
two Nostr pubkeys, rewrite old events, silently migrate Marmot membership, or
make one seed node globally authoritative.

It does not regenerate conformance vectors during ongoing protocol editing.
The current snapshot remains bound to its historical specification version
and repository commit.

## 4. Interoperability criterion

The baseline is interoperable when all of the following hold:

- A vanilla client can import the active `nsec` or use a standard NIP-46
  connection and obtains the same npub as a Heterodyne client.
- It can read and update the persona's kind `0`, NIP-05, kind `10002`, notes,
  replies, reactions, and supported standard lists.
- It can publish and retrieve exact NIP-01 events through ordinary relays and
  a clearnet repo relay without knowing that Radicle backs the latter.
- A vanilla Marmot client can use the active key as its account identity,
  publish standard KeyPackages, and maintain independent device leaves.
- Unknown Heterodyne profile fields, labels, and event kinds do not obstruct
  baseline behavior.

Compatibility does not imply semantic awareness. A vanilla client will show a
persona-key-signed automated note as authored by that persona because it does
not understand Heterodyne's automation label.

## 5. Persona and identity model

### 5.1 Active-key identity

A Heterodyne persona is identified by exactly one active Nostr public key.
Human and organizational personas share the same wire model. Their differences
are authorization policy, custody, delegates, and presentation.

The active key:

- is the persona's npub and Marmot account identity;
- authors its standard profile, relay list, public events, lists,
  KeyPackages, and account-to-leaf proofs;
- is normally long-lived and changes only through exceptional succession or
  recovery; and
- remains the only identity used in Nostr filters, tags, coordinates,
  signatures, and replaceable-event namespaces.

An agent key is a separate Nostr author. A client connection key or delegated
key that signs an event directly is likewise the actual Nostr author of that
event. Heterodyne association never changes NIP-01 authorship.

### 5.2 Full-node persona isolation

A full node may manage zero or more isolated persona vaults. Every vault has
its own active key, repository set, relay configuration, delegates, signer
policy, OIDC context, agents, and audit state. A full node may hold user keys,
organization keys, agent keys, or any combination. The node does not become
those personas.

Every signer authorization binds exactly one persona, selected signing key,
key class, and permission set. Cross-vault lookup or fallback is forbidden.

### 5.3 Succession

A successor active key is a new Nostr identity. A valid optional Assurance
chain can prove continuity to Heterodyne clients, but it cannot alias the old
and new pubkeys.

Heterodyne clients may display one verified identity history. Local follow
migration may follow user policy. Events, trust decisions, moderation state,
Marmot membership, group authority, financial permissions, and subordinate
keys do not silently transfer.

## 6. Profile, NIP-05, and outbox discovery

### 6.1 Kind `0`

Every persona publishes an ordinary replaceable kind `0` profile signed by its
active key. Standard fields include `name`, `display_name`, `about`, `picture`,
`banner`, `website`, and `nip05` when applicable.

A profile may include one closed `heterodyne` object. `profile` is required
when the object is present; every other member is optional:

| Member | Exact value class | Meaning |
|---|---|---|
| `profile` | canonical `rad:z` RID | Persona-owned repository that acts as the Heterodyne profile and public outbox root |
| `identity_chain` | canonical NIP-19 `naddr` | Current optional Assurance chain address |
| `cold_root` | 64-character lowercase hexadecimal x-only public key | Discovery hint for the attached cold root |
| `succession_authority` | 64-character lowercase hexadecimal x-only public key | Discovery hint for the current designated succession authority |

The object permits no other members. An invalid object is ignored as a whole
without invalidating the surrounding standard kind `0`. All members are hints
signed by the active key, not independent authority. A Heterodyne client checks
them against signed repository records and previously pinned Assurance state.
A vanilla client ignores them.

Editing the profile in a vanilla client may remove unknown fields. Their
absence removes optional discovery hints; it does not invalidate the persona,
its Nostr events, or previously pinned Assurance state.

### 6.2 NIP-05

NIP-05 remains a DNS-based identifier mapping, not an event type. The
`/.well-known/nostr.json` response maps a name to the active persona key. Its
optional relay hints aid bootstrap but do not replace NIP-65.

When succession changes the active key, the operator updates the NIP-05
mapping. Vanilla clients see a new npub. Heterodyne clients may additionally
verify continuity through Assurance.

### 6.3 NIP-65

Every persona publishes a standard kind `10002` relay list. Ordinary read and
write relays use normal NIP-65 semantics. A publicly reachable repo relay is
listed as an ordinary relay endpoint. The list stays small enough for
conventional clients.

Kind `0` and kind `10002` are spread to ordinary index relays and stored
unchanged in the persona's repository.

The normal discovery walk is:

1. Resolve an active npub directly or through NIP-05.
2. Fetch kind `0` and kind `10002` from known relays.
3. Use the declared write relays to retrieve the persona's events.
4. A Heterodyne client may additionally fetch the repository and optional
   Assurance chain.

Required kind `31005` identity pointers and kind `31007` public feed indexes
are retired. Public discovery uses NIP-01 filters and NIP-65 outboxes.

## 7. Source-neutral current state and freshness

Relay and repository copies are the same exact signed events. A client unions
valid candidates from every reachable carrier and selects current replaceable
state using NIP-01: greatest `created_at`, then lowest event ID on a tie.
Carrier location never changes which candidate wins.

When reachable, the persona repository is the preferred durable source and
reconciliation target. It is not a source-priority override. A newer valid
relay event missing from the repository wins immediately. The repository is
behind until an authorized writer ingests those exact bytes.

When the repository is unreachable, relay-derived state remains fully usable
ordinary Nostr state. Repository reconciliation fills missing exact events
without re-signing, normalizing, or replacing a newer event.

Heterodyne publishing clients refresh kind `0` and kind `10002` at least once
every seven days, even when their contents are unchanged. A local signer,
NIP-46 service, or full node may schedule the refresh. Exceeding seven days
produces a visible staleness or liveness warning; it never invalidates the
last correctly signed events.

## 8. Publishing and retrieval

One publication intent produces exactly one signed Nostr event. The client
fans out the exact bytes without re-signing.

Public destinations include the author's NIP-65 write relays, applicable read
relays of tagged recipients, any repo relay already present in kind `10002`,
and other explicitly selected ordinary relays.

A repository-backed relay receives the same NIP-01 `EVENT` message as any
ordinary relay. It persists the event through an authorized Radicle writer
ref. It adds no envelope or storage signature to the Nostr object.

Retrieval queries the author's write relays and reachable repository relays,
verifies every event locally, deduplicates by event ID, and applies ordinary
replaceable-event selection.

Partial delivery succeeds when at least one intended destination accepts the
event. Failed destinations remain eligible for retry using the same bytes and
event ID. If none accept, the event stays locally pending. There is no custom
public feed index into which it could be prematurely committed.

## 9. Signing, NIP-46, and OIDC

### 9.1 Custody choices

One logical Nostr identity does not require copying its secret into every
client. A user may select local-key mode, NIP-46 remote signing, several
authorized signers under an explicit custody policy, or a combination.

Marmot MLS leaf secrets remain independent and device-local in every mode.

### 9.2 OIDC-bound remote signing

OIDC authorizes signer use; it does not change NIP-46 or Nostr wire formats.
The recommended flow is:

1. A client completes an OAuth/OIDC authorization flow.
2. The grant binds the exact persona, NIP-46 client pubkey, signer audience,
   key class, permitted methods and event kinds, finite limits, and expiry.
3. The signer issues a one-use NIP-46 connection secret or activates a pending
   connection.
4. Standard NIP-46 requests operate under that server-side grant.

Access tokens, private claims, and audit identifiers never enter public Nostr
events or bunker URLs. NIP-46 requested permissions and client metadata are
hints only; signer policy is authoritative.

### 9.3 Automated authorship

Agent-key signing is the preferred default. An explicit OIDC scope may permit
a persona key to sign agent-originated content.

Every automated request receives mandatory NIP-32-compatible automation
attribution before signing, regardless of selected key. A separate
Heterodyne tag may point to an associated agent key or role without exposing
OIDC subjects, client IDs, token IDs, or private authorization records.

An automated caller cannot remove, replace, or falsify attribution.
Heterodyne clients always render the event as automated. Vanilla clients
ignore unknown labels and otherwise process the event normally.

Human organization delegates remain private audit subjects unless the
organization requires a public byline for that event class.

## 10. Marmot identity and compromise

The active persona key is its Marmot account identity. Heterodyne removes the
separate `marmot:human-messaging` account key.

Several clients may have independent MLS leaves bound to the same account
through Marmot's standard account-identity proof. Sharing an account identity
does not permit concurrent sharing of one leaf secret. NIP-46 or a full-node
signer may produce account-level proofs while clients create, rotate, and
store their leaves locally.

Agent keys are separate Marmot accounts when they participate. Organization
personas use the same account and multi-leaf model.

Routine device changes use standard KeyPackages, Adds, Welcomes, Removes, and
group epoch advancement.

A Nostr-key succession creates a new Marmot account identity. Every affected
group must explicitly remove old leaves and add new leaves bound to the
successor. Heterodyne continuity cannot alias accounts inside MLS.

A compromise-driven succession performs a full reset:

- revoke old NIP-46 sessions and OIDC tokens;
- invalidate subordinate client, delegate, node, user, and agent signing
  grants;
- remove every old Marmot leaf;
- advance reachable groups to fresh cryptographic state;
- publish fresh KeyPackages and add fresh successor-account leaves;
- explicitly reauthorize agents, delegates, full nodes, repositories, and
  trusted seeds; and
- mark groups unable to transition as compromised or stalled.

This intentionally assumes compromise of the active Nostr key may coincide
with compromise of the account's MLS material.

## 11. Optional Assurance specification

### 11.1 First-class unassured personas

A bare active Nostr key is a complete Heterodyne persona. It requires no cold
root, KERI state, succession authority, warning, or downgraded conformance
label. Clients may report the presence of additional assurance factually but
must not call an ordinary key invalid or incomplete.

### 11.2 Enrollment

An existing Nostr persona may later attach Assurance without changing its
active key or history.

Enrollment uses reciprocal proof:

- the cold root signs an inception record binding the active key and optional
  succession, epoch, witness, or threshold policy; and
- the active key signs an acceptance record binding that exact inception.

Reciprocal proof is required only to attach the optional layer. A persona that
never attaches it needs neither proof.

Earlier Nostr events remain valid but are accurately described as predating
enhanced assurance.

Once a client pins Assurance, the active key cannot remove or weaken it
unilaterally. A downgrade requires the current recovery authority and active
key consent when the active key remains available. New clients may use
trust-on-first-use; established clients retain pinned state when profile hints
disappear or conflict.

### 11.3 Chain and associated keys

Assurance records may be carried unchanged through relays and repositories.
They can retain KERI-style pre-rotation, designated succession, witnesses,
thresholds, and epoch authority.

Cold roots provide rare recovery authority. Succession authorities authorize
future replacement active keys. Epoch keys may issue bounded administrative
attestations and associated-key grants. None routinely authors persona Nostr
events.

A succession record binds the previous active key and head, new active key,
authorizing evidence, new-key acceptance, routine or compromise class,
effective compromise time when applicable, and any explicit subordinate
reauthorizations. No authority transfers implicitly. Compromise transitions
carry no continuations.

Associated-key records bind an exact role, scope, issuer, subject key,
creation time, optional expiry, predecessor, chain head, and active or revoked
state. Public agent associations require subject-key proof of possession.
Private client and human-delegate grants stay in protected repositories unless
policy requires publication.

Assurance proves enhanced continuity. It never changes Nostr signature,
addressing, filtering, replacement, or Marmot membership rules.

## 12. Radicle event repositories

A logical Nostr event repository belongs to one persona or group. Its RID is a
stable storage locator, not an identity.

Logical contents are the union of currently authorized Radicle writer refs:

- each native writer uses its own NID and signed ref;
- a relay-ingest node uses its own NID and designated ingest ref;
- refs contain exact signed Nostr event bytes;
- events are deduplicated by Nostr event ID;
- replaceable state is derived with NIP-01 rules across the union;
- unauthorized or revoked refs do not enter the accepted view; and
- derived indexes are rebuildable and non-authoritative.

There is no merged event branch whose committer becomes the event author.
Writer authorization and repository ownership are separate. A seed can write
an authorized ingest ref without becoming an owner or Radicle delegate.

Persona repositories may be public or access-restricted. Group repositories
are private unless the group deliberately permits public replication.
Repository access controls replication; Nostr or Marmot cryptography controls
content confidentiality.

## 13. Full nodes and trusted seed nodes

### 13.1 Full node

A full node is an authority and policy node. It may manage persona vaults,
hold or access signing keys, issue and enforce OIDC grants, serve NIP-46 and
Control, manage optional Assurance, and write repositories with its own NID.

It may also host relays or seed repositories, but neither is required.

### 13.2 Seed node

A seed node is an availability provider whose base role is hosting authorized
Radicle repositories. Optional features add public NIP-01 repo relay, private
group relay, trusted routing, and relay-ingest writing.

A seed receives no persona signing, organization, group-administration,
repository-owner, or MLS authority merely by implementing those features. A
combined deployment may implement full-node and seed roles, but their grants
and conformance claims remain independent.

Trusted seeds are configured by Radicle NID. Endpoint advertisements bind
relay and Radicle endpoints to that NID. A relay may expose a standard Nostr
relay identity, but the Heterodyne trust decision remains anchored to the
configured seed NID.

Several trusted seeds may be authorized concurrently. Each has an independent
endpoint, ACL grant, and writer ref. Seeds are replaceable availability
providers, not primary or canonical group authorities.

### 13.3 Private group relay

Private relay access uses NIP-42 account authentication. This deliberately
reveals account-to-group membership to the explicitly trusted seed; Marmot's
transport already exposes metadata, and this confines the added trust to
chosen hosts.

The seed enforces a current, private, admin-signed ACL projection containing:

- allowed account keys and read/write roles;
- current Marmot routing identifier;
- target private RID;
- authorized seed NIDs;
- sequence and predecessor;
- binding to the relevant Marmot group-state transition; and
- expiry.

The seed maps authenticated routing hints to the authorized repository and
writes accepted exact events under its own NID. It receives no MLS leaf or
content-decryption key. Missing, stale, expired, conflicting, unauthorized,
or ambiguous ACL state fails closed.

## 14. Organization personas

Organizations use the same persona model as humans: one active Nostr key, one
standard profile and relay list, and optional Assurance.

Several human delegates and agents may request organization signatures through
NIP-46 and OIDC. Human delegate identity stays in private audit state by
default; organization policy may require a public byline. Agent origin is
always publicly marked.

Several administrative nodes may hold or access the active organization key.
Replicated custody, hardware signers, or threshold signing are implementation
choices because the public result remains an ordinary BIP-340 signature.

## 15. Failure and security behavior

The protocol distinguishes cryptographic validity, selected current state,
durability, and availability.

A malicious relay or seed may omit, delay, replay, or selectively serve events
but cannot forge an active-key signature. Clients use multiple relays and
authorized seeds, verify locally, and apply source-neutral selection.

Repository consumers ignore unauthorized or revoked refs, validate every
event, reject routing or author mismatches, and treat writer NIDs only as
storage provenance. Newer relay state makes a repository visibly stale until
reconciled.

Private seeds require both NIP-42 authentication and current ACL authority for
reads and writes. They fail closed for unknown groups, ambiguous routes, stale
projections, unauthorized accounts, and revoked seeds.

Signer authorization is persona-specific, key-class-specific,
audience-restricted, sender-constrained, scope-limited, and short-lived.
NIP-46 metadata cannot grant authority. Automated callers cannot bypass
attribution. Tokens and private audit data never enter public events.

Pinned Assurance cannot be downgraded by an active key alone. Succession never
rewrites authorship. Compromise resets subordinate authority and Marmot state.
Absence of Assurance never invalidates a baseline persona.

Loss of repository access falls back to ordinary relays. Loss of ordinary
relay access may fall back to a repo relay or native repository access.
Missing weekly refresh yields a warning, not invalidity.

## 16. Specification ownership

The protocol family is reorganized as follows:

- **Core:** active-key personas, NIP-01 verification, profile and relay-list
  semantics, source-neutral state selection, Radicle event repositories, and
  public seed/repo-relay primitives;
- **Assurance:** optional cold root, enrollment, KERI, succession, witnesses,
  epoch authority, downgrade resistance, and enhanced associated keys;
- **Comms:** standard publishing and retrieval, Marmot, agent accounts,
  automation attribution, private group routing, and trusted-seed private
  relay ACLs;
- **Control:** multi-client and multi-persona signer management, NIP-46, OIDC,
  signer selection, private grants, compromise recovery, and trusted-seed
  provisioning;
- **Social:** vanilla-compatible social NIPs without required KEL or custom
  feed-index resolution; and
- **Workspace:** active-key workspace and organization personas, governance,
  and delegate policy rather than cold-root identity.

Assurance depends on Core. Other documents may optionally compose Assurance
but cannot require it for their baseline features.

## 17. Pre-1.0 migration

This is a semantic replacement, not a compatibility-preserving revision.

- Existing vanilla Nostr users adopt Heterodyne with their current key.
- Existing Heterodyne users select an active Nostr key, normally their current
  operational key.
- A former cold root may be attached through reciprocal Assurance enrollment.
- Old profiles may publish ordinary breadcrumbs to the selected active npub.
- Existing separate Marmot accounts transition through standard group
  operations.
- Historical events remain valid under their original rules but do not define
  current conformance.

No pre-1.0 revision number or vector identifier constrains this redesign.

## 18. Verification and vector policy

Before vector reconciliation, protocol work verifies prose consistency,
closed schemas, registry coherence, standard interoperability, and targeted
behavior.

Acceptance coverage will include:

- vanilla Nostr local-key and NIP-46 use;
- vanilla Marmot account and multi-leaf operation;
- personas with no Assurance;
- later reciprocal Assurance enrollment and downgrade resistance;
- routine and compromise succession;
- full Marmot compromise reset;
- user-key and agent-key automated publication;
- OIDC-bound NIP-46 and cross-persona isolation;
- source-neutral relay/repository selection and seven-day staleness;
- exact-byte repository ingestion and authorized-ref union;
- concurrent and revoked trusted seeds;
- NIP-42 private relay access and ACL transitions; and
- stale, conflicting, expired, unauthorized, or misrouted private-group
  state.

The current vector corpus is not rewritten as part of ongoing protocol
editing. It remains a historical snapshot tied to its declared specification
version and repository commit. A later deliberate reconciliation authors one
new latest snapshot against the stabilized protocol.

## 19. External protocol references

- [NIP-01: basic protocol flow and event semantics](https://github.com/nostr-protocol/nips/blob/master/01.md)
- [NIP-05: DNS-based identifiers](https://github.com/nostr-protocol/nips/blob/master/05.md)
- [NIP-32: labeling](https://github.com/nostr-protocol/nips/blob/master/32.md)
- [NIP-42: relay authentication](https://github.com/nostr-protocol/nips/blob/master/42.md)
- [NIP-46: remote signing](https://github.com/nostr-protocol/nips/blob/master/46.md)
- [NIP-65: relay-list metadata and outbox routing](https://github.com/nostr-protocol/nips/blob/master/65.md)
- [Marmot identity, credentials, and capabilities](https://github.com/marmot-protocol/marmot/blob/master/foundation/identity.md)
- [Marmot protocol principles](https://github.com/marmot-protocol/marmot/blob/master/principles.md)
- [Radicle user and repository model](https://github.com/radicle-dev/heartwood/blob/master/rad.1.adoc)
