# Research — Radicle Heartwood as a candidate core for Heterodyne

Date: 2026-07-01
Slug: `radicle-nostr-pivot`

Prompt: Assess the current (2025-2026) state of the Radicle peer-to-peer code
collaboration network ("Heartwood" stack, Radicle 1.x) to inform a possible
protocol redesign that replaces **Matrix-as-core** with **Radicle-as-core**,
keeps **Nostr** (secp256k1 identity) for identity/discovery, and demotes
Matrix to an optional encrypted-discussion add-on.

## Method & source-quality note

Primary sources used: the Radicle team's own protocol overview on HackMD
(["Radicle Protocol Overview (Heartwood Release)"](https://hackmd.io/@radicle/rJ2UH54P6),
dated 23-Dec-2023 / updated 2-Jan-2024), the `radicle-dev/heartwood` GitHub
repo, and the Radicle release-notes blog (`radicle.dev/YYYY/...`). The
canonical guide at `radicle.dev/guides/protocol` and the mirror
`docs.radicle.xyz/guides/protocol` returned **HTTP 403 / connection refused**
to the automated fetcher on 2026-07-01, so where the guide is cited the text
was reached via search excerpts and the HackMD overview rather than a direct
page fetch. The HackMD overview is authored by the Radicle team and its
technical content matches the guide's search excerpts, so it is treated here as
a primary source, but it predates the 1.0 GA (Sept 2024) and later releases;
version drift is flagged where relevant.

Where a claim could not be confirmed against a primary source it is marked
**UNVERIFIED**.

---

## Key facts (summary)

| # | Topic | Finding | Confidence |
|---|---|---|---|
| 1 | Node identity curve | **Ed25519**, encoded as `did:key`; NID = Node ID = Peer ID = public key. Keys stored in OpenSSH format under `$RAD_HOME/keys`. | High |
| 1 | Repo identity | Canonical-JSON **identity document** (name, `defaultBranch`, `description`, `delegates`, `threshold`), managed as the `xyz.radicle.id` COB. | High |
| 1 | Threshold | Changes require a **quorum of `threshold`-of-N delegates** to sign a new revision. Sole delegate = auto-accept. | High |
| 2 | "Orgs" today | The old **Ethereum/Gnosis-Safe "Radicle Orgs"** (anchoring + multisig) are **deprecated**. Heartwood has **no blockchain dependency** — multi-party control is pure Ed25519 delegates + threshold. "Orgs" now also denotes **Radworks governance groups** (unrelated to the protocol). | High |
| 3 | Repo ID (RID) | `rad:z…` — multibase (base58-btc) of a **SHA-1 hash of the initial identity document**; stable across doc changes. | High |
| 3 | Canonical refs | Each peer signs its refs into `refs/rad/sigrefs` (Ed25519). Canonical `defaultBranch` = the commit a **threshold of delegates** agree on. | High |
| 3 | Generic content store | Repos are bare git repos; **arbitrary signed git objects can be stored and gossiped**. COBs already exploit this (arbitrary structured data as git objects). No content-type restriction found. | Med-High |
| 4 | Private repos | Supported. `visibility: {type: private, allow: [did:key…]}` in the identity doc. | High |
| 4 | Private confidentiality | **NOT encrypted at rest.** Privacy = *selective replication* only. **Plaintext on every allowed/seed node.** Any allowed seeder can read everything. | **High — confirmed verbatim in Radicle docs** |
| 5 | Gossip | 3 message types: **node announcements**, **inventory announcements** (routing table), **reference announcements** (relayed only to seeders of that repo). Data pulled via **git-fetch**. | High |
| 5 | Replication driver | Driven by **explicit seeding policy**, not popularity. No automatic popularity-proportional replication. Followers do not auto-mirror unless they seed. | High |
| 5 | Transport | **Noise XK** over TCP (initiator must know responder's pubkey). **Tor/.onion supported** (a Heartwood goal vs the old QUIC transport). | High |
| 6 | COBs | Collaborative Objects: issues/patches/identity stored as **git objects**, merged with a **custom Rust CRDT inspired by Automerge**. | High |
| 6 | Custom COBs | Yes — reverse-DNS type IDs (`xyz.radicle.issue`, `com.acme.task`), stored under `refs/cobs/<type>/<id>`. New types need **no protocol change**. | High |
| 7 | Curve mismatch | Radicle = **Ed25519**; Nostr = **secp256k1 / BIP-340 Schnorr**. Not interoperable at the key level. | High |
| 7 | KERI stance | KERI is **curve-agnostic** (supports both Ed25519 and secp256k1); pre-rotation commits to a *digest* of next keys regardless of curve. | High |
| 8 | Prior art | Git-over-social exists: **git-ssb** (SSB, likely defunct), **ngit/gitworkshop.dev + NIP-34** (Nostr, active, OpenSats-funded). **No Radicle↔Nostr bridge found.** | Med-High |
| 9 | Node reach | **No official mobile app; no browser/WASM full node.** Node is a native daemon (Linux/macOS). Browsers reach it read-only via `radicle-httpd`. NAT traversal relies on seed nodes (hole-punching in development). | High |

---

## 1. Identity model

**Node identity.** A Radicle node's identity ("NID" — used interchangeably with
Node ID, Peer ID, and Public Key) is an **Ed25519 key pair encoded as a
`did:key` DID**.
(["...generating their unique `NodeId` (NID), which is an Ed25519 key pair that
is encoded as a Decentralized Identifier (DID) using the `did:key` method."](https://hackmd.io/@radicle/rJ2UH54P6))
Keys are stored in **standard OpenSSH format** under `$RAD_HOME/keys`, so
`ssh-add` and friends work on them
([search corpus, radicle.dev docs](https://radicle.dev/guides/user)).
Stability: **stable / core to Heartwood.**

**Repository identity document.** Each repository has an **identity document**
— a **Canonical JSON** document with a `payload` (`name`, `defaultBranch`,
`description`), a `delegates` list, and a `threshold`. It is versioned; changes
must be signed by a quorum of delegates.
(["The identity document is versioned and changes to it must be signed by a
quorum of delegates... stored as a Canonical JSON document."](https://hackmd.io/@radicle/rJ2UH54P6))
The document itself is managed as the **`xyz.radicle.id` COB** ("The
repository's identity document is entirely defined and managed through an `id`
COB" — [protocol/user guide corpus](https://radicle.dev/guides/protocol)).
Stability: **stable.** RIP-2 is referenced as the underlying spec for repo
identity (per search excerpts of the guide); RIP-2 text itself was not fetched
directly — treat the RIP number as **UNVERIFIED**.

**Delegates.** The `delegates` list holds the **public Ed25519 keys**
(expressed as `did:key:` DIDs) empowered to change the identity document and to
establish the canonical main branch
([HackMD overview](https://hackmd.io/@radicle/rJ2UH54P6);
[search corpus](https://radicle.dev/guides/protocol)). Any number of delegates
is supported.

**Threshold.** The `threshold` is an integer M in an M-of-N scheme: an identity
change is authoritative once M delegates sign the proposed revision. If you are
the sole delegate, proposed changes auto-accept.
(["...set the threshold to 2, meaning two delegates must sign off on future
identity changes. Note that if you are the repository's only delegate, proposed
changes will be automatically accepted."](https://github.com/radicle-dev/heartwood/blob/master/rad-id.1.adoc))

**Rotation / delegate change.** Handled through `rad id`, which **proposes a new
revision** to the identity document (with a title and description, like a
commit); the revision is accepted once the threshold signs.
(["The `rad id` command is used to manage and propose changes to the identity...
it proposes a new revision to the identity document."](https://github.com/radicle-dev/heartwood/blob/master/rad-id.1.adoc))
This covers **adding/removing delegates and changing the threshold**. Rotating a
single node's *own* Ed25519 key (key compromise recovery for an individual
delegate) is **not clearly documented as a first-class flow**; in practice a new
key would be added as a delegate and the old removed via a threshold-approved
revision. Treat single-key rotation semantics as **partially UNVERIFIED** —
Radicle has no KERI-style pre-rotation commitment; recovery relies on the
remaining delegates' quorum.

---

## 2. "Orgs" — deprecated on-chain model vs. today

There are **two distinct things** called "Orgs" in Radicle's history; conflating
them is the main risk here.

**(a) The deprecated Ethereum "Radicle Orgs" (2021 era).** Radicle shipped an
**opt-in Ethereum integration** in 2021: teams could **anchor canonical project
metadata to Ethereum** and govern a codebase via a **Gnosis Safe multisig**.
(["With Radicle Orgs, teams can ensure project state immutability by anchoring
canonical project metadata to Ethereum and coordinate on projects with a Gnosis
Safe multi-sig."](https://messari.io/report/radicle-decentralizing-the-code-collaboration-stack))
This belonged to the pre-Heartwood generation and is now **obsolete**:
(["Previous iterations of Radicle... are considered deprecated in favor of
Heartwood."](https://radicle.dev/faq))

**(b) No blockchain in Heartwood.** The current protocol has **moved entirely
away from any blockchain dependency**:
(["Radicle itself is a true peer-to-peer protocol and does not use or depend on
any blockchain or cryptocurrency."](https://radicle.dev/faq))
Heartwood replaced the old QUIC transport with a **Noise-based wire protocol**,
"eliminating the need for TLS certificates and enabling Tor support"
([FAQ / release corpus](https://radicle.dev/faq)). Multi-party control of a repo
is now **purely cryptographic**: the Ed25519 **delegates + threshold** in the
identity document (§1) are the direct successor to the Gnosis-Safe multisig,
with no on-chain anchoring.

**(c) The RAD token / "Orgs" today.** RAD was deployed on Ethereum in Feb 2021
and is now a **governance token only**, under the rebranded **Radworks** DAO.
Confusingly, "Orgs" is **also** the name for **Radworks governance groups**
(Radicle and Drips became independent DAO-supported "Orgs" in May 2023).
(["...the project split into two products: Radicle and Drips, both of which
became independent, DAO-supported Orgs within the DAO, now known as
Radworks."](https://messari.io/report/radicle-decentralizing-the-code-collaboration-stack))
**This governance sense of "Org" is unrelated to the protocol** and imposes no
runtime dependency on a Heterodyne build.

Stability: **high.** The "no blockchain" claim is stated directly in the current
FAQ. Messari (secondary source) supplies the historical Gnosis-Safe/RAD detail;
that history is not load-bearing for the redesign beyond confirming the old
model is gone.

---

## 3. Repositories as data

**RID (Repository Identifier).** Repos are identified by a **content-derived
hash**: the RID is "deterministically derived from the initial version of the
repository's identity document" via **`git hash-object` (SHA-1)**, then
**multibase-encoded (base58-btc)** and **`rad:`-prefixed** (e.g.
`rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5`).
(["The RID is deterministically derived from the initial version of the
repository's identity document... a SHA-1 hash of the document... encoded using
`multibase`... with the `base58-btc` alphabet... prefixed with
`rad:`"](https://hackmd.io/@radicle/rJ2UH54P6))
Because it's derived from the **initial** doc, the RID is **stable even as the
identity document changes**. Note: SHA-1 (git's default object hash); the
overview does not mention SHA-256 git repos, so assume SHA-1 collision-domain
caveats apply — **flag for Heterodyne threat modeling**.

**Signed refs & canonicity.** Each peer authenticates its own view of a repo by
**signing over its heads, tags, and git refs** with its Ed25519 key; these
**signed refs live under `refs/rad/sigrefs`**.
(["...cryptographically signing over repository heads, tags, and pertinent Git
references... These signatures are termed signed refs and are stored under the
`refs/rad/sigref` directory."](https://hackmd.io/@radicle/rJ2UH54P6) — note the
overview text says `sigref`; current code uses the plural **`refs/rad/sigrefs`**,
confirmed by the `rad inspect --sigrefs` command and storage layout
[Radicle 1.7.0 / 1.8.0 notes](https://radicle.dev/2026/03/30/radicle-1.8.0).)
The **canonical `defaultBranch`** is "established dynamically based on the
threshold of delegates having the same commit" — i.e. the commit a threshold of
delegates agree on becomes the authoritative head
([HackMD overview](https://hackmd.io/@radicle/rJ2UH54P6);
[Radicle "Canonical References", 2025-08-12](https://radicle.dev/2025/08/12/canonical-references)).
Recent hardening (relevant if Heterodyne relies on sigrefs as an append log):
`refs/rad/root` and `refs/rad/sigrefs-parent` were added as **anti-replay /
anti-downgrade** measures, with monotonic "feature levels" (`none` → `root` →
`parent`) to detect downgrade attacks
([Radicle 1.7.0](https://radicle.dev/2026/03/18/radicle-1.7.0),
[1.8.0](https://radicle.dev/2026/03/30/radicle-1.8.0)). Stability:
**stable and actively hardened.**

**Can it be a generic append-log / content store?** Effectively **yes.** A
Radicle repo is a **bare git repository** replicated as git objects; COBs
already store **arbitrary structured data as git objects** replayed via CRDT
(§6). Nothing in the sources restricts stored objects to "source code" — you can
commit **arbitrary signed blobs (e.g. signed JSON events)** and they will
replicate like any other git object to seeders of that RID. **Caveat / UNVERIFIED:**
no explicit statement was found on **per-object or per-repo size limits**,
storage-quota policy, or garbage-collection of unreferenced objects; a
high-write social event log would need its own benchmarking. The canonical,
threshold-verified surface is currently limited to the **`defaultBranch`** — the
overview notes "only the branch specified under the `defaultBranch` attribute...
is set automatically based on a signature threshold. In the future, additional
branches may be supported" ([HackMD overview](https://hackmd.io/@radicle/rJ2UH54P6)).
So a multi-writer social log would either share one canonical branch (needing
threshold agreement) or lean on **per-author signed refs / COBs** (each author
signs their own namespace) rather than a single canonical head.

---

## 4. Private repositories — confidentiality semantics (CRITICAL)

**Supported:** Yes. Privacy is chosen at `rad init` and encoded in the identity
document as `visibility`:

```json
"visibility": {
  "type": "private",
  "allow": ["did:key:z6Mkt67GdsW7715MEfRuP4pSZxJRJh6kj6Y48WRqVv4N1tRk"]
}
```

([HackMD overview](https://hackmd.io/@radicle/rJ2UH54P6)). The `allow` list is
optional; access defaults to the repo's delegates plus any explicitly allowed
NIDs/seed nodes.

**Confidentiality model — the decisive point:** Private repos are **NOT
encrypted at rest.** Confidentiality is achieved **only by selective
replication** — the repo is invisible to and un-fetchable by nodes not on the
allow list, but **its contents are plaintext on every node that is allowed to
hold it.**

> "the data is not encrypted at rest, these repositories rely on selective
> replication through the allow list for privacy, which renders them invisible
> and inaccessible to other nodes."
> — [Radicle Protocol Overview (Heartwood Release)](https://hackmd.io/@radicle/rJ2UH54P6)

The user-facing docs make the trust consequence explicit:

> "private repositories are not encrypted at rest, so any seed node that you add
> to the allow list will have visibility to the data... The allow list should be
> limited to people or devices that you trust."
> — [Radicle User Guide corpus](https://radicle.dev/guides/user)

**Threat model as stated by Radicle:** confidentiality is against *the rest of
the network* (non-allowed nodes never see the repo exists), reinforced by
**encrypted+authenticated transport (Noise XK)** between peers. It is **NOT**
confidentiality against an allowed seeder. A community seed node you add to the
allow list can read the full plaintext. Stability: **high, and repeatedly and
explicitly stated** in both the protocol overview and user guide.

**Implication for Heterodyne:** this is the inverse of Heterodyne's current
Matrix/Megolm posture, where the homeserver is a **blind** state manager that
holds only ciphertext. A Radicle "private repo" gives you **not-publicly-gossiped
plaintext**, not **confidential-against-the-host**. If Heterodyne's
`private_broadcast` / `private_discussion` kinds must preserve
"host-can't-read-payload," Radicle private repos **do not provide that on their
own** — Heterodyne would have to keep encrypting content at the application layer
(as it does today) *before* committing it, and treat Radicle purely as an
access-controlled transport/store.

---

## 5. Replication / seeding / gossip

**Gossip protocol — three message types**
([HackMD overview](https://hackmd.io/@radicle/rJ2UH54P6)):

1. **Node announcements** — broadcast the network addresses on which a node is
   reachable (peer discovery). Each announcement carries the originating Node ID,
   a signature, and a timestamp so relayers can verify authenticity.
2. **Inventory announcements** — broadcast which repositories a node holds;
   these build the **routing table** (which RIDs live where).
3. **Reference announcements** — broadcast updates to a repo's refs, **relayed
   only to nodes seeding that repo.**

**Fetch mechanism.** Announcements carry metadata; actual data moves by
**`git-fetch` over the git protocol** once a seeding node learns of an update.
(["...the node initiates a `git-fetch` operation, using the Git protocol, to
download the relevant Git objects."](https://hackmd.io/@radicle/rJ2UH54P6)) So the
model is **announce-then-pull**, not push of payload.

**Seeding.** "Seeding" a repo = choosing to store and help replicate it. Nodes
run a **seeding policy**: an explicit list of repos of interest plus retention
rules. Seed-node archetypes: **public** (seed everything) and **community**
(seed only from trusted peers).
(["Users configure nodes with a seeding policy which specifies the list of
repositories they are interested in seeding... nodes aren't just seeding random
repositories, users have an active choice."](https://hackmd.io/@radicle/rJ2UH54P6))

**Do followers auto-mirror? Popularity-proportional replication?** **No** — there
is no automatic popularity-weighted replication. Replication is **driven by
explicit seeding policy.** A peer only mirrors repos it (or its seed nodes) have
chosen to seed. This is a meaningful difference from Nostr's "post to many
relays" broadcast diffusion and from BitTorrent-style swarm popularity. For a
social feed, **reach is a function of who seeds you**, not of engagement.
Stability: **high.**

**Transport.** Peer connections use **Noise XK** — the responder's static key
must be known to the initiator ahead of time (you dial a node by its Node ID),
carried **over TCP**. After the handshake, transport messages are encrypted.
(["All connections are encrypted with Noise XK (requiring the initiator to know
the public key of the responder...)"](https://github.com/radicle-dev/heartwood/blob/master/HACKING.md);
[HackMD overview](https://hackmd.io/@radicle/rJ2UH54P6)) **Tor / `.onion`** is
supported for address privacy — a stated motivation for the Noise-over-QUIC
switch (["Radicle also has a Tor integration... identified by an `.onion`
address"](https://hackmd.io/@radicle/rJ2UH54P6);
[FAQ](https://radicle.dev/faq)). **Default port UNVERIFIED** — commonly cited as
TCP **8776** in community docs but not confirmed against a primary source here;
verify against `radicle-node` config before relying on it.

---

## 6. Collaborative Objects (COBs)

**What they are.** COBs supplement git with **social artifacts** (issues,
patches, and the identity doc). They are **stored as git objects within each
repository** and merged with a **CRDT**.
(["Collaborative Objects (COBs)... stored within each repository as Git objects,
using Conflict-Free Replicated Data Types (CRDTs) for data
consistency."](https://hackmd.io/@radicle/rJ2UH54P6))

**CRDT — is it Automerge?** It is a **custom Rust CRDT inspired by** Ink &
Switch's Automerge, **not the Automerge JS library itself**:
(["Radicle's CRDTs, inspired by Ink & Switch's Automerge JavaScript library yet
implemented in Rust..."](https://hackmd.io/@radicle/rJ2UH54P6)). Lives in the
**`radicle-cob`** crate (confirmed present under `crates/` in the heartwood repo,
alongside `radicle-crypto`, `radicle-dag`, `radicle-node`, `radicle-fetch`).
Each modification is a **separate git object**; the current state is
reconstructed by **replaying all changes in a deterministic order**, giving a
git-compatible change DAG.
(["Each modification is stored as a separate Git object... replays all the
changes in a deterministic order to reconstruct the object."](https://radicle.dev/guides/protocol))
Stability: **stable core mechanism**; the "inspired by Automerge, custom Rust"
detail is from the team overview and matches the `radicle-cob` crate's existence.

**Three predefined types:** `xyz.radicle.issue`, `xyz.radicle.patch`,
`xyz.radicle.id` ([protocol guide corpus](https://radicle.dev/guides/protocol)).

**Custom COB types by third parties — YES.** COBs are identified by a
**reverse-DNS type name** plus an object ID, so third parties can define new
types under their own namespace (e.g. `com.acme.task`) with **no protocol change
and no network-wide coordination**.
(["globally-unique Type IDs, such as `xyz.radicle.issue`... prevent naming
collisions... users have full control to customize them or define entirely new
datatypes."](https://radicle.dev/guides/protocol)) Storage layout is
**`refs/cobs/<type>/<object-id>`** (the RFC-0662 lineage used
`refs/namespaces/<ns>/cob/<typename>/<objectID>`; current Heartwood uses the
`refs/cobs/…` hierarchy).
(["it's also possible to define... an entirely new COB such as
`org.YourOrg.YourCOB`... without changing the protocol version."](https://radicle.dev/guides/protocol))
Stability: **documented and stable as a concept.** **UNVERIFIED:** the exact
`radicle-cob` Rust API for registering a custom type + schema (trait names,
schema/validation surface) was not fetched from `docs.rs`; a Heterodyne COB
(e.g. `xyz.heterodyne.post`) is plausible but needs an implementation spike to
confirm the authoring ergonomics and whether custom types replicate/verify like
built-ins.

---

## 7. Curve / crypto interop (Ed25519 vs secp256k1)

**The mismatch.** Radicle signs **everything** — node identity, signed refs,
COBs, identity doc — with **Ed25519** ([`radicle-crypto` crate; HackMD
overview](https://hackmd.io/@radicle/rJ2UH54P6)). Nostr identity and event
signatures are **secp256k1 with BIP-340 Schnorr** (`npub`). These are **different
curves and different signature schemes**; a key from one is **not usable** in the
other, and neither natively verifies the other's signatures. There is **no
"convert the key"** — an npub cannot become a Radicle NID or vice versa.

**Binding patterns (prior art for linking the two identities):**

- **NIP-39 external identities** — a Nostr `kind:0` profile can carry `i` tags
  claiming control of external identities via a proof, and clients "SHOULD
  process any `i` tags with more than 2 values for future extensibility."
  ([NIP-39](https://nips.nostr.com/39)). Existing proof types are platform IDs
  (github/twitter/…), and there is an **active PR line adding cryptographic
  identities** ("Linked cryptographic identities... as drafted can work for any
  key that can produce a signature",
  [nostr-protocol/nips#1182](https://github.com/nostr-protocol/nips/pull/1182);
  PGP variant [#1041](https://github.com/nostr-protocol/nips/pull/1041)). This is
  the most idiomatic Nostr-side hook for a **`i ["radicle:<NID>", <proof>]`**
  claim. Stability: NIP-39 itself is stable; the cryptographic-key extension is
  **draft/UNVERIFIED** as merged.
- **Bidirectional cross-attestation** (application-defined): the npub signs a
  statement "I control Radicle NID X" (secp256k1/Schnorr) **and** the Ed25519 NID
  signs "I am controlled by npub Y". Two signatures, one per curve, mutually
  referencing each other — this is exactly the shape Heterodyne already uses for
  its §3.3 delegation and its ATProto/NIP-39 external-identity binding, so it
  extends naturally. No existing Radicle↔Nostr binding standard was found
  (see §8), so Heterodyne would define this.

**KERI's stance.** KERI is **curve-agnostic**: its derivation-code tables define
codes for **both Ed25519 and ECDSA secp256k1** signatures (and Ed448), all at the
128-bit minimum security level.
(["...such as Ed25519 or EcDSA secp256k1... The specification includes codes for
Ed25519 signature... and ECDSA secp256k1 signature..."](https://identity.foundation/keri/kids/kid0001Comment.html);
[KERI, arXiv 1907.02143](https://arxiv.org/pdf/1907.02143)). KERI's **pre-rotation**
commits to a **digest of the next key set** regardless of curve, so a KERI
identifier can even **rotate across curves** (e.g. Ed25519 now, secp256k1 next)
as long as each next-key digest matches. This matters because **Heterodyne's
identity is already KERI-anchored (secp256k1 cold root / epoch keys per
`docs/superpowers/specs/2026-05-21-cold-root-epoch-keys-design.md`)** — a KERI
event stream is a natural, curve-neutral place to authorize an Ed25519 Radicle
NID as a delegated/attested device key without abandoning the secp256k1 root.

---

## 8. Prior art

**Radicle ↔ Nostr bridge:** **No dedicated project found.** Searches surfaced
conceptual discussion and adjacent tooling but **no shipped Radicle-to-Nostr
bridge**. Treat "a bridge exists" as **false / no evidence found** as of
2026-07-01.

**Git-as-social-substrate lineage (real projects):**

- **git-ssb** — the original "GitHub on a P2P social protocol": Git repos, issue
  tracking, and PRs over **Secure Scuttlebutt** append-only feeds
  ([git-ssb intro / P2P Foundation directory](https://wiki.p2pfoundation.net/List_of_Community-Hosted_Code_Forge_Instances)).
  Maturity: **historically important but likely defunct** (directory annotates it
  "maybe defunct"). SSB identity is also **Ed25519**, which is why the SSB→git
  mapping was clean.
- **ngit / `git-remote-nostr` + gitworkshop.dev (NIP-34)** — the modern,
  **active** Nostr equivalent: git repo announcements and patches/issues as Nostr
  events; `git clone nostr://<npub>/<id>`; companion web UI at
  [gitworkshop.dev](https://gitworkshop.dev/). **NIP-34** is an actively
  maintained spec ([nips.nostr.com/34](https://nips.nostr.com/34), PR
  [#997](https://github.com/nostr-protocol/nips/pull/997)); **ngit** is
  **OpenSats-funded** (2023, renewed 2025) and has stable releases
  ([ngit on docs.rs, v1.6.1 2025-04-16 / 2.x](https://docs.rs/crate/ngit/latest);
  [OpenSats](https://opensats.org/projects/ngit)). A complementary host protocol
  **GRASP** ([gitgrasp.com](https://gitgrasp.com/)) and additional clients
  (**gittr**, [github.com/arbadacarbaYK/gittr](https://github.com/arbadacarbaYK/gittr))
  interoperate on the same events. Maturity: **active, multi-client, funded** —
  the most directly relevant prior art, and notably it **keeps Nostr for
  metadata while git data lives on ordinary git servers** (a very different
  split from Radicle-as-core).
- **Secure Scuttlebutt (SSB)** itself — unforgeable Ed25519 append-only feeds for
  a P2P social network ([ssbc](https://github.com/ssbc/ssb-server)); the
  intellectual ancestor of "signed append log as social substrate." Maturity:
  mature but declining activity.

**Radicle used as a generic social/event log:** **No evidence found** of a
production or notable-experimental project using Radicle repos as an
activity/event log for a social app. This appears to be **novel territory** for
Heterodyne. (Marked **UNVERIFIED-absence** — absence of evidence, not proof of
absence.)

---

## 9. Limitations relevant to social use

**Gossip propagation latency.** **No hard numbers found** in primary sources —
**UNVERIFIED.** Architecturally, propagation is **announce-then-fetch**: a
reference announcement is relayed to seeders, who then `git-fetch`. Practical
latency depends on connectivity, NAT, and seed-node availability rather than a
fixed SLA. For a chat-grade "instant" social feed, expect **seconds-to-minutes
and variable**, not real-time — but this is an inference, not a measured figure.

**Real-time push.** There is **no payload push**. The wire protocol pushes
**announcements** (metadata), and peers **pull git objects on demand**. There is
no documented streaming/subscription channel for live message delivery to a
passive client. A responsive UX would need a `radicle-httpd`-style gateway
polling/long-polling a node, or an out-of-band notification layer (this is
exactly the sort of role Heterodyne might keep **Matrix** for).

**Mobile.** **No official mobile app.** Node requirements are a
**Linux/Unix/macOS** machine and terminal familiarity; "every Radicle user...
runs a node on their device," and the node is a **persistent native daemon**
([HackMD user guide](https://hackmd.io/@radicle/H1QjlQKoT);
[radicle.dev](https://radicle.dev/)). A persistent background daemon fits poorly
with mobile app lifecycles (aggressive backgrounding, no long-lived raw TCP).
**No iOS/Android Radicle node found — UNVERIFIED that one exists.**

**Browser / WASM.** **No full node in the browser / no WASM node found.** The web
app ([app.radicle.xyz](https://radicle.dev/)) is a **frontend that talks to a
node via `radicle-httpd`**, the HTTP daemon that exposes the node's storage as a
**read-only JSON API**. So "Radicle in the browser" means **a read-only web
client over a remote node's HTTP gateway**, not a browser peer joining the P2P
network. `radicle-httpd` is a separate component (not currently under `crates/`
in the heartwood mirror snapshot — **UNVERIFIED** whether it moved to its own
repo or was renamed; the `rad web` / `app.radicle.xyz` flow is documented and
current).

**Hard blockers to browser/mobile replication:**

1. **Raw TCP + Noise XK.** Browsers cannot open raw TCP sockets, and the Noise XK
   handshake is a native transport — a browser cannot join the gossip network
   directly. (WebSocket/WebTransport bridging is not documented.)
2. **Persistent daemon model.** Full participation requires an always-on node
   that continuously announces/fetches; incompatible with sandboxed/backgrounded
   environments.
3. **NAT traversal.** Peers behind NAT currently **depend on seed nodes** to
   relay data; direct hole-punching is **"under development"** (**UNVERIFIED**
   ship date). Mobile carrier NAT makes this worse.
4. **Write path needs signing keys on-device.** Publishing (signing refs/COBs)
   requires the Ed25519 key locally; a thin web client over `httpd` is
   effectively **read-mostly** unless it also holds keys and can reach a writable
   node.

Net: for Heterodyne, a **Radicle-as-core** design implies **every user runs a
native seed/node** (desktop/server), with **mobile and web as read-oriented
clients over an HTTP gateway** — the opposite of Matrix's thin-client /
always-available-homeserver model.

---

## Tensions / open questions for the redesign

1. **Private-repo confidentiality is the biggest semantic gap.** Radicle private
   repos are **plaintext on allowed seeders** (§4). Heterodyne today treats the
   host as a **blind** ciphertext router (Megolm). Replacing Matrix-core with
   Radicle-core **loses host-blindness unless Heterodyne keeps encrypting at the
   app layer before committing** — i.e. Radicle becomes an access-controlled
   *store of ciphertext*, and Heterodyne still owns group crypto. That erases one
   of the original "outsource group privacy to Matrix's ratchet" wins. Decide
   explicitly: is the value of Radicle the **content-addressed signed log +
   git-native replication**, with encryption staying in Heterodyne?

2. **Curve mismatch is unavoidable and must be bridged in-protocol.** secp256k1
   (Nostr identity) ≠ Ed25519 (Radicle NID). There is **no drop-in binding
   standard** (§7, §8). Heterodyne must define a **KERI-anchored attestation**
   authorizing a per-device Ed25519 Radicle NID from the secp256k1 root/epoch key
   (this fits the existing cold-root/epoch design and NIP-39's emerging
   cryptographic-identity `i` tag). Open question: does the Radicle NID become a
   **§3.3-style delegated key** in the KERI stream, and how is its revocation
   propagated to seeders who only speak git?

3. **Reach model is "who seeds you," not broadcast diffusion (§5).** No
   popularity-proportional replication; a post reaches only nodes that seed your
   RID. This is closer to "follower keyring = seed set" (which actually maps
   nicely onto `private_broadcast`'s follower model) but **breaks the
   open-broadcast, relay-fanout assumption of `public_broadcast`**. How does an
   open Twitter-style public feed get wide reach without relays? Likely answer:
   **keep Nostr relays for public broadcast**, use Radicle only for
   private/closed kinds — which argues for Radicle-as-*one-transport*, not
   Radicle-as-sole-core.

4. **No real-time push / uncertain latency (§9).** Announce-then-fetch with
   no measured propagation SLA is a poor fit for chat-grade discussion. This is a
   direct argument for **keeping Matrix (or Nostr relays) as the low-latency
   discussion transport** and letting Radicle carry the durable, signed,
   content-addressed record.

5. **Mobile/browser are read-mostly over an HTTP gateway (§9).** A native node
   per user is heavy for a consumer social app. If most users are on phones, the
   realistic topology is **user-run/community seed nodes + thin `httpd` clients**,
   which reintroduces a semi-trusted-server shape (the seed node sees plaintext,
   per §4) — re-examine whether that beats the current Matrix homeserver model.

6. **Canonical head is single-branch + threshold today (§3).** A multi-writer
   social event log can't rely on one threshold-canonical branch per author.
   Design question: **one repo per persona with per-author signed refs / COBs**,
   or **one shared repo with COB-based multi-writer semantics**? Confirm COB
   write/replication ergonomics for a custom `xyz.heterodyne.*` type before
   committing (the custom-COB API is **UNVERIFIED** at the crate level).

7. **SHA-1 object hashing (§3).** RID and git objects are SHA-1-based per the
   overview. For a security-sensitive social protocol, confirm whether
   SHA-256-mode git repos are supported and model the SHA-1 collision surface.

8. **Version drift caveat.** The richest single primary source (the HackMD
   overview) predates 1.0 GA (Sept 2024) and the 1.7-1.9 releases (2026). Sigrefs
   hardening, canonical-references changes (2025-08), and any private-repo or COB
   API changes since should be re-verified against the **live protocol guide**
   (which blocked the automated fetcher on 2026-07-01 — fetch manually) and the
   `heartwood` source before locking design decisions.

---

## Appendix — primary sources

- Radicle Protocol Overview (Heartwood Release), HackMD (Radicle team): https://hackmd.io/@radicle/rJ2UH54P6
- Radicle User Guide, HackMD: https://hackmd.io/@radicle/H1QjlQKoT
- Radicle Protocol Guide (403 to fetcher; verify manually): https://radicle.dev/guides/protocol
- `radicle-dev/heartwood` (repo + `rad-id.1.adoc`, `HACKING.md`): https://github.com/radicle-dev/heartwood
- Radicle FAQ ("no blockchain / previous iterations deprecated"): https://radicle.dev/faq
- Radicle "Canonical References" (2025-08-12): https://radicle.dev/2025/08/12/canonical-references
- Radicle 1.7.0 / 1.8.0 release notes (sigrefs hardening, feature levels): https://radicle.dev/2026/03/18/radicle-1.7.0 , https://radicle.dev/2026/03/30/radicle-1.8.0
- Messari report (historical Orgs/RAD/Gnosis-Safe context; secondary): https://messari.io/report/radicle-decentralizing-the-code-collaboration-stack
- NIP-34 (git over Nostr): https://nips.nostr.com/34 ; ngit / gitworkshop.dev: https://gitworkshop.dev/ ; OpenSats: https://opensats.org/projects/ngit
- NIP-39 (external identities) + linked-crypto-identity PRs: https://nips.nostr.com/39 , https://github.com/nostr-protocol/nips/pull/1182
- KERI: arXiv 1907.02143 https://arxiv.org/pdf/1907.02143 ; derivation/curve tables: https://identity.foundation/keri/kids/kid0001Comment.html ; pre-rotation: https://identity.foundation/keri/kids/kid0005Comment.html
