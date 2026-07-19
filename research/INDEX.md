# Research index

Topic-keyed map into [`sources/`](sources/). Use it to jump to the exact file
and line range that covers a given topic.

Research sources are non-normative background. Apply them through the current
four-document family boundary:

| Family document | Research themes |
|---|---|
| [Heterodyne Core](../docs/spec/heterodyne-core.md) | Nostr identity and signatures, KERI, Radicle identity/storage, decentralized bootstrap |
| [Heterodyne Comms](../docs/spec/heterodyne-comms.md) | Nostr delivery, outbox location, privacy tiers, NIP-44, double-ratchet communication |
| [Heterodyne Control](../docs/spec/heterodyne-control.md) | MCP data layer and agent-session prior art; Control 0.5.0 remains incomplete |
| [Heterodyne Social](../docs/spec/heterodyne-social.md) | Social graph, moderation, lists, Matrix, MLS, and ATProto attachment |

The family dependency graph is `Core <- Comms <- Control` and
`Core <- Comms <- Social`. A source's historical framing does not change
current ownership. In particular, pre-split 0.4.0 source annotations are
archive context, not current section or conformance references.

## Sources

| ID | File | Title | Lines |
|---|---|---|---|
| 01 | [`sources/01-matrix-nostr-integration.md`](sources/01-matrix-nostr-integration.md) | Matrix and Nostr Integration Research | 148 |
| 02 | [`sources/02-nostr-bot-moderation.md`](sources/02-nostr-bot-moderation.md) | Nostr NIPs for Bot Content Moderation | 191 |
| 03 | [`sources/03-nostr-feed-aggregation.md`](sources/03-nostr-feed-aggregation.md) | Nostr NIPs for Feed Aggregation | 174 |

Sources are stored verbatim from Gemini deep-research output, including
"Works cited" sections. **Do not edit them** — treat them as immutable
research artifacts. New analysis, opinion, or design notes belong elsewhere
in the repo.

## Topic → source map

### Architecture foundations

| Topic | Source | Lines |
|---|---|---|
| Matrix federation, DAG, state resolution | 01 | 12–16 |
| Nostr relay-broadcast model, secp256k1 identity | 01 | 17–29 |
| Side-by-side architectural comparison table | 01 | 22–29 |

### Matrix ↔ Nostr bridges and prior art

| Topic | Source | Lines |
|---|---|---|
| `matrix-nostr-bridge` (8go) — stdin/stdout pipeline | 01 | 35–42 |
| Cetacea-Proto (Limit-LAB) — protocol hybridization | 01 | 43–47 |
| Mostr, ActivityPub, REST2NOSTR — broader bridging | 01 | 48–53 |

### Matrix as a social-media substrate

| Topic | Source | Lines |
|---|---|---|
| Rooms as generic data containers | 01 | 58–67 |
| MSC3089 (file storage), MSC2313 (moderation policy rooms), MSC1769 (profile rooms), MSC2946 (Spaces) | 01 | 60–66 |
| MSC3639 — social-media use case spec | 01 | 68–79 |
| MinesTRIX, matrix-social, Posca, Cactus Comments | 01 | 75–79 |
| Cerulean microblogging + MSC2836 free-form threading | 01 | 80–89 |
| Timeline-rooms vs thread-rooms pattern | 01 | 85–87 |
| Decentralized reputation filtering in practice (MSC2313) | 01 | 88–89 |

### Nostr — protocol mechanics and social NIPs

| Topic | Source | Lines |
|---|---|---|
| NIP-01 event structure, "kind" integer, signing | 01 | 94–98 |
| NIP-51 curated lists & private (NIP-44-encrypted) list items | 01 | 99–101 |
| NIP-99 classified listings / kind 30402 | 01 | 102–104 |
| NIP-60 Cashu ecash wallets | 01 | 105 |
| NIP-77 Negentropy sync (set reconciliation) | 01 | 106–107 |
| WebRTC over Nostr (issue #771) — cites Matrix as model | 01 | 96–98 |

### MLS / group cryptography

| Topic | Source | Lines |
|---|---|---|
| NIP-04 deprecation, NIP-44 transition | 01 | 110 |
| Pairwise-encryption scaling problem (Double Ratchet, Megolm) | 01 | 111 |
| NIP-EE — MLS-based Nostr E2EE | 01 | 112–113 |
| Matrix MLS migration, O(log N) vs O(N) | 01 | 114 |
| Marmot Protocol (supersedes NIP-EE in some impls), White Noise | 02 | 173–177 |

### Nostr identity & authenticity

| Topic | Source | Lines |
|---|---|---|
| Cryptographic identity baseline (secp256k1, npub/nsec) | 02 | 7–10 |
| NIP-05 DNS identifiers + relay discovery hints | 02 | 11–23 |
| Verifiable machine identity (BlindOracle kinds 30010–30020) | 02 | 24–29 |
| NIP-89 application handlers w/ social-graph inheritance | 02 | 30–35 |

### Anti-spam / economic friction

| Topic | Source | Lines |
|---|---|---|
| NIP-13 Proof of Work — leading zero bits, difficulty commitment | 02 | 40–49 |
| NIP-43 relay access metadata, invite (kind 28935) / join (28934), NIP-98 auth | 02 | 50–58 |
| NIP-86 relay management API (`banpubkey`, `banevent`, `blockip`) | 02 | 59–60 |
| NIP-57 Zaps as Sybil-resistant economic signal, pay-to-play relays | 02 | 61–66 |

### Relay-side heuristics

| Topic | Source | Lines |
|---|---|---|
| CouchDB Map-Reduce temporal velocity tracking | 02 | 68–72 |
| Collaborative filtering, replicated spam scores | 02 | 73–75 |
| Legal pressure on relay operators (CSAM, malware) | 02 | 76 |

### Outbox routing (NIP-65)

| Topic | Source | Lines |
|---|---|---|
| Outbox topology overview, kind 10002 mechanics | 02 | 77–86 |
| read / write markers, sparse routing recommendation | 03 | 28–37 |
| Feed aggregation flow under the Outbox model | 03 | 38–43 |
| Inbox routing for replies & mentions | 03 | 42–43 |

### Distributed moderation & labeling

| Topic | Source | Lines |
|---|---|---|
| NIP-56 reporting taxonomy (kind 1984), severity indices | 02 | 91–102 |
| Social-graph-weighted moderation (vs global delete) | 02 | 101–102 |
| NIP-32 labeling (kind 1985, `L`/`l` namespaces) | 02 | 103–108 |
| Podcast namespace case study (kind 1985 cross-app curation) | 02 | 108 |
| Ontological labeling for feeds (ISO geo/language, retro-tagging) | 03 | 94–100 |

### Mute lists, curation sets, starter packs

| Topic | Source | Lines |
|---|---|---|
| NIP-51 mute lists kind 10000, kind 30007 surgical mutes, curation 30004–30006 | 02 | 109–120 |
| Hybrid public/private list (NIP-44 encrypted content) | 02 | 118–120 |
| NIP-51 advanced lists (bookmarks 30003, interest sets 30015) | 03 | 60–77 |
| Starter Packs (kind:39089), Media Starter Packs (kind:39092) | 03 | 78–83 |

### Moderated communities & relay groups

| Topic | Source | Lines |
|---|---|---|
| NIP-72 reddit-style: 34550 definition, 1111 submission, 4550 approval | 02 | 125–134 |
| Mod-key revocation via NIP-09 deletion of `p` tag in 34550 | 02 | 133–134 |
| NIP-29 relay-based groups, `<host>'<group-id>` addressing | 02 | 135–141 |
| NIP-29 server-enforced roles, moderation events 9000–9020 | 02 | 137–141 |
| NIP-70 Protected Events `-` tag | 02 | 141 |
| Community feed aggregation via 4550 approval signatures | 03 | 156–161 |

### Web of Trust & reputation

| Topic | Source | Lines |
|---|---|---|
| NIP-85 trusted assertions, kind 10040 authorization, kind 30382/30383/30385 | 02 | 142–155 |
| wot-scoring (PageRank over follow graph) | 02 | 149 |
| Personalized points of view via provider choice | 03 | 132–142 |
| WoT-driven feed ranking & Damus reply sorter | 02 | 153–155 |

### Data Vending Machines (NIP-90)

| Topic | Source | Lines |
|---|---|---|
| NIP-90 kind ranges (5000–6999 requests/results, 7000 feedback) | 02 | 156–171 |
| DVM moderation flow (job request → payment-required → result) | 02 | 161–171 |
| TrueMatch case study (NIP-90 → NIP-17 negotiation) | 02 | 169–171 |
| DVM marketplace for compute, bid tags, Bolt11 settlement | 03 | 116–131 |
| Algorithmic feed generation via DVMs (commoditized recommendation) | 03 | 126–131 |

### Social graph & threading

| Topic | Source | Lines |
|---|---|---|
| NIP-02 follow lists (kind:3), Petname scheme, suggested-follows heuristic | 03 | 9–19 |
| NIP-10 threading conventions (positional `e`/`p` tags) | 03 | 20–26 |

### Infrastructure & relay discovery

| Topic | Source | Lines |
|---|---|---|
| NIP-11 Relay Information Document (capabilities, limits, auth/payment) | 03 | 44–52 |
| NIP-66 liveness monitoring (kind 30166, RTT telemetry, network type) | 03 | 53–58 |

### Search & active discovery

| Topic | Source | Lines |
|---|---|---|
| NIP-50 search capability framework, relevance scoring | 03 | 84–93 |

### Economic signaling for discovery

| Topic | Source | Lines |
|---|---|---|
| NIP-57 zaps (kind 9734 request, 9735 receipt), trending feeds | 03 | 101–110 |
| NIP-75 zap goals (kind 9041) | 03 | 111–115 |

### Application handlers

| Topic | Source | Lines |
|---|---|---|
| NIP-89 kind 31989 recommendation + 31990 handler info | 03 | 143–155 |

### Long-form, calendar, specialized media

| Topic | Source | Lines |
|---|---|---|
| NIP-23 long-form (kind 30023 article, 30024 draft) | 03 | 162–166 |
| NIP-52 calendar events (date kind 31922, time kind 31923, RSVP 31925) | 03 | 166 |

### Security research & academic context

| Topic | Source | Lines |
|---|---|---|
| Matrix vulnerability taxonomy, channel-input attack surface | 01 | 119–125 |
| Nostr cryptographic vulnerabilities ("Not in The Prophecies") | 01 | 125 |
| FEDSTR (federated learning over Nostr, NeurIPS-adjacent) | 01 | 126–132 |
| Sociological / governance research (federation vs broadcast) | 01 | 133–138 |

### Strategic implications

| Topic | Source | Lines |
|---|---|---|
| Convergence via permissionless bridging | 01 | 141 |
| State-sync vs ephemeral-broadcast dichotomy | 01 | 142 |
| Unified MLS for cross-protocol E2EE bridging | 01 | 143 |
| Beyond human communication (decentralized AI infrastructure) | 01 | 144–146 |
| Cold-start problem in decentralized networks | 03 | 78–83 |

## How to use this index

1. Skim the section headers above to locate the relevant topic.
2. Open the cited source file and jump to the line range.
3. Cite back to `research/sources/NN-file.md:LINE_RANGE` when referencing
   research in design docs, ADRs, or commit messages.
4. If you add a new source, append a row to the **Sources** table and add
   topic entries below.
