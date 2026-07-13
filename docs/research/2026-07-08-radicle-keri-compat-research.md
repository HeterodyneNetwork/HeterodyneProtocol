# radicle-keri compatibility research

Date: 2026-07-08
Status: research (non-normative)
Subject: https://github.com/radicle-dev/radicle-keri vs Heterodyne's KERI
profile (spec section 3.5, 3.3.1, 3.9.10)

## Summary

radicle-keri is a dormant (Nov-Dec 2022) Rust exploration by two Radicle
developers of using KERI for Radicle identity management, abandoned before
Heartwood shipped. It consists of a design README plus three crates: a
vendored fork of keriox 0.8.2, a partially implemented git-backed KERI event
store, and a fully stubbed controller. Heartwood 1.x ultimately shipped
without KERI (plain Ed25519 NIDs + a majority-quorum identity document with
no key rotation) - the exact gap Heterodyne's section 3.9.10 reconciliation
rules exist to cover.

The overlap with Heterodyne is architectural, not code-level: both anchor a
KEL in git, both graft rotation onto Radicle's rotation-less identity, and
both use threshold multi-party attestation over identity changes. The most
reusable artifact is the design README's git-anchoring layout - especially
the "signed refs parent the identity state in force at signing time" trick,
which gives point-in-time key-state verification without KEL replay. The
code itself is not reusable (stubs, 2022 dependencies, superseded upstream).
Heterodyne should cite the design, optionally adopt the ref-layout and
commit-linkage ideas for repo relays, and keep its Nostr-native wire format,
secp256k1 cold root, and epoch-key split as deliberate divergences.

## radicle-keri: what it is and status

Repo: https://github.com/radicle-dev/radicle-keri ("Implementation of KERI
to be used in Git"). HEAD at time of research:
`1bc35c159d4ca0163ec6b96902c0280f016437b2`.

Status: dormant/abandoned.

- First commit 2022-11-19; last commit 2022-12-15 ("README outlining the
  design"). No activity since (3.5+ years). 0 stars, 1 fork, not archived.
- Authors: Jorge Iglesias <jorge@munin.space> (10 code commits) and Fintan
  Halpenny <fintan.halpenny@gmail.com> (the design README; a core
  radicle-link developer).
- Language: Rust. Cargo workspace of three crates:
  - `keri-core`: a vendored copy of **keriox 0.8.2** (the Jolocom/DIF-era
    Rust KERI implementation; Cargo.toml authors "Decentralized Identity
    Foundation", Charles Cunningham, Ivan Temchenko). ed25519-dalek 1.0.1 +
    k256 0.9; JSON/CBOR/MessagePack event serialization; sled/lmdb stores
    behind an `EventDatabase` trait. Pre-CESR-spec attachment parsing.
  - `keri-git`: the actual contribution. `KeriStore`
    (`keri-git/src/keri_store.rs`) reads a KEL out of git: ref
    `rad/keri/id` points at a head commit; one KERI message blob per
    commit; parents are walked to enumerate the log (`log_head`,
    `log_entry_sn`, `log_entries`). `GitStorageDatabase`
    (`keri-git/src/gitdb.rs`) implements keriox's `EventDatabase`:
    read-side (`get_kerl`, `last_event_at_sn`) is implemented; the entire
    write side (`log_event`, `finalise_event`, all escrow and receipt
    methods, gitdb.rs lines 111-214) is `todo!()`.
  - `keri-radicle`: `KeriController`
    (`keri-radicle/src/keri_controller.rs`) - `new`, `inception`,
    `validate` are all `todo!()`. Its header comment: "Since this code
    will probably live in `heartwood`, this type should be the heartwood
    SignedRef type."
- Era: the radicle-link -> Heartwood transition. Dependencies are the
  radicle-link-era `radicle-dev/radicle-git` crates (`git-storage`,
  `git-ref-format`, `git-commit`) and the `~/.rad/storage` namespaced-refs
  layout, but the controller comment shows it targeted Heartwood. Heartwood
  1.x shipped without it: identity is a per-node Ed25519 NID (`did:key`),
  an identity-document COB (`xyz.radicle.id`) with delegates + threshold,
  majority propose/accept revisions, and **no native key rotation**.
  radicle-keri is the road not taken.

### Key design decisions (root README.md, commit 1bc35c1)

- **KEL storage**: one KERI event blob per git commit; each commit's parent
  is the prior event's commit, mirroring the KERI hash chain onto the git
  DAG. Ref names: `refs/keri/kel` per identity namespace in the prose
  (README lines 135, 303); the code uses `rad/keri/id`
  (keri_store.rs line 70).
- **Materialized key state ("DID") as a parallel commit chain**: each
  key-state commit has two parents - the prior key-state commit and the KEL
  commit that produced it (README lines 377-462) - so state and log
  histories stay cryptographically synced.
- **Signed refs parent the identity state**: a signed-ref commit takes the
  identity commit in force at signing time as a parent, so any historical
  ref can be verified against the correct key state "without having to walk
  all the identity history" (README lines 463-469).
- **Person identity**: a multi-sig self-addressing AID over multiple device
  keys; multi-device inception via a local-identity-server sync of the KEL
  (README lines 112-225).
- **Project identity**: a delegated self-addressing AID where **Radicle
  delegates are modeled as KERI witnesses** and the delegate quorum is the
  witness threshold (`wt`), managed via interaction events (`wa`/`wr`)
  (README lines 23, 227-289).
- **Serialization**: KERI v1 JSON (`KERI10JSON...` version strings);
  keriox `TimestampedSignedEventMessage` serde_json in blobs; CBOR
  (ciborium) only as internal trait plumbing. No CESR framing.
- **DID method**: explicitly optional - "it is not necessary to use this
  DID method [did:keri] to use the KERI methodology" (README line 13).
- **Implementation choice**: keripy rejected (Python FFI, "written as
  demonstrator"); keriox as-is rejected (slow upstream pace); **fork
  keriox** chosen (README lines 542-633). `keri-core` is that fork.

## Heterodyne's KERI design (for comparison)

Normative source: `docs/spec/heterodyne.md` section 3.5 (lines 1094-1521),
3.3.1 (875-961), 3.3.3 (1066-1083), 3.9.9-3.9.10 (2428-2490). The
2026-05-21 Cold Root + Epoch Keys design doc
(`docs/superpowers/specs/2026-05-21-cold-root-epoch-keys-design.md`) is
INFORMATIVE and predates the v0.4.0 substrate pivot (it still assumes
mandatory Matrix identity rooms).

- **Cold root** = secp256k1/BIP-340 key; its npub is the persona's
  permanent public anchor. Signs only `kind:31002` inception,
  `committed`-strategy `kind:31003` rotation, and the `kind:31005`
  npub->RID pointer.
- **Epoch keys** (also secp256k1) sign all routine attestations: root
  attestation (31000), delegations (31001), feed indexes (31007), posts,
  approvals.
- **KEL** = the ordered `kind:31002`/`kind:31003` Nostr events, discovered
  by the relay-indexed `#p` cold-root tag query on both backends (ordinary
  relays and repo relays). `prior_digest` = SHA-256 of the prior event's
  canonical NIP-01 serialization; witness receipts ride in `content` as a
  JSON array, each signing a `witness_digest` computed with `content` set
  empty (section 3.5.2). Fork resolution is canonical KERI first-seen with
  weighted witness thresholds; an unmet threshold stalls the KEL
  (section 3.5.3).
- **Witnesses**: Nostr pubkeys, ATProto DIDs, or bare `did:key` ids, each
  with a weight; `threshold` gates rotation acceptance. Informal
  `kind:31008` vouches are advisory-only (never counted).
- **Rotation strategies**: `committed` (cold-root-signed) and `none`
  (cold-root loss; prior-epoch-key-signed, witness-attested continuity).
- **NID delegation** (`kind:31001`, section 3.3.1): bidirectional binding of
  the persona npub, the device's secp256k1 publishing key, and the device's
  Ed25519 Radicle NID over the domain-separated payload
  `heterodyne-nid-binding-v1|<npub>|<nid>|radicle-nid-delegation`.
- **KEL precedence** (section 3.9.10, ADR-027): the Radicle identity
  document's `delegates` set is a **derived projection** of
  KERI-authorized NIDs; on divergence the KEL wins; dual write,
  add-before-remove, and emergency re-anchor to a fresh RID via a
  cold-root-signed `kind:31005` when the delegate quorum deadlocks.
- **Curve-agnosticism** (section 3.5.0 note): KERI pre-rotation commits to
  a digest of the next key set regardless of curve, so the secp256k1 chain
  authorizes Ed25519 NIDs through delegations without touching the KEL
  machinery.
- **Serialization**: Nostr NIP-01 JSON with the mandatory `nip01_raw`
  canonical-serialization field - not `KERI10JSON`, not CESR.

## Overlap analysis

1. **KEL anchored in git.** radicle-keri stores the KEL as a
   commit-per-event chain under a dedicated ref in Radicle storage.
   Heterodyne's KEL events already land in git via repo relays (the event
   store IS a Radicle repo), but as generic events with no dedicated
   KEL ref layout. Same durable carrier, different granularity.
2. **Rotation grafted onto rotation-less Radicle.** Both projects exist
   because Radicle identities cannot rotate keys. radicle-keri wanted KERI
   to *replace* the Radicle identity mechanism; Heterodyne *subordinates*
   the stock Heartwood identity document to an external KEL
   (section 3.9.10 projection + precedence rules).
3. **Threshold multi-party attestation over identity changes.**
   radicle-keri: witness quorum (`wt`) gates project-identity events.
   Heterodyne: weighted declared-witness threshold gates rotations, and
   separately the Radicle delegate majority gates identity-document
   revisions and canonical-branch acceptance. Same shape, split into two
   cleanly separated mechanisms in Heterodyne.
4. **Multiple device keys under one identity.** radicle-keri: multi-sig
   AID whose key state lists all device keys. Heterodyne: single cold
   root + per-device (epoch key, publishing key, NID) authorized via
   `kind:31001` delegation events. Different mechanism, same goal.
5. **Point-in-time verification of signed refs.** radicle-keri parents
   each signed-ref commit on the identity state at signing time.
   Heterodyne states the equivalent requirement abstractly - the signing
   epoch key "MUST have been KERI-authoritative at the evaluation time t"
   (section 3.3.1) - but has no git-level mechanism binding content to the
   KEL position in force when it was signed.
6. **Implementation posture.** Both reject keripy-over-FFI and prefer a
   Rust core with storage behind a trait/adapter boundary.

## Usable pieces

- **The design README itself** (commit 1bc35c1) as citable prior art: it is
  the only public Radicle-team document mapping KERI onto Radicle storage,
  and it validates Heterodyne's core premise (git as KEL carrier,
  witnesses/thresholds for continuity) from inside the Radicle project.
- **Signed-ref -> identity-state linkage** (README "Signed Refs" section):
  the strongest reusable idea. Adapted to Heterodyne, a repo relay or full
  node could record the KEL head (event id of the latest accepted
  `31002`/`31003`) in force at commit time - as a commit trailer rather
  than a parent, to avoid polluting the DAG - giving verifiers O(1) lookup
  of the epoch key to check instead of a full KEL replay per event.
- **KEL-as-commit-chain ref layout** (one event per commit, parent = prior
  event; separate materialized-state ref whose commits merge-parent the
  producing log commit): a clean pattern for an OPTIONAL git-materialized
  KEL mirror inside repo relays, and the layout any future
  Radicle-ecosystem KERI revival would most plausibly resemble.
- **The witnesses-as-delegates analysis** (README project-identity
  section): useful as a cautionary citation for Heterodyne's org-persona
  design - see "Divergences" below.
- **The implementation-options analysis** (keripy vs keriox vs fork):
  directionally still valid, but its conclusion is superseded - the live
  keriox lineage is THCLab/keriox (`keri-core` 0.17.x on crates.io), so
  "fork keriox 0.8.2" should not be repeated.
- **Code**: effectively nothing. The write path, controller, and
  verification are stubs; `keri-core` is a stale vendored fork
  (ed25519-dalek 1.0.1 carries RUSTSEC-2022-0093; git2 0.15; link-era
  radicle-git dependencies).

## Compatibility options (cost/benefit)

1. **Cite radicle-keri as prior art in ADR/spec rationale.**
   Cost: trivial. Benefit: anchors section 3.9.10's "Radicle has no native
   rotation" claim in a Radicle-team source. Recommended.
2. **Adopt a KEL-head reference on committed content (trailer variant of
   the signed-ref trick).** Cost: medium (new normative field on repo-relay
   commits or sigref metadata; consistency rules when the KEL advances).
   Benefit: point-in-time epoch-key verification without KEL replay;
   hardens historical verification after rotations. Recommended for
   consideration as a 0.x addition.
3. **Specify an OPTIONAL git-materialized KEL ref layout in repo relays**
   (e.g. `refs/heterodyne/keri/log` commit-per-event chain +
   `refs/heterodyne/keri/state`), mirroring radicle-keri's layout.
   Cost: medium - the KEL already exists as events in the repo-relay event
   store, so a second layout is a duplication/consistency surface.
   Benefit: git-native audit trail, `git log`-able key history, layout
   convergence with any future Radicle KERI work. Optional; only if the
   audit-trail UX is wanted.
4. **Align event serialization with KERI native formats (KERI10JSON or
   CESR).** Cost: high - breaks the load-bearing invariant that every
   Heterodyne event is a vanilla NIP-01 event verifiable by relays and
   light clients (`nip01_raw`, section 3.0.1). Benefit: low (interop with
   keripy tooling only). Not recommended as the wire format. A lossless
   *export mapping* (Heterodyne KEL -> canonical KERI icp/rot events) could
   be an OPTIONAL interop appendix if did:webs/keripy interop is ever
   wanted.
5. **Document an npub <-> KERI basic-prefix mapping.** The npub is a raw
   public key, i.e. conceptually a KERI *basic* (non-self-addressing,
   non-transferable-style) prefix; a short informative mapping
   (secp256k1 multicodec / CESR code) would name Heterodyne identities in
   KERI terms. Cost: low (documentation only). Benefit: modest interop
   clarity. Optional.
6. **Use current keriox (THCLab) if a Rust implementation is built.**
   Cost: dependency on EUPL-1.2-licensed `keri-core` (copyleft; verify
   license compatibility with the client's intended license). Benefit:
   maintained, claims second-most-complete after keripy, witness/watcher
   infra and CESR (cesrox) available. Evaluate at milestone 2; do not
   vendored-fork 0.8.2 as radicle-keri did.

## Divergences to keep

- **secp256k1/BIP-340 cold root and epoch keys.** Nostr signature
  verification requires it; radicle-keri/keriox default to Ed25519. KERI's
  digest-based pre-rotation is curve-agnostic (section 3.5.0 note), so no
  alignment is needed or wanted.
- **The npub (raw key) as public anchor, not a self-addressing AID.**
  Vanilla Nostr discovery (`authors:[npub]`, `#p` filters) depends on the
  anchor being the key itself. A derived AID prefix would break every
  vanilla-client path.
- **Cold-root/epoch-key split.** Canonical KERI signs everything with the
  current key set; Heterodyne deliberately restricts the cold root to rare
  ceremonies for exposure minimization. Keep.
- **KEL carried as relay events on BOTH backends, not only in git.** Light
  clients must verify key continuity without git access; radicle-keri's
  git-only KEL assumed every verifier is a node.
- **Stock Heartwood, identity document as projection.** radicle-keri
  required changing Radicle itself; Heterodyne runs against unmodified
  Heartwood 1.x and keeps KEL precedence (section 3.9.10). Keep - this is
  the whole point of the reconciliation rules.
- **Witnesses are not delegates.** radicle-keri overloaded KERI witnesses
  as Radicle project delegates. In canonical KERI, witnesses are
  receipt/availability infrastructure, not controllers; the conflation
  muddles both roles. Heterodyne's separation - declared witnesses gate
  rotation continuity; Radicle delegates + threshold gate repo canonicity -
  is cleaner and should stay.
- **JSON-array witness receipts in `content`** (with the empty-content
  witness_digest construction) rather than KERI receipt (`rct`) events or
  CESR attachments: keeps receipts inside a single NIP-01-verifiable
  event. Keep; note the correspondence to KERI receipts informatively.

## Ecosystem versions and deprecations

Provenance is SHOULD-level (current as of 2026-07-08), not a lock.

- **keripy** (reference impl, WebOfTrust/keripy): stable 1.3.5
  (2026-05-27, PyPI `keri`), 1.2.13 maintenance line; 2.0.0 in
  pre-release (2.0.0.dev3, Jan 2026). Requires Python >= 3.12.2. The 2022
  "demonstrator, not for use" criticism in radicle-keri's README is
  outdated - keripy is production infrastructure (GLEIF vLEI ecosystem).
- **KERIA** (agent): 0.4.0 (2026-03-26, PyPI `keria`).
- **keriox**: live lineage is THCLab/keriox; crates.io `keri-core` 0.17.10
  (EUPL-1.2), plus `teliox` (TEL) and cesrox. The
  decentralized-identity/keriox and WebOfTrust/keriox lineages - the source
  of radicle-keri's vendored 0.8.2 - are stale.
- **ToIP KSWG specs**: KERI, ACDC, and CESR specifications are ToIP Draft
  status under the KERI Suite Working Group (**KSWG**, not TSWG - the
  `tswg-keri-...` URL 404s, per AGENTS.md). CESR 2.0 is in progress.
- **did:webs**: v0.9.17 draft; the active KERI-backed DID method. Naming
  trap: its repo/URL genuinely is `tswg-did-method-webs-specification`
  (historical), unlike the KERI/CESR/ACDC `kswg-` repos.
- **Deprecated / avoid**:
  - IETF `draft-ssmith-keri` is **expired** - cite arXiv 1907.02143
    (project convention, AGENTS.md lines 125-132).
  - `did:keri` method spec (weboftrust.github.io/did-keri) is effectively
    dormant; radicle-keri already treated it as optional. Prefer did:webs
    for any KERI DID interop.
  - keriox 0.8.2 as vendored in radicle-keri: ed25519-dalek 1.0.1
    (RUSTSEC-2022-0093 double-key-oracle advisory), pre-CESR parsing,
    unmaintained. Do not build on it.
  - radicle-link-era `radicle-dev/radicle-git` storage crates
    (`git-storage`, `git-ref-format`) as used by keri-git: superseded by
    Heartwood's own stack.

## Sources

radicle-keri (clone at /tmp/radicle-keri, HEAD
1bc35c159d4ca0163ec6b96902c0280f016437b2):

- https://github.com/radicle-dev/radicle-keri - repo; GitHub API metadata:
  created 2022-11-23, pushed 2022-12-15, language Rust, 0 stars, 1 fork,
  not archived.
- README.md (design doc, commit 1bc35c1, 2022-12-15, Fintan Halpenny):
  did:keri optional (line 13); witnesses-as-delegates (line 23);
  person identity (lines 112-225); project identity (lines 227-289);
  KEL/DID commit-chain layout (lines 291-462); signed refs
  (lines 463-469); implementation options (lines 542-633).
- keri-git/src/keri_store.rs: ref `rad/keri/id` (line 70); log walk
  (lines 93-186).
- keri-git/src/gitdb.rs: EventDatabase impl; write side `todo!()`
  (lines 111-214).
- keri-radicle/src/keri_controller.rs: heartwood comment (lines 8-10);
  all methods `todo!()`.
- keri-core/Cargo.toml: `keri` 0.8.2, authors DIF/Jolocom (keriox fork
  provenance).
- Git history: first commit 10f4c89 (2022-11-19), last 1bc35c1
  (2022-12-15); authors Jorge Iglesias <jorge@munin.space>, Fintan
  Halpenny <fintan.halpenny@gmail.com>.

Heterodyne:

- docs/spec/heterodyne.md: section 3.5 (lines 1094-1521, incl. 3.5.0
  primitives 1115-1177, curve-agnostic note 1166-1176, schemas
  1204-1329, verifier 1330-1399, vouchers 1422-1494); section 3.3.1
  (lines 875-961); section 3.3.3 (1066-1083); sections 3.9.9-3.9.10
  (lines 2428-2490, incl. Heartwood 1.9.1 note 2468-2485).
- docs/superpowers/specs/2026-05-21-cold-root-epoch-keys-design.md
  (INFORMATIVE; pre-pivot, Matrix-era assumptions).
- AGENTS.md lines 125-141 (KERI reference conventions).

Ecosystem (retrieved 2026-07-08):

- https://pypi.org/project/keri/ (1.3.5); https://pypi.org/project/keria/
  (0.4.0); https://github.com/WebOfTrust/keripy
- https://github.com/THCLab/keriox;
  https://crates.io/crates/keri-core (0.17.10, EUPL-1.2)
- https://trustoverip.github.io/kswg-keri-specification/ (ToIP Draft);
  https://github.com/trustoverip/kswg-cesr-specification (ToIP Draft)
- https://trustoverip.github.io/tswg-did-method-webs-specification/
  (did:webs v0.9.17)
- https://arxiv.org/abs/1907.02143 (primary KERI citation)
