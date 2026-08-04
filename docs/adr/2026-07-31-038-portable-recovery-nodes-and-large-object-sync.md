# ADR-038: Portable recovery, recovery nodes, and large-object sync

**Date:** 2026-07-31
**Status:** Accepted
**Decision makers:** user and protocol maintainers
**Design record:**
[`docs/superpowers/specs/2026-07-31-portable-recovery-and-large-object-design.md`](../superpowers/specs/2026-07-31-portable-recovery-and-large-object-design.md)
**Acceptance dependency:** ADR-037; both decisions form one registry-revision-4
batch
**Spec targets:** `heterodyne:core/0.5.0#core-keys-repository`,
`heterodyne:core/0.5.0#core-recovery`,
`heterodyne:core/0.5.0#core-node-roles`,
`heterodyne:core/0.5.0#core-tor-reachability`,
`heterodyne:core/0.5.0#core-capabilities`,
`heterodyne:comms/0.5.0#comms-config-repository`,
`heterodyne:comms/0.5.0#comms-retrieval`,
and the Core and Comms conformance sections

**Review scope:** design only. This proposed ADR does not itself change the
normative family documents, registry, schemas, or vector corpus; those changes
remain a follow-on implementation batch after explicit acceptance.

## Context

Core already requires an encrypted local keys repository and names offline
restore as the path for locating protected repositories. The threat model
recommends encrypted removable-media backups, a freshness indicator, offline
media, and restore testing. It does not define a portable archive, wrapper
slots, platform configuration layout, hardware-key recovery, or a network
bootstrap for a new full node.

Platform keystores are useful but not portable:

- Apple Keychain/Secure Enclave, Android Keystore/StrongBox, and Windows
  CNG/TPM bind keys to a device or security state;
- Linux has no universal hardware keystore;
- browser WebCrypto does not guarantee hardware-backed storage and
  origin-scoped IndexedDB can be cleared; and
- WebAuthn PRF is suitable for deriving a wrapping key but its credential is
  scoped to a relying-party ID.

Repositories and media are bulk data. Hardware authenticators and platform
keystores should wrap a random archive DEK rather than store repository bytes.
The same envelope must support cold-root, epoch, hardware, passphrase, and
device-local recovery without directly reusing a signing key as the bulk-data
cipher key.

Full nodes also need a bounded path for files too large for ordinary Radicle
replication and for recovery data such as media, audit logs, and observability
records. Tor already provides reachability and NAT traversal, so an optional
onion-only transfer service can avoid exposing node locations.

## Decision

### 1. Standardize one encrypted portable container

Core defines `heterodyne-recovery-v1` as a single-file container with:

- fixed magic and length-delimited JCS header;
- fresh independent 256-bit bulk and authority DEKs for every archive;
- an encrypted canonical manifest;
- an ordered, length-checked entry stream;
- independently authenticated AES-256-GCM chunks of at most 1 MiB; and
- no container-level compression.

The clear header contains cryptographic framing and opaque recipient slots,
not persona, repository, platform, path, timestamp, media, or per-entry size
metadata. The total ciphertext length remains visible.
The encrypted manifest covers every byte and rejects absolute or traversing
paths, links, device files, duplicates, undeclared data, and unsafe filesystem
metadata.

Full archive generations use one epoch-signed Core chain per persona; the
Comms composition commits the same records to the encrypted config repository
for shared finality. A manifest binds its generation-record digest, and an
epoch-signed finalization binds the signed manifest, descriptor, exact
ciphertext digest, and length. A full-chain fork is quarantined until a
cold-root-signed generation-resolution record selects one successor or rejects
all, after a fresh canonical epoch rotation and compromise cutoff. The
resolver must freeze and enumerate every locally retained, independently
valid maximal sibling; omitting a then-known branch is producer
nonconformance and retained audit evidence, but verifier acceptance cannot
depend on whether that omitted branch arrived before or after the resolution.
The accepted post-rotation resolution terminalizes every omitted valid
pre-rotation sibling in either order.

That terminal rule is transitive. Every pre-resolution allocation, manifest,
finalization, or abandonment descending from any conflicting sibling,
including the selected sibling, is noncanonical unless it descends from the
accepted resolution digest. Stores retain those bytes and recompute backup
freshness without them. The next allocation must name the resolution digest:
selection advances from the selected generation, while reject-all retries
that generation, and both use the fresh epoch state. A second nonidentical
resolution is cold-root duplicity and halts recovery.

Conflicting manifests, finalizations, abandonments, or
finalization-versus-abandonment claims attached to one otherwise canonical
allocation use a separate cold-root-signed artifact-resolution record. It
freezes the complete candidate sets, derives the exact conflict kinds, selects
one consistent finalized outcome or an abandoned outcome, rejects every other
candidate, and requires the same fresh post-conflict epoch/KEL state. It never
selects another allocation or changes the generation chain's predecessor
relation; all rejected and late pre-rotation evidence remains retained.

`device-local` and `clone-device` archives instead have separate signed chains
for each `(persona, device NID, backup class)`. Their generation,
finalization, and abandonment records bind the active delegation. A fork
quarantines that NID/class lineage permanently because two physical holders
of one NID have equal authority; recovery revokes the old NID, delegates a
fresh NID, and starts a new generation-one chain rather than selecting an old
branch. An offline-created archive remains pending for shared freshness until
its matching allocation and finalization are canonical. A crashed, pending,
abandoned, or quarantined allocation never makes the last matching finalized
backup stale.

Archive identity is an exact cross-record invariant. Header, manifest,
allocation, and finalization must agree on archive ID and generation identity;
manifest authority, persona, producer, KEL/delegation state, and allocation
digest must match the applicable chain; finalization must match the complete
signed manifest digest, payload-descriptor digest, ciphertext digest, and
actual ciphertext length. Any transplanted manifest/header, mismatched
authority, or nonidentical terminal record is a conflict and cannot advance
freshness. Two otherwise identical headers that differ only in sorted,
individually valid recipient slots are authorized rewrap variants of the same
artifact; slots are outside the immutable payload identity and do not change
the manifest, finalization, freshness, or conflict-resolution digest. Any
other header difference remains a conflict or validation failure.

For a full archive, one exact `(persona, epoch_pubkey, kel_head)` authority
tuple must JCS-equal across the allocation, manifest authority,
`manifest.high_water.kel`, current-epoch authority envelope, decrypted epoch
secret, and finalization. The scalar must derive that exact epoch key. No
ancestor, same-sequence alternative, newer locally preferred head, or merely
decryptable source may substitute.

Every epoch-changing rotation also has one signed recovery-state rollover.
The rollover commits complete archive, approval, and role frontiers rather
than relying on local arrival order. `archive_freshness_chains` is a bijection
with `archive_generation_heads`: there is one byte-identical scope row for
every generation head and no other row. Each row carries the complete accepted
finalized fallback chain in strictly decreasing generation order, including
the exact allocation, manifest, finalization, and optional artifact resolution
for every member. Freshness selects the first member that remains valid. A
later abandonment, compromise cutoff, pending greater allocation, or
unresolved greater conflict can therefore expose the next ratified finalized
archive instead of erasing recovery history.

An ordinary rollover cannot skip a canonical rotation whose rollover bytes
are unavailable. The only repair is a cold-root-signed
`heterodyne.recovery-state-rollover-gap.v1` record. It binds the last earlier
unique accepted base, a nonempty canonical sequence of skipped rotations, a
fresh compromise-declaring repair rotation, the exact missing-digest/evidence
projection, and digests of all six frontier arrays in the repairing rollover.
An `authenticated-reference` is backed only by the exact bytes of a signed
recovery record with `evidence_type:"signed-recovery-record"`,
`evidence_profile:"core.recovery-state-rollover.v1"`, and allocated semantic
`evidence_member:"previous-rollover-head"`. The selected
`previous_rollover_heads` row must name the skipped rotation and candidate
digest exactly; its signature, persona, KEL state, and signer-time authority
validate. No other profile, member, substring, or lookalike object counts.
Storage-index or provider metadata is always an `audit-only-reference` with
`evidence_type:"audit-storage-metadata"` and null profile/member: hashing and
retaining it proves neither that the rollover existed nor that it was valid.
Every referenced
evidence artifact is retained byte-exactly, and the cold-root signature over
the gap does not upgrade audit-only evidence. A rollover whose complete bytes
are available must instead enter ordinary unique/conflict validation and
cannot be demoted to audit-only evidence.

The repairing rollover must cite that exact gap and match every committed
frontier. A candidate digest whose bytes remain missing is an unresolved
reference, not a validity claim. A nonunique base, an available unique or
conflicting rollover frontier, an incomplete skipped sequence, or unavailable
gap/evidence closure remains fail-closed. Records signed by skipped epoch
keys, late-arriving skipped-rollover bytes, and their descendants are
permanently `gap-unratified` audit evidence and cannot reopen or enter a later
operational frontier.

### 2. Map backup entries to live stores

The logical archive contains complete Git bundles for public, private, and
config repositories plus owner-scoped configuration and protected records:

```text
repositories/public/<rid-id>/bundle
repositories/private/<rid-id>/bundle
repositories/config/<rid-id>/bundle
keys/<owner>/<record>/value
keys/device/<nid-id>/clone-secret
config/shared/<owner>/<schema>/value
config/platform/<platform>/<owner>/<schema>/value
config/device/<nid-id>/<owner>/<schema>/value
objects/<object-id>/stored
history/<owner>/<record>/value
```

The manifest binds each path-safe identifier to the full RID, NID, owner, or
schema. Repository owner pairing is exact: public bundles use
`role:"repository-bundle", owner:"core"`, while private and config bundles
use `role:"repository-bundle", owner:"comms"`. Core protected records use
`owner:"core"`; the sole clone-secret path uses
`role:"device-clone-secret", owner:"core"` and is legal only in a
`clone-device` archive. Configuration entries use the allocated owner of
their governing schema, managed objects use Comms, and audit history uses the
record profile's owner. A wrong role/owner pairing rejects.

Shared configuration is portable. Platform configuration is opaque outside
its owning platform. Allocated but locally unsupported owner/platform records
and unknown non-authority schemas are preserved but cannot grant authority;
unallocated owner/platform tokens reject.

Every full archive carries exactly two `special_authority_bindings`, ordered
as cold root and epoch. The cold-root row identifies the independently
NIP-49-wrapped Core record; the epoch row identifies the one current-epoch
authority envelope under the archive authority DEK. A Core-only archive has
null credential source identity for those rows. In a Comms full archive each
row instead binds the exact capability identity, complete current-holder
source/assignment lineages, selected credential checkpoint, and
historical-decrypt-obligation-set digest. Both special rows are current, so
their historical-obligation and retired-provenance sets are empty.

ADR-037's 19 closed secret classes have one total portable disposition:

| ADR-037 class | Portable disposition | Material form / lifecycle |
|---|---|---|
| `cold-root` | Special NIP-49 Core protected record | wrapped cold-root / current |
| `epoch` | Special authority-DEK epoch envelope | `heterodyne-recovery-epoch-secret-v1` / current |
| `device-signing` | Explicit `clone-device` only | `heterodyne-recovery-device-clone-secret-v1` / current |
| `agent-signing` | Generic authority envelope | `heterodyne-recovery-agent-signing-secret-v1` / current |
| `config-audience`, `tier3-audience`, `claim-ledger-audience`, `object-dek` | Generic authority envelope | `heterodyne-recovery-symmetric-secret-32-v1` / current or historical-decrypt |
| `recovery-wrap` | Generic authority envelope | `heterodyne-recovery-symmetric-secret-32-v1` / current only |
| `oauth-signing` | Generic authority envelope | `heterodyne-recovery-oauth-signing-private-jwk-v1` / current |
| `oauth-pairwise` | Generic authority envelope | `heterodyne-recovery-symmetric-secret-32-v1` / current |
| `core-protected`, `radicle-access` | Protected nonsecret metadata, never a generic secret | ordinary capability record / no secret lifecycle |
| `double-ratchet`, `bearer-credential`, `ssh-client`, `ssh-host`, `onion-service-identity`, `tls-serving` | Forbidden session, credential, or node-local secret; reestablish after restore | no portable secret material |

Each generic authority envelope binds its owner, class, secret ID, instance
commitment, lifecycle, credential checkpoint, canonical record locator,
complete `current_holder_lineages`,
`historical_obligation_record_digests`, `retired_provenance_lineages`, and the
checkpoint's `governed_decrypt_key_bindings_sha256` and
`historical_decrypt_obligations_sha256` values. For `current`, the holder set
is the complete conservative unretired per-holder source/assignment
set—including staged and competing variants—and both historical arrays are
empty. For `historical-decrypt`, the holder set remains nonempty and is
separate from the complete active-obligation and retired-provenance sets. An
arbitrary old or merely reachable source cannot substitute.

The canonical `record_value` is a domain-separated digest of that complete
generic identity and binding state. It maps to exactly one
`keys/<owner>/<record>/value` entry. The manifest's sorted durable-secret
inventory and its generic authority entries form a bijection: owner, locator,
path, entry digest, holder lineages, historical evidence, checkpoint digests,
and repeated decrypted identity all agree, with no omitted or extra entry.
The two special bindings and every non-generic class are outside that
inventory.

A retained ciphertext or pointer must independently mark that it is a governed
decrypt dependency and authenticate its exact secret tuple. When its governing
profile does not embed that tuple, one signed
`heterodyne.governed-decrypt-key-binding.v1` record binds the exact typed
ciphertext locator to `(secret_class, secret_id, instance_commitment)`. Its ID
is derived from that locator, conflicting variants quarantine the dependency,
and the artifact must preexist the binding, which must preexist its obligation
and checkpoint. An obligation can never be the sole source of the secret
tuple.

The repository universe is closed by the signed
`heterodyne.repository-retention-inventory.v1` record, profile
`comms.repository-retention-inventory.v1`, at:

```text
credential-sync/repository-retention-inventories/
  <inventory-sequence>-<record-digest>.json
```

It contains exactly `type`, `persona`, `inventory_sequence`,
`previous_records`, `basis_checkpoint_digest`, `target_generation`,
`target_sequence`, `repository_refs`, `issued_at`, `epoch_pubkey`, `kel_head`,
and `epoch_signature`. Genesis sequence zero has no parents and a null basis.
Each successor sequence is one greater than its maximum parent and names the
complete individually valid maximal frontier; ordinary state has one parent,
while emergency reset names every competing maximum. Its ordinary basis is the
accepted predecessor checkpoint; emergency basis is the last-common reset
checkpoint.

The target tuple is activation-exact. Genesis names exactly
`(target_generation=0,target_sequence=0)`, an ordinary successor names the
immediate candidate checkpoint, and an emergency successor names
`(new_generation,0)`. A visible record is
staged and ineffective before that exact checkpoint and cannot activate late
or at a different tuple. Once accepted against its exact basis, its frontier
remains effective through descendant checkpoints until a valid targeted
successor replaces it.

Each closed `repository_refs` row contains exactly
`repository_ref_id`, `repository_class`, `repository_rid`, `ref_name`,
`object_format`, `retired`, and typed-Git `scan_head`. Class is `config`,
`private`, or `public`; format is `sha1` or `sha256`; retirement is Boolean.
The ID is:

```text
lowercase_hex(SHA256(
  UTF8("heterodyne-repository-retention-ref-id-v1") || 0x00 ||
  UTF8(JCS({repository_class,repository_rid,ref_name,object_format}))
))
```

Rows sort by unsigned UTF-8 class/RID/ref bytes, format ASCII, and decoded ID.
Semantic or ID duplicates, aliases, ID mismatch, and typed-Git mismatch reject.
Every ordinary predecessor row persists. An active head may remain equal,
advance to a descendant, or retire at an equal-or-descendant final head.
Retirement is ordinarily immutable and absorbing. New refs must already exist
and be fully scanned before first governed use.

For candidate checkpoint `C`, `EffectiveRefs(C)` is the complete set of every
`repository_refs` row variant in the activated maximal inventory frontier after
these successor rules; conflicting variants remain distinct and reject
ordinary acceptance. Rows found only in ancestor records are authenticated
audit history, not effective registrations.

Config-key acceptance has one controlled deregistration. In ordinary
succession it deregisters exactly the old active `config` row only when its
successor adds the fully scanned active
`refs/heads/enc/<new-config-key-id>` row, the accepted transition's closure
basis `B` proves complete logical-tree re-encryption with no surviving
old-config-key dependency, and the same signed multi-ref compare-and-swap
accepts the new ref and deletes the exact old signed ref. The predecessor row
and accepting transition/CAS remain required ancestor evidence. Receipts for
the accepting candidate still authenticate and scan the old ref as the exact
source/closure basis and verify the deletion preconditions, while its result
`EffectiveRefs(C)` and `K(C)` exclude that ref. Descendant receipts and
archives validate the ancestor and accepting transition/CAS evidence without
fetching or scanning the deleted ref. This is not retirement, and no other
ordinary transition may deregister a row.

An emergency multi-parent successor contains the union of every semantic row
present in `EffectiveRefs` of any maximal parent; absence on another branch is
never deletion. A prior valid config deregistration suppresses a row only when
it is absent from every maximal parent's `EffectiveRefs`.
A row present on only a subset, or byte-identical wherever present, is
preserved, ordinarily advanced, or explicitly retired at an
equal-or-descendant cut and cannot be omitted.

After first forming that complete union, emergency config-key acceptance may
subtract exactly `V_old`, the complete variant set for the one old active
`config` semantic identity whose ref is
`refs/heads/enc/<old-config-key-id>` and whose current signed target is the
transition's `source_ref_head`. Every maximal-parent variant of that semantic
identity belongs to `V_old`. Reset `K(I)`, closure basis `B`, and class-complete
actions authenticate and scan every variant tree, terminally account every
locator/binding/obligation pair, re-encrypt the complete logical union under
the fully scanned new active config row, and prove no result dependency on the
old config key. The same reset CAS accepts the new ref and deletes the exact
old signed ref. Accepting-reset receipts scan every `V_old` variant as
source/closure evidence; result and descendant `EffectiveRefs(C)`/`K(C)`
exclude them, while ancestor rows and reset/CAS proof remain audit evidence.
Partial-variant, wrong-identity, wrong-ref, or different-ref subtraction
rejects; every row outside `V_old` remains unioned.

The successor has one narrow convergence exception for two or more divergent
variants of the same semantic row outside a valid `V_old` terminal
deregistration. Its one replacement `scan_head` is a newly
materialized Git commit whose complete direct-parent set is exactly
the distinct variant heads in decoded-OID-sorted order (or the one shared head
when only retirement flags differ). The reset may choose an active or retired
replacement. Every parent record/variant remains in the signed frontier, every
parent commit/tree remains reachable as audit history, and the replacement's
exact tree is fully scanned.

For a config row, this H* is the sole exception to the linear config Git
profile. Its fixed commit grammar has one tree header, the exact nonempty
decoded-OID-sorted variant parent list, the canonical zero-time Heterodyne
author/committer headers, and exact message
`heterodyne-config-retention-resolution-v1\n`. It is valid only as the exact
H* bound by the complete cold-root emergency inventory/reset predicates; all
other config commits retain the zero-or-one-parent
`heterodyne-config-v1\n` grammar, and every unbound merge rejects.
The replacement's retirement flag equals the reset's explicit signed result,
not a local merge choice; a retired config resolution must add a separate
fully scanned active config row.

Reset inventory first unions every allocated, authenticated marked artifact
locator in every variant exact tree, even where a tuple was current on that
parent. For each locator it derives the complete candidate tuple set from all
profile-embedded tuples plus every individually valid K(I) binding variant,
including all conflicting variants; unavailable required binding bytes keep
reset pending. The reset
therefore reasons over exact `(locator,tuple)` pairs rather than choosing one
binding or collapsing a legitimate multi-tuple locator.

A tuple is conservatively current only if every applicable complete parent
key-state projection agrees that it is the same sole current instance with no
retirement, competition, different current, or missing required state. Thus
current-on-A/retired-on-B ciphertext, a multi-tuple locator, and conflicting
`L->t1`/`L->t2` bindings cannot vanish through parent-local classification.

Class actions give every physical locator one and only one disposition:
preserved into the H* tree, re-encrypted/replaced, or deleted/closed, while
cleanup/provenance covers every candidate tuple. Ancestor reachability is
never a disposition. Because repository head is part of each governed locator,
unchanged bytes copied into H* acquire fresh locators.

Candidate cleanup is distinct from the exact result pairs authenticated by the
H* source profile and, where required, one uniquely validated fresh fallback
binding. Every old `(locator,tuple)` candidate is carried to an identical
result pair, re-encrypted/replaced, resolved-and-closed as a rejected binding
candidate, or deleted/closed. A fresh fallback is accepted only after every old
candidate is terminally accounted and independent profile/ciphertext
validation proves one result; otherwise preservation is forbidden. Legitimate
profile-embedded multi-tuples remain pairwise.

Old-head obligations are closed/replaced, while active H* obligations cover
only the noncurrent authenticated result pairs—not rejected old candidates.
Post-reset `G(B)=O(B)` must hold. This is the only permitted retired-head
advance or reactivation. A retired replacement becomes absorbing again; an
active replacement resumes ordinary descendant-only advancement.

Ordinary accepted state has exactly one active config ref; a candidate config
ref is staging only, with a registered pre-inventory ancestor, until
checkpoint acceptance.

Each cut in `EffectiveRefs(C)` scans only the exact recursive tree selected by
`scan_head`, not ancestor-commit reachability or loose retained objects.
Ciphertext absent from that tree is audit residue unless an explicit registered
frozen retention ref still names it. A descendant tree may therefore
reencrypt/delete an artifact and permit obligation close while preserving the
old commit as evidence. A retired effective row continues to scan its immutable
final tree; a validly deregistered config row is validated through its ancestor
record and accepting transition/CAS instead and is not fetched or scanned.
Non-descendant history rewrites are not accepted.

The ordinary current epoch signs the domain-separated JCS record with BIP-340.
Emergency uses the fresh reset target epoch only after the cold-root-authorized
KEL rotation and takes effect only with the reset checkpoint. Complete-record
SHA-256 must match the path. KEL ancestry, rollover, historical signer, and
cutoff rules apply.

The inventory defines the canonical protocol universe; it does not claim that
unknown physical private repositories cannot exist. An unregistered ref cannot
carry canonical governed-decrypt source-profile content. Private/config RIDs
remain confined to encrypted credential sync and recovery archives. Every
target-roster member fetches and verifies every listed RID/ref, signed ref,
format, ancestry, and exact scan cut. Because vanilla Radicle has no
cross-repository atomic CAS, producers freeze candidate writes and authenticate
immutable cutoffs; post-cut old-key content is noncanonical.

At credential checkpoint/config head `C`, validators independently derive:

```text
K(C) = {
  repository_inventory_records,
  governed_heads,
  binding_records
}
```

`repository_inventory_records` is the complete activated maximal frontier of
`{inventory_sequence,record_digest}` rows, sorted by sequence then decoded
digest and dereferenced through the complete valid ancestor graph. All conflict
variants are included and reject ordinary acceptance; emergency reset merges
the complete branch union without arrival-order selection.

`governed_heads` is the complete strictly sorted unique set of closed
`{owner,repository_rid,ref_name,repository_head}` rows derived from
`EffectiveRefs(C)`. For each active or retired config/public/private cut,
validators scan every noncurrent marked dependency under its one
registry-selected authenticated source profile and emit exactly one row per
distinct allocated `owner` produced by those locator expansions. A mixed-owner
cut emits multiple rows; a cut with no noncurrent dependency emits none. Rows
sort by owner, RID, and full ref-name UTF-8, then object-format ASCII and
decoded OID. A fallback binding's retained-ciphertext `owner` must equal the
selected profile owner; missing, extra, or mismatched projections reject. This
is not a set of moving current tips, and ordinary posts under a current key do
not change it. `binding_records` is the complete operational binding frontier
for those snapshots, including every conflict variant.
Retirement, retained-set change, re-encryption, deletion, or final close must
advance the inventory and applicable snapshot/binding state through the same
transition. Every accepted config-key transition activates the targeted
inventory successor that deregisters the exact old active config-ref row and
registers the new fully scanned active row. `repository_inventory_records`,
`K(C)`, and `governed_decrypt_key_bindings_sha256` therefore MUST change even
when no noncurrent dependency appears; `governed_heads`, `binding_records`,
and the historical-obligation digest remain byte-identical when their
respective governed-dependency and obligation frontiers do not change. This
permitted non-null inventory-only advance is separate from the narrow null
transition, which may register or advance a fully scanned ref only when no
noncurrent dependency appears and heads/bindings remain byte-identical;
`K(C)` still changes through its inventory frontier. The
checkpoint commits:

```text
governed_decrypt_key_bindings_sha256 =
  lowercase_hex(SHA256(
    UTF8("heterodyne-governed-decrypt-key-binding-set-v1") || 0x00 ||
    UTF8(JCS(K(C)))
  ))
```

The existing domain commits the enlarged object; no checkpoint field is added.
Every receipt recomputes this state from the checkpoint-authenticated
inventory and the closed registry source-profile table. The full manifest
repeats the digest and archives the exact inventory frontier and ancestors,
every `EffectiveRefs(C)` repository/ref scan head and signed-ref proof,
retention snapshots, and binding frontier, along with the complete
maximal historical-decrypt-obligation frontier in
`historical_decrypt_obligation_records` and its separately domain-separated
digest. This lets validators derive governed ciphertext independently and
require its exact bijection with active retain obligations.

Inventory records and signed-ref evidence are bulk-visible
`protected-metadata-record` entries. Repository bundle/ref/head projections
cover every effective inventory row, or `K(C)` is unrecomputable and restore
rejects. An ancestor-only config row deregistered by accepted config-key
rotation instead requires its exact ancestor inventory and accepting
transition/CAS evidence; its deleted ref snapshot and bundle are not live
archive inputs and need not be retained.
Neither an inventory nor an inventory scan snapshot may be externalized as a
large object; network-assisted archives may omit only already-declared
large-object ciphertext. Manifest high-water, generic envelopes and inventory
rows, transition and reset bases, candidate/closure/audit/CAS state,
offline/transfer restore bases, archive lifecycle, and normal-or-gap rollover
all carry the existing governed-binding digest with this enlarged meaning.

Revision 4 adds `governed-decrypt-source-profile` to the closed
`allocation_kind` enum. Its exact globally unique, owner-bound values and the
normative table of allowed secret classes and deterministic locator expansion
must exhaust every profile that can produce a governed dependency, including
the six Tier-3 Nostr content profiles, Tier-3 index/descriptor, config and
claim-ledger encryption, applicable recovery wrapping, and
`comms.large-object-pointer.v1`. The batch cannot freeze with implicit,
wildcard, placeholder, unknown, wrong-owner, or signer-supplied profiles.

A source profile emits a distinct locator per encryption layer or authenticates
the complete sorted tuple set. One signed binding may fill exactly one
otherwise-unembedded tuple for one locator. Zero/multiple candidate tuples,
validator selection, or one binding reused across locators rejects. A redundant
binding may accompany exactly one embedded tuple only if it matches; a
locator-only binding beside a multi-tuple embedded set is ambiguous and
rejects.

An encrypted large-object pointer embeds both complete decrypt tuples and
expands deterministically once per noncurrent dependency. A historical
config/Tier-3 audience emits the exact encrypted pointer/wrapped-DEK Git-blob
row; a historical object DEK emits the exact stored-byte large-object row.
Distinct locators yield distinct binding IDs. If both instances become
historical, both rows and both obligation coverages are mandatory; if only one
is historical, exactly its corresponding row is present. Neither may be
collapsed into the other, and a still-current dependency cannot add a row.

The complete dependency graph is:

```text
accepted predecessor -> artifact A -> optional binding K ->
repository inventory R -> obligation O -> transition T -> checkpoint C ->
receipts
```

These arrows are logical record dependency and signing order, not canonical
Git tree-entry order and, for a config-key transition, not necessarily
distinct commits. Closure basis `B = result_basis.config_head` remains the
parentless new-key root and the new active config row's pre-inventory
`scan_head`. Every artifact and scan head preexists `R`. A required `K` is
signed after its locator exists and before `R`; it is either already reachable
at an independently authenticated pre-inventory head or, when its locator
commits `B` and embedding it in `B` would self-reference, first carried in
direct-child commit `T`. That commit may atomically carry finalized `K`, `R`,
`O`, every `O`-dependent source/assignment/retirement and transition-action
record, reset where applicable, and the transition, but their bytes and
signatures are produced in dependency order and none names `T`'s commit OID.
Result and target digests project those records. New transition-bound
`K`/`R`/`O` and dependent proof records are not placed in `B`; copied
predecessor audit records remain there.

Every scan head and external object preexists `R`; the config cut is a strict
ancestor of the commit first containing `R`. Artifacts, bindings, and cuts
cannot depend on `R` or a descendant. `R` references only its basis and parent
records. Any cycle,
unregistered source, or post-cut old-key artifact rejects.

All Git identities in this state are typed rather than ambiguous strings.
Repository snapshot heads and each obligation locator's `repository_head` and
`git_blob_oid` use exactly
`{object_format:"sha1"|"sha256",oid}`. SHA-1 OIDs are 40 lowercase
hexadecimal characters, SHA-256 OIDs are 64, and a locator's two object
formats must match its repository. Bare, mixed-format, wrong-length, or
declared-format-mismatched OIDs reject.

When governed ciphertext still needs an old instance, the accepting ADR-037
transition retires every prior operational and historical assignment and
creates a fresh-ID, same-instance historical assignment for each exact
recovery/decrypt-only holder. Those live assignments enter the ordinary
exposure digest, and their sources bind every active obligation, applicable
governed-key binding, and governing artifact. They authorize only decryption
of the exact governed rows—not new encryption, signing, delegation, minting,
serving, or other use of the old key. Each active obligation accumulates the
retired provenance. Closing the final dependency retires the complete live
historical assignment set; a historical secret with no holder or obligation
cannot remain in the archive.

The special epoch envelope and all generic envelopes use AES-256-GCM under the
same authority DEK and share one archive-wide nonce-uniqueness set. Each nonce
is unpadded base64url for exactly 12 fresh random bytes. Each ciphertext is
unpadded base64url for exactly `ciphertext || 16-byte tag`, wholly inside the
declared entry bytes. A producer resamples collisions; a verifier rejects a
malformed or duplicate nonce across the combined special/generic set before
attempting authority-DEK decryption.

Restoration verifies bundle integrity, Radicle identity and signed refs, RID,
head, KEL authority, and high-water marks before atomic installation.

Opening a full archive through a bootstrap slot yields only the bulk DEK and
therefore has a distinct non-authoritative `bootstrap-validated` result. The
client must authenticate the grant, completed transfer, complete bulk stream,
manifest, allocation/finalization or accepted artifact resolution,
repositories, KEL, available high-water marks, and every available member of
the full-archive authority equality matrix. It may defer only authentication
and decryption of authority-DEK-protected special and generic envelopes and
validation of their hidden material. A mismatch in any available source
rejects; absence of the authority DEK is never treated as successful authority
validation.

`bootstrap-validated` is isolated bulk staging only. It does not expose a
repository or configuration through a live read path, install or exercise an
archived secret, publish, mint, issue, delegate, revoke, activate another
node, or claim full recovery. A later authority activation does not upgrade
or mutate that verdict. Its transient scalar must open the archive's original,
byte-identical required epoch slot and yield the complete bulk/authority
two-DEK bundle. The client then discards every bootstrap parse object and
performs a new ordinary restore from the immutable bytes, including all
authority-envelope, inventory, checkpoint, rollover, and rollback checks.
Only that independently successful ordinary restore may atomically install
authority.

Without comparison state, offline authority opening is allowed only for
`backup_class:"full"` and only through a two-boundary procedure. The restorer
first opens only the bulk DEK and requires an independently available cold-root
signer; a cold root recoverable only from the archive cannot authorize its own
opening. A combined recipient slot is eligible only through a compartment that
withholds the authority DEK and all authority plaintext. Implementations unable
to enforce that separation may inspect through a true bulk-only slot but cannot
perform offline authority activation. `device-local` and `clone-device`
archives cannot produce either offline intent or activation record.

Before releasing the authority handle, the independent cold root signs one
closed `heterodyne.offline-recovery-pre-unseal-intent.v1`. It binds the exact
archive/restore basis, fresh NID and activation ID, and a complete preimage
template for every archive-derived or preexisting persona-authority capability
that the handle could expose. It is stored create-only at
`keys/core/recovery/offline-pre-unseal-intents/<activation-id>/<digest>.json`.
The independent signer confirms `created_at` no later than its trusted current
time; first observation permits at most 300 seconds of verifier clock skew.
Without a trusted signer clock, zero or another conservatively earlier
user-confirmed value is used, never a host-proposed future time.
The signed intent and immutable archive become durable before authority
release. This is the first irreversible exposure boundary even if the operator
cancels, the authority AEAD fails, hidden material mismatches its commitment,
or no activation is completed. Before it, only bulk-visible/non-authority
scratch may be discarded.

After intent durability, the compartment exercises but never exports the
authority DEK. Each hidden object is internally authenticated/decrypted and
its schema, repeated outer identity/binding, commitment, and exact template are
validated before exact material or a bound signing operation is released.
Mismatch yields no output and zeroizes the result; implementations unable to
enforce validated release cannot offline-activate.

Each archived-epoch signature and assignment source digest is then added to the
exact fixed templates and no other byte may change. The resulting cold-root-
signed `heterodyne.offline-recovery-activation.v1` names the intent
digest, repeats every shared top-level persona, activation/archive/generation/
manifest/KEL, NID, restore-basis, timestamp, and stale-risk member
byte-identically, and embeds the completed source/assignment records. Its
exposure set
includes archived current and historical-decrypt secrets, an exposed cold
root or its applicable protected-wrapper capability. It excludes every
device-signing clone secret and fresh NID/device/publishing, SSH,
X25519-recipient, and platform-wrapper key that was neither archived nor
preexisting persona authority.

The completed records and protected entries remain inert in an isolated
candidate namespace. Before any completed secret-bearing candidate byte
becomes durable, a second monotonic `secret-bearing-prepare` journal preserves
the already-durable intent, exact activation, embedded records, digests, and
protected inventory. This second boundary cannot replace the first. Crash
recovery always retains the intent and, after completed prepare, either
finishes both activation visibility publications or retains the exact
activation evidence. An incomplete candidate installs no authority, but
neither evidence layer may disappear.

Let `ObservedPreUnsealIntents` and `ObservedActivations` contain every valid
variant, including failures, incomplete prepared candidates, and collisions.
An intent or activation is reconciled only when one accepted, fully receipted
ADR-037 transition inventories its exact digest/set row, includes every exact
origin in the matching class action, retires every real assignment observed at
the frozen basis, completes every required rotation/replacement/termination/
migration and governed-ciphertext/obligation update, and accepts its checkpoint
and rollover. Target inclusion additionally requires a linked completed
activation plus delivery and role closure; an intent-only NID is excluded and
receives no successor, delivery, or role. Therefore:

```text
UnreconciledPreUnsealIntents =
  ObservedPreUnsealIntents - { I | ReconciledIntent(I) }

UnreconciledActivations =
  ObservedActivations - { A | Reconciled(A) }
```

The transition inventory commits the exact unreconciled projections and
separate complete intent- and activation-collision projections. Real
assignment items remain the only members of predecessor/result exposure-set
digests. Transition exposures/actions additionally carry exact tagged
`{intent_record_digest,preimage_id}` origins. Both origin arrays are
independently complete; an intent cannot hide a co-keyed real assignment.
Retirement records remain one-to-one only with actual assignments, while
accepted class actions terminalize intent origins without inventing
pseudo-assignments.

Reconciled evidence remains immutable audit history without reentering cleanup.
A final activation first observed after its intent was reconciled contributes
only its new real assignments; accepted audit proof satisfies the intent link.
A nonidentical intent variant, or nonidentical fully signed activation variant,
is never collapsed by template equivalence or arrival order. A late same-ID
variant still forces the collision-only cold-root emergency reset, while only
unreconciled variants enter cleanup. One intent and its correctly linked
activation sharing an ID are the expected two phases and do not collide.

At first network contact, an ancestor/equal fully available state may use
`routine-addition`; divergence, missing checkpoint/rollover state, or either
collision requires `emergency-reset`. Both perform class-complete action over
every assignment and intent origin and preserve same-instance historical
decrypt only through fresh decrypt-only assignments. Any transition whose
unreconciled evidence plans or records exposure of the predecessor-current
epoch performs a fresh compromise-declaring KEL rotation with
`compromise_since` no later than the earliest relevant linked intent
`created_at`, including an intent already reconciled before a later activation,
carries the cutoff through rollover, and rejects intervening signatures. This
applies to ordinary addition as well as reset.

For first conservative inventory only, exact activation completions remain
admissible when their archived-epoch source/assignment signatures fail current
KEL-window or compromise-cutoff authority eligibility. Validators still
require raw BIP-340 validity under the intent-bound archived key, exact
template completion, cold-root links, shared top-level equality, provenance,
commitments, and schemas. The exception grants no authority; it exists only so
cutoff-invalid evidence cannot vanish before retirement and rotation.

Offline recovery permits local inspection and editing but not publication,
minting, delegation, revocation, persona/agent signing, recovery serving, or
authority-bearing backup finalization. Only a subsequent current-state
activation after checkpoint, rollover, delivery, and role closure installs
fresh successor material and moves `offline-recovered` to `online-current`;
the isolated archived secrets never become live authority.

### 3. Require cold-root and epoch recovery slots

A full-recovery archive contains both current cold-root and current epoch
recipient slots and should contain an independent hardware-token or
passphrase slot. The client warns when the independent slot is absent.

It contains complete authoritative public, private, config, and keys
repositories and known configuration. If size policy omits managed large
objects, the signed manifest lists them and labels the archive
`network-assisted`; only a no-omission archive is `standalone`.

The manifest has three closed backup classes. Only `full` may carry protected
cold-root and current-epoch authority; its ordinary recovery recipients open
both DEKs. `device-local` contains no persona or device signing secret, token,
ratchet state, or epoch authority. `clone-device` may carry only the
explicitly selected device secret/configuration and no persona authority,
token, or ratchet state. The latter two destroy their unused authority DEK.
Choosing a portable device recipient for `full` produces an explicit warning
that the device recovery key can restore current epoch authority.

Cold-root and epoch slots use an ephemeral secp256k1 sender and NIP-44 v2 to
wrap the 64-byte bulk/authority backup-key bundle to the recipient public key.
Signing-key bytes are never used as an AES key. The cold-root record preserves
Core's independent NIP-49 boundary. The current epoch secret is held behind
the archive's separate authority DEK: an ordinary full-restore slot
intentionally opens both DEKs, while a bootstrap-only bulk-DEK slot cannot
open current epoch authority. After the complete full-archive authority
and durable-secret equality matrices succeed, an ordinary
authority-complete restore atomically installs the epoch secret and every
required generic current or historical-decrypt secret under the destination's
protected stores and erases transient plaintext.

A device NID binds a dedicated X25519 recovery-recipient key. A platform may
instead create a clearly labeled same-device wrapper in its native keystore.
A device-local archive may rely on that wrapper alone only after warning that
device loss or reset destroys recovery.

The portable device wrapper uses RFC 9180 HPKE base mode with
DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, and AES-256-GCM. The common hardware
and passphrase profiles wrap the fixed backup-key bundle with RFC 3394 AES-KW.

### 4. Support hardware, passphrase, and native extension slots

The common hardware profile uses WebAuthn Level 3 `prf`, backed by CTAP
`hmac-secret` where available, with user verification. Its output derives a
domain-separated KEK that wraps only the backup-key bundle.

Each authenticator receives an independent slot. Clients should enroll at
least two. The slot records backup eligibility/state so a UI can distinguish
a single-device physical credential from a synced multi-device credential.
The reference hosted browser uses the Heterodyne reference RP; an unrelated
browser origin needs its own slot or an explicitly allowed related-origin
relationship.

Argon2id version `0x13` provides the optional passphrase slot. Its baseline is
64 MiB memory, three iterations, parallelism four, a fresh 16-byte salt, and a
32-byte output. PIV/PKCS#11 and OpenPGP-card recipients are optional native
extensions, not base browser requirements; revision 4 allocates no slot for
them, so interoperable use requires a later schema-bearing allocation.

### 5. Create fresh devices by default

Ordinary archives omit device NID secrets, active Double Ratchet state,
temporary OIDC/workload tokens, sender proofs, and message keys.

An explicit `clone-device` export may include exactly one closed clone-secret
entry for its producer NID, and only with a non-device-local recovery slot
that can open the archive without either cloned secret. It may carry the
32-byte Ed25519 NID seed and, when explicitly selected, its delegated
secp256k1 publishing secret; the manifest and schema require both public-key
derivations and the exact active delegation.

The warning is irreversible and explicit: restoring the seed creates two
physical installations of one logical NID, both of which can sign while its
delegation remains active. The protocol cannot distinguish the copies or
prove source erasure, and revoking that NID invalidates both. Same-NID cloning
is therefore possible but operationally risky; taking the source offline is a
recommendation, not a protocol precondition falsely presented as provable
retirement. The preferred path restores data without clone secrets, creates
and delegates a fresh destination NID/publishing key, migrates desired
capabilities, and then revokes the old NID. Active ratchet state is never
cloned, and either path establishes fresh sessions.

Exact cloning creates no new ADR-037 logical holder, source companion, or
assignment: both physical installations deliberately use the same NID and the
existing assignment remains unchanged. The clone archive's signed generation,
manifest/finality lineage, explicit confirmation, and mandatory warning are
the available audit evidence; the protocol cannot observe the physical-copy
event as a new holder. A separately accountable holder uses a fresh NID and
ordinary enrollment.

The default restore generates and delegates a new device NID.

### 6. Define recovery nodes as an optional full-node capability

A recovery node is a full node that:

- holds the current epoch secret under Core protection;
- maintains encrypted recovery material;
- is explicitly authorized for the persona; and
- may expose the recovery service on a persistent onion endpoint.

It need not hold the cold root. Not every full node is a recovery node.
Clients warn that each recovery node expands the epoch-authority attack
surface.

Registry revision 4 allocates:

```text
core.portable-recovery.v1
core.recovery-node.v1
comms.portable-recovery.v1
comms.recovery-orchestration.v1
comms.recovery-client.v1
comms.recovery-provider.v1
comms.large-object-sync.v1
comms.large-object-sync-consumer.v1
comms.large-object-sync-provider.v1
```

The same revision exhaustively allocates the six baseline slot types, every
recipient/content role, owner, platform, native provider, signed-record reason,
transfer error, and recovery wire profile used by this decision. Schema-bearing
slots and profiles name exact repository schema paths; the implementation
creates the closed schema files and records their raw-file SHA-256 digests
before publishing revision 4. There are no placeholder digests or implicit
recovery vocabulary values.

The closed profile batch expressly includes the ordinary rollover and
rollover-gap records, archive manifest and lifecycle records, special epoch
and generic authority-secret envelopes, recovery grants and roles, the
epoch-activation envelope, transfer frames/receipts, and large-object pointer.
Revision 4 also allocates
`rollover-gap-reason:rollover_state_unrecoverable`, extends the closed
`allocation_kind` enum with `rollover-gap-reason`,
`rollover-reference-member`, `historical-decrypt-obligation-action`, and
`governed-decrypt-source-profile`,
allocates `rollover-reference-member:previous-rollover-head`, and
allocates the obligation kind's exact `retain` and `close` values. The
governed-source kind is the exhaustive owner-bound table described above;
revision 4 cannot freeze until every current source profile has one exact
globally unique value. In particular,
`core.recovery-state-rollover-gap.v1`,
`core.recovery-authority-protected-secret.v1`, and
`core.recovery-epoch-activation-envelope.v1` each bind an exact closed schema
path and raw-file digest. The same is true for
`core.offline-recovery-pre-unseal-intent.v1` at
`docs/spec/schemas/recovery/offline-recovery-pre-unseal-intent-v1.schema.json`
and
`core.offline-recovery-activation.v1` at
`docs/spec/schemas/recovery/offline-recovery-activation-v1.schema.json`.
Every schema must exist before its allocation or wire-profile entry is
finalized, and all registry entries, schemas, family artifacts, and vectors
land as one internally consistent implementation batch.

The shared ADR-037/ADR-038 batch also binds these exact Comms profiles:

```text
comms.governed-decrypt-key-binding.v1
  -> docs/spec/schemas/comms/governed-decrypt-key-binding-v1.schema.json
comms.historical-decrypt-obligation.v1
  -> docs/spec/schemas/comms/historical-decrypt-obligation-v1.schema.json
comms.repository-retention-inventory.v1
  -> docs/spec/schemas/comms/repository-retention-inventory-v1.schema.json
```

The checkpoint schema gains the required governed-binding and
historical-obligation-frontier digests. Transition actions gain the explicit
historical-decrypt holder/assignment arrays; transition, reset, candidate,
receipt, and exact-tip/CAS bases carry both digests; and recovery inventories
gain the closed unreconciled pre-unseal-intent/activation projections, their
separate complete collision projections, and independently complete
per-exposure/per-action intent origins. The recovery
manifest, generic authority-secret envelope, pre-unseal-intent and activation
bases, and transfer-grant activation basis repeat both digests where
applicable; the
manifest also commits the exact obligation-frontier records. The rollover-gap
schema permits signed recovery-record bytes as authenticated evidence and
storage/provider metadata only as audit-only evidence. Raw schema hashes,
wire-profile hashes, and the registry entry-set digest are frozen only after
that complete closure is present. The new inventory schema is closed, fixes
the type constant, and validates safe integers, typed Git/KEL values, canonical
RID/ref names, and exact path/digest/signature encodings.

`core.recovery-node.v1` requires `core.portable-recovery.v1` and
`core.onion-service-host.v1`. `comms.portable-recovery.v1` is the offline
full-persona composition and requires only `core.portable-recovery.v1`.
`comms.recovery-orchestration.v1` requires that Comms composition and
`comms.double-ratchet.v1`. Its client role requires `core.outbound-tor.v1`;
its provider role requires `core.recovery-node.v1`. The common
`comms.large-object-sync.v1` semantics similarly have distinct consumer
(outbound Tor) and provider (recovery node) features. A consumer does not
inherit provider/full-node requirements. Core owns the generic container,
recovery policy, and transfer role without depending upward on a Comms carrier
or repository.

### 7. Use a key-bound eight-hour enrollment grant

A prospective recovery node generates a provisional NID, dedicated SSH
authentication key, and X25519 recovery-recipient key. An existing recovery
device authorizes them for one exact target recovery node and onion endpoint.

The epoch-authorized grant binds the target node and SSH host key, all
prospective keys, requested scopes, byte ceiling, archive generation, issue
time, expiry, and collision-resistant grant ID. Its lifetime is at most eight
hours. The authorizing recovery NID signs the closed grant and current epoch
authority countersigns it after checking that NID's recovery-approval
authority. The target receives it through an already authenticated path.

One closed grant schema has explicit `bootstrap`, `delegated-transfer`, and
`authority-activation` modes. Mode-specific fields are present with exact
value/null rules: only bootstrap carries a prospective delegation intent,
ordinary delegated transfer carries neither prospective nor recovery-key
fields, and authority activation binds the active node role and its recovery
key. Archive generation is non-null only for a sole archive resource.

The grant is not a bearer token. The new node must prove possession of its
bound SSH key, and the client must pin the onion endpoint and host key.
Recovery approval is a separate durable, epoch-signed Core policy with
absorbing revocation; it does not open the gated general Control profile.
Approval policy is a mergeable set of independent authorization-ID lineages
with `grant`, `renew`, and `revoke` actions. A fork quarantines only its ID,
and active overlap quarantines only the affected
`(persona,target,scope)` tuple. Unrelated approvals continue to work.
Same-ID renewal must occur before expiry; a post-expiry grant uses a fresh ID
and names every overlapping terminal head. A fresh-ID grant after any revoke
also requires a different post-revocation epoch key. Removing a target or
scope revokes every active contributing ID. Ordinary KEL rotation does not
expire an otherwise valid lineage. Core owns the per-ID canonical set; the
Comms composition mirrors the same byte-identical set into the encrypted
config repository and uses DR as its standard delivery path.

A fork-, overlap-, or cutoff-quarantined approval tuple recovers only through
a fresh authorization ID that supersedes the complete maximal frontier of
every affected lineage. Every named head must already be inactive, and a
later canonical rotation to a different epoch key must sign the resolution;
wall-clock ordering cannot replace KEL ancestry or compromise-cutoff
validation. One active approval ID must itself contain every scope required by
an operation—scopes from separate IDs are never combined.

Because the prospective NID is not active yet, server rewrap uses a distinct
grant-bound HPKE bootstrap slot. It proves the delegation intent and both grant
signatures rather than falsely claiming an active device delegation. The bulk
DEK reveals the archive's complete non-authority private-data payload,
including private/config repositories, configuration, history, and included
objects; bootstrap is explicit authorization for that disclosure. It still
cannot open the authority-DEK special epoch or generic durable-secret
envelopes, or the independently wrapped cold root.

Bootstrap completion is not node admission. The prospective NID first
receives an ordinary Core delegation and then completes ADR-037's fully
receipted `routine-addition` checkpoint. That checkpoint names the NID in the
roster, rotates both the config-audience and OAuth-pairwise identities before
candidate delivery, and completes every mandatory and cleanup exposure
action. A merely local delegation, pending checkpoint, missing receipt, or
missing mandatory rotation cannot advance enrollment.

Only after that accepted addition may a separate authorization mutation and
fully receipted checkpoint grant credential synchronization or protected
transfer. Canonical source companions and per-holder assignments are then
created for the current epoch and for every generic current or
historical-decrypt secret the node will receive. A historical delivery uses
the accepted transition's exact `historical_decrypt_nids` and
`historical_assignment_digests`: every assignment has a fresh ID but preserves
the old secret tuple, and its source binds the complete active obligation,
governed-key-binding, and artifact evidence. It is decrypt-only for those
governed rows and cannot authorize new encryption or another use of the old
instance.

One or more separate post-addition delivery checkpoints must bind those exact
exposures; each is strictly after the addition checkpoint, and the final one
equals the archive's credential checkpoint, current-holder lineages,
governed retention-snapshot/binding state `K(C)`, complete maximal
historical-obligation frontier, active obligation/provenance projections,
special epoch binding, and durable-secret inventory. Claimed erasure, non-use,
or a failed activation never undoes a recorded exposure.

A separate epoch-signed `heterodyne.recovery-node-role.v1` record durably
authorizes the admitted node NID, recovery key, onion endpoint, and host key.
An authority-activation grant is legal only after that role, all admission and
delivery checkpoints, and reconciliation are canonical. Its closed
`archive_restore_basis` binds the prior archive-transfer grant, immutable
finalized archive identity, exact archive-authority tuple, original required
epoch-slot ID and digest, addition checkpoint, ordered delivery checkpoints,
final credential checkpoint, governed-decrypt-key-binding and
historical-decrypt-obligation digests
(`governed_decrypt_key_bindings_sha256` and
`historical_decrypt_obligations_sha256`), durable-secret inventory, and
special-authority-binding digest. The exact completion receipt for that prior
grant and resource must also be present and revalidated. The named archive
must be produced and finalized at or after that post-addition exposure state.
A bootstrap-delivered archive produced before that transition, a stale
authority tuple, or any other pretransition archive is permanently ineligible
for activation even if it remains useful for isolated inspection; a later,
independently authorized ordinary two-DEK transfer is a new restore path, not
promotion of the old bootstrap verdict.

Only then can a second resource-bound `authority.read` grant carry an HPKE
activation envelope to the role's X25519 key. The current epoch-authority
process creates the randomized envelope before signing, binds the
domain-separated `archive_restore_basis` digest in the grant, outer envelope,
plaintext, HPKE context, and immutable resource, and registers the complete
encrypted payload with the serving node through the authenticated control
path. `authority.put` is not a data-plane operation.

The decrypted scalar is only a transient slot-opening capability. It must
derive the grant's current epoch key and open the exact original required
epoch slot committed by the basis; that slot must yield the complete 64-byte
bulk/authority key bundle. Successful opening starts a new ordinary restore
from the immutable archive bytes. The client reparses and reauthenticates the
entire archive, validates the combined nonce set, all special/generic
envelopes and source/inventory equations, `K(C)`, the complete obligation
frontier and governed-ciphertext bijection, the normal-or-gap rollover closure,
and current rollback state. Only a fully successful new restore may atomically
install the epoch scalar and every required durable secret. Any intervening
KEL, checkpoint, role, approval, archive, source, assignment, governed head,
key binding, obligation, provenance, or inventory change rejects and erases
transient keys without installing authority.

Recovery-node roles are likewise a mergeable set of independent role-ID
lineages with `grant`, `update`, and absorbing `revoke` actions. An update may
replace the recovery key, onion endpoint, or SSH host key; a fork or active
overlap quarantines only that target. A valid role survives ordinary KEL
rotation. Every grant/update names one canonical active target-device
delegation; revoking that exact delegation makes the role permanently
inactive immediately, including when the target acts only as a server.

An ordinary fresh-ID regrant names every latest terminal head for every prior
role ID of that target. A terminal head is either an absorbing role revoke or
a grant/update whose exact target delegation has an absorbing canonical
revocation. The regrant is signed by a different epoch key reached through a
canonical rotation later than every named role or delegation revocation.

Role-fork, overlap, or cutoff recovery uses a fresh role ID whose `supersedes`
set is the complete maximal frontier of every affected lineage, including all
competing branches and every latest terminal role- or delegation-revoked
head. The target must have one current active delegation, and the canonical
post-conflict epoch rotation must follow every named role KEL state and every
delegation revocation that made a named head terminal before its different
key signs the resolution. Incomplete frontiers, a still-active
nonconflicting role, stale delegation or signer, and a second nonidentical
resolution remain quarantined. Core's keys store owns the per-ID set; Comms
claimants additionally require its byte-identical canonical config-repository
mirror. No stale endpoint or key remains valid through an otherwise
unexpired transfer grant.

Every transfer grant binds `server_role_record_digest` to the exact unique
active server-role head, and its server NID, onion endpoint, and host key must
equal that role. Any role update, revoke, overlap, or target-local fork
invalidates the grant immediately. Client authorization independently binds
the exact applicable approval or client-role head. Each resource is a closed
`{class,id,descriptor_sha256,payload_sha256,payload_length}` identity;
`payload_length` is the immutable ciphertext-stream length for an archive,
the stored-byte length for an object, or the exact JCS envelope length for
epoch activation. At issuance, every resource must resolve to canonical bytes
and the sum of signed payload lengths must fit `max_bytes`.

Each epoch rotation first accepts its complete ordinary-or-gap recovery-state
rollover. It redistributes the new secret only to roles active in that
ratified policy state and only after ADR-037 source/assignment exposure and
reconciliation again cover the exact delivered set. Removing a recovery node
requires an absorbing role revoke, epoch rotation, accepted rollover,
reconciliation, and redistribution excluding that node; revocation alone
cannot claw back a copied secret and is reported as incomplete.

Grant IDs are globally unique within
`(persona, server_nid, grant_id)`. Exact duplicate complete grant-envelope
bytes are idempotent; nonidentical reuse permanently quarantines every
claimant under that tuple, opens no channel or stage, and requires a fresh ID
and signatures. No arrival-order or signature-order tie-break is permitted.

For authority activation, the outer HPKE envelope and decrypted plaintext
must exactly equal the signed grant and active role on `grant_id`,
`role_record_digest`, `archive_restore_basis` digest, `issued_at`, persona,
target NID, recovery key, current epoch key, and KEL head. Immediately before
slot opening and again before protected installation the recipient
re-evaluates the complete registered envelope and `grant_active(now,state)`;
stale epoch state, a revoked delegation or role, an inactive approval, expiry,
or any outer/inner mismatch rejects even after successful HPKE
authentication.

### 8. Expose a constrained SSH-over-Tor subsystem

The optional SSH service represents a logical
`epoch-recovery:<persona>:<grant-id>` principal, not an operating-system
account. It uses the closed `heterodyne-transfer-v1` subsystem with
length-delimited JCS frames and bounded raw bodies. It supports resumable
authorized reads of recovery archives and large objects, integrity metadata,
signed completion receipts, retry, and cancellation. It also carries the
separately authorized HPKE epoch-activation envelope; it never carries a
plaintext epoch secret.

Already delegated devices or recovery peers may receive separately scoped,
resource-bound `archive.put` or `object.put` grants. Writes are staged,
digest-bound and byte-limited; objects are content-addressed, while archives
retain their random archive ID. Promotion follows complete integrity
verification. Each transfer grant has exactly one read or write direction, so
coverage, receipt, and closure state cannot mix directions. A prospective
bootstrap node is read-only.

An `archive.put` is promoted only if the destination can authenticate and
open an ordinary recipient slot in the uploaded header under its active role
and protected-key boundary. A bootstrap-only slot never suffices. For `full`,
the slot must yield both the bulk and authority DEKs and both must validate
the entry stream, epoch-authority envelope, and full authority equality
matrix; device classes require their class-sufficient bulk key. Failure is
`transfer_destination_unrecoverable`, produces no completion receipt, and
does not silently create a replacement slot.

It otherwise prohibits:

- interactive shell and arbitrary exec;
- filesystem browsing and arbitrary writes;
- PTY allocation;
- TCP, Unix-socket, X11, or agent forwarding; and
- access outside the grant's archive, objects, byte limit, target, and
  lifetime.

The recovery node rewraps the archive DEK to the prospective recovery key.
Neither the DEK nor epoch secret appears in plaintext on the transfer
protocol; the server handles the transient key bundle inside its protected key
boundary and copies only the bulk DEK into the bootstrap slot. The server
freezes one byte-identical recipient-rewrapped archive for bootstrap
per grant/resource, including its length and complete-file digest, so retries
cannot mix randomized headers. Delegated archive transfer serves the already
stored bytes and requires an existing ordinary recipient slot.

Every resource completes a direction-aware stat before data transfer. A read
stat declares no length or transfer digest; the server freezes the exact
source and returns its positive complete length and SHA-256. A write stat
declares and freezes the positive complete length and SHA-256 before any put;
the server starts an empty durable stage. Object declarations must equal the
signed `payload_length/payload_sha256`. Archive transfer length includes the
magic, prefix, and mutable recipient-slot header and is therefore greater than
the resource's immutable ciphertext `payload_length`; complete parsing must
reconfirm the signed descriptor, ciphertext digest, and payload length before
promotion. A changed declaration or a read/put before successful stat
rejects.

Transfer ranges are a fixed grid over the complete resource and may cross
archive/object cipher-chunk boundaries.
An end-offset range does not complete a resource until the verified range
bitmap covers every byte, so out-of-order resume cannot close a partially
downloaded object. Read ranges and accepted put requests/responses remain
byte-identically replayable through the grant lifetime; after completion the
cached receipt accompanies replay, so a lost read response, put response, or
write receipt does not require reauthorization or duplicate promotion. Grant,
approval, or required-role revocation immediately stops cached replay as well
as new data authorization.
Downloading the archive does not grant authority. Ordinary delegation,
durable recovery-node authorization, and the distinct epoch activation
complete enrollment in that order.

An error frame is emitted only when every required echoed field has a
canonical value representable by the closed error schema. An invalid length
prefix, non-JCS or unparseable header, missing/wrong-type echo field,
unallocated operation, malformed resource, noncanonical integer/hash, or
otherwise unrepresentable value closes the subsystem without an error frame.
`transfer_bad_frame` applies only after a complete canonical echo basis exists;
the allocated error table then supplies exact reason precedence.

The SSH algorithm profile is `curve25519-sha256`, `ssh-ed25519`, and
`aes256-gcm@openssh.com`, with public-key authentication only and no
compression.

### 9. Add a large-object pointer profile

The default Radicle-eligible object limit is 100 MiB. A larger object is
represented by a `heterodyne-large-object-v1` pointer only in a Tier 2 private
repository or Tier 3/config protected branch and is transferred through the
constrained onion service. Tier 1 public content remains Radicle-retrievable
in the baseline; a public object above the threshold requires a future
optional public carrier rather than an inaccessible grant-only pointer.

The pointer is a magic-prefixed JCS blob. It binds the SHA-256 of exact stored
bytes, sizes at the appropriate privacy tier, media/role metadata, encryption
profile and key ID, ordered stored-chunk digests, and authorized recovery-node
hints. Tier 2 stored bytes remain plaintext as its declared trust boundary
requires. Tier 3/config objects use the AES-256-GCM chunk profile and a random
object DEK wrapped by a KEK derived from the protected branch audience key;
SSH and Tor protect transport but do not replace object encryption.

Fixed-resource-range retries reassemble stored bytes, then verify every cipher
chunk and the complete object digest before visibility.

### 10. Define storage-pressure defaults

For each persona on each node:

- managed storage defaults to exactly `5 * 2^30` bytes;
- Radicle-eligible objects default to at most `100 * 2^20` bytes each;
- the client warns when the lesser of quota remaining and filesystem free
  space falls below `1 * 2^30` bytes; and
- `64 * 2^20` bytes are reserved by default for KEL, revocation, credential-ledger,
  status, and other security-critical records.

All values are configurable policy defaults, not network hard limits. At the
hard limit, nonessential media, log, observability, and cache writes fail
before security-critical state. Authoritative data is never silently evicted.
The budget covers client-managed repositories, recovery archives, large
objects, audit/observability/log data, and caches for that persona on that
node. The reserve is inside the 5 GiB budget; user-managed offline copies are
outside it. This local safety policy does not define repo-relay admission,
tenant retention, quota, or garbage collection reserved for a future ADR.

### 11. Keep platform bindings non-normative

Clients should use the platform's protected key service where available:

- Apple Keychain/Secure Enclave;
- Android Keystore, preferring hardware-backed/StrongBox;
- Windows CNG/TPM with DPAPI fallback;
- freedesktop Secret Service or an explicitly detected TPM/PKCS#11 provider;
  and
- non-extractable WebCrypto keys in IndexedDB for browser-local wrappers.

These stores protect small wrappers. They are not the only full-recovery path,
and a browser does not claim hardware backing merely because a key is
non-extractable.

## Consequences

### Positive

- One archive can restore across browser, native, and full-node
  implementations.
- Live configuration ownership maps directly to archive paths.
- Cold-root, epoch, hardware, passphrase, and device-local recovery coexist
  without encrypting repository bytes directly under a signing key.
- A new full node can bootstrap through offline media or an authorized
  onion-only recovery node.
- Large files do not force unbounded Git/Radicle history.
- Storage warnings and a critical reserve preserve revocation and identity
  operations under pressure.

### Negative

- The family gains a new binary framing and chunked encryption profile.
- A recovery node holds epoch authority and is a high-value target.
- A hosted browser hardware slot is constrained by WebAuthn RP-ID rules.
- Device cloning remains operationally dangerous even with explicit warnings.
- Large-object availability depends on authorized recovery nodes or offline
  backups rather than ordinary Radicle replication.
- A lost recipient cannot be revoked from already distributed archive copies;
  recovery requires re-encryption under a new DEK.
- Network enrollment requires multiple fully receipted ADR-037 checkpoints and
  a newly finalized post-transition archive before authority activation, which
  increases recovery latency in exchange for complete exposure accounting.

## Alternatives considered

### Recommendations without a portable format

Rejected. Platform storage advice alone cannot provide cross-client restore or
byte-exact conformance.

### Store repositories directly on a hardware token

Rejected. Authenticator storage is small and not intended for bulk data.
Tokens derive or protect wrapping keys.

### Use platform keystores as the only backup

Rejected. Their keys are commonly device-bound and may disappear on reset,
reimage, profile loss, or origin-storage clearing.

### Use a general SSH/SFTP account

Rejected. Shells, filesystem namespaces, writes, and forwarding create
unnecessary authority and attack surface. The recovery protocol needs a closed
transfer subsystem with reads and explicitly scoped, immutable,
integrity-checked puts.

### Reuse the device Ed25519 key for encryption

Rejected. Device signing and recovery encryption remain separate. The NID
authorizes a dedicated X25519 recipient.

### Put every media object in Git

Rejected. Large immutable blobs bloat history and replication. A
content-addressed pointer preserves integrity while allowing bounded,
resumable recovery-node transfer.

## Conformance impact

The container, recipient slots, manifest, restore state machine, grants,
constrained subsystem, pointers, and storage boundaries require normative
vectors. Coverage includes arrival-order-independent and transitive archive
fork resolution, slot-only rewrap equivalence, the bulk-only
`bootstrap-validated` boundary, full role/delegation conflict frontiers and
post-revocation rotation ordering, class-sufficient destination archive
slots, and canonical-frame versus connection-close error handling. Exact
coverage is listed in the linked design record.

The implementation batch must additionally include positive and negative
vectors for:

- ordinary rollover linkage, cold-root gap repair from classified missing-
  candidate evidence, exact signed-recovery-record-only
  `authenticated-reference` classification through only the allocated
  `core.recovery-state-rollover.v1`/`previous-rollover-head` dispatch,
  rejection of other profiles or members, explicit audit-only
  storage/provider evidence, complete evidence-byte retention, rejection of
  classification upgrades or available-candidate demotion, permanent
  `gap-unratified` treatment of skipped/late authority, and restore-pending
  behavior when any normal-or-gap closure byte is unavailable;
- the one-to-one generation-scope/freshness-chain relation and complete
  decreasing finalized fallback arrays, including fallback after a newer
  finalization is abandoned or cutoff and preservation under greater pending,
  abandoned, or conflicting state;
- the governed-decrypt binding's closed shape, deterministic locator ID,
  authority and acyclic artifact/binding/inventory/obligation/transition/
  checkpoint ordering; exact `K(C)` derivation from the complete repository-
  inventory, frozen retention snapshots, and binding frontiers; checkpoint
  digest propagation and independent receipt recomputation; embedded-tuple and
  signed-binding positives; and missing, extra, late, conflicting, unrelated,
  ambiguous-multi-tuple, or validator-selected bindings, unallocated source
  profiles, mixed-owner head projection, missing/extra/mismatched projected
  owner, snapshot drift, and current-post false mutation negatives;
- the repository-retention inventory's closed record, signature, sequence,
  target/basis activation, deterministic ref ID, exact path, maximal frontier,
  typed SHA-1/SHA-256 scan heads, monotonic rows, and absorbing retirement.
  Positives cover genesis config/private refs, head advance, registration and
  full scan before first governed use, discovery during rotation, unchanged
  `K(C)` for current posts, exact-tree re-encryption/deletion followed by close
  despite retained ancestor audit evidence, exact ordinary config-key-
  acceptance deregistration, including no-dependency rotation/addition/removal
  with changed inventory/`K(C)`/governed-binding digest but byte-identical
  governed heads, binding records, and obligation digest, the exact
  parentless-`B`/direct-child-`T` carrier with logically ordered
  `K`/`R`/`O`/dependent proofs/transition co-committed independently of
  lexical tree order, emergency complete-`V_old` deregistration,
  complete closure basis and same-CAS old-ref deletion, ancestor-only audit
  retention without later ref scan, complete emergency branch merge,
  and active/active, active/retired, retired/retired, and same-head/different-
  retired convergence in SHA-1 and SHA-256 through a fully scanned resolution
  commit whose sorted direct parents are exactly every distinct variant head.
  Each union locator has one disposition, fresh H*-based bindings/obligations
  replace old-head forms, `G(B)=O(B)`, the signed retirement result is exact,
  a retired config result supplies a separate active row, and a row registered
  on only one branch survives the parent union unless it belongs to complete
  `V_old`. Config H* uses the sole bound
  multi-parent resolution grammar while ordinary config history stays linear.
  Cross-branch lifecycle vectors classify current-on-A/retired-on-B and
  current-on-A/different-current-on-B ciphertext conservatively. A legitimate
  same-locator multi-tuple profile remains pairwise, and conflicting fallback
  bindings clean every candidate before one uniquely validated H* result; a
  rejected candidate remains terminal audit evidence without an active
  obligation.
  Negatives cover omitted prior
  rows outside those exceptions, wrong/non-config/premature deregistration,
  incomplete/partial-variant/different-ref emergency subtraction, incomplete
  logical-tree closure, missing old-ref deletion,
  private RID/ref or branch-only row outside `V_old` or
  dependency, unregistered governed content, missing conflict parents,
  extra/wrong-order parents, arrival-order choice, ordinary retired-row drop/
  reactivation/advance, incomplete or non-common-descendant emergency merge,
  unscanned tree, parent-local-current omission, path collision or branch
  artifact without total
  disposition, silent ancestor-only disappearance, wrong retirement result,
  missing active config row, stale binding/locator reuse, missing fresh H*
  binding, `G(B)!=O(B)`, later retired-H* advance, regression/alias/format/ID
  mismatch, unbound/ordinary config merge, wrong/extra/unsorted config parents
  or resolution message, singular multi-tuple selection, omitted/unavailable
  binding candidate, unvalidated fresh fallback binding, active obligation for
  a rejected candidate, unauthenticated result pair, cycles, an unchanged
  predecessor governed-binding digest across mandatory config-row replacement,
  any other unchanged digest during inventory drift, a new transition-bound
  `K`/`R`/`O`/dependent proof in `B`, transition signing before those proofs
  are complete, an intermediate commit between `B` and `T`, a dependency on
  `T`'s commit OID, or use of lexical tree order as dependency order,
  archive omission,
  ancestor-only/loose-object misclassification, omitted frozen retention ref,
  and post-cut old-key acceptance. A late pre-cut branch remains audit
  evidence but does not reopen the accepted reset;
- the full retain/update/close obligation frontier and independently derived
  governed-ciphertext bijection, including typed SHA-1/SHA-256 repository and
  blob OIDs, exact format/length/sorting rules, active obligation and retired-
  provenance completeness, explicit fresh-ID same-old-instance
  historical-decrypt-only holder assignments, prohibition on operational/new-
  encryption use, and final-close retirement of every live historical holder;
- the exact two special authority bindings, total disposition of all 19
  ADR-037 secret classes, generic entry/inventory/record-locator bijection,
  complete current-holder, active-obligation, retired-provenance, checkpoint,
  governed-binding, and obligation-digest derivation, and malformed, duplicate,
  or colliding special/generic nonce rejection before authority decryption;
- offline activation coverage over exactly full-archive-derived or preexisting
  persona authority, with every clone/device-signing secret and fresh
  NID/device/publishing, SSH, X25519, and platform-wrapper key excluded;
  rejection of pre-unseal intent or activation for `device-local` or
  `clone-device`, and unchanged logical holder/assignment state for exact
  same-NID cloning;
  independent cold-root signing and bulk-only/compartmentalized opening; exact
  trusted-clock and conservative-zero timestamp handling;
  nonexportable authority-DEK use and validation before hidden material/signing
  release;
  pre-unseal intent/template shape, path, signature, bijection, and completion;
  durable intent before authority release; cancellation, failed AEAD, hidden
  mismatch, and crash-before-completion remaining unreconciled evidence; the
  second completed `secret-bearing-prepare` boundary; rejection of
  secret-first durability; noninstallation of incomplete candidates; exact
  `ObservedPreUnsealIntents`/`ReconciledIntent(I)`/
  `UnreconciledPreUnsealIntents` and activation partitions; complete tagged
  assignment/intent origin union without intent pseudo-items in exposure-set
  digests; independently complete action arrays and real-assignment-only
  retirements; intent-only target exclusion; simultaneous intent+activation
  reconciliation; late activation after prior intent reconciliation; exact
  duplicate idempotence versus nonidentical intent and completed-activation
  collision variants; mixed reconciled-plus-late collision emergency reset
  inventorying only unreconciled variants; general predecessor-current epoch
  compromise cutoff no later than earliest relevant intent time, including
  an already reconciled intent, ordinary addition, and rejection of interval
  signatures; inventory-only acceptance and retirement of an exact raw-valid
  completion made authority-ineligible by that cutoff, with rejection of bad
  raw signatures or operational use; and full
  routine-addition/emergency-reset cleanup through rollover, delivery, and
  role reconciliation;
- isolated bootstrap staging; ordinary delegation and fully receipted
  `routine-addition`; separate authorization and post-addition delivery
  checkpoints with same-instance historical-decrypt-only delivery and exact
  `K(C)`/obligation/inventory state; exact `archive_restore_basis`; stale and
  pretransition archive refusal; exact required-epoch-slot opening to two DEKs;
  fresh ordinary restore; and atomic installation only after all authority,
  source, binding, obligation, inventory, rollover, and rollback checks
  succeed; and
- the closed revision-4 allocation, wire-profile, schema-path, and raw-schema-
  digest closure for every new reason and profile, including the closed
  `historical-decrypt-obligation-action` allocation kind and its `retain`/
  `close` values, the closed `governed-decrypt-source-profile` kind and
  exhaustive owner-bound table, governed-binding, obligation, and repository-
  inventory profiles, rollover gap, generic authority envelope, offline
  activation, and epoch-activation envelope, plus all checkpoint/transition/
  manifest/restore-basis schema propagation; and
- simultaneous historical audience-key and object-DEK retention for one
  encrypted large-object pointer with two distinct locator/obligation rows,
  plus one-row omission, tuple swap/substitution, collapse, and ambiguous
  fallback rejection.

Those vectors and normative artifacts follow only after ADR acceptance; this
design-review change does not pre-allocate or partially publish revision 4.
