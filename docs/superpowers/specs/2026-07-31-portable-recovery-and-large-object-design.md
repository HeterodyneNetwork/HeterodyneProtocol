# Portable Recovery and Large-Object Design

**Date:** 2026-07-31
**Status:** Approved for implementation planning
**Protocol owners:** Core and Comms
**Registry target:** revision 4
**Decision record:** ADR-038

## Goal

Provide one encrypted, cross-platform backup format that maps cleanly to live
Heterodyne repositories and configuration files, and provide an optional
onion-only recovery-node service for restoring a new full node or transferring
objects too large for ordinary Radicle replication.

The design supports offline removable media and online recovery from an
already authorized recovery device. Platform keystores and hardware
authenticators wrap backup keys; they do not become bulk-data stores or
replace Heterodyne signing authority.

## Design principles

1. Every backup is encrypted, including a backup containing only public
   repositories.
2. Bulk data is encrypted under a fresh random data-encryption key (DEK).
   A separate fresh authority DEK protects recoverable epoch-secret material.
   Cold-root, epoch, device, platform, hardware-token, and passphrase
   mechanisms wrap only the fixed backup-key bundle, never repository bytes.
3. Signing keys are not fed directly to the bulk-data cipher. The
   secp256k1 cold-root and epoch keys use an ephemeral,
   NIP-44-v2-derived recipient-wrap envelope. Device NIDs bind a separate
   recovery-encryption key or a
   platform-sealed same-device wrapper.
4. A normal restore creates a fresh device NID. Copying an existing device
   secret is an explicit migration operation, not the default.
5. The container's logical paths map to live configuration ownership, while
   platform-specific content remains opaque to other platforms.
6. A recovery-node network service exposes a constrained transfer subsystem,
   never a general shell.
7. Storage pressure must not prevent identity rotation, revocation, or other
   security-critical writes.

## Roles

### Recovery node

A **recovery node** is an optional capability of a conforming full node. It:

- holds the current epoch secret under the Core key-protection profile;
- maintains current encrypted recovery material for one or more personas;
- may host the constrained recovery and large-object subsystem on a
  persistent onion service; and
- is explicitly authorized as a recovery node by the persona.

Not every full node is a recovery node. A recovery node need not hold the cold
root. Adding one increases the number of systems capable of exercising epoch
authority and therefore requires an explicit warning and protected local
storage.

### Recovery device

A **recovery device** is an authorized client capable of approving a new
recovery node. It may be a recovery node itself or a trusted device connected
to one through the authenticated Control/DR path. Approval does not turn a
browser tab or light client into a secret-holding full node.

### Document ownership boundary

Core owns the portable container, Core key/public-repository entries,
per-persona generation chain, epoch-authorized recovery policy, and generic
onion transfer role. None of those requires a Comms repository or carrier.

Comms owns the full-persona composition that adds private/config repositories,
shared generation finality, DR delivery of recovery approvals/grants, and
large-object synchronization. `comms.portable-recovery.v1` is the offline
composition and does not require a recovery node or a network carrier;
`comms.recovery-orchestration.v1` adds network enrollment and transfer. The
standard Heterodyne path uses those compositions, but Core remains
implementable without an upward dependency.

## `heterodyne-recovery-v1` container

### Outer framing

The portable artifact is one file. Its framing has:

1. the fixed ASCII magic `HETERODYNE-RECOVERY-V1\n`;
2. a four-byte unsigned big-endian header length, no greater than 1 MiB;
3. a JCS-canonical UTF-8 JSON header;
4. a sequence of independently authenticated ciphertext chunks; and
5. no trailing undeclared bytes.

The clear header contains only:

- `format`, exactly `heterodyne-recovery-v1`;
- `archive_id`, exactly 32 random bytes encoded as 64 lowercase hexadecimal
  characters;
- the immutable payload descriptor, including algorithms, chunk count, fixed
  chunk size, and final plaintext length;
- opaque recipient slots;
- the ciphertext length and SHA-256 digest.

The exact version-1 header shape is:

```json
{
  "format": "heterodyne-recovery-v1",
  "archive_id": "<64 lowercase hex>",
  "payload_descriptor": {
    "cipher": "AES-256-GCM",
    "chunk_plaintext_bytes": 1048576,
    "chunk_count": 1,
    "final_plaintext_length": 1,
    "nonce_profile": "HDRY-u64be-v1",
    "aad_profile": "heterodyne-recovery-chunk-v1"
  },
  "recipient_slots": [],
  "ciphertext_length": 17,
  "ciphertext_sha256": "<64 lowercase hex>"
}
```

The base header and payload descriptor are closed with exactly those members;
a later format literal is required to add one. Slots are sorted by decoded
`slot_id` bytes and have the common closed envelope
`{"slot_id":"<32 lowercase hex>","slot_type":"<allocated type>","body":{...}}`.
Slot IDs are unique random 16-byte values. It contains at most 64 recipient
slots, has a maximum nesting depth of 16, and contains no string longer than
16 KiB except an allocated ciphertext member with its own bound.
`chunk_count` is an integer from 1 through `2^32 - 1`;
`final_plaintext_length` is from 1 through 1 MiB. The declared ciphertext
length MUST equal:

```text
(chunk_count - 1) * (1 MiB + 16) + final_plaintext_length + 16
```

where 16 is the AES-GCM tag length. An implementation applies its advertised
archive-size policy before allocating memory or evaluating an expensive
recipient slot.

Each `slot_type` has a registry-bound closed body schema. An unallocated type
is rejected. A consumer may skip a well-formed allocated type it does not
implement and try another slot, but it cannot claim that recipient feature;
restore fails if no supported slot authenticates and unwraps its declared
backup-key material.

Persona identifiers, RIDs, repository names, logical paths, media types,
platform identifiers, timestamps, and file sizes remain inside the encrypted
manifest. Recipient slots expose only the information required to select and
exercise the wrapper. Clients should use non-correlating recipient hints where
the wrapper permits them.

### Bulk encryption

Every archive uses a new random 32-byte DEK and a distinct random 32-byte
authority DEK. `archive_key_bundle` is the fixed 64 bytes
`DEK || authority_DEK`. The encrypted entry stream uses the first key;
full-recovery epoch-authority material uses the second key as defined below.
The encrypted stream uses AES-256-GCM with a maximum plaintext chunk size of
1 MiB. Chunk indices begin at zero. The 96-bit nonce is:

```text
0x48445259 || uint64be(chunk_index)
```

where `0x48445259` is the ASCII domain marker `HDRY`. Reusing a DEK for a
different archive is prohibited. Each chunk is stored as ciphertext followed
by its 16-byte tag. Its associated data is the UTF-8 encoding of:

```text
heterodyne-recovery-chunk-v1|<archive_id>|<descriptor_sha256>|<index>|<plaintext_length>|<final>
```

`archive_id` and `descriptor_sha256` are lowercase hex, integers are canonical
unsigned decimal without leading zeroes, and `final` is `0` or `1`. Exactly
the last declared chunk uses `final=1`; all preceding chunks are exactly
1 MiB and use `final=0`. The payload-descriptor digest is SHA-256 over the JCS
bytes of the exact descriptor in the header.

Recipient slots are outside the immutable payload descriptor, allowing an
unchanged encrypted payload to be rewrapped for another authorized recipient.
Removing a slot from a new copy does not revoke old archive copies. A stolen
recipient requires a new DEK, a new archive generation, and replacement of
distributed copies.

The container adds no global compression. Individual entries, including Git
bundles, media, and logs, may use their native compression and declare it in
the encrypted manifest.

### Encrypted manifest and entry stream

The first plaintext record is a four-byte unsigned big-endian manifest length,
no greater than 16 MiB, followed by the JCS manifest. Remaining plaintext bytes
are the file entries in manifest order. Entry offsets are relative to the
first byte after the manifest. Each entry declares:

- a strict relative UTF-8 path;
- byte offset and length;
- SHA-256 digest;
- content role and owner;
- optional media type and native compression;
- repository RID/head or configuration schema where applicable; and
- restore policy: `authoritative`, `cache`, `history`, or `optional`.

Version-1 paths are ASCII and each component matches
`[a-z0-9][a-z0-9._-]{0,127}`. Paths are sorted by ASCII byte order and unique.
Entry offsets and lengths form a contiguous, non-overlapping partition of all
bytes after the manifest. Absolute paths, `.` or `..` components, empty
components, backslashes, control characters, symlinks, hardlinks, device
files, sparse-file tricks, a component ending in `.`, or a component whose
first dot-delimited segment is `con`, `prn`, `aux`, `nul`, `com1` through
`com9`, or `lpt1` through `lpt9` are rejected before extraction. The
lowercase-ASCII alphabet makes case-folding and Unicode-normalization aliases
impossible. Extraction never preserves executable,
set-user-ID, ownership, ACL, or platform extended-attribute state.

The manifest and all nested objects are closed. Every field is present; `null`
represents an allocated but inapplicable value:

```json
{
  "format": "heterodyne-recovery-manifest-v1",
  "archive_id": "<64 lowercase hex>",
  "archive_generation": 1,
  "generation_record_digest": "<64 lowercase hex>",
  "created_at": 0,
  "backup_class": "full",
  "content_completeness": "standalone",
  "protocol_context": {
    "registry": {
      "revision": 4,
      "entry_set_sha256": "<64 lowercase hex>"
    },
    "documents": [],
    "claimed_features": [],
    "configuration_owners": []
  },
  "persona": "<64 lowercase hex cold-root public key>",
  "producer_nid": "<canonical Ed25519 did:key>",
  "authority": {
    "signer_type": "epoch-secp256k1",
    "signer": "<64 lowercase hex>",
    "kel_head": {"event_id": "<64 lowercase hex>", "seq": 0},
    "delegation_event_id": null
  },
  "high_water": {
    "kel": {"event_id": "<64 lowercase hex>", "seq": 0},
    "repositories": [],
    "credential_ledger": {
      "generation": 0,
      "checkpoint_digest": "<64 lowercase hex>",
      "exposure_set_sha256": "<64 lowercase hex>",
      "governed_decrypt_key_bindings_sha256": "<64 lowercase hex>",
      "historical_decrypt_obligations_sha256": "<64 lowercase hex>",
      "secret_inventory_sha256": "<64 lowercase hex>"
    },
    "status_lists": []
  },
  "historical_decrypt_obligation_records": [],
  "special_authority_bindings": [],
  "durable_secret_inventory": [],
  "path_mappings": [],
  "entries": [],
  "external_objects": [],
  "required_recipient_slots": [
    {
      "slot_id": "<cold-root slot ID: 32 lowercase hex>",
      "recipient_role": "cold-root",
      "slot_sha256": "<64 lowercase hex>"
    },
    {
      "slot_id": "<epoch slot ID: 32 lowercase hex>",
      "recipient_role": "epoch",
      "slot_sha256": "<64 lowercase hex>"
    }
  ],
  "signature": {
    "suite": "BIP340",
    "value": "<128 lowercase hex>"
  }
}
```

`ciphertext_sha256` is lowercase-hex SHA-256 over the exact concatenation, in
increasing chunk-index order, of every stored `ciphertext || tag` chunk.

`backup_class` is `full`, `device-local`, or `clone-device`.
`content_completeness` is `standalone` or `network-assisted`;
`external_objects` is a sorted unique array of stored-byte object IDs omitted
from the archive. A repository
high-water entry has exactly `rid`, `class`, and `head`; it is sorted by
canonical RID UTF-8 bytes then class, where class is `public`, `private`, or
`config`.
A status-list high-water entry has exactly `issuer`, `list_id`, `generation`,
and `digest`, sorted by their UTF-8 tuple. Numeric fields are JSON-safe
nonnegative integers. A path mapping has exactly `path_id`, `kind`, and
`canonical_value`, is sorted by `path_id`, and uses kind `rid`, `nid`, `owner`,
`schema`, `platform`, `record`, or `object`. `path_id` is exactly `m-` followed by 32
lowercase hexadecimal characters, is unique across the whole manifest
regardless of kind, and maps to exactly one `(kind, canonical_value)` pair.
Every dynamic component in the allocated logical layout is an `m-*` ID and
MUST resolve through exactly one mapping; dynamic values are never embedded
literally even when already path-safe. Fixed layout components are protocol
literals and never begin `m-`, so lookup is unambiguous without another entry
reference. Entry descriptors have exactly `path`, `offset`,
`length`, `sha256`, `role`, `owner`, `media_type`, `compression`,
`restore_policy`, and `repository`; `media_type`, `compression`, and
`repository` are null when inapplicable. A non-null repository object has
exactly `rid`, `class`, `head`, `object_format`, and `included_refs`, with
sorted unique refs. `role` and `owner` are allocated ASCII identifiers,
`restore_policy` is `authoritative`, `cache`, `history`, or `optional`, and
lengths/offsets are JSON-safe nonnegative integers.

`protocol_context` is a signed completeness input, not a hint inferred from
which entries happen to be present. For `heterodyne-recovery-v1` it is a closed
revision-4 object. `registry` contains exactly `revision:4` and the exact
revision-4 `entry_set_sha256`. `documents` is a strictly
qualified-version-sorted unique array of closed
`{qualified_version,artifact_manifest_path,artifact_set_sha256}` objects. It
contains the exact selected current or superseded artifact pair for Core and
for every family document whose behavior/configuration the archive claims;
recursive dependencies satisfy ADR-037's one-byte-identical-pair-per-qualified-
version closure. `claimed_features` is the sorted unique complete prerequisite
closure of recovery features claimed by the archive and every item is provided
by one selected document artifact. `configuration_owners` is the sorted unique
set of owners permitted for configuration and protected entries; `core`,
`comms`, `control`, and `social` require their corresponding selected document,
while `client` is non-authority configuration only.

Every archive claims `core.portable-recovery.v1`; any archive containing a
private/config repository, credential high-water, or Comms durable secret also
claims `comms.portable-recovery.v1`. A Control or Social owner appears only
when its exact selected document artifact and governing schemas are present.
The required repository, configuration, history, durable-secret, and object
inventories are derived from this entire context. Removing a document,
feature, or owner to make an omitted entry appear optional changes the signed
manifest and is not an interpretation choice. An unsupported revision,
artifact pair, feature, owner/schema, or closure is an unsupported archive,
not permission to validate against a smaller locally known composition.

`high_water.credential_ledger` may be null only when that backup class contains
no credential-plane authority. For the Comms full composition it is non-null:
its generation, checkpoint, exposure-set digest, and
`governed_decrypt_key_bindings_sha256` exactly equal the accepted
credential-ledger checkpoint. The governed-binding digest is independently
recomputed from the archived checkpoint/config/repository snapshot as defined
below. Its
`historical_decrypt_obligations_sha256` equals that checkpoint field and the
domain-separated digest of the exact complete
`historical_decrypt_obligation_records` array defined below.
`secret_inventory_sha256` is lowercase-hex SHA-256 of the UTF-8 JCS
serialization of the exact `durable_secret_inventory` manifest member.
Every other backup composition uses exactly empty obligation-record and
durable-secret arrays; it does not invent credential-plane state outside a
Comms full archive.

The revision-4 role/owner pairing is exact.
`repositories/public/*` bundles use `role:"repository-bundle"` and
`owner:"core"`; `repositories/private/*` and `repositories/config/*` bundles
use `role:"repository-bundle"` and `owner:"comms"`.
`keys/<owner>/*` entries use the exact allocated family owner (`core`,
`comms`, `control`, or `social`) and one of three disjoint roles.
`core-protected-record` is owner `core` and contains only the independently
NIP-49-wrapped cold-root record. `protected-metadata-record` contains signed
policy/history/location material whose bulk-visible bytes cannot yield a
private key or live symmetric secret: KEL/delegation records, archive
allocation/signed-manifest/finalization/abandonment/resolution records,
recovery-state rollovers, recovery approval/role/grant records, credential
source/exposure descriptors, governed-decrypt key bindings, historical-decrypt
obligations, offline pre-unseal intents and activations, their accepted
collision/terminalization evidence, and protection metadata.
`authority-protected-secret` contains exactly the
special current-epoch envelope or the generic authority-DEK durable-secret
envelope below. A record whose bulk-decrypted
bytes can yield secret capability material can never use either metadata role;
an opaque signed/nonsecret record can never be hidden under the secret role
merely to make bootstrap validation skip it.
`keys/device/*/clone-secret` uses `role:"device-clone-secret"` and
`owner:"core"` and is legal only for `backup_class:"clone-device"`. Shared, platform, and
device configuration use their corresponding
`shared-configuration`, `platform-configuration`, or `device-configuration`
role and the allocated owner of the governing schema (`core`, `comms`,
`control`, `social`, or `client`). Managed stored objects use
`role:"large-object"` and `owner:"comms"`. History uses
`role:"audit-history"` and the owner of the record profile. The `media` role
is reserved for the large-object pointer's semantic content-role member, not
an archive-entry role. Recipient wrapper roles are exactly `cold-root`,
`epoch`, `device`, or `bootstrap`. Any other pairing rejects rather than being
treated as an opaque authority-bearing entry.

Backup-class authority is closed:

| Class | Permitted secret-bearing entries | Authority slot rule |
|---|---|---|
| `full` | protected cold-root record, `current-epoch-authority`, every owner-scoped durable secret required by the claimed composition, and the complete repository/configuration set required by that composition | ordinary cold-root, epoch, hardware, passphrase, or explicitly selected device slots wrap both DEKs; the producer warns that any selected device recovery key can restore current epoch and other durable authority |
| `device-local` | portable device configuration and non-authority protected records only; no cold-root record, epoch secret, NID secret, token, or active ratchet state | device/platform-local slots may be sufficient, but the authority DEK is unused and destroyed |
| `clone-device` | the explicitly selected device NID secret and portable device configuration; no cold-root record, epoch secret, token, active ratchet state, or persona-wide authority record | at least one non-device-local recipient opens the archive; the authority DEK is unused and destroyed |

`current-epoch-authority` is valid only in `backup_class:"full"`. A
device-specific archive never becomes a persona-authority archive merely
because its wrapper plaintext has the fixed 64-byte key-bundle shape.
For a Core-only full archive, “complete” means every authoritative Core keys
record, public repository, Core-owned configuration/history record, and
externally listed Core object; it neither requires nor permits inventing
private/config repositories or a credential-ledger high-water mark when Comms
is absent. A `comms.portable-recovery.v1` full archive is the standard
Heterodyne composition and additionally requires every authoritative private
and config repository, every Comms-owned configuration/history record, every
required owner-scoped durable secret, the credential-ledger/exposure/inventory
high-water mark, and its governed external objects. In both cases
`standalone`/`network-assisted` completeness is evaluated against that exact
claimed feature composition. An archive cannot claim the Comms feature while
silently emitting the smaller Core-only set or ciphertext without the
authority-protected keys required to decrypt and continue it.

Every full archive whose `high_water.kel` includes an epoch rotation also
contains, as protected metadata, the complete applicable rollover linkage
closure through that KEL head. This is the unique rollover bound to the latest
such rotation, every earlier rollover recursively named by its
`previous_rollover_heads` closure back to the first post-inception rotation,
and every archive, approval, and role record needed to resolve every included
rollover's committed head frontiers. A linked prior conflict includes every
competing rollover named by the later accepted record, not just one convenient
parent. When the latest or an intermediate rollover binds a valid
`rollover_gap_digest`, the closure instead includes that exact gap record, its
last earlier unique base linkage, every skipped and repair KEL event, and every
frontier byte and exact rollover-reference-evidence byte the gap and repairing
rollover commit; the missing rollover records named by the gap are deliberately
replaced only by that cold-root closure and are not silently inferred.
`standalone` cannot omit any member of the applicable normal-or-gap closure;
`network-assisted` may omit only declared large-object ciphertext. A missing
intermediate normal rollover, required gap record, skipped/repair KEL event,
reference-evidence artifact, or referenced frontier byte leaves restore
`restore-pending`, even when the latest rollover and archive manifest
authenticate. An archive that predates a later network rotation is not
malformed, but it cannot exercise current recovery authority until
synchronization establishes the later rollover state.

The signature object contains exactly `suite` and `value`. For
`backup_class:"full"`, `suite` is `BIP340` and `value` is a 64-byte BIP-340
signature encoded as 128 lowercase hexadecimal characters. For
`backup_class:"device-local"` or `backup_class:"clone-device"`, `suite` is
`Ed25519` and `value` is a 64-byte Ed25519 signature encoded as unpadded
base64url. Every other suite/backup-class pairing or encoding is rejected.
The signature input for either suite is:

```text
SHA256(
  UTF8("heterodyne-recovery-manifest-v1") || 0x00 ||
  JCS(manifest with the signature member omitted)
)
```

A full-recovery manifest uses BIP-340 under the current epoch key. Either
device-class manifest uses Ed25519 under the active NID. The signer reference,
KEL head or delegation evidence, and signature suite are explicit. A verifier
first checks the signature mathematically and then establishes that the signer
was authorized by the restored KEL/delegation state and any trusted local
high-water mark. `archive_generation` is one monotonically increasing
per-persona counter. Core defines the signed chain and permits each node to
retain its latest known state locally; the Comms full-recovery composition
adds shared repository finality without changing the counter. Device-local
and clone-device backups use separate per-`(NID,backup_class)` generations.

### Portable signer and epoch-rollover authority

Every signed record first undergoes historical signer validation.
`created_at` (or `issued_at` for policy records) is checked against the
record's exact canonical KEL head and, where applicable, exact delegation
state. The named signing head MUST be an ancestor of the verifier's current
canonical KEL and no canonical `compromise_since` cutoff may invalidate the
record. A device delegation MUST have authorized the exact NID, persona, and
operation under the named state. This validation proves that the signature
bytes are historically well formed; by itself it does not let a retired epoch
key create new portable authority by backdating a record into its former
interval.

Epoch-signed recovery records use these two authority classes:

- A **current-epoch record** names the epoch key established by the verifier's
  latest canonical epoch-establishing event and a KEL head at or after that
  event while the same key remains current. If that event is a rotation,
  recovery authority is `rollover-pending` until the unique valid
  `heterodyne.recovery-state-rollover.v1` bound to that rotation is accepted.
  After acceptance, current-epoch records may create a new lineage or extend
  one of the exact committed heads.
- A **retired-epoch record** names an ancestor key that a later canonical
  rotation replaced. It remains authoritative after that rotation only when
  it belongs to the family-specific validated closure of a head committed by
  the latest applicable accepted state rollover.
  A retired-key root, successor, manifest, finalization, abandonment,
  approval, or role record omitted from that closed state is audit evidence
  only. Backdated `created_at`/`issued_at`, unique arrival, and prior local
  acceptance cannot make it a candidate. A committed old head ratifies its
  ancestors, not an unlisted old-key descendant.

The inception epoch has no predecessor and needs no rollover. Every later
epoch-changing rotation requires one before archive freshness, approval
authority, recovery-node roles, transfer grants, authority redistribution, or
persona-wide backup production can resume. Device-class archive records remain
device-local claims governed by their exact delegation lineage and absorbing
revocation; an epoch rollover neither ratifies nor reactivates a revoked NID.

While `rollover-pending`, the new epoch and cold root may produce and stage,
under each record's existing signature rule, the rollover, archive resolutions,
or approval/role recovery roots needed to construct the snapshot. None is
operational until the unique rollover commits the resulting frontier. Such a
repair record is `rollover-provisional`: validators complete all of its normal
signature, KEL, frontier, and schema checks, but do not apply its authority or
terminal effect before rollover acceptance. Alternatively, the rollover may
preserve the old conflict frontier; after acceptance the current epoch/cold
root may create the ordinary repair record against exactly that ratified
frontier, and that current-authority update remains valid until the next
rotation. An accepted rollover is never amended in place.

The closed rollover record contains exactly:

```text
type, persona, rotation_event_id,
prior_epoch_pubkey, prior_kel_head,
new_epoch_pubkey, new_kel_head,
previous_rollover_heads, rollover_gap_digest,
archive_generation_heads, archive_manifest_heads, archive_terminal_heads,
archive_freshness_chains,
approval_heads, role_heads, created_at, signature
```

`type` is exactly `heterodyne.recovery-state-rollover.v1`. `persona`,
`prior_epoch_pubkey`, and `new_epoch_pubkey` are 64 lowercase hexadecimal
characters. `rotation_event_id` is a 64-lowercase-hex event ID.
`prior_kel_head` and `new_kel_head` are the same closed
`{"event_id","seq"}` objects used elsewhere in this design.
`rollover_gap_digest` is null for the ordinary linkage form and otherwise is
the 64-lowercase-hex complete digest of the one gap record defined below.
When it is null, `previous_rollover_heads` is the complete strictly sorted
unique array of closed `{rotation_event_id,rollover_digest}` objects that links
this record to the rollover frontier for the immediately preceding canonical
epoch-changing rotation. The first post-inception rotation uses an empty
array. Every later ordinary rotation uses one entry when the preceding
rotation has one unique accepted rollover, or every competing candidate when
that preceding rotation is `rollover-conflicted`. Entries sort by decoded
rotation-event ID and then decoded complete rollover-record digest; both
members are exactly 64 lowercase hexadecimal characters. The non-null gap
form instead uses the exact last-earlier-base array committed by the gap
record; no record can combine ordinary immediate linkage with a gap.

`archive_generation_heads` is the complete strictly sorted unique array of
closed `{record_type,record_digest}` objects for every maximal full-archive
generation frontier. `record_type` is `archive-generation` or
`archive-generation-resolution`. Competing maximal records are all listed and
remain quarantined under their existing archive-conflict rule; the rollover
does not select between them. Entries sort by record type and decoded record
digest.

`archive_manifest_heads` is the complete strictly sorted unique array of
closed `{generation_record_digest,manifest_digest}` objects.
It lists every maximal signed-manifest candidate for every allocation whose
artifact state is maximal under the generation frontier, plus the exact
selected manifest of every member of every
`archive_freshness_chains.finalized_fallbacks` array. Competing unresolved
manifests are all listed and remain quarantined. Every listed finalization
candidate and every fallback member's exact bound manifest MUST be listed.
After an accepted artifact resolution, only its selected manifest is listed
for that allocation's `finalized` outcome and none is listed for that
allocation's `abandoned` outcome; an earlier freshness allocation remains
listed independently. Rejected manifests remain audit evidence rather than
ratified heads. Entries sort by decoded generation-record digest and decoded
complete signed-manifest digest.

`archive_terminal_heads` is the complete strictly sorted unique array
containing the maximal terminal frontier for every allocation whose artifact
state is maximal under the generation frontier and the exact accepted terminal
for every member of every `archive_freshness_chains.finalized_fallbacks`
array:

```text
generation, generation_record_digest, state,
terminal_record_type, terminal_record_digest
```

`state` is `pending`, `finalized`, or `abandoned`. For `pending`, both terminal
members are null and that allocation has no terminal candidate. Otherwise
`terminal_record_type` is `archive-finalization`,
`archive-abandonment`, or `archive-artifact-resolution`;
`terminal_record_digest` is its complete record digest, and the dereferenced
record derives exactly the stated outcome. Every competing maximal terminal is
listed and remains quarantined. Entries sort by generation, decoded
generation-record digest, null-before-non-null terminal type, and decoded
terminal digest; a generation-record digest resolves to a full allocation with
the exact generation.

`archive_freshness_chains` is the complete strictly sorted unique array of
closed scope rows containing exactly:

```text
generation_head_type, generation_head_digest, finalized_fallbacks
```

There is exactly one scope row for every entry in
`archive_generation_heads`, with byte-identical head type and digest, and no
other row. The head identifies one chain or unresolved generation-conflict
scope. `generation_head_type` has the same closed value set as the
corresponding generation-head `record_type`. Scope rows sort by
generation-head type and decoded generation-head digest.

`finalized_fallbacks` is the complete possibly empty array of every accepted
finalized allocation reachable in that scope's operational closure, ordered
by strictly decreasing generation so the greatest candidate is first. Each
closed member contains exactly:

```text
generation, generation_record_digest, manifest_digest,
finalization_record_digest, artifact_resolution_digest
```

`generation` is a JSON-safe positive integer and every non-null digest is
exactly 64 lowercase hexadecimal characters.
`artifact_resolution_digest` is null when the finalization was accepted
without artifact resolution; otherwise it is the exact accepted `finalized`
artifact-resolution digest, whose selected manifest and selected finalization
equal the member. The corresponding `archive_terminal_heads` row is
`finalized` and names `archive-finalization` with
`finalization_record_digest` when the resolution member is null, or names
`archive-artifact-resolution` with `artifact_resolution_digest` when it is
non-null. No generation appears twice and no accepted finalized allocation in
the reachable closure is omitted.

A producer and verifier independently recompute each complete fallback array
from the eligible rotation-boundary snapshot. The high-water mark is the first
member whose allocation, manifest, finalization, optional resolution, signer,
KEL ancestry, and current compromise cutoff all remain valid. A later accepted
abandonment outcome or cutoff that disqualifies a newer finalized member falls
back to the next ratified member rather than erasing recovery history. A
pending or abandoned maximal allocation, an unresolved artifact conflict at
the maximal allocation, or an unresolved generation fork never removes an
earlier finalized member. A rollover-provisional cold-root resolution may
change an array only by resolving the exact frozen pre-rotation conflict
frontier and being committed by this same rollover. A missing, extra,
misordered, or mismatched generation, allocation, manifest, finalization, or
resolution digest makes the rollover invalid.

Archive closure follows operational edges, not every evidence reference.
Generation heads ratify their canonical predecessor chain and the
selected/null continuation semantics of an accepted generation resolution;
allocations rejected by that resolution are excluded. Manifest heads ratify
only the listed complete signed manifests. A finalization ratifies exactly its
bound listed manifest. An artifact-resolution terminal ratifies its selected
outcome and selected manifest/terminal, while its rejected arrays remain audit
evidence. A pending allocation has no terminal entry beyond its one
null-terminal row but may have zero, one, or multiple listed manifest heads.
An unlisted retired-key manifest or terminal cannot create or reopen an
artifact conflict. Every fallback member additionally ratifies its reachable
allocation, listed manifest, exact named finalization, and, when non-null,
listed artifact resolution and that resolution's selected closure. Rejected
evidence referenced by a resolution remains non-operational evidence.

Core retains each exact complete signed full-archive manifest in its protected
recovery store at
`keys/core/recovery/archive-manifests/<generation-record-digest>/<manifest-digest>.json`.
The Comms composition mirrors the same bytes at
`recovery/archive-manifests/<generation-record-digest>/<manifest-digest>.json`
in the canonical encrypted config repository. These are protected metadata,
not public repository objects. A referenced manifest digest without its exact
bytes keeps rollover validation pending.

`approval_heads` is the strictly `(authorization_id,record_digest)`-sorted
unique array of closed `{authorization_id,record_digest}` objects containing
every maximal head of every approval-ID lineage, including all competing,
revoked, and expired heads. `role_heads` is the corresponding strictly
`(role_id,record_digest)`-sorted unique array of closed
`{role_id,record_digest}` objects containing every maximal head, including all
competing, role-revoked, and delegation-revoked heads. IDs and digests sort by
decoded bytes. Conflicting entries preserve their existing per-ID or
per-target quarantine and do not stall unrelated approval or role authority.
Each digest is lowercase-hex SHA-256 of the complete JCS signed record. A
conforming producer emits all four archive arrays empty only when no
full-archive lineage exists, and emits an approval or role array empty only
when no corresponding lineage exists. Approval or role authority reduction
uses the ordinary signed revocations and includes their terminal heads;
intentional omission is not a reset mechanism.

The new epoch key signs:

```text
SHA256(
  UTF8("heterodyne-recovery-state-rollover-v1") || 0x00 ||
  JCS(record with signature omitted)
)
```

with BIP-340; `signature` is exactly 64 signature bytes encoded as 128
lowercase hexadecimal characters. The complete rollover-record digest is
lowercase-hex SHA-256 over its signed JCS bytes. Core stores the record at
`keys/core/recovery/state-rollovers/<rotation-event-id>/<rollover-digest>.json`.
The Comms composition mirrors the same bytes at
`recovery/state-rollovers/<rotation-event-id>/<rollover-digest>.json` in the
canonical encrypted config repository.
Core's record is authoritative for a Core-only claimant. A Comms claimant
additionally requires the byte-identical rollover to be durable and canonical
in that encrypted repository; a missing or divergent mirror remains
`rollover-pending` and does not make Core depend upward on Comms.

A canonical epoch rotation whose rollover bytes are genuinely missing or
unrecoverable cannot be skipped by an ordinary successor. Cold-root recovery
uses one closed
`heterodyne.recovery-state-rollover-gap.v1` record containing exactly:

```text
type, persona, base_state, skipped_rotations, repair_rotation,
frontier_digests, created_at, reason, cold_root_signature
```

`base_state` contains exactly `kind`, `kel_head`, `rotation_event_id`, and
`rollover_digest`. `kind` is `inception` or `rollover`. For `inception`,
`kel_head` is the exact canonical inception head and both remaining members
are null. For `rollover`, `kel_head` is the `new_kel_head` of the last earlier
unique accepted rollover and the event ID and complete digest identify that
same record. A conflicted predecessor is not a unique base and cannot be
bypassed with this form.

`skipped_rotations` is a nonempty canonical-KEL-ordered array. Each closed
entry contains exactly:

```text
rotation_event_id, prior_kel_head, new_kel_head,
prior_epoch_pubkey, new_epoch_pubkey, compromise_since,
unrecoverable_rollover_digests, rollover_reference_evidence
```

Each entry repeats one canonical epoch rotation exactly. `compromise_since` is
null for a routine rotation or equals its one canonical compromise tag.
`unrecoverable_rollover_digests` is the complete decoded-byte-sorted unique
array of every 64-lowercase-hex candidate digest reference learned for that
rotation from an authenticated signed recovery record or from audit-only
storage metadata when the gap is frozen but whose exact rollover bytes cannot
be recovered; candidate validity is unresolved until those bytes exist. It is
empty when no such candidate reference is known.

`rollover_reference_evidence` is a complete possibly empty strictly sorted
unique array of closed rows containing exactly:

```text
rollover_digest, evidence_class, evidence_type, evidence_profile,
evidence_member, evidence_path, evidence_sha256
```

Rows sort by decoded rollover digest, `evidence_class`, `evidence_type`,
nullable `evidence_profile`, nullable `evidence_member`, and `evidence_path`
UTF-8 bytes, then decoded evidence digest; null sorts before a string.
`evidence_class` is
`authenticated-reference` or `audit-only-reference`.
For `authenticated-reference`, `evidence_type` is exactly
`signed-recovery-record`, `evidence_profile` is exactly
`core.recovery-state-rollover.v1`, and `evidence_member` is exactly the
allocated semantic member `previous-rollover-head`. The exact bytes at the
protected, slash-normalized `evidence_path` must validate under that closed
profile. Its `previous_rollover_heads` array contains exactly one row whose
`rotation_event_id` equals this skipped entry's `rotation_event_id` and whose
`rollover_digest` equals the evidence row's digest; that selected row is the
sole meaning of `previous-rollover-head`. Its signature, persona, canonical KEL
position, and signer-time authority all validate independently. No other
profile, field, substring, JSON Pointer, or same-looking object can supply an
authenticated reference. A storage index or storage-provider assertion is
never an authenticated reference. For
`audit-only-reference`, `evidence_type` is exactly
`audit-storage-metadata` and both `evidence_profile` and `evidence_member` are
null; the exact storage-index/provider-metadata bytes need only hash to
`evidence_sha256` and explicitly contain the named digest. They are preserved
evidence, not proof that a rollover existed or was valid.
For both classes, `evidence_sha256` is exactly 64 lowercase hexadecimal
characters and equals SHA-256 of the complete bytes at the one protected
slash-normalized `evidence_path`; aliases, partial extracts, or reconstructed
summaries cannot satisfy the row.

The decoded unique projection of `rollover_reference_evidence.rollover_digest`
MUST equal `unrecoverable_rollover_digests`; every digest therefore has at
least one exact evidence artifact. The evidence array contains every distinct
reference artifact retained at gap freeze for those digests, including all
authenticated and audit-only variants. The cold-root gap signature
authenticates the frozen evidence set and its raw-byte hashes but does not
upgrade an audit-only artifact or validate unavailable rollover bytes. An
omitted, extra, unavailable, hash-mismatched, misclassified, or nonreferencing
evidence artifact makes gap validation pending or invalid as applicable.

The first skipped entry's prior head/key follow `base_state`; each later
entry's prior head/key equal the previous entry's new head/key; and every
`rotation_event_id` equals its `new_kel_head.event_id`. No non-rotation KEL
event, fully available unique rollover, or fully available conflicted
candidate frontier may be hidden in these reference arrays. A fully available
rollover candidate is processed by the ordinary unique/conflict rule and is
never demoted to audit-only evidence merely because some metadata describes
it.

`repair_rotation` contains exactly:

```text
rotation_event_id, prior_kel_head, new_kel_head,
prior_epoch_pubkey, new_epoch_pubkey, compromise_since
```

It repeats the next canonical cold-root-authorized epoch rotation after the
last skipped entry. Its prior head/key equal that entry's new head/key, its
event ID equals `new_kel_head.event_id`, and its new epoch key is fresh and
different from the base and every skipped key. It is a compromise-declaring
rotation: `compromise_since` is a JSON-safe nonnegative integer equal to its
sole canonical KEL tag and no later than the earliest skipped rotation's
canonical event `created_at`. Normal KEL replay and the Core 300-second
effective-cutoff rule still apply; the gap rule below is stricter for skipped
authority.

`frontier_digests` is a closed object containing exactly:

```text
archive_generation_heads_sha256, archive_manifest_heads_sha256,
archive_terminal_heads_sha256, archive_freshness_chains_sha256,
approval_heads_sha256, role_heads_sha256
```

Each member is lowercase-hex SHA-256 over:

```text
UTF8("heterodyne-recovery-rollover-gap-frontier-v1") || 0x00 ||
UTF8(<exact rollover field name>) || 0x00 ||
UTF8(JCS(<exact complete array in the repairing rollover>))
```

The cold root signs:

```text
SHA256(
  UTF8("heterodyne-recovery-state-rollover-gap-v1") || 0x00 ||
  JCS(record with cold_root_signature omitted)
)
```

with BIP-340; `cold_root_signature` is 128 lowercase hexadecimal characters
and verifies only under `persona`. `reason` is exactly
`rollover_state_unrecoverable`; `created_at` is a JSON-safe nonnegative integer
no earlier than the repair rotation event's canonical `created_at`. The
complete gap-record digest is lowercase-hex SHA-256 of the complete signed JCS
bytes. Core stores it at
`keys/core/recovery/state-rollover-gaps/<repair-rotation-event-id>/<gap-digest>.json`;
the Comms composition mirrors the byte-identical record at
`recovery/state-rollover-gaps/<repair-rotation-event-id>/<gap-digest>.json` in
the canonical encrypted config repository under the same Core-only/Comms
mirror rule as a rollover.

The rollover for `repair_rotation` MUST set `rollover_gap_digest` to this
record, set `previous_rollover_heads` to exactly empty for an inception base
or the one `{rotation_event_id,rollover_digest}` base entry, repeat the repair
rotation's prior/new key and head fields, and make every frontier array hash to
the corresponding gap member. No other rollover may cite the gap. Its eligible
state is only the base's ratified operational closure, valid base-epoch
successors produced before the first skipped rotation, and fresh
rollover-provisional repair roots/resolutions under the repair state. Every
record signed by a skipped epoch key, every skipped-rotation rollover learned
later (whether its now-available bytes prove valid or invalid), and every
descendant that depends on either is permanently `gap-unratified` audit
evidence: it cannot reopen the gap, enter conflict processing, or become
directly eligible for a later rollover.

Two nonidentical valid gap records for one repair rotation are cold-root
duplicity and halt recovery. A missing gap record, base record, skipped or
repair KEL event, reference-evidence byte, frontier byte, or Comms mirror
remains `rollover-pending`; neither the repairing rollover nor an archive may
reconstruct those bytes from the digest commitments.

Acceptance replays the canonical KEL after normal fork and compromise-cutoff
processing. `rotation_event_id` MUST equal `new_kel_head.event_id`; that exact
event MUST be an epoch rotation whose immediate canonical predecessor is
`prior_kel_head`, whose pre-event epoch key is `prior_epoch_pubkey`, and whose
resulting epoch key is `new_epoch_pubkey`. The signature verifies only under
that new key. The rollover head may be an ancestor of a later canonical KEL,
but a newer epoch rotation requires its own rollover and supersedes the older
snapshot. `created_at` is audit data; KEL event linkage and the signed head
sets, not signer-controlled wall time, establish ordering.

The canonical KEL also determines the preceding epoch-changing rotation. When
`rollover_gap_digest` is null, an empty `previous_rollover_heads` is valid
exactly when no such preceding rotation exists. Otherwise every entry names
that one preceding rotation and the array MUST equal its complete rollover
candidate frontier as frozen for this new rotation: one unique accepted
predecessor in the ordinary case, or all nonidentical competing valid
predecessors in the conflicted case. The linked rollover bytes and their own
recursive links MUST validate. A wrong rotation ID, candidate proven omitted
from the frozen frontier, unrelated extra candidate, duplicate, broken
recursive link, or digest mismatch makes the new rollover invalid. A valid
predecessor candidate learned only after the new rollover was accepted remains
superseded audit evidence under the arrival-order rule below. Linking a
conflicted frontier preserves its evidence but does not ratify either
conflicting snapshot's recovery state.

When `rollover_gap_digest` is non-null, the ordinary immediate-predecessor
equation is replaced only by the gap record's base/skipped/repair equations
and frontier hashes. `previous_rollover_heads` MUST equal the gap's exact base
array, and the gap's repair rotation MUST equal this rollover rotation.
Unavailable linked or gap bytes keep validation `rollover-pending`; a verifier
MUST NOT infer or reconstruct inherited authority state from the current
record alone.

The eligible input to a rollover is closed. For the first rotation it is the
historically valid operational state under the inception epoch. Thereafter it
is only (a) the closure ratified by the uniquely accepted rollover linked for
the preceding rotation and (b) structurally valid records produced under the
still-current epoch that extend or explicitly resolve that closure. When the
linked preceding frontier is conflicted, the base is the last earlier unique
ratified closure plus fresh rollover-provisional repair records under the new
canonical state; a head present only in one conflicted predecessor is not
directly eligible. A cold-root resolution may operate only through its defined
selected and rejected evidence fields. A record already classified
`unratified-pre-rotation` never becomes directly eligible for any later
rollover. Except for one valid cold-root gap form, no later rotation can skip
an intervening canonical rotation whose rollover bytes or linkage closure are
unavailable; recovery remains pending until the exact normal chain or
gap-repair closure is present.

Before signing, a producer MUST derive the complete archive, approval, and
role maximal frontiers from that operational candidate set and include every
then-known eligible head. Audit-only records in the same Core stores are not
eligible input. Existing archive, approval, and role conflicts remain
represented and quarantined at their existing lineage/tuple/target scope; a
rollover cannot omit eligible siblings to select a convenient branch. A head
entry with a wrong ID, wrong type, invalid signature, invalid ancestry, a
predecessor that is nonmaximal relative to another listed ratified entry,
noncanonical terminal outcome, duplicate, or unrelated extra digest makes the
rollover invalid. Maximality is evaluated inside the signed snapshot; an
omitted retired-key descendant learned later does not retroactively demote a
listed head. No rollover can resurrect a head invalidated by the canonical
compromise cutoff. A referenced digest whose bytes are not yet available
leaves validation `rollover-pending` rather than proving absence or invalidity.

Exact duplicate rollover bytes are idempotent. Two nonidentical otherwise
valid rollovers for one `rotation_event_id` put all recovery authority into
`rollover-conflicted`; neither snapshot is selected. Recovery requires a later
canonical rotation to a different epoch key and one unique rollover under
that key whose `previous_rollover_heads` names the complete competing
predecessor frontier. Its eligible base is the last earlier unique ratified
closure plus fresh rollover-provisional repair records; a head present only in
one conflicted rollover is not directly eligible. Once accepted, the later
snapshot supersedes every linked earlier rollover candidate and prevents a
late prior-rotation candidate from reopening state.

Omission is deliberately fail-closed and arrival-order independent. A known
omission is producer nonconformance and is retained in audit output, but a
retired-epoch record learned after rollover acceptance is not inserted into
the signed snapshot and does not invalidate or reopen it. It remains
permanent `unratified-pre-rotation` evidence and is never directly ratified by
a later rollover. Current authority may reproduce the intended effect only
through a fresh current-epoch root or regrant, or an applicable cold-root
resolution that derives new operational state without selecting or continuing
the omitted record.
The omitted record is not an active/conflicting head, a valid
predecessor, or a required member of a later `supersedes` frontier. A
restore that reaches an epoch rotation but lacks its unique valid rollover,
has a rollover conflict, lacks any intermediate rollover in the recursive
`previous_rollover_heads` closure without a valid gap repair, lacks a gap
record or any member of its base/skipped/repair/frontier closure, or cannot
validate every referenced head remains `restore-pending`: it may authenticate
and stage bytes but cannot exercise archive, approval, role, transfer, or epoch
authority.

Local arrival time, a verifier-private “accepted while current” bit, wall-clock
receipt order, and repository fetch order are never authority evidence.
Stores recompute current-epoch heads, rollover-ratified retired heads,
conflicts, terminal state, and freshness from portable evidence after
reconciliation.

Full-backup generations are allocated by a closed, epoch-signed
`heterodyne.recovery-archive-generation.v1` record. It contains exactly
`type`, `persona`, `generation`,
`previous_record`, `archive_id`, `producer_nid`, `epoch_pubkey`, `kel_head`,
`created_at`, and `signature`
and is stored by Core at
`keys/core/recovery/archive-generations/<generation>-<record-digest>.json`.
Its
signature is a 64-byte BIP-340 signature encoded as 128 lowercase hexadecimal
characters over:

```text
SHA256(
  UTF8("heterodyne-recovery-archive-generation-v1") || 0x00 ||
  JCS(record with signature omitted)
)
```

The initial record has `generation:1` and `previous_record:null`. Every later
record increments the prior persona record by exactly one and names its
lowercase-hex digest. `record-digest` is lowercase-hex SHA-256 over the JCS
bytes of the complete signed record. `kel_head` is the closed event-ID/sequence
object used by the manifest; a verifier requires `epoch_pubkey` to be current
under that accepted KEL head for historical signature validation and then
applies the current-epoch/rollover authority rule above. Later allocations
have `created_at` no earlier than their predecessor. A retired-epoch allocation
remains a candidate only when the latest applicable rollover commits it as a
generation head or commits a validated descendant from which it is reachable.
An omitted retired-key sibling remains evidence and cannot enter conflict
processing merely because it arrives late; a canonical compromise cutoff
invalidates even its historical signer basis. Every nonidentical sibling
authorized by the current epoch or a committed rollover frontier enters
ordinary conflict processing.
The manifest's `archive_id`,
`archive_generation`, `producer_nid`, and `generation_record_digest` MUST
match that allocation record.

Two different valid successors of one record are a chain conflict. Two
different valid signed manifests that name the same generation record are an
artifact conflict even if one reuses the same `archive_id`; neither conflict
becomes the rollback high-water mark until the corresponding cold-root
resolution below is accepted. Repository durability supplies the complete
evidence set but does not choose a branch.

The chain cannot be bricked permanently by a racing or compromised epoch
signer. Cold-root recovery uses one closed
`heterodyne.recovery-archive-generation-resolution.v1` containing exactly
`type`, `persona`, `conflict_predecessor`, `conflicting_records`,
`selected_record`, `rejected_records`, `new_epoch_pubkey`, `new_kel_head`,
`created_at`, `reason`, and `cold_root_signature`. The conflicting array is a
set of at least two complete-record digests and the rejected array is a
nonempty subset, each strictly sorted by decoded digest bytes;
`selected_record` is null or exactly
one conflicting member absent from `rejected_records`, and
`conflicting_records == rejected_records union {selected_record when
non-null}`. `reason` is `archive_generation_fork`.
`conflict_predecessor` is JSON null exactly for a conflict among
generation-one roots; otherwise it is the 64-lowercase-hex complete-record
digest of the one common predecessor allocation or accepted resolution.
Every member of `conflicting_records` is a distinct, individually valid
allocation for the same persona and generation and has `previous_record`
exactly equal to `conflict_predecessor`; when it is null, every member has
`generation:1` and `previous_record:null`.
The array names every such candidate retained by the resolving Core store
when it freezes the complete local conflict frontier before the required
post-conflict epoch rotation. Before signing, the resolver MUST enumerate all
allocation records reachable from its canonical Core recovery stores for that
predecessor, validate each candidate independently through historical
signer/KEL checks and then-current authority, and include every valid maximal
candidate. For a post-rollover resolution, “candidate” is limited to the
operationally eligible ratified frontier; `unratified-pre-rotation` audit
evidence is never selected or rejected as authority.
Omitting a then-known valid candidate, including a third or later fork branch,
is resolver nonconformance and retained audit evidence; evidence that fails
independent validation is retained but is not a candidate. Verifier acceptance
does not depend on whether an omitted valid sibling happened to arrive locally
before or after the cold-root resolution. The accepted resolution's objective
post-rotation cutoff rule below terminalizes every omitted pre-rotation
sibling in either arrival order.

`type` is exactly
`heterodyne.recovery-archive-generation-resolution.v1`; `persona` and
`new_epoch_pubkey` are each exactly 64 lowercase hexadecimal characters, as
are every non-null digest and event ID. `new_kel_head` is the same closed
`event_id`/`seq` object used by an allocation, and `created_at` is a JSON-safe
nonnegative integer. `cold_root_signature` is
exactly a 64-byte BIP-340 signature encoded as 128 lowercase hexadecimal
characters; the implicit signature suite for this closed record type is
exactly `BIP340`. The `persona` cold-root key signs:

```text
SHA256(
  UTF8("heterodyne-recovery-archive-generation-resolution-v1") || 0x00 ||
  JCS(record with cold_root_signature omitted)
)
```

The resolution digest is lowercase-hex SHA-256 over the JCS bytes of the
complete signed record. Signature verification MUST use exactly the
record's `persona`; neither an epoch key nor another recovery persona can
substitute for the cold root.

Acceptance requires replay of the canonical KEL after normal fork,
compromise-cutoff, and freshness processing. That replay MUST establish a
cold-root-authorized epoch rotation whose resulting current epoch key and
head are exactly `new_epoch_pubkey` and `new_kel_head`. The rotation event is
later in the accepted KEL than every non-cut-off conflicting allocation head;
for a conflicting head excluded by recovery, the canonical compromise cutoff
MUST invalidate that head's signing authority. Every conflicting allocation's
`created_at` is no later than the resolution's `created_at`; canonical KEL
ordering, rather than a KEL wall-clock field, proves that the rotation follows
the conflicting authority. On every replay, `new_kel_head` MUST be the
verifier's current accepted KEL head or its canonical ancestor,
`new_epoch_pubkey` MUST be the epoch key established by that exact head, and no
applicable cutoff may invalidate the resolution state. These conditions make
the named state a fresh post-conflict state. If the resolution is
rollover-provisional, that rollover commits it as the archive-generation head.
If the rollover instead preserves every conflicting generation head, a later
resolution under the same current state may operate only against exactly that
ratified frontier and becomes a current post-rollover update. Every later
rotation ratifies the then-current head again.

Each listed rejected allocation becomes terminal-abandoned for freshness and
can never be selected later. The same terminal classification applies,
regardless of local observation order, to every otherwise-valid allocation
signed under a pre-resolution epoch state whose `previous_record` equals the
resolved `conflict_predecessor` but which was omitted from
`conflicting_records`.

The cutoff is transitive. Every allocation, manifest, finalization, or
abandonment already descending from any conflicting sibling—including a
descendant of the selected sibling—that does not itself descend from the
accepted resolution digest is terminal-rejected and noncanonical, even if a
store accepted or finalized it before learning of the fork. All such bytes
remain conflict evidence and are excluded when every store recomputes the
finalized-generation high-water mark.

When `selected_record` is non-null it is the sole selected sibling and the
next canonical allocation uses its generation plus one and names the
resolution digest as `previous_record`; when null, the next allocation reuses
the conflicted generation number and also names the resolution digest. Both
forms are signed by the fresh epoch key, name exactly
`new_epoch_pubkey/new_kel_head`, and have `created_at` no earlier than the
resolution. An allocation under the fresh epoch state is valid only when it
follows the resolution as this unique chain head and obeys that selected/null
generation rule; reusing the old predecessor or a pre-resolution branch tip
is invalid. Future and previously observed verification therefore converge on
the resolution head. A second nonidentical resolution for the same conflict
is cold-root duplicity and halts recovery rather than choosing conveniently.

Core and Comms store the resolution beside the generation chain and never
discard the rejected evidence. For repository paths,
`<conflict-predecessor-component>` is literal `root` when
`conflict_predecessor` is null and otherwise is its exact digest. Exact paths
are
`keys/core/recovery/archive-generation-resolutions/<conflict-predecessor-component>/<resolution-digest>.json`
and, for the Comms composition,
`recovery/archive-generation-resolutions/<conflict-predecessor-component>/<resolution-digest>.json`.

A completed artifact can be committed
by a closed, epoch-signed
`heterodyne.recovery-archive-finalization.v1` record containing exactly
`type`, `persona`, `generation_record_digest`, `archive_id`,
`manifest_digest`, `descriptor_sha256`, `ciphertext_sha256`,
`archive_payload_length`, `epoch_pubkey`, `kel_head`, `created_at`, and
`signature`.
`manifest_digest` hashes the complete signed JCS manifest;
`archive_payload_length` is the ciphertext length and excludes the mutable
outer prefix/header. Its signature and complete-record digest use the same
rules above with domain
`heterodyne-recovery-archive-finalization-v1`, including the same
historical epoch/KEL and current-epoch/rollover validation. Conflicting
finalizations for one
allocation quarantine every claimant until resolved. A finalization or
abandonment requires `created_at` no earlier than its allocation; arrival
order adds no acceptance condition and the authority rules above remain
mandatory.

An allocation with neither finalization nor abandonment is `pending` and does
not advance backup freshness. It remains in the generation chain, so a later
allocation increments from it rather than reusing its number. An epoch-signed
closed `heterodyne.recovery-archive-abandonment.v1` record contains exactly
`type`, `persona`, `generation_record_digest`, `archive_id`, `reason_code`,
`epoch_pubkey`, `kel_head`, `created_at`, and `signature`, uses the matching
domain-separated transcript, and is absorbing. `reason_code` is exactly
`recovery_archive_cancelled` or `recovery_archive_production_failed`. A
generation cannot have both a valid finalization and abandonment; that
conflict quarantines both.

Conflicts among artifacts attached to one otherwise canonical full allocation
use a different cold-root wire. They do not use generation-allocation
resolution and never select a different allocation or alter the allocation
chain's `previous_record` relation. The closed
`heterodyne.recovery-archive-artifact-resolution.v1` record contains exactly:

```text
type
persona
generation_record_digest
archive_id
conflict_kinds
conflicting_manifest_digests
conflicting_terminal_records
selected_manifest_digest
selected_terminal_record
rejected_manifest_digests
rejected_terminal_records
outcome
new_epoch_pubkey
new_kel_head
created_at
reason
cold_root_signature
```

`type` is exactly `heterodyne.recovery-archive-artifact-resolution.v1`.
`persona`, `generation_record_digest`, and `archive_id` exactly equal the
canonical allocation. `conflict_kinds` is a nonempty, ASCII-sorted unique
array whose only values are `manifest_conflict`,
`finalization_conflict`, `abandonment_conflict`, and
`finalization_abandonment_conflict`.
`conflicting_manifest_digests` is an array of complete signed-manifest
digests, strictly sorted by decoded digest bytes.
`conflicting_terminal_records` is an array of closed
`{"record_type","record_digest"}` objects, sorted by `record_type` ASCII bytes
and then decoded digest bytes; `record_type` is exactly `finalization` or
`abandonment`. The arrays name every distinct, individually valid candidate
for this allocation that is retained by the resolving Core store when the
candidate set is frozen before the required post-conflict rotation. Each
candidate MUST have passed its mathematical signature, historical
KEL/delegation, then-current authority, and cross-record checks before
mutual-conflict processing.
For a post-rollover artifact resolution, both candidate arrays are limited to
the exact operationally eligible manifest/terminal frontier committed by the
rollover; unratified audit evidence is excluded.
Every finalization candidate's `manifest_digest`
MUST be present in `conflicting_manifest_digests`; every candidate has the
exact allocation persona, allocation digest, and archive ID.

The conflict-kind array is derived rather than chosen: it contains
`manifest_conflict` exactly when there are at least two distinct manifest
digests, `finalization_conflict` exactly when there are at least two distinct
finalization record digests, `abandonment_conflict` exactly when there are at
least two distinct abandonment record digests, and
`finalization_abandonment_conflict` exactly when at least one finalization and
one abandonment are present. A record with no derived conflict kind is
invalid.

`selected_manifest_digest` is null or one exact member of
`conflicting_manifest_digests`. `selected_terminal_record` is null or one
byte-identical member of `conflicting_terminal_records`.
`rejected_manifest_digests` and `rejected_terminal_records` use the same
sorting and closed shapes as their conflicting arrays, and the following set
equalities are exact:

```text
conflicting_manifest_digests
  = rejected_manifest_digests
    union {selected_manifest_digest when non-null}
conflicting_terminal_records
  = rejected_terminal_records
    union {selected_terminal_record when non-null}
```

`outcome` is exactly `finalized` or `abandoned`. For `finalized`,
`selected_terminal_record.record_type` is `finalization`,
`selected_manifest_digest` equals that finalization's `manifest_digest`, and
the selected finalization, manifest, header, and ciphertext satisfy the whole
cross-record equality matrix below. For `abandoned`,
`selected_manifest_digest` is null, every manifest is rejected, and
`selected_terminal_record` is either null or an `abandonment`. A null
selection makes the resolution itself the terminal abandonment and is the
only valid outcome for a manifest-only conflict with no terminal candidate.
Selecting a finalization while abandoning, selecting an abandonment while
finalizing, or omitting a nonselected candidate from a rejected set is
invalid. `reason` is exactly `archive_artifact_conflict`.

The artifact resolution uses the same exact `new_epoch_pubkey`,
`new_kel_head`, `created_at`, cold-root authority, BIP-340 encoding,
post-conflict KEL rotation, historical signer validation, rollover gating, and
complete-record digest rules defined for generation resolution. In applying
those rules, the post-conflict rotation is later in the accepted KEL than the
canonical allocation head and every non-cut-off terminal candidate head; each
candidate head excluded by recovery is invalidated by the canonical
compromise cutoff. The resolution's `created_at` is no earlier than the
allocation and every candidate manifest and terminal record. Its distinct
signature transcript is:

```text
SHA256(
  UTF8("heterodyne-recovery-archive-artifact-resolution-v1") || 0x00 ||
  JCS(record with cold_root_signature omitted)
)
```

The artifact-resolution digest is lowercase-hex SHA-256 over the JCS bytes of
the complete signed record. Core stores it at
`keys/core/recovery/archive-artifact-resolutions/<generation-record-digest>/<resolution-digest>.json`;
the Comms composition mirrors it at
`recovery/archive-artifact-resolutions/<generation-record-digest>/<resolution-digest>.json`.
If the artifact resolution is rollover-provisional, that rollover commits it
as the affected allocation's terminal head. If the rollover instead preserves
the complete manifest/terminal conflict, a later resolution under the same
current state may advance freshness only against exactly that ratified
frontier and becomes a current post-rollover update.
All candidate manifests and terminal records, including rejected and
late-arriving pre-rotation candidates, remain immutable conflict evidence.
After one artifact resolution is accepted, a different resolution for that
allocation is cold-root duplicity and halts full-recovery processing. A
late-arriving candidate signed under a superseded pre-resolution epoch cannot
reopen selection and is retained as rejected evidence.

An accepted `finalized` outcome makes only the selected finalization the
allocation's terminal record and lets that generation participate in the
ordinary greatest-finalized-generation high-water calculation. An accepted
`abandoned` outcome makes the allocation terminal-abandoned and leaves the
last earlier accepted finalized generation as the high-water mark. A repair
archive uses the ordinary next allocation in the already-selected generation
chain, names the canonical allocation head rather than the artifact-resolution
digest as `previous_record`, and is signed under the fresh epoch state with
`created_at` no earlier than the resolution. If the allocation chain has
already advanced, the resolution does not renumber or rewrite its successors;
freshness is recomputed solely from accepted terminal outcomes.
The selected old-epoch candidate is accepted through the cold-root resolution
and is not required to become current again after the mandatory rotation; the
candidate's frozen pre-rotation validation evidence and the resolution are
required, and the rollover either commits that provisional resolution or
commits the exact conflict frontier against which the later current resolution
operates.

Core stores finalizations at
`keys/core/recovery/archive-finalizations/<generation-record-digest>/<finalization-digest>.json`.
It stores abandonments at
`keys/core/recovery/archive-abandonments/<generation-record-digest>/<abandonment-digest>.json`.
The Comms full-recovery composition commits the same Core generation and
finalization records at
`recovery/archive-generations/<generation>-<record-digest>.json` in the
canonical encrypted config repository and
`recovery/archive-finalizations/<generation-record-digest>/<finalization-digest>.json`
respectively, and mirrors abandonments under
`recovery/archive-abandonments/<generation-record-digest>/<abandonment-digest>.json`.
It retains every individually valid competing successor or terminal record as
conflict evidence and rejects only treating any competitor as canonical until
the corresponding generation or artifact resolution is accepted; no
conflicting bytes are discarded merely because they arrived second. An
offline producer may create and locally finalize an archive,
but the allocation remains Comms-pending and cannot be presented as a
persona-wide canonical generation until both records commit.

A device-class generation record is closed and contains exactly `type`,
`persona`, `backup_class`, `device_nid`, `generation`, `previous_record`,
`archive_id`, `kel_head`, `delegation_event_id`, `created_at`, and `signature`,
with exact type `heterodyne.recovery-device-archive-generation.v1`. `persona`
is the 64-lowercase-hex cold-root public key. Its initial record uses
`generation:1` and `previous_record:null`; later records increment by one and
name the prior complete-record digest in the same
`(persona,device_nid,backup_class)` lineage. `backup_class` is exactly
`device-local` or `clone-device`; the two classes have independent counters
and cannot name one another as predecessor. The active device NID produces a
64-byte Ed25519 signature encoded as unpadded base64url over SHA-256 of the
same domain-separated JCS transcript under
`heterodyne-recovery-device-archive-generation-v1`. Its complete-record digest
uses the same lowercase-hex SHA-256-over-JCS rule as the full allocation, and
exact duplicate bytes are idempotent. It is stored locally at
`recovery/device-archive-generations/<persona>/<backup-class>/<nid-sha256>/<generation>-<record-digest>.json`
and is not a persona-wide finality claim. In every device-chain path,
`<persona>` is the exact record field and `<nid-sha256>` is lowercase-hex
SHA-256 of the UTF-8 canonical `device_nid`. The verifier requires the named
delegation to authorize that NID for the exact record persona at `created_at`
and to bind that persona's accepted KEL head under historical signer
validation. Successor `created_at` values may not decrease. Later delegation
revocation makes the lineage operationally terminal as defined below but does
not make stores disagree about whether its historically valid records enter
fork detection.

Two nonidentical valid roots or successors in one
`(persona,device_nid,backup_class)` lineage permanently quarantine every
competing record and descendant. No branch selection under the same NID is
valid, because every copy or compromise of that NID has equal signing
authority. The last matching finalized allocation strictly before the fork
remains the historical high-water mark; a root fork has none. Resuming device
backup production requires canonical revocation of the conflicted NID and
canonical delegation of a different fresh NID under the current accepted
persona state after KEL fork, cutoff, and freshness processing. For every
conflicting record, either its named KEL head is an ancestor of that canonical
state and the old-NID revocation removes its authority, or the canonical
compromise cutoff invalidates the record; no accepted restart requires one
head to descend from divergent branches. The new
`(persona,fresh_nid,backup_class)` lineage starts at `generation:1` with
`previous_record:null`; it does not claim continuity from either rejected
branch. Revoking the old NID makes both of its device-class lineages terminal:
their earlier finalized artifacts remain historical evidence, but neither
class accepts a successor. Each class produced by the fresh NID starts its own
generation-one lineage. Records in the conflicted old lineage remain conflict
evidence and can never advance freshness.

Every device-class allocation also has a closed
`heterodyne.recovery-device-archive-finalization.v1` record with exactly
`type`, `persona`, `backup_class`, `device_nid`,
`generation_record_digest`, `archive_id`, `manifest_digest`,
`descriptor_sha256`, `ciphertext_sha256`,
`archive_payload_length`, `kel_head`, `delegation_event_id`, `created_at`, and
`signature`. It uses the identical Ed25519/delegation rules with domain
`heterodyne-recovery-device-archive-finalization-v1` and is stored at
`recovery/device-archive-finalizations/<persona>/<backup-class>/<nid-sha256>/<generation-record-digest>/<finalization-digest>.json`.
Pending and abandoned device allocations follow the same freshness rule; a
device abandonment is a closed
`heterodyne.recovery-device-archive-abandonment.v1` record containing exactly
`type`, `persona`, `backup_class`, `device_nid`,
`generation_record_digest`, `archive_id`, `reason_code`, `kel_head`,
`delegation_event_id`, `created_at`, and `signature`. The active device signs
the same transcript form under domain
`heterodyne-recovery-device-archive-abandonment-v1`; the signature is exactly
64 Ed25519 bytes encoded as unpadded base64url. Its complete-record digest is
lowercase-hex SHA-256 of the JCS bytes, and it is stored at
`recovery/device-archive-abandonments/<persona>/<backup-class>/<nid-sha256>/<generation-record-digest>/<abandonment-digest>.json`.
Its reason code uses the same closed two-value abandonment set. It is
absorbing. A device allocation with both a valid finalization and abandonment
quarantines both records. Either device terminal record requires its persona,
named delegation, and KEL head to equal the allocation, requires that
delegation/head to have been valid at the record's `created_at` under the
historical signer rule, and requires `created_at` no earlier than the
allocation. Device lineage authority and terminal revocation are independent
of epoch-state rollover.

Archive identity is cross-record, never inferred. Except for the explicitly
non-authoritative `bootstrap-validated` path below, `full` validation, and
separately each `(persona,device_nid,backup_class)` device-lineage validation,
requires this exact equality matrix:

- header, decrypted manifest, allocation, and finalization `archive_id` are
  identical;
- manifest `archive_generation` equals allocation `generation`, and manifest
  `generation_record_digest` equals the complete signed allocation digest;
- a full archive has exactly one mapped `current-epoch-authority` entry. Its
  allocation `persona`, manifest `persona`, authority-envelope `persona`, and
  decrypted epoch-secret `persona` are identical. The allocation
  `epoch_pubkey`, manifest `authority.signer`, authority-envelope
  `epoch_pubkey`, and decrypted epoch-secret `epoch_pubkey` are identical.
  The allocation `kel_head`, manifest `authority.kel_head`,
  manifest `high_water.kel`, authority-envelope `kel_head`, and decrypted
  epoch-secret `kel_head` are byte-identical JCS values.
  `manifest.authority.signer_type` is exactly `epoch-secp256k1`,
  `manifest.authority.delegation_event_id` is null, and the manifest signature
  verifies under that exact common epoch key. No ancestor, same-sequence
  alternative, or independently current key satisfies this equality;
- a full manifest's `producer_nid` equals the allocation's `producer_nid`; a
  device manifest's `persona` and `backup_class` equal the device allocation's
  corresponding fields, its `producer_nid` and authority signer both equal
  the allocation's `device_nid`, its delegation-event ID and KEL head equal
  the allocation's corresponding fields, and the named delegation binds all
  of them to that exact persona;
- finalization `generation_record_digest`, `archive_id`, and
  `manifest_digest` equal the allocation digest, archive ID, and SHA-256 of
  the exact complete signed manifest;
- finalization `descriptor_sha256` equals SHA-256 of the exact JCS
  `header.payload_descriptor`;
- finalization `ciphertext_sha256` and `archive_payload_length` equal the
  header's `ciphertext_sha256` and `ciphertext_length`, and the actual stored
  ciphertext-plus-tag stream has both that digest and length; and
- the finalization persona and authority/KEL/delegation fields equal the
  allocation and manifest persona and authority fields for that class. For a
  full archive, finalization `persona`, `epoch_pubkey`, and `kel_head` are
  therefore also exactly the common persona, epoch key, and KEL head above.

An abandonment repeats and equals its allocation's persona, device NID and
backup class where applicable, allocation digest, and archive ID. Any
cross-record mismatch, a different signed manifest claiming one allocation,
a header with different immutable `format`, `archive_id`,
`payload_descriptor`, `ciphertext_length`, or `ciphertext_sha256`
commitments, or nonidentical terminal records for one allocation is a
conflict and cannot advance freshness. Exact duplicate bytes are idempotent.
Two headers that differ only in their sorted, individually valid
`recipient_slots` arrays while every immutable header member and the complete
ciphertext bytes are identical are authorized rewrap variants of one artifact,
not distinct manifest/artifact candidates and not a conflict. A slot-only
variant does not change any signed manifest, allocation, finalization,
freshness, or artifact-resolution digest. It is nevertheless a usable,
recoverability-conformant copy only when every slot committed by the signed
manifest's `required_recipient_slots` array is present byte-identically in the
header. Removing or relabeling a required slot does not create a second payload
artifact, but that header variant is unhealthy, cannot satisfy backup
freshness/availability policy, and cannot be promoted by `archive.put`. Any
difference outside `recipient_slots`, or a malformed or unauthenticated
selected slot, remains a conflict or validation failure under the applicable
rule.

For every nonconflicting persona or device chain, the freshness high-water
mark is the greatest allocation with one accepted matching finalization, not
merely the greatest allocation. The full-chain resolution rule and permanent
device-fork rule above override ordinary comparison while their conflicts
exist. At an epoch boundary, each full chain or conflict scope starts from its
complete `archive_freshness_chains.finalized_fallbacks` array ratified by the
accepted rollover. Validation selects its first still-valid member; valid
current-epoch finalizations prepend newer candidates to the operational
fallback chain until the next rollover commits the recomputed complete array.
Pending or abandoned allocations never make a prior usable backup stale, and
later invalidation of a newer finalization exposes the next ratified fallback.
A canonical finalization is retained as freshness evidence even if one local
node no longer holds the archive bytes. A UI or policy counts a stored copy as
available only after testing that exact header variant's required-slot
commitments and at least one locally exercisable recovery path. For
`clone-device`, that exercisable path MUST be one of the committed
non-device-local slots rather than an added same-device slot; a finalization
alone does not make a stripped or untested copy healthy.

For `full`, `authority.signer_type` is `epoch-secp256k1`, `signer` is the
64-hex epoch public key, `delegation_event_id` is null, and the signature suite
is `BIP340`. For either device class, `signer_type` is `device-ed25519`,
`signer` is the canonical NID, `delegation_event_id` names its active Core
delegation, and the suite is `Ed25519`.

### Logical layout

The initial path allocation is:

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

Every angle-bracketed component is a manifest-local `m-<32 lowercase hex>`
identifier; the manifest maps it to its complete canonical typed value.
Owners, schemas, platforms, records, RIDs, and NIDs always use mappings,
including values that would already satisfy the path alphabet. Mapping IDs
may be random or derived, but uniqueness and the one-to-one manifest mapping
are authoritative; a value is never lossy-normalized into a path.

Repository entries are complete Git bundles containing the authoritative refs
and their reachable object history. The manifest records the RID, advertised
head, object format, included refs, and bundle digest. A restore verifies the
Git bundle, Radicle identity, signed refs, RID, KEL bindings, and expected head
before installing it.

Cold-root secret material in `keys/core` remains independently wrapped under
Core's NIP-49 at-rest profile inside its owner-scoped protected entry. Archive
encryption is an outer backup boundary, not permission to place plaintext
cold-root material in the entry stream. Opening an epoch recipient slot
therefore does not expose a plaintext cold-root secret.

A full backup stores exactly one current epoch secret, only at
`keys/core/<record>/value`, where the mapped record value is
`current-epoch-authority`, as this closed envelope:

```json
{
  "type": "heterodyne-recovery-epoch-authority-envelope-v1",
  "persona": "<64 lowercase hex>",
  "epoch_pubkey": "<64 lowercase hex>",
  "kel_head": {"event_id": "<64 lowercase hex>", "seq": 0},
  "cipher": "AES-256-GCM",
  "nonce": "<unpadded base64url 12 random bytes>",
  "ciphertext": "<unpadded base64url ciphertext plus 16-byte tag>"
}
```

The authority DEK encrypts the JCS bytes of exactly:

```json
{
  "type": "heterodyne-recovery-epoch-secret-v1",
  "persona": "<64 lowercase hex>",
  "epoch_pubkey": "<64 lowercase hex>",
  "kel_head": {"event_id": "<64 lowercase hex>", "seq": 0},
  "epoch_secret": "<64 lowercase hex valid secp256k1 scalar>"
}
```

AAD is the JCS bytes of the envelope with `nonce` and `ciphertext` omitted.
The restored scalar MUST derive `epoch_pubkey`, and KEL replay MUST make that
key current before an ordinary full restore may install it. The authority DEK
never appears in the encrypted entry stream.

### Historical-decrypt obligations

A retained ciphertext that still needs a retired secret is canonical
credential state, not an implementation-local reason to keep an arbitrary old
key. The accepted credential checkpoint adds
`governed_decrypt_key_bindings_sha256` immediately before
`historical_decrypt_obligations_sha256`, which remains immediately before
`secret_transition_digest`, in its closed shape. Its exact `config_head`
authenticates the complete governed-head/binding state and obligation lineages
below. A checkpoint produced without either field, or with a digest computed
from any other state, is not a revision-4 checkpoint.

The closed record type is
`heterodyne.historical-decrypt-obligation.v1` and contains exactly:

```text
type, persona, obligation_id, lineage_sequence, previous_record, action,
secret_class, secret_id, instance_commitment, retained_ciphertexts,
retired_provenance_lineages, transition_id, issued_at, authority, signature
```

`obligation_id` is 16 fresh random bytes encoded as 32 lowercase hexadecimal
characters. A root has `lineage_sequence:0`, `previous_record:null`, and
`action:"retain"`. Every successor increments the sequence by one and names
the lowercase-hex SHA-256 digest of the complete immediately preceding JCS
record. `action` is `retain` or `close`. A retaining head has a nonempty
`retained_ciphertexts` array. A closing head has an exactly empty array,
repeats the complete identity, and is absorbing; retaining ciphertext again
requires a fresh obligation ID. Every successor's retired-provenance set is a
superset of its predecessor and adds exactly any assignment retirements made
effective by its transition; no prior row may disappear or change. Exact
duplicate bytes are idempotent. Nonidentical roots or successors
quarantine that obligation ID and make every ordinary checkpoint that names
either competing head unacceptable. Different nonconflicting IDs may cover
disjoint ciphertext rows for the same secret tuple; duplicate coverage of one
governed decrypt dependency is invalid under the set equation below.

Only a class whose portable table below permits `historical-decrypt` may use a
retaining obligation. `lineage_sequence` and `issued_at` are JSON-safe
nonnegative integers, successor `issued_at` never decreases, and
`transition_id` is 32 lowercase hexadecimal characters. On a retaining root it
identifies the exact accepted ADR-037 transition that retired the old
capability assignments while preserving governed ciphertext that requires
this instance. On a retaining update it identifies the accepted transition
that changed the exact retained artifact set without authorizing new
encryption under the old key. On `close` it identifies the accepted transition
that reencrypted or removed every remaining governed dependency. The identity
fields equal every source, assignment, retirement, durable-inventory, and
encrypted-material binding for that same instance. `authority` is the exact closed
`{signer_type,signer,kel_head}` object selected by that transition's
class-complete authority rule. The mode-appropriate epoch or cold root signs:

```text
SHA256(
  UTF8("heterodyne-historical-decrypt-obligation-v1") || 0x00 ||
  UTF8(JCS(record with signature omitted))
)
```

using BIP-340 encoded as 128 lowercase hexadecimal characters. Historical
signer validation, transition acceptance, KEL ancestry, and compromise cutoff
all apply. The complete-record digest is lowercase-hex SHA-256 of the complete
signed JCS bytes. The record is reachable from the checkpoint's exact
`config_head` at:

```text
credential-sync/historical-decrypt-obligations/
  <obligation-id>/<lineage-sequence>-<record-digest>.json
```

`retained_ciphertexts` is strictly sorted and unique by every member in the
listed order. Each closed member contains exactly:

```text
storage_class, owner, repository_rid, repository_head, ref_name, path,
git_blob_oid, object_id, ciphertext_sha256, ciphertext_length
```

`storage_class` is `git-blob` or `large-object`; `owner` is the allocated
family owner governing the encrypted data. `repository_head` and
`git_blob_oid` are each the closed typed Git object:

```text
{object_format:"sha1"|"sha256",oid}
```

Their `object_format` values are identical and equal the repository's declared
object format. A `sha1` OID is exactly 40 lowercase hexadecimal characters; a
`sha256` OID is exactly 64. Mixed formats, bare-string OIDs, a declared-format
mismatch, or the wrong length rejects. Repository RID, typed canonical
repository head, full ref name, slash-normalized repository-relative path, and
typed Git blob object ID are non-null and identify the exact ciphertext blob
or exact governing large-object pointer. For `git-blob`, `object_id` is null
and `ciphertext_sha256`/`ciphertext_length` cover exactly the Git blob content
bytes. For `large-object`, `object_id` is non-null, equals the lowercase-hex
SHA-256 of the complete retained stored bytes, equals `ciphertext_sha256`, and
`ciphertext_length` is their exact positive length; the repository fields and
`git_blob_oid` identify the exact canonical pointer that governs those bytes.
Only `object_id` when non-null and `ciphertext_sha256` are unconditionally 64
lowercase hexadecimal characters. Every length is a JSON-safe positive
integer, and no mutable alias or locally invented path may substitute for
these exact locators.

The exact row comparator expands the listed object members: compare
`storage_class`, `owner`, and `repository_rid` by UTF-8 bytes; then
`repository_head.object_format` by ASCII and its decoded `oid` bytes; then
`ref_name` and `path` by UTF-8; then `git_blob_oid.object_format` and decoded
`oid`; then `object_id` with null before a non-null decoded digest; then
decoded `ciphertext_sha256`; then numeric `ciphertext_length`. Equality under
that full comparator is a duplicate and rejects.

Every named repository/object head and ciphertext byte string exists before
the obligation record is created. For a config-repository locator, that
artifact head is a strict ancestor of the commit that first stores the
obligation; for another repository or the large-object store, the record binds
an independently materialized head/object that the checkpoint high-water
authenticates. The checkpoint `config_head` then reaches the obligation record
and binds those preexisting artifacts. A ciphertext/pointer artifact may not
reference the later inventory, obligation, transition, checkpoint, or a
descendant of any of them; the complete acyclic order is defined below.

Every authenticated ciphertext/pointer profile independently marks whether its
bytes are a governed decrypt dependency. A marked source profile expands its
authenticated bytes into a complete deterministic set of distinct
`(retained_ciphertext,secret_class,secret_id,instance_commitment)` items. It
emits a distinct locator row for every encryption layer whose noncurrent key is
needed, or the profile itself authenticates the complete strictly sorted unique
tuple set for all such layers. A single signed-binding fallback is legal only
when one exact locator has exactly one otherwise-unembedded tuple. Zero
candidate tuples, more than one candidate tuple, a validator-selected tuple,
or one binding reused across distinct locators rejects. If that one tuple is
not embedded, one closed `heterodyne.governed-decrypt-key-binding.v1` record
supplies it and contains exactly:

```text
type, persona, binding_id, retained_ciphertext, secret_class, secret_id,
instance_commitment, issued_at, authority, signature
```

`retained_ciphertext` is the exact typed locator row. Its deterministic ID is:

```text
binding_id =
  lowercase_hex(SHA256(
    UTF8("heterodyne-governed-decrypt-key-binding-id-v1") || 0x00 ||
    UTF8(JCS(retained_ciphertext))
  ))
```

`issued_at` is a JSON-safe nonnegative integer. `authority` is the exact closed
`{signer_type,signer,kel_head}` selected by the governing owner and class at
artifact creation: current epoch authority for an ordinary binding or the
exact cold-root/reset authority for emergency reconstruction. Historical
signer, KEL ancestry, and compromise-cutoff validation apply. The selected
authority signs:

```text
SHA256(
  UTF8("heterodyne-governed-decrypt-key-binding-v1") || 0x00 ||
  UTF8(JCS(record with signature omitted))
)
```

using BIP-340 encoded as 128 lowercase hexadecimal characters. The complete
record digest is lowercase-hex SHA-256 of the complete signed JCS bytes. It is
stored at:

```text
credential-sync/governed-decrypt-key-bindings/
  <binding-id>/<record-digest>.json
```

The path ID equals the recomputed locator-derived ID and the filename digest
equals the lowercase-hex SHA-256 of the complete signed JCS record. Exact
duplicate bytes are idempotent. Nonidentical otherwise-valid records for one
`(persona,binding_id)` conflict and reject every dependent obligation and
ordinary checkpoint; no digest or arrival-order tie-break exists. When the
governing profile embeds exactly one tuple for a locator, a binding is
unnecessary, but every otherwise-valid binding record present for that locator
is still committed and must agree with that exact tuple. When a locator's
profile-authenticated set has more than one tuple, a locator-only binding is
extra and ambiguous and rejects; validators never choose which embedded member
it was intended to match.

#### Canonical repository-retention inventory

The repository universe used for governed-decrypt validation is itself a
signed, monotonic protocol record. Its closed record type is exactly
`heterodyne.repository-retention-inventory.v1`, its wire profile is
`comms.repository-retention-inventory.v1`, and the record contains exactly:

```text
type, persona, inventory_sequence, previous_records,
basis_checkpoint_digest, target_generation, target_sequence,
repository_refs, issued_at, epoch_pubkey, kel_head, epoch_signature
```

`type` is the exact record type above. `persona`, `epoch_pubkey`, and every
non-null digest are 64 lowercase hexadecimal characters. `inventory_sequence`,
`target_generation`, `target_sequence`, `issued_at`, and `kel_head.seq` are
JSON-safe nonnegative integers. The genesis record has
`inventory_sequence:0`, `previous_records:[]`, and
`basis_checkpoint_digest:null`. A successor has
`inventory_sequence = max(parent.inventory_sequence) + 1` and
`previous_records` equal to the complete individually valid maximal record
frontier at its basis, including all competing variants, represented as a
strictly sorted unique array of
`{inventory_sequence,record_digest}` ordered by numeric sequence and then
decoded digest bytes. An ordinary successor has exactly one parent. A
cold-root emergency-reset successor names every maximal competing parent
variant and no arrival-order or digest tie-break may omit one.

`basis_checkpoint_digest` on an ordinary successor is the complete signed
digest of its accepted predecessor checkpoint. On emergency reset it is the
accepted last-common reset checkpoint. `target_generation` and
`target_sequence` name the one first checkpoint that may activate the record,
avoiding a digest cycle with that future checkpoint. Genesis names exactly
`(target_generation=0,target_sequence=0)`. An ordinary successor's target is
the immediate candidate checkpoint generation/sequence after its exact
accepted predecessor. An emergency successor targets exactly
`(new_generation,0)` after the named last-common reset basis.

A record first enters effective `K(C)` only when `C` exactly matches that
target tuple, exactly descends from the named ordinary basis or implements the
named emergency reset basis, and accepts the record through its committed
frontier. Before that checkpoint it is staged and non-effective even if its
bytes are visible. After acceptance, its accepted maximal frontier remains
effective at every descendant checkpoint until a valid targeted successor
replaces it. A record with a stale, skipped, future, or otherwise mismatched
target can never activate at a different checkpoint. The record is stored at:

```text
credential-sync/repository-retention-inventories/
  <inventory-sequence>-<record-digest>.json
```

where `record_digest` is lowercase-hex SHA-256 of the complete signed JCS
record and must equal the filename component. The exact closed schema is:

```text
docs/spec/schemas/comms/repository-retention-inventory-v1.schema.json
```

`repository_refs` is a nonempty strictly sorted unique array. Each closed row
contains exactly:

```text
repository_ref_id, repository_class, repository_rid, ref_name,
object_format, retired, scan_head
```

`repository_class` is exactly `config`, `private`, or `public`.
`repository_rid` is the canonical Radicle RID, `ref_name` is one canonical
full ref name, `object_format` is `sha1` or `sha256`, and `retired` is a JSON
Boolean. `scan_head` is the closed typed Git object
`{object_format:"sha1"|"sha256",oid}`; its object format equals the row and its
OID has the exact length and lowercase encoding required above. The
deterministic semantic ID is:

```text
repository_ref_id =
  lowercase_hex(SHA256(
    UTF8("heterodyne-repository-retention-ref-id-v1") || 0x00 ||
    UTF8(JCS({
      repository_class,
      repository_rid,
      ref_name,
      object_format
    }))
  ))
```

Rows sort by unsigned UTF-8 bytes of class, RID, and ref name, then object
format ASCII and decoded ref-ID bytes. Duplicate semantic identities,
duplicate IDs, an ID/preimage mismatch, noncanonical RID/ref aliases, a
declared-format mismatch, or an object-ID length mismatch rejects.

Every ordinary single-parent successor contains every predecessor semantic
row. An existing active row's `scan_head` either remains equal, advances to a
Git descendant, or advances to an equal-or-descendant final head while changing
`retired` from false to true. A retired row is ordinarily immutable and
absorbing: it cannot disappear, reactivate, or advance. A new row names an
already materialized complete scan head and is fully scanned before any
artifact on that ref may enter governed use.

For candidate checkpoint `C`, `EffectiveRefs(C)` is the complete set of every
`repository_refs` row variant in the activated maximal inventory frontier after
these successor rules; conflicting variants remain distinct and reject
ordinary acceptance. A row present only in a signed ancestor record is
authenticated audit history, not an effective registration.

Config-key acceptance has one controlled deregistration. In ordinary
succession, its successor omits and thereby deregisters exactly the old active
`config` row only when it also adds the one fully scanned active
`refs/heads/enc/<new-config-key-id>` row, closure basis `B` proves the complete
decrypted predecessor logical tree was re-encrypted under the new key with no
surviving old-config-key dependency, and the same signed multi-ref
compare-and-swap accepts the new ref and deletes the exact old signed ref. This
is not retirement. The predecessor row and accepting
transition/CAS remain required ancestor evidence. Receipts for the accepting
candidate still authenticate and scan the old ref as the exact source/closure
basis and verify deletion preconditions, while its result `EffectiveRefs(C)`
and `K(C)` exclude that ref. Descendant receipts and archives validate the
ancestor and accepting transition/CAS evidence without fetching or scanning
the deleted ref. No other ordinary transition may deregister a row.

A cold-root emergency successor that names multiple parent inventory records
contains the union of every semantic row present in `EffectiveRefs` of any
maximal parent plus any valid new rows. Absence from another branch is never a
deletion or retirement signal. A prior valid config deregistration suppresses
a row only when it is absent from every maximal parent's `EffectiveRefs`. A row
present in only a subset of parents, or present byte-identically in all
applicable parents, follows its one unique variant: the successor preserves it,
advances it ordinarily, or explicitly retires it at an equal-or-descendant cut
through the reset. It cannot omit it.

After first forming that complete union, emergency config-key acceptance may
subtract exactly `V_old`, the complete variant set for the one old active
`config` semantic identity whose ref name is
`refs/heads/enc/<old-config-key-id>` and whose current signed target is
`inventory_basis.source_ref_head`. Every maximal-parent variant of that
semantic identity belongs to `V_old`. Reset `K(I)`, closure basis `B`, and
class-complete actions authenticate and scan every variant tree, terminally
account every locator/binding/obligation pair, re-encrypt the complete logical
union under the one fully scanned new active config row, and prove no result
dependency on the old config key. The same reset CAS accepts the new ref and
deletes the exact old signed ref. Accepting-reset receipts scan every `V_old`
variant as source/closure evidence; result and descendant
`EffectiveRefs(C)`/`K(C)` exclude them, while every ancestor record and
reset/CAS proof remains audit evidence. Partial-variant, wrong-identity,
wrong-ref, or different-ref subtraction rejects, and every row outside
`V_old` remains in the emergency union.

For a semantic row with two or more present parent variants that disagree on
`scan_head` or `retired` and is outside a valid `V_old` terminal
deregistration, the emergency successor applies one exact convergence
exception. It contains one replacement row with the same semantic ID and a
newly materialized resolution `scan_head` `H*`. The raw Git commit at `H*` has
as its complete direct-parent set every
distinct variant `scan_head` and no other parent, in decoded-OID-sorted order
and the declared object format. If all variants share one head but disagree
only on `retired`, `H*` has that one head as its sole parent. Its exact commit
tree is the pre-materialized reconciled cut scanned by the reset; every parent
commit/tree remains reachable as immutable audit history but, under the
exact-tree rule, does not itself remain governed content.

For `repository_class:"config"`, `H*` is the sole multi-parent exception to
the otherwise linear `comms.config-repository-git-structure.v1` profile. Its
commit body is the exact concatenation of:

```text
UTF8("tree ") || canonical_tree_oid || LF ||
for each decoded-OID-sorted variant head:
  UTF8("parent ") || canonical_parent_oid || LF ||
UTF8("author Heterodyne Protocol <noreply@heterodyne.invalid> 0 +0000\n") ||
UTF8("committer Heterodyne Protocol <noreply@heterodyne.invalid> 0 +0000\n") ||
LF ||
UTF8("heterodyne-config-retention-resolution-v1\n")
```

There is at least one parent and the exact parent-list predicates above apply.
The tree, modes, canonical paths, and encrypted blob rules are otherwise
unchanged. This grammar is legal only when the commit is the exact config-class
`H*` named by a cold-root emergency repository-inventory successor satisfying
the complete frontier, union, and reset predicates. An unbound merge, an
ordinary commit with multiple parents, or the resolution message on any other
commit rejects. Ordinary config commits retain the existing zero-or-one-parent
`heterodyne-config-v1` grammar.

The replacement row's `retired` value equals the reset's explicit signed
result for that semantic row; it is not a local merge choice. If a config row
resolves retired, the same inventory contains a separate fully scanned active
config row so the exactly-one-active invariant still holds. This is the sole
permitted advance from, or reactivation of, a retired variant, and is valid
only when every maximal parent variant appears in `previous_records`, every
variant head is an exact direct parent of `H*`, and the reset inventory `K(I)`
plus class-complete actions account for the complete locator/tuple universe in
every variant's exact tree.

For the conflicted semantic row `S`, let `L(S)` contain every locator produced
by an allocated authenticated decrypt-dependency source profile in any parent
variant's exact tree, regardless of parent-local currentness. For each locator
`l`, `Bound_I(l)` is the complete set containing every tuple in every
individually valid profile-authenticated embedded tuple set and every tuple in
every individually valid signed-binding variant for `l` preserved in parent
`K(I)`. Conflicting binding variants all contribute; no digest or arrival-order
winner is selected. If the selected source profile requires a fallback binding
and any candidate binding bytes are missing or unavailable, the reset remains
pending.

Let `Current_I(t)` be true only when every complete parent key-state projection
applicable to the artifact's class/namespace exists, names `t` as the same sole
current instance, and contains no retirement, competing variant, or different-
current state for `t`. Missing applicable state or any disagreement makes it
false. `Current_B(t)` is the ordinary post-reset unique-current predicate
replayed from projected result basis `B` after all exact class actions; it is
true only for the one nonconflicting current instance selected by that class's
normal rules. Define:

```text
L(S) =
  union(all marked decrypt-dependency artifact locators in every
        parent variant exact tree)

L(S) =
  preserved_at_H_star disjoint-union
  reencrypted_or_replaced disjoint-union
  deleted_and_closed

D(S) = { (l,t) | l in L(S) and t in Bound_I(l) }

U(S) = { (l,t) in D(S) | not Current_I(t) }

ResultPairs(H*) =
  exact (H*-based locator,tuple) pairs authenticated by the result
  source profile plus its one uniquely validated fallback binding, if required

ResultHistoricalPairs(H*) =
  { (l,t) in ResultPairs(H*) | not Current_B(t) }
```

The locator projection is total and exact. Each old locator appears in exactly
one disposition, including both sides of a path/content collision; ancestor
reachability alone is never a disposition. Class-complete cleanup and
provenance account for every candidate pair in `D(S)`, not one convenient
tuple. Thus a multi-tuple locator, conflicting `l -> t1`/`l -> t2` bindings, or
ciphertext whose tuple is current on one parent but retired, competing,
differently current, or unprovable on another enters conservative pairwise
accounting rather than disappearing through parent-local classification. The
replacement tree may omit an old artifact only through the same transition's
independently materialized re-encryption/replacement or deletion, exposure
cleanup, and obligation close/replacement.

Because every governed locator commits `repository_head`, even unchanged
ciphertext copied into `H*` has a fresh H*-based locator. Every old pair in
`D(S)` has exactly one terminal pair outcome: carried to an identical tuple in
`ResultPairs(H*)`, re-encrypted/replaced, rejected binding candidate resolved
and closed, or deleted and closed. A physical locator may be preserved while
one conflicting old binding candidate is terminalized as audit/cleanup
evidence rather than carried into the result.

If the result profile requires a single fallback tuple, one fresh
nonconflicting H*-based signed binding is materialized before the inventory
record only after all old candidates are accounted and profile/ciphertext
validation proves that unique result tuple; otherwise preserving the artifact
is forbidden and it must be re-encrypted/replaced or deleted. A profile-
authenticated multi-tuple result preserves each authenticated result pair
without collapsing it into one binding.

The transition closes or replaces every old-head obligation pair. Active H*
obligations are created for exactly `ResultHistoricalPairs(H*)`, never for a
rejected old binding candidate merely because it was in `U(S)`. Independently
derived post-reset state then satisfies `G(B) = O(B)`. Reusing an old-head
locator/binding, selecting one conflicting candidate without terminalizing the
others, inventing an unauthenticated result pair, or omitting a candidate tuple
rejects. After acceptance, a retired replacement is again absorbing; an
active replacement follows the ordinary equal/descendant rule. No ordinary
successor, digest selection, non-common descendant, merge missing or adding a
direct parent, unscanned merge tree, or incomplete disposition can use this
exception.

Ordinary accepted state has exactly one active `config` row. During candidate
construction, the candidate config ref is only a deterministic staging
transport; its registered config `scan_head` is the strict pre-inventory
ancestor of the commit that first contains this record, and the candidate
gains canonical authority only through checkpoint acceptance.

For this mechanism, scanning a `scan_head` in `EffectiveRefs(C)` means scanning
the exact recursive tree selected by that commit, not every blob reachable
through its ancestor commit graph and not arbitrary objects retained in the
local object database. Ancestor ciphertext that is absent from the selected
tree is audit residue, not a current governed dependency merely because Git
still retains the old commit. Intentionally retained historical ciphertext
absent from a moving tree must instead remain named by an explicit registered
frozen retention ref. Thus a descendant tree may reencrypt or delete an
artifact and eliminate its dependency, after which the obligation can close,
while the old commit remains audit evidence. A retired effective row's
immutable final `scan_head` continues to scan that exact final tree. A validly
deregistered config row is validated through its ancestor record and accepting
transition/CAS instead and is not fetched or scanned. History rewriting or a
non-descendant replacement is not an alternative to these rules.

The current epoch key signs:

```text
SHA256(
  UTF8("heterodyne-repository-retention-inventory-v1") || 0x00 ||
  UTF8(JCS(record with epoch_signature omitted))
)
```

using BIP-340 encoded as 128 lowercase hexadecimal characters. Ordinary
records use the current epoch and accepted KEL head. An emergency record uses
the fresh reset target epoch only after the cold-root-authorized KEL rotation
and becomes effective only with that reset and its checkpoint. Historical
signer validation, KEL ancestry, rollover ratification, compromise cutoffs,
and post-cutoff rejection apply in both modes.

This inventory is the protocol's canonical repository/ref registry, not a
signer's assertion that no other physical repository exists. A verifier cannot
prove physical absence of an unknown private repository; instead, a ref that
is not registered and completely scanned cannot carry canonical
governed-decrypt source-profile content. Registration and the complete scan
therefore precede first governed use. Config and private RIDs remain confined
to encrypted config/credential synchronization and recovery archives; the
inventory does not make them public.

All target-roster receipt producers fetch and authenticate every
`EffectiveRefs(C)` RID/ref under the repository's ordinary Radicle identity,
signed-ref, authorization, object-format, and ancestry rules, then scan exactly
each listed `scan_head`. A validly deregistered config ref instead requires its
ancestor inventory and accepting transition/CAS proof and is not fetched.
Vanilla Radicle cannot provide a cross-repository atomic
compare-and-swap. Producers instead freeze writes for the candidate, bind
authenticated immutable cutoffs in this record, and require every receipt to
recompute those exact cuts. Content created under an old key after a committed
cutoff is noncanonical and cannot be admitted by backdating or a later fetch.

The artifact/ciphertext first exists at authenticated head `A`. Any required
signed binding record `K` is materialized after its locator exists and before
inventory record `R`; `R` then names only preexisting scan heads. Obligation
`O`, transition `T`, checkpoint `C`, and receipts follow in this exact acyclic
record-dependency order:

```text
accepted predecessor -> artifact A -> optional binding K ->
repository inventory R -> obligation O -> transition T -> checkpoint C ->
receipts
```

For an embedded tuple, `K` is omitted without changing the order. The arrows
are logical record dependency and signing order, not canonical Git tree-entry
order and, for a config-key transition, not necessarily distinct commits.
Closure basis `B = result_basis.config_head` remains the parentless new-key
root and the new active config row's pre-inventory `scan_head`. Every artifact
and scan head preexists `R`; every external scan head is independently
materialized. A required `K` is either already reachable at an independently
authenticated pre-inventory head or, when its locator commits `B` and
embedding it in `B` would self-reference, first carried in direct-child commit
`T`. That commit may atomically carry finalized `K`, `R`, `O`,
every `O`-dependent source/assignment/retirement and transition-action record,
reset where applicable, and the transition, but their bytes and signatures are
produced in dependency order and none names `T`'s commit OID. Result and
target digests project those records. New transition-bound `K`/`R`/`O` and
dependent proof records are not placed in `B`; copied predecessor audit
records remain there.

The config scan head is a strict ancestor of the commit first containing `R`.
Artifacts, bindings, and scan heads cannot depend on `R` or any descendant.
`R` references only its accepted basis and parent inventory records.
Obligations follow `R`, and no self-reference or digest cycle is legal. An
unmarked arbitrary ciphertext, a missing/extra/conflicting or late binding, a
locator/tuple mismatch, an unregistered source ref, or an obligation used as
the sole tuple source rejects.

At candidate checkpoint head `C`, validators derive the closed object `K(C)`
containing exactly:

```text
{repository_inventory_records,governed_heads,binding_records}
```

`repository_inventory_records` is the complete maximal inventory frontier
activated at or retained through `C` by the target/basis rule above, represented by the exact
`{inventory_sequence,record_digest}` rows above and sorted by numeric sequence
then decoded digest. Every row dereferences the exact valid signed record and
its complete ancestor graph. Every individually valid maximal conflict variant
is included. A conflict rejects an ordinary checkpoint; emergency reset starts
from the last common accepted checkpoint and the complete branch union, then
uses one fresh-epoch inventory record whose parents are all maximal variants.
Arrival order and digest choice never select a branch.

`governed_heads` is the complete strictly sorted unique array of closed
`{owner,repository_rid,ref_name,repository_head}` rows derived from
`EffectiveRefs(C)`. For every active or retired config/public/private cut,
validators scan each noncurrent marked dependency under its one
registry-selected authenticated source profile and emit exactly one row for
each distinct allocated `owner` produced by those locator expansions.
`repository_head` has the typed-Git shape above and matches the inventory row's
declared format. A mixed-owner cut emits multiple rows; a cut with no
noncurrent dependency emits none. Rows sort by owner, RID, and full ref-name
UTF-8 bytes, then object-format ASCII and decoded OID. A fallback binding's
retained-ciphertext `owner` must equal the selected source-profile owner;
missing, extra, or mismatched head-owner projections reject. These are frozen
retention snapshots, not moving current tips: retirement of a key or a change
to its retained dependency set advances the applicable inventory cut and
creates or replaces the applicable rows through the same transition; later
posts encrypted under a current key do not alter `K(C)`.

For every exact retained head, validators scan the governing artifact/pointer
profiles, derive every marked dependency locator and deterministic binding ID,
and require either the exact embedded tuple or one unique matching
pre-obligation signed binding. `binding_records` is the complete strictly
sorted unique array of `{binding_id,record_digest}` for every individually
valid binding-record variant at the canonical operational paths for those
derived IDs, including all conflicting variants. It sorts by decoded binding
ID then decoded record digest. A binding for no dependency enumerated by
`governed_heads` is extra and rejects rather than expanding authority. Closed
or replaced bytes remain audit history but not part of the operational
frontier. A conflict remains represented in `K(C)` but rejects ordinary
checkpoint acceptance.

The checkpoint's required
`governed_decrypt_key_bindings_sha256` is:

```text
lowercase_hex(SHA256(
  UTF8("heterodyne-governed-decrypt-key-binding-set-v1") || 0x00 ||
  UTF8(JCS(K(C)))
))
```

Its exact `config_head` authenticates the inventory-record frontier and
complete binding-record frontier. The unchanged digest domain therefore
commits the enlarged closed `K(C)`; no second checkpoint digest is added. An
omitted or extra inventory record/ref, governed head, source-profile marker,
binding, conflict variant, or ciphertext locator changes the digest or fails
the exact scan rather than shrinking or expanding the verifier's universe.

The registry-selected source-profile universe is closed independently of
repository content. Revision 4 adds
`governed-decrypt-source-profile` to the closed `allocation_kind` enum. Each
allocation value is one exact globally unique source-profile ID and its owner
equals the family owner that validates and expands that profile. The Comms
normative source-profile table binds each allocated ID to its allowed secret
classes and deterministic locator/tuple expansion. The selected pinned
registry and table must exhaust every profile capable of producing a governed
dependency, including the six existing Tier-3 Nostr wrapped-content profiles,
the Tier-3 feed-index and descriptor profiles, the config-repository encryption
profile, the private claim-ledger encryption profile, every recovery-wrapped
profile that can retain governed ciphertext, and
`comms.large-object-pointer.v1`. The revision cannot freeze until the exact
config, claim-ledger, recovery, and all other current spellings are allocated
and tabled; this requirement is not permission for placeholder or wildcard
values. An unknown, unallocated, wrong-owner, or signer-supplied profile marker
rejects. Profiles incapable of producing a governed dependency are absent from
this allocation kind and cannot expand the scan.

`retired_provenance_lineages` is a nonempty strictly sorted unique array of
closed rows containing exactly:

```text
holder_nid, assignment_id, source_record_digest,
assignment_record_digest, retirement_record_digest
```

Rows sort by canonical holder NID UTF-8, decoded assignment ID, then decoded
source, assignment, and retirement digests. Each row dereferences one exact
valid source companion, one exact otherwise-valid assign variant, and the one
accepted absorbing retirement that supersedes that assignment. All repeat the
record's secret tuple and holder, and every retirement is effective through
the record's named transition or an accepted predecessor transition. The array
is the complete retired provenance for this retained instance, including
competing assignment variants that were individually retired. An unretired
holder belongs in the separate current-holder array below, never in this
provenance set. Claimed erasure, non-use, or loss of a source byte is not a
retirement and cannot remove a row.

At a candidate checkpoint head `C`, validators independently derive
`G(C)`, the complete set of retained governed decrypt dependencies. Each
element is the tuple
`(persona,secret_class,secret_id,instance_commitment,<complete retained
ciphertext row>)` obtained from every canonical repository/blob and
large-object pointer discovered from the exact
`K(C).repository_inventory_records` and `K(C).governed_heads` scan and whose
allocated authenticated source profile or unique canonical binding record
binds the exact preexisting repository/object head whose bytes still require a
noncurrent secret. The secret tuple comes only from that preexisting allocated
artifact/pointer profile or binding record, never by trusting an obligation's
own claim.

An authenticated encrypted large-object pointer expands deterministically into
two distinct items when both dependencies are noncurrent. Its `git-blob`
locator names the exact encrypted pointer/wrapped-DEK blob and binds the
config- or Tier-3-audience tuple; its `large-object` locator names the exact
stored ciphertext bytes and binds the object-DEK tuple. The pointer profile
embeds both complete tuples, or each distinct locator resolves its own
locator-derived binding. One logical pointer can therefore require two
obligations without overloading one binding ID. Omitting, swapping, or
collapsing either item rejects.

After applying the checkpoint's exact accepted-transition projection,
validators derive `F(C)`, the complete maximal obligation frontier. It is a
strictly sorted unique array of closed items containing exactly
`{obligation_id,lineage_sequence,action,record_digest}`, ordered by decoded
obligation ID, numeric sequence, explicit `retain`-before-`close` action rank,
then decoded digest. Every
valid maximal competing branch and every maximal `close` is present. A unique
maximal `retain` is active, a unique maximal `close` is inactive, and multiple
maxima quarantine the ID and reject an ordinary checkpoint.

`Active(C)` is the subset containing the one maximal `retain` only for each
nonforked ID; a close or fork contributes no active item. Validators derive
`O(C)` by expanding the ciphertext arrays of `Active(C)` with each record's
secret tuple. Acceptance requires the exact set equation:

```text
G(C) = O(C)
```

and requires one unique maximal head for every obligation ID in `F(C)`. A
retained governed ciphertext without an active obligation, an
obligation row without matching retained ciphertext, duplicate coverage,
wrong digest/length/locator, a missing provenance member, or an active
obligation for a fully eliminated dependency rejects the checkpoint.
`close` is valid only when every ciphertext row named by that lineage's
preceding retain head is absent from independently derived `G(C)`.

The checkpoint field is lowercase-hex SHA-256 and commits the complete
frontier, not merely active retain heads:

```text
SHA256(
  UTF8("heterodyne-historical-decrypt-obligation-set-v1") || 0x00 ||
  UTF8(JCS(F(C)))
)
```

The Comms full manifest's
`historical_decrypt_obligation_records` equals `F(C)` byte for byte and its
high-water field repeats that digest. The exact obligation bytes, their
source/assignment/retirement provenance, every
`K(C).repository_inventory_records` frontier and ancestor record byte, every
`K(C).binding_records` byte, every `K(C).governed_heads` repository snapshot,
every `EffectiveRefs(C)` config/private/public ref at its exact `scan_head`, its
Radicle identity and signed-ref evidence, and every governed locator remain
reachable from the archived config and repository snapshots. Repository bundle
entries and their ref/head projections cover every effective inventory row;
omission of one makes `K(C)` unrecomputable and rejects. An ancestor-only config
row deregistered by accepted config-key rotation instead requires its exact
ancestor inventory and accepting transition/CAS evidence; its deleted ref
snapshot and bundle are not live archive inputs and need not be retained.

The inventory records and signed-ref evidence use
`role:"protected-metadata-record"`. The manifest credential high-water repeats
the exact `governed_decrypt_key_bindings_sha256` derived from the enlarged
`K(C)`; no additional manifest digest is introduced. A standalone archive
cannot omit any of these bytes. Network-assisted mode may externalize only the
already-declared large-object stored bytes, never an inventory record, scan
snapshot, repository bundle, pointer, governed head, binding record,
obligation record, signed-ref proof, or provenance. In particular, neither a
repository-retention inventory nor any inventory scan snapshot may be encoded
as or replaced by a large object. The scan-snapshot requirement applies to
`EffectiveRefs(C)`; an ancestor-only config row validly deregistered by an
accepted config-key rotation retains its inventory and transition/CAS evidence
but has no required deleted-ref snapshot.

Both governed-decrypt digests are load-bearing throughout ADR-037. Every
secret-transition `target` and `inventory_basis` contains
`governed_decrypt_key_bindings_sha256` and
`historical_decrypt_obligations_sha256`; `result_basis` is exactly
`{config_head,exposure_set_sha256,governed_decrypt_key_bindings_sha256,
historical_decrypt_obligations_sha256}`. Routine rotation/addition/removal
always activates the mandatory targeted inventory successor that deregisters
the exact old active config-ref row and registers the new fully scanned active
row. Its target, result, and successor checkpoint bind
`governed_decrypt_key_bindings_sha256` recomputed from successor `K(C)`;
`repository_inventory_records`, `K(C)`, and that digest MUST change even when
no noncurrent dependency exists. `governed_heads` and `binding_records`
remain byte-identical unless exact independently materialized
binding/snapshot records change governed ciphertext, and
`historical_decrypt_obligations_sha256` remains byte-identical unless exact
obligation actions change the complete frontier. This permitted non-null
inventory-only advance is separate from the null-transition exception. A
null-transition may change the governed-binding digest only for an inventory
successor that registers a fully scanned ref or advances an existing scan head,
when that change introduces no noncurrent decrypt dependency and
`governed_heads` and `binding_records` remain byte-identical. The overall
`K(C)` and its digest still change because `repository_inventory_records`
changes. Every other null transition preserves both digests byte-identically;
ordinary current-key posts alone never create an inventory successor.
Candidate abandonment binds `candidate_governed_decrypt_key_bindings_sha256` and
`candidate_historical_decrypt_obligations_sha256`; same-key candidate audit,
emergency reset, source-basis closure, exact-tip compare-and-swap, and
reconstruction bind both predecessor and result digests. Hidden binding
variants, inventory-frontier/ref drift, retained-snapshot drift,
retain/close records, or governed-locator drift invalidate the candidate just
as source/assignment drift does.

Every other existing carrier of `governed_decrypt_key_bindings_sha256`
inherits that same enlarged `K` meaning without a new field: checkpoint and
receipt, manifest credential high-water, generic authority-secret envelopes
and durable-inventory rows, candidate abandonment and same-key audit,
transition target/inventory/result bases, emergency reset and closure,
source-basis and reconstruction records, exact-tip/CAS guards, offline
pre-unseal/activation and transfer-grant `archive_restore_basis` objects,
archive generation/finalization/abandonment and restore comparison, and
normal-or-gap rollover closure. A carrier that preserves the old digest while
its repository-inventory frontier changes is invalid.

In routine mode,
`inventory_basis.governed_decrypt_key_bindings_sha256` equals the predecessor
checkpoint's independently recomputed `K(C)`. In emergency mode it commits
`K(I)`, the complete repository-inventory frontier, retention-snapshot, and
binding-record union recovered from every named config, source, staging,
recovered, same-key-candidate, and unreconciled-offline basis. `K(I)` includes
every conflicting inventory and binding variant; reset cannot select one by
arrival order. The exact transition projects that inventory to nonconflicting
`K(B)` only through a fresh inventory record that parents the complete maximal
inventory frontier and by preserving, replacing, or removing the snapshots and
bindings whose governed dependencies its actions actually change. The result
digest equals the transition target and successor checkpoint field.

Every target-roster receipt independently fetches and authenticates every
`EffectiveRefs(C)` RID/ref and exact scan cut, validates every ancestor-only
config deregistration through its accepting transition/CAS without fetching
the deleted ref, derives every retention-snapshot head from the closed
allocated source-profile table, recomputes `K(C)` and its digest, and then
recomputes `G(C)`, `F(C)`, `Active(C)`, `O(C)`, the obligation-set digest,
every record signature/lineage, every locator and available ciphertext digest,
and the exact provenance dereferences before it counts. Thus the complete
receipt set proves the same repository-universe, governed-head/binding
completeness and
ciphertext/obligation bijection at the checkpoint's exact `config_head`; a
later local deletion, an unavailable external copy, or a promise not to use
the key cannot validate a mismatched candidate. Any inventory record/ref/cut,
governed head, binding record, governed ciphertext, obligation, source,
assignment, or retirement mutation between the candidate basis and receipt
completion invalidates the candidate and requires reproposal.

An obligation fork has one escape: a cold-root `emergency-reset` starts from
the last common accepted checkpoint, inventories every branch and its complete
retained-ciphertext/provenance union, and creates fresh obligation IDs for the
objectively retained dependency set in the new generation. The reset's
accepted-transition projection terminalizes the old operational generation;
all old branch bytes remain audit evidence, while `F(C)` for the reset
checkpoint contains the fresh nonconflicting frontier. The reset also
preserves every old inventory and binding variant, derives the complete
registered-ref and retained-snapshot union, and creates any fresh
nonconflicting bindings needed by the rebuilt state. Omitting an inventory,
binding, or obligation branch, a registered ref, or a still-retained
dependency, or reusing a forked or closed ID, rejects the reset.

For every full archive, `special_authority_bindings` is exactly two closed rows
ordered `cold-root`, then `epoch`. Each contains exactly
`secret_class`, `lifecycle`, `source_identity`, `entry_path`, and
`entry_sha256`; `lifecycle` is exactly `current`. The cold-root row names the
one `core-protected-record` containing the independently NIP-49-wrapped
cold-root record. The epoch row names the one special
`heterodyne-recovery-epoch-authority-envelope-v1`. `entry_path` and
`entry_sha256` equal the exact manifest descriptor path and digest.
Device-class archives use an exactly empty array.

For a Core-only full archive each `source_identity` is null and Core authority
and entry equality remain complete. For a Comms full archive it is the closed
object containing exactly:

```text
secret_id, instance_commitment, current_holder_lineages,
historical_obligation_record_digests, retired_provenance_lineages,
credential_checkpoint_digest, historical_decrypt_obligations_sha256
```

`current_holder_lineages` is a nonempty strictly sorted unique array of closed
rows containing exactly:

```text
holder_nid, assignment_id, source_record_digest, assignment_record_digest
```

Rows sort by canonical holder NID UTF-8, decoded assignment ID, then decoded
source and assignment digests. Each row dereferences one exact valid source
companion and one exact otherwise-valid assign variant for the same holder and
secret tuple. The array is the checkpoint's complete conservative unretired
holder set for that lifecycle; distinct holder assignments are never
collapsed into one source digest. For lifecycle `current`, it includes every
staged or competing unretired assignment variant selected by the checkpoint's
conservative exposure projection. The stricter `historical-decrypt` projection
is defined below.

Both special rows have lifecycle `current`, so
`historical_obligation_record_digests` and
`retired_provenance_lineages` are exactly empty.
They do not claim governed historical ciphertext and therefore do not repeat
`governed_decrypt_key_bindings_sha256`; their exact
`credential_checkpoint_digest` still binds the complete checkpoint including
that global field. Generic entries carry the field explicitly below.
`credential_checkpoint_digest` and
`historical_decrypt_obligations_sha256` equal the manifest's non-null Comms
credential high-water fields. The cold-root identity's commitment derives the
exact persona public key and matches the NIP-49 record; the epoch identity's
commitment derives the exact `epoch_pubkey`, and its current holder lineages,
manifest authority, allocation, special envelope, decrypted scalar, KEL head,
and finalization all satisfy the full equality matrix. An activation-target
NID in the online authority-activation flow that will receive either capability
is already one exact holder row committed by the activation-basis checkpoint.
An offline restore's new NID is instead represented only by its signed
provisional candidate records until first-sync reconciliation. A missing
special row, holder, source, or assignment, an entry mismatch, a nonempty
historical array, or a generic envelope that duplicates either special class
rejects.

Every generic `authority-protected-secret` entry is an opaque envelope under
the authority DEK rather than plaintext protected only by the bulk DEK. Its
outer JCS object contains exactly:

```text
type, owner, secret_class, secret_id, instance_commitment, lifecycle,
record_value, current_holder_lineages,
historical_obligation_record_digests, retired_provenance_lineages,
credential_checkpoint_digest, governed_decrypt_key_bindings_sha256,
historical_decrypt_obligations_sha256,
cipher, nonce, ciphertext
```

`type` is `heterodyne-recovery-authority-protected-secret-v1`; `cipher` is
`AES-256-GCM`; and `lifecycle` is `current` or `historical-decrypt`.
`current_holder_lineages` has the exact nonempty row shape, sorting, and
conservative-set semantics above for both lifecycle values. It therefore names
every NID that can currently unwrap the archived capability under its
lifecycle-specific permissions, including a newly admitted online activation
target. For `historical-decrypt`, that permission is decrypt-only for exact
governed rows and never general exercise of the old key. An offline restore
target is added only in the provisional overlay below. The AAD is the JCS
object with `nonce` and `ciphertext` omitted. The decrypted closed object
repeats every identity/binding member and adds exactly `material_schema` and
`material`; the table below selects its one exact schema. That schema validates
the material and recomputes `instance_commitment` before staging.
`credential_checkpoint_digest`,
`governed_decrypt_key_bindings_sha256`, and
`historical_decrypt_obligations_sha256` exactly equal the corresponding
non-null Comms full manifest high-water fields; a generic envelope is not legal
in a Core-only or device-class archive.

A nonempty `current_holder_lineages` array says that the archived capability
still has holders; it does not imply lifecycle `current`. A
`historical-decrypt` key necessarily has current holders while its retired
provenance and active obligations separately explain why new encryption is
forbidden but retained ciphertext remains decryptable.

For lifecycle `current`, `historical_obligation_record_digests` and
`retired_provenance_lineages` are exactly empty. For lifecycle
`historical-decrypt`, both arrays are nonempty.
`historical_obligation_record_digests` is strictly sorted by decoded digest
bytes and equals the complete active obligation-head digest set whose secret
tuple matches this entry. `retired_provenance_lineages` has the exact row
shape and sorting defined for an obligation record and equals the deduplicated
complete union of those obligations' provenance rows. A historical entry
therefore binds both its current holders and the separately retired
distributions that explain why the underlying data became historical. Missing
or extra obligation, source, assignment, or retirement bytes; an inactive or
forked obligation; wrong holder; a
`governed_decrypt_key_bindings_sha256` value that differs from the selected
checkpoint/manifest `K(C)` digest; or a current entry with either historical
array rejects.

For `historical-decrypt`, `current_holder_lineages` is not a surviving subset
of the retired operational assignments. It equals the complete unretired
projection of the accepted ADR-037 transition-action
`historical_assignment_digests` for this exact old
`(secret_class,secret_id,instance_commitment)` tuple; that action array is
strictly sorted uniquely by decoded assignment-record digest. The corresponding
`historical_decrypt_nids` is the exact strictly sorted unique canonical-NID
target-roster
recovery/decrypt-only holder set selected by the governing class policy and is
the holder-NID projection of these rows. It may overlap the action's
`authorized_nids`, but neither set implies membership in the other. Each
digest dereferences one fresh-assignment-ID `action:"assign"` record with that
transition ID, the same old tuple, and one holder, forming a complete
one-to-one projection. Its current nonretired source companion is newly staged
or already current under the accepting epoch and its `artifact_refs` bind the
complete projected-active retain-obligation head set for the old tuple, every
applicable governed-decrypt key binding, and every governing artifact/pointer
proof. A stale source without that complete reference set or an old assignment
ID cannot supply a current-holder row.

All prior operational and prior historical assignments retire atomically and
appear in `retired_provenance_lineages` on every projected-active obligation
successor for that old tuple; the fresh historical assignments simultaneously
enter the result exposure digest. The same NID may therefore appear once in
retired provenance under its old assignment and once in
`current_holder_lineages` under a fresh live historical assignment. That is
required provenance separation, not a duplicate holder. These live
assignments authorize only decryption of exact `G(C)` rows covered by their
cited complete active-obligation/key-binding evidence. They cannot authorize
new encryption under the old instance or any signing, delegation, minting,
serving, or other authority. Both action arrays are nonempty whenever an
active retain remains for the old tuple. Closing the final matching obligation
retires the complete live historical assignment set and leaves both arrays
empty; no `historical-decrypt` inventory entry survives with an empty holder
set.

`record_value` is the canonical live-record locator:

```text
"authority-secret-v1:" || lowercase_hex(SHA256(
  UTF8("heterodyne-recovery-authority-secret-record-v1") || 0x00 ||
  UTF8(JCS({
    "owner": owner,
    "secret_class": secret_class,
    "secret_id": secret_id,
    "instance_commitment": instance_commitment,
    "lifecycle": lifecycle,
    "current_holder_lineages": current_holder_lineages,
    "historical_obligation_record_digests":
      historical_obligation_record_digests,
    "retired_provenance_lineages": retired_provenance_lineages,
    "credential_checkpoint_digest": credential_checkpoint_digest,
    "governed_decrypt_key_bindings_sha256":
      governed_decrypt_key_bindings_sha256,
    "historical_decrypt_obligations_sha256":
      historical_decrypt_obligations_sha256
  }))
))
```

The generic entry path is exactly `keys/<owner>/<record>/value`; its mapped
owner equals the envelope owner and its mapped record canonical value equals
`record_value`. Both mappings and the complete entry path are unique. A
record-map substitution, two different preimages resolving to one record
value, a locator/path collision, or an entry descriptor whose owner differs
rejects before authority decryption.

For the Comms full composition, the manifest's `durable_secret_inventory`
member is a strictly sorted unique array of closed objects containing exactly
`owner`, `secret_class`, `secret_id`, `instance_commitment`, `lifecycle`,
`record_value`, `current_holder_lineages`,
`historical_obligation_record_digests`, `retired_provenance_lineages`,
`credential_checkpoint_digest`, `governed_decrypt_key_bindings_sha256`,
`historical_decrypt_obligations_sha256`,
`entry_path`, and `entry_sha256`.
Sorting uses the UTF-8 tuple
`(owner,secret_class,secret_id,instance_commitment,lifecycle,record_value)`.
`entry_path` names exactly one generic authority-protected entry;
`entry_sha256` equals that entry descriptor's `sha256` member over the exact
outer-envelope bytes.

This is a complete bijection. Every generic durable-secret obligation derived
from the accepted credential checkpoint's full live source and conservative
exposure state produces exactly one inventory member, and every generic
authority-secret entry produces exactly one member. The inventory excludes
exactly the two special cold-root/epoch entries and every non-generic category
in the table below. Every inventory row, outer envelope, and decrypted object
contains the byte-identical complete `current_holder_lineages` array. For
`current`, the two historical arrays are empty. For `historical-decrypt`, the
current-holder set is exactly the accepted action's fresh live
`historical_assignment_digests`/`historical_decrypt_nids` projection, while
the obligation-digest set and retired-provenance union are independently
derived from the active retain subset of the checkpoint's complete maximal
obligation frontier. Every historical holder source carries the complete
projected-active obligation-head, governed-binding, and artifact/pointer
references. This
makes a new decrypt-only assignment distinct from the same holder's retired
operational assignment, preserves every per-holder capability lineage, and
prevents an arbitrary old source from justifying key retention.

The mapped path owner, entry descriptor owner, inventory owner, outer-envelope
owner, repeated decrypted owner, and governing material-schema owner are
identical. Every other inventory identity/binding member equals the
corresponding outer-envelope and repeated decrypted member. The selected
checkpoint's `exposure_set_sha256`,
`governed_decrypt_key_bindings_sha256`, and
`historical_decrypt_obligations_sha256` equal the manifest high-water members,
its exact `K(C)` is reconstructible from the archived retention snapshots and
binding frontier, its complete maximal obligation frontier equals
`historical_decrypt_obligation_records`, every historical inventory row binds
the matching active-retain and fresh historical-assignment subsets, and the
JCS inventory-array digest equals `secret_inventory_sha256`. The inventory
contains every current
generic secret and every permitted `historical-decrypt` secret needed to open
or continue an authoritative repository, retained object, retained history,
or included service. There are no caller-selected omissions.

ADR-037's complete `secret_class` set has this total portable mapping; no
implementation may reclassify a value:

| `secret_class` | Exact portable category | Exact material schema | Allowed lifecycle |
|---|---|---|---|
| `cold-root` | special NIP-49 `core-protected-record` | Core NIP-49 wrapped-cold-root record | `current` |
| `epoch` | special epoch authority envelope | `heterodyne-recovery-epoch-secret-v1` | `current` |
| `device-signing` | `clone-device` only; never a full archive generic entry | `heterodyne-recovery-device-clone-secret-v1` | `current` |
| `agent-signing` | generic authority secret | `heterodyne-recovery-agent-signing-secret-v1` | `current` |
| `core-protected` | `protected-metadata-record`; no generic secret entry | `heterodyne.node-secret-capability.core-protected.v1` | none |
| `config-audience` | generic authority secret | `heterodyne-recovery-symmetric-secret-32-v1` | `current`, `historical-decrypt` |
| `tier3-audience` | generic authority secret | `heterodyne-recovery-symmetric-secret-32-v1` | `current`, `historical-decrypt` |
| `claim-ledger-audience` | generic authority secret | `heterodyne-recovery-symmetric-secret-32-v1` | `current`, `historical-decrypt` |
| `object-dek` | generic authority secret | `heterodyne-recovery-symmetric-secret-32-v1` | `current`, `historical-decrypt` |
| `double-ratchet` | forbidden session-state omission; source/exposure metadata only | none | none |
| `radicle-access` | `protected-metadata-record`; no generic secret entry | `heterodyne.node-secret-capability.radicle-access.v1` | none |
| `oauth-signing` | generic authority secret | `heterodyne-recovery-oauth-signing-private-jwk-v1` | `current` |
| `oauth-pairwise` | generic authority secret | `heterodyne-recovery-symmetric-secret-32-v1` | `current` |
| `bearer-credential` | forbidden credential/session omission; reissue after restore | none | none |
| `ssh-client` | forbidden device/node-local omission; reissue after restore | none | none |
| `ssh-host` | forbidden node-local omission; replace after restore | none | none |
| `recovery-wrap` | generic authority secret | `heterodyne-recovery-symmetric-secret-32-v1` | `current` |
| `onion-service-identity` | forbidden node-local omission; replace after restore | none | none |
| `tls-serving` | forbidden node-local omission; replace after restore | none | none |

Protected nonsecret and forbidden classes retain their complete source,
assignment, retirement, and action records as protected metadata but never
place private capability material in a generic envelope. Authorization/device
codes, one-time keys, transient HPKE/archive keys, refresh tokens, and retired
private signing keys remain forbidden even though they are not additional
ADR-037 class values. A class whose exact category or schema cannot be
established makes production fail.

`recovery-wrap` never survives as `historical-decrypt`. Portable archive slots
remain recoverable through their archive-specific recipient wrappers; they are
not governed ciphertext under a persona `recovery-wrap` instance. Rotation
rewraps a still-current protected item under a fresh instance or retires the
item/generation and old wrapper. Therefore no retained archive file, recipient
slot, or provider-local wrapper can create a `G(C)` dependency outside the
closed `git-blob`/`large-object` locator grammar.

Every `heterodyne-recovery-*` material schema named in the table is a closed
discriminated branch of the planned
`authority-protected-secret-v1.schema.json`, not a new top-level wire profile.
The protected-nonsecret capability schemas validate their ordinary metadata
entries and cannot validate the generic envelope's decrypted `material`.

The special epoch envelope and every generic envelope share one
archive-authority-DEK nonce-uniqueness set. Every `nonce` is unpadded base64url
encoding of exactly 12 fresh random bytes. Every `ciphertext` is unpadded
base64url encoding of exactly `AES-GCM ciphertext || 16-byte tag` for the
complete JCS plaintext, with no prefix, suffix, detached tag, or bytes outside
the exact manifest entry bounds. The decoded nonce values MUST all be unique.
A producer resamples before encryption on collision. After bulk
authentication, a verifier collects the special and generic nonces and rejects
any duplicate or malformed encoding before attempting any authority-DEK
decryption. The entry descriptor length and digest cover exactly the outer JCS
envelope bytes.

Neither generic plaintext nor the authority DEK is persisted outside the
platform keys store. A `standalone` Comms full archive MUST have every special
binding, generic inventory entry, current-holder source/assignment record,
complete historical-obligation-frontier record, retired-provenance
source/assignment/retirement record, and envelope locally present and
authenticated. `network-assisted` may omit only large-object ciphertext named
in `external_objects`; it MUST NOT omit any of those authority records,
governing pointers, or locator metadata. A bootstrap-only opener sees the
envelopes as authenticated opaque bulk bytes but, without the authority DEK,
cannot decrypt, install, or exercise them. Ordinary full restore opens them
only after the complete archive-authority, checkpoint, exposure,
obligation/bijection, special-binding, inventory, and entry equality matrices
succeed.

The special epoch envelope and decrypted plaintext do not establish a second
authority view. Their `persona`, `epoch_pubkey`, and complete `kel_head` object
MUST equal the allocation and manifest values under the full-archive equality
matrix before the scalar may be staged for protected installation. A mismatch
is an archive-authority conflict and is never repaired by preferring the newest
sequence or the successfully decryptable copy.

Every ordinary recipient slot wraps the complete `archive_key_bundle`; the
bootstrap slot wraps only the bulk DEK. Thus cold-root, epoch, hardware,
passphrase, and explicitly chosen device recipients can perform a complete
full restore, while recipient-slot rewrapping for a prospective node leaves
the epoch envelope cryptographically inaccessible until separate activation.
For an archive with no epoch-authority entry, the unused authority DEK is
destroyed after slot verification.

Shared configuration is portable. Platform configuration is owned by a
platform identifier such as `android`, `ios`, `macos`, `windows`, `linux`, or
`browser` and is opaque to other platforms. Device configuration is scoped by
NID. An owner or platform allocated by the archive's pinned catalog but not
implemented locally, and an unknown non-authority configuration schema under
such an owner, is preserved but never interpreted as authority. A truly
unallocated owner/platform token rejects.

## Recipient slots

### Required recoverability commitments

A full-recovery backup must contain:

- one slot for the current cold-root public key;
- one slot for the current epoch public key; and
- preferably at least one independent hardware-token or passphrase slot.

Every `required_recipient_slots` entry is the closed object
`{slot_id,recipient_role,slot_sha256}`. `slot_id` equals its header slot;
`recipient_role` is the authenticated `cold-root`, `epoch`, or `device` role
when that wrapper defines one and is null for an ordinary wrapper without a
role member. `slot_sha256` is lowercase-hex SHA-256 of the UTF-8 JCS
serialization of the complete common slot envelope. It therefore commits byte
identity and slot type without exposing a hidden recipient key.

For `backup_class:"full"`, `required_recipient_slots` is exactly two entries,
sorted by `recipient_role` (`cold-root`, then `epoch`). Each role equals its
original required header slot. Before signing the manifest, the producer
constructs and locally cryptographically self-tests both slots, including the
authenticated inner recipient role, public key, archive ID, descriptor digest,
and complete two-DEK bundle.

For `backup_class:"clone-device"`, `required_recipient_slots` contains one or
more entries sorted by decoded `slot_id`. Every committed slot is an ordinary
non-device-local recipient: it is not `platform-device-local` or
`hpke-x25519-bootstrap`, unwraps the complete 64-byte key bundle, remains
usable after loss of the producer host, and can be opened without either the
archived `nid_seed` or `publishing_secret`. Before manifest signing the
producer cryptographically self-tests every committed clone slot through
archive-chunk authentication and then destroys the unused authority DEK. A
portable device recipient, external hardware authenticator, passphrase, cold
root, or epoch recipient may qualify when its opening material satisfies that
independence rule. `backup_class:"device-local"` is the only class for which
`required_recipient_slots` is exactly `[]`.

Rewrapping may add, replace, or remove only non-required slots. Every header
variant offered as a healthy backup MUST retain every byte-identical required
envelope: both full slots or every entry in the nonempty clone array, as
applicable. A consumer that opens any slot decrypts the manifest and then
checks the complete required array against the exact header before reporting
recovery health. A consumer using one required slot also validates all
authenticated inner role/key bindings after decryption. Clear role labels
alone never prove required-recipient targeting.

The client must warn before producing a full-recovery archive without an
independent third slot.

Within the feature composition it claims, it contains the complete current
repository/key/configuration set defined above. A Core-only full archive
contains Core keys, public repositories, Core history, and Core-owned shared,
platform, and device configuration; the Comms full-persona composition adds
every private/config repository, Comms history/configuration, and credential
state. It should include every managed large object in that same composition.
When configured size policy leaves any large object external, the manifest
uses `content_completeness:"network-assisted"`, lists every omitted stored-byte
ID, and the UI warns that identity/repository recovery is complete but content
recovery still requires an authorized recovery node or another backup. Only an
archive with no external objects is `standalone`.

### Cold-root and epoch slots

These slots generate an ephemeral secp256k1 key and use an explicitly adapted
NIP-44-v2-derived cryptographic envelope to encrypt a closed key-bundle
plaintext to the selected cold-root or epoch public key. Upstream NIP-44
requires its encrypted payload to be carried by a signed NIP-01 event and
requires that event signature to be validated before decryption. A recovery
slot is not a Nostr event, so this profile does not claim NIP-44 event or
payload conformance.

The adapted envelope reuses exactly the NIP-44 v2 secp256k1 ECDH x-coordinate,
HKDF-SHA256 `nip44-v2` conversation-key salt, per-message key derivation,
padding, ChaCha20, HMAC-SHA256 over `nonce || ciphertext`, version byte `2`,
and padded base64 encoding. It deliberately carries no NIP-01 event ID, kind,
tags, timestamp, pubkey, or Schnorr signature, conveys no Nostr authorship, and
MUST NOT be submitted to an API as a conforming NIP-44 event. The slot schema,
inner equality checks, and archive AEAD provide the recovery-specific binding.

The plaintext binds the archive ID, payload-descriptor digest, recipient role,
both 32-byte backup keys, and wrapper version. It is a JCS-canonical object
with no extension members. The ephemeral private key is destroyed after the
slot is produced. The slot carries the ephemeral public key plus the adapted
base64 envelope. The recipient key remains inside the authenticated plaintext
so the clear header does not identify the persona. Possession of the
corresponding nsec is required to recover the DEK.

Its `slot_type` is `nip44-v2-secp256k1-adapted-envelope`, and `body` has
exactly:

```json
{
  "recipient_role": "epoch",
  "ephemeral_pubkey": "<64 lowercase hex>",
  "payload": "<NIP-44-v2-derived padded-base64 envelope>"
}
```

`recipient_role` is `cold-root` or `epoch`; it reveals authority class but not
key identity. The decrypted payload is:

```json
{
  "type": "heterodyne-recovery-key-bundle-wrap-v1",
  "slot_id": "<32 lowercase hex>",
  "archive_id": "<64 lowercase hex>",
  "descriptor_sha256": "<64 lowercase hex>",
  "recipient_role": "epoch",
  "recipient_pubkey": "<64 lowercase hex>",
  "dek": "<64 lowercase hex>",
  "authority_dek": "<64 lowercase hex>"
}
```

Before decryption, the consumer validates the ephemeral point, exact version,
encoding, and resource bounds, derives the conversation key, and verifies the
derived-key HMAC in constant time. Only then may it decrypt, unpad, parse the
closed JCS object, and compare every inner value with the outer header, role,
and locally selected recipient. The HMAC authenticates the nonce and
ciphertext; the enforced version, inner equalities, committed required-slot
digest where applicable, and successful archive AEAD authentication complete
the binding. Changing the outer label, recipient, ephemeral key, descriptor,
or wrapped DEK therefore fails without relying on sender identity.

### Device slots

A device NID remains an Ed25519 signing key. It does not become an encryption
key. A portable device recipient uses a dedicated X25519 recovery key bound to
the NID through a signed, domain-separated proof and the active Core
delegation. The DEK is wrapped with RFC 9180 HPKE base mode using
DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, and AES-256-GCM. HPKE `info` and
associated data bind `heterodyne-recovery-device-slot-v1`, archive ID,
payload-descriptor digest, canonical NID, and SHA-256 fingerprint of the raw
32-byte X25519 public key. The slot carries only the HPKE encapsulated key,
ciphertext, and suite identifiers in clear; the NID binding proof is inside
the HPKE plaintext.

Its `slot_type` is `hpke-x25519-device`; `body` has exactly `kem`, `kdf`,
`aead`, `enc`, and `ciphertext`. `enc` and ciphertext use unpadded base64url.
Suite literals are
`DHKEM-X25519-HKDF-SHA256`, `HKDF-SHA256`, and `AES-256-GCM`. The NID signs:

```text
SHA256(
  UTF8("heterodyne-recovery-recipient-v1") || 0x00 ||
  JCS({slot_id, archive_id, descriptor_sha256, nid, recipient_key,
       delegation_event_id})
)
```

with Ed25519. HPKE encrypts this closed object:

```json
{
  "type": "heterodyne-recovery-key-bundle-wrap-v1",
  "slot_id": "<32 lowercase hex>",
  "archive_id": "<64 lowercase hex>",
  "descriptor_sha256": "<64 lowercase hex>",
  "recipient_role": "device",
  "nid": "<canonical Ed25519 did:key>",
  "recipient_key": "<unpadded base64url 32-byte X25519 key>",
  "recipient_fingerprint": "<64 lowercase hex>",
  "delegation_event_id": "<64 lowercase hex>",
  "binding_signature": "<unpadded base64url 64-byte Ed25519 signature>",
  "dek": "<64 lowercase hex>",
  "authority_dek": "<64 lowercase hex>"
}
```

Both HPKE `info` and AAD are the JCS object
`{type,slot_id,archive_id,descriptor_sha256,nid,recipient_fingerprint}`, where
`type` is `heterodyne-recovery-device-slot-v1`.

An enrollment rewrap cannot claim an active delegation for the prospective
NID. It therefore uses the separate allocated
`hpke-x25519-bootstrap` slot type. Its clear HPKE body and suite are identical,
and encrypts this exact closed plaintext:

```json
{
  "type": "heterodyne-recovery-bootstrap-dek-wrap-v1",
  "slot_id": "<32 lowercase hex>",
  "archive_id": "<64 lowercase hex>",
  "descriptor_sha256": "<64 lowercase hex>",
  "recipient_role": "bootstrap",
  "prospective_nid": "<canonical Ed25519 did:key>",
  "recipient_key": "<unpadded base64url 32-byte X25519 key>",
  "recipient_fingerprint": "<64 lowercase hex>",
  "grant_id": "<32 lowercase hex>",
  "grant_digest": "<64 lowercase hex>",
  "delegation_intent_digest": "<64 lowercase hex>",
  "authorizer_signature": "<unpadded base64url 64-byte Ed25519 signature>",
  "epoch_signature": "<128 lowercase hex>",
  "dek": "<64 lowercase hex>"
}
```

`recipient_fingerprint` is SHA-256 of the decoded `recipient_key`.
`recipient_key` MUST equal
`grant.client_recovery_key.public_key`, and `prospective_nid`, `grant_id`, and
the descriptor/archive values MUST equal the same grant and staged resource.
`grant_digest` is lowercase-hex SHA-256 over the JCS bytes of the complete
signed recovery-grant envelope, including its embedded authorizer-delegation
evidence. `delegation_intent_digest` is lowercase-hex SHA-256 over the JCS
bytes of the exact closed `delegation_intent` object in that grant. The two
signature strings MUST byte-for-byte equal the grant's signatures.

For both HPKE `info` and AAD, the producer uses the JCS bytes of exactly:

```json
{
  "type": "heterodyne-recovery-bootstrap-slot-v1",
  "slot_id": "<32 lowercase hex>",
  "archive_id": "<64 lowercase hex>",
  "descriptor_sha256": "<64 lowercase hex>",
  "grant_id": "<32 lowercase hex>",
  "prospective_nid": "<canonical Ed25519 did:key>",
  "recipient_fingerprint": "<64 lowercase hex>"
}
```

The recipient verifies the complete recovery grant, signatures, server,
prospective NID/key, resource, and successful in-lifetime read-completion
receipt before accepting the archive. Grant expiry stops new delivery; it
cannot revoke an archive copy already delivered to the bound X25519 private
key. After enrollment, the new node produces or obtains a normal active-device
slot and does not treat a bootstrap slot as durable authorization.

The bulk DEK reveals every non-authority archive entry: private and config
repository bundles, configuration, history, included objects, and the already
protected `keys/core` records. Bootstrap is therefore an explicit
authorization to disclose the archive's complete private-data payload to the
bound prospective node, not a narrow key-store operation. It still cannot
open the separate authority-DEK envelope or Core's independently wrapped
cold-root secret. An ordinary full-restore slot intentionally yields both
DEKs and therefore current epoch authority; a bootstrap slot yields only the
bulk DEK. The separately authorized epoch-activation procedure below is the
only network enrollment path that releases current epoch authority.

A platform may instead seal a same-device key-bundle wrapper in its native keystore.
That slot is explicitly `device-local` and may not be represented as portable.
A device-local backup may contain only this slot, but the client must warn
that device reset or loss makes the archive unusable.

The `platform-device-local` slot body contains exactly `platform`, `provider`,
`key_handle`, `context`, and `wrapped_key_bundle`. `platform` and `provider`
are allocated lowercase ASCII identifiers; the remaining members are
unpadded base64url byte strings. `wrapped_key_bundle` authenticates and
decrypts to exactly 64 bytes. `context` is the JCS bytes of
`{slot_id,archive_id,descriptor_sha256,platform,provider,key_handle}`. The
platform adapter must authenticate that context. If its native primitive has
no authenticated metadata, it derives an archive-specific KEK and uses
AES-KW so context substitution fails; wrapping the 64-byte bundle produces
exactly 72 bytes.

### Hardware authenticator slots

The common browser/native hardware profile uses WebAuthn Level 3 `prf`,
implemented through CTAP `hmac-secret` where applicable. It:

- requires user verification;
- stores credential ID, RP ID, random PRF input, algorithm identifiers, and
  wrapped key bundle in the slot;
- derives a domain-separated KEK from the 32-byte PRF output; and
- never stores repository data on the authenticator.

The base profile derives the 32-byte KEK with HKDF-SHA256:

```text
IKM  = WebAuthn PRF first output
salt = random 32-byte slot salt
info = UTF8("heterodyne-recovery-webauthn-prf-kek-v1|"
            + slot_id + "|" + archive_id + "|" + descriptor_sha256 + "|"
            + rp_id + "|" + sha256(credential_id) + "|"
            + backup_eligible + "|" + backup_state)
L    = 32
```

It wraps the 64-byte `archive_key_bundle` with AES Key Wrap from RFC 3394. The slot records the
salt and all non-secret inputs needed to reproduce the KEK. The PRF input is a
fresh random 32-byte value supplied as `prf.eval.first`; an implementation
uses the WebAuthn/CTAP transcript as specified and does not add a second,
implementation-specific prehash.

Its `slot_type` is `webauthn-prf-a256kw`. The closed body contains exactly
`rp_id`, `credential_id`, `backup_eligible`, `backup_state`, `prf_input`,
`kdf`, `kdf_salt`, `wrap`, and `wrapped_key_bundle`. Credential IDs are unpadded
base64url of 1 through 1024 bytes; PRF input and salt encode exactly 32 bytes;
the wrapped key bundle encodes exactly 72 bytes. Algorithm literals are
`HKDF-SHA256` and `A256KW`. The HKDF `info` above also includes `slot_id`, and
the credential-ID digest is lowercase-hex SHA-256 of its decoded bytes.
Booleans in that transcript are the lowercase ASCII literals `true` and
`false`.

Each authenticator receives an independent slot for the same key bundle. Clients
should enroll at least two authenticators. A single-device credential is
recommended for a physical recovery key; backup eligibility/state is recorded
so the client can distinguish a hardware-bound credential from a synced
multi-device credential.

WebAuthn credentials are RP-ID scoped. The reference browser recovery flow
uses the Heterodyne reference RP; independently hosted browser origins need
their own slot or an explicitly permitted related-origin relationship. Native
clients may perform the same user-verified PRF transcript through CTAP.

PIV/PKCS#11 and OpenPGP-card recipients are optional native extensions. They
wrap only the backup-key bundle and do not define the base browser profile.
Revision 4 allocates no slot type for them; an interoperable extension requires
a later schema-bearing slot allocation before such a slot may appear in a
conforming archive.

### Passphrase slot

The portable passphrase profile derives a 32-byte KEK with Argon2id version
`0x13`. The revision-4 baseline is RFC 9106's memory-constrained profile:
64 MiB memory, three iterations, parallelism four, a fresh 16-byte salt, and a
32-byte output. That output is IKM to HKDF-SHA256 with an empty salt and
`info` equal to the UTF-8 domain
`heterodyne-recovery-passphrase-kek-v1|<slot_id>|<archive_id>|<descriptor_sha256>|<version>|<memory_kib>|<iterations>|<parallelism>|<salt_base64url>`;
the 32-byte result is the AES-KW KEK. Producers may use stronger recorded
Argon2id parameters, but consumers must apply a configured ceiling before
evaluating them; the default pre-authorization ceiling is 1 GiB memory, ten
iterations, and parallelism 16. AES-KW from RFC 3394 wraps only the random
64-byte backup-key bundle. A passphrase slot is never described as
hardware-backed.

Its `slot_type` is `argon2id-a256kw`. The closed body contains exactly
`version`, `memory_kib`, `iterations`, `parallelism`, `salt`,
`passphrase_encoding`, `context_kdf`, `wrap`, and `wrapped_key_bundle`. `version` is
19, `passphrase_encoding` is `utf8-nfc`, `context_kdf` is `HKDF-SHA256`,
`wrap` is `A256KW`, the salt is unpadded base64url of exactly 16 bytes, and the
wrapped key bundle is unpadded base64url of exactly 72 bytes. The user string is
normalized to Unicode NFC once and then encoded as UTF-8; no trimming, case
folding, or terminating zero is added.

## Device cloning

Ordinary backups exclude device NID secrets, active Double Ratchet state,
temporary OIDC tokens, workload tokens, sender proofs, and ephemeral message
keys.

An explicit `clone-device` export may include exactly one
`keys/device/<nid-id>/clone-secret` entry whose mapped NID equals
`producer_nid`. Its closed JCS value contains exactly:

```text
type, device_nid, delegation_event_id, nid_seed,
publishing_secret, created_at
```

`type` is `heterodyne.recovery-device-clone-secret.v1`; `nid_seed` is
unpadded base64url of the exact 32-byte Ed25519 seed and MUST derive
`device_nid`. `publishing_secret` is null or the closed object
`{algorithm:"secp256k1",secret_key,public_key}`; both keys are 32 bytes encoded
as 64 lowercase hex, the scalar is valid and derives the public key, and the
named canonical delegation MUST bind that publishing key to `device_nid`.
Null means the restored clone can authenticate as the NID where Ed25519 is
accepted but cannot publish through that delegated key. The entry uses
`role:"device-clone-secret"`, `owner:"core"`,
`restore_policy:"authoritative"`, media/compression/repository null, and the
schema `core.recovery-device-clone-secret.v1`. No other entry may contain
either secret.

Clone export requires at least one non-device-local recipient slot capable of
opening the archive without either cloned secret, commits and self-tests it
through the manifest rule above, and presents an irreversible warning that the
protocol cannot distinguish physical copies or prove source erasure.
Restoring the same seed deliberately creates two physical installations of
one logical NID; the existing delegation remains active and both copies can
sign as that NID. Revoking that delegation or NID invalidates both copies, so
the protocol does not falsely require “retire the source while keeping the
clone active.”

Exact cloning creates no new ADR-037 logical holder, source companion, or
assignment: both physical installations deliberately remain the same
protocol-indistinguishable NID, and the existing assignment is unchanged. The
signed clone generation, manifest/finality lineage, explicit confirmation, and
mandatory warning are the available audit evidence; the protocol cannot
observe the physical-copy event as a new holder. A separately accountable
holder uses the fresh-NID enrollment path.

The recommended migration is instead to restore data without clone secrets,
create a fresh destination NID and publishing key, delegate them canonically,
move desired sessions/capabilities, and then revoke the old NID. A user who
chooses exact cloning accepts the concurrent-use risk and SHOULD take the
source offline before enabling the destination. Active ratchet state is never
cloned in either path. Historic encrypted messages may be copied, but every
destination establishes fresh Double Ratchet sessions and never resumes the
source's sending chain. Temporary OIDC/workload tokens, sender proofs, and
ephemeral message keys remain forbidden.

## Backup production and restoration

### Production

A producer:

1. verifies the complete applicable state-rollover linkage closure, then
   allocates and, when online, commits the next archive-generation record;
2. freezes a consistent post-allocation view of the keys store and every
   included repository, including that record;
3. records KEL, repository, credential-ledger, the complete
   repository-retention inventory frontier and ancestor records, every
   `EffectiveRefs(C)` ref/scan snapshot and signed-ref proof, every accepted
   config-deregistration transition/CAS proof, complete governed
   retention-snapshot/binding state, complete maximal
   historical-decrypt-obligation frontier, durable-secret-inventory, and
   status-list high-water marks;
4. generates the fresh DEKs and required recipient slots, self-tests them, and
   commits their exact digests into `required_recipient_slots`;
5. writes and signs the inner manifest with the current epoch key for a full
   backup or the active NID for either device-class backup;
6. generates the entry stream and verifies every declared digest;
7. encrypts under the fresh DEK and adds any non-required recipient slots;
8. verifies the completed archive, every required-slot commitment, and every
   locally exercisable required slot;
9. signs and durably commits the matching finalization record when online;
   and
10. updates the visible backup-freshness indicator only after the artifact
    and any required canonical finality record are durable.

### Offline restore

A restorer treats the archive and removable medium as hostile. It:

1. checks framing, lengths, algorithms, resource ceilings, and recipient slot
   syntax before expensive work;
2. unwraps the backup-key bundle, or the bulk DEK for a bootstrap slot,
   through one authorized slot;
3. authenticates every chunk and the complete ciphertext digest;
4. validates manifest authority and exact entry digests;
5. stages entries outside the live stores;
6. replays KEL, the complete applicable recovery-state rollover linkage
   closure, repository authority, and high-water marks;
7. compares against newer network state when available;
8. creates a fresh device NID and platform wrapper before making any protected
   full-archive material durable, or installs the exact clone seed only for an
   explicitly confirmed `clone-device` restore under the cloning rules above;
9. atomically installs only online-current validated state, or enters the
   crash-consistent prepare/publication sequence for complete protected
   material plus provisional exposure records in the isolated
   offline-candidate namespace defined below; and
10. performs normal delegation, revocation, and synchronization before
    publishing.

An offline client cannot know that a newer archive or network state exists. It
must display the archive generation and creation time and remain in a
restore-pending state until rollback checks complete.
Even with an otherwise complete archive, a KEL that reaches an epoch rotation
without the unique valid latest rollover, every member of its applicable
normal-or-gap linkage closure, and all referenced head bytes remains
`restore-pending`; signer-time validation is not a fallback.

For a full archive, rollback logic uses one **archive authority binding**:
the exact `(persona, epoch_pubkey, kel_head)` triple established by equality
among the allocation, manifest authority, `manifest.high_water.kel`, authority
envelope, decrypted epoch-secret object, and, when present, finalization. A
verifier MUST establish equality among every available source before comparing
any sequence. It MUST NOT select a different one of those sources because it
is newer, locally trusted, or successfully decrypted.

A network-enrollment client that opens a `full` archive only through an
authenticated bootstrap slot receives the bulk DEK but deliberately lacks the
authority DEK. It therefore cannot authenticate the authority-envelope
ciphertext or compare the decrypted epoch-secret object, and it MUST NOT claim
ordinary full-archive authority validation. Instead it enters the closed
non-authoritative `bootstrap-validated` state only after all of these checks
succeed:

- the bootstrap grant, slot binding, complete-transfer receipt, framing,
  immutable header commitments, ciphertext digest, and every bulk-encrypted
  chunk and entry authenticate;
- the signed manifest, allocation, finalization or accepted artifact
  resolution, canonical KEL, complete applicable state-rollover linkage
  or gap-repair closure and all referenced frontiers, repository heads, and
  available high-water marks pass their ordinary checks;
- allocation, manifest authority, `manifest.high_water.kel`, finalization,
  and the clear authenticated fields of the authority envelope all equal one
  exact `(persona,epoch_pubkey,kel_head)` tuple; and
- every equality in the full matrix that does not require the unavailable
  authority DEK or decrypted epoch-secret bytes succeeds.

All `core-protected-record` and `protected-metadata-record` entries required by
those checks, including the complete repository-inventory frontier and
ancestors, every `EffectiveRefs(C)` repository/ref scan snapshot and signed-ref
proof, every accepted config-deregistration transition/CAS proof, the complete
historical-obligation frontier, exact governed
retention-snapshot heads, complete governed-decrypt binding frontier, exact
governed ciphertext locators, and current-holder/retired-provenance record
bytes, are bulk-visible and independently validated. The generic and epoch
`authority-protected-secret` outer envelopes, commitments, inventory, lineage
arrays, and ciphertext digests are likewise bulk-visible, but their hidden
material is not. An implementation cannot move required policy/finality
metadata into opaque secret ciphertext and call the unavailable check deferred.

The only deferred checks are authentication/decryption of every
`authority-protected-secret` envelope and schema/commitment/equality validation
of its hidden material, including the epoch-secret object. A mismatch in any
available source rejects; absence of the authority DEK is not treated as a
match. This deferral is noninterpretation: a bootstrap-only opener MUST NOT
classify hidden material as absent, present, matching, schema-valid, invalid,
installed, current, or authority-bearing. An outer-valid envelope whose hidden
material would fail an ordinary authority-opening restore therefore remains
opaque under bootstrap; bootstrap neither accepts nor rejects that hidden
claim. `bootstrap-validated` permits only isolated staging of authenticated
bulk bytes. It does not install or expose repositories/configuration to live
read paths, install or exercise any archived secret, or itself publish, mint,
issue, delegate, revoke, activate another node, or claim full-recovery
authority. Fresh-device delegation, roster admission, and checkpoint
transitions are separately authorized operations against current canonical
state, never authority inferred from staged archive content.

A later authority-activation transfer never upgrades or mutates the
`bootstrap-validated` verdict. It may provide the exact current scalar needed
to open the archive's already committed required epoch slot, but successful
HPKE delivery alone installs no scalar or durable secret. The client starts a
new ordinary restore from the immutable archive bytes, opens that required
slot to obtain both DEKs, and evaluates the complete full matrix independently.
Only that new ordinary restore can stage protected installation. A stale or
pretransition archive is refused for activation; a future separately
authorized ordinary two-DEK rewrap/transfer may make such an archive
inspectable or recoverable under its own rollback result, but cannot turn the
old bootstrap verdict into authority or evade the post-addition checkpoint
rules below.

The rollback comparison is deterministic:

- a trusted local or network finalized-generation high-water mark greater than
  the archive generation quarantines it as stale; pending or abandoned
  allocations do not participate; the archive may be inspected but does not
  replace live authority;
- an equal archive generation requires the same allocation record and, when a
  trusted finalization exists, exact manifest/descriptor/ciphertext
  commitments; any other equal-generation artifact is quarantined as a
  conflict;
- for `full`, a known KEL sequence greater than the archive authority
  binding's `kel_head.seq` requires that exact
  `kel_head.event_id` to be an ancestor of the known accepted state and that
  replay at the archive head yield the binding's exact `persona` and
  `epoch_pubkey`; an equal sequence requires the identical event ID and exact
  persona/epoch key. Either a lower known sequence or a different event ID at
  equal sequence leaves rollback unresolved rather than authorizing a write;
  a device-class archive applies the same greater/equal event-ID rule to its
  one allocation/manifest/delegation KEL head;
- a known repository head must equal or descend from the manifest head;
  divergence is a repository conflict, never an overwrite;
- a greater credential-ledger generation rejects credential authority from
  the archive, and equal generations require the recorded checkpoint to be on
  the accepted checkpoint chain with byte-identical exposure,
  governed-decrypt-key-binding, historical-decrypt-obligation, and
  durable-secret-inventory digests; and
- status-list generations and digests obey the same greater/equal rule.

When no trusted comparison state exists, successful cryptographic restore
remains `restore-pending`; the client may use local read-only recovery
functions but does not publish, mint, delegate, or revoke until it either
obtains current state or the user performs the cold-root-authorized offline
recovery procedure.

Before an offline `backup_class:"full"` restore unwraps, releases, or exercises
any authority DEK, archive epoch secret, generic secret, NIP-49 cold-root
scalar, or other
persona-authority plaintext, it creates a fresh `new_device_nid` and a random
`activation_id` of exactly 16 bytes encoded as 32 lowercase hexadecimal
characters. It first obtains only the bulk DEK, authenticates the bulk stream,
and validates all bulk-visible inventory, bindings, envelopes, and provenance.
An ordinary combined-bundle slot is eligible for this step only through a
cryptographically compartmentalized opener that returns the bulk DEK while
keeping the authority DEK as a non-exportable, non-decrypting pending handle.
An implementation that cannot prove that separation may use a true bulk-only
slot for inspection but MUST NOT perform offline authority activation through
the combined slot.

Offline authority activation also requires a cold-root signing capability
available independently of the archive authority material about to be opened,
for example a hardware/USB cold-root signer. A cold-root scalar first recovered
from this same archive cannot authorize its own pre-unseal evidence. Without
that independent signer the archive remains read-only or
`bootstrap-validated`/`restore-pending` until an online recovery device
authorizes it; decryptability under an epoch, passphrase, or local wrapper does
not waive this boundary.

From only the authenticated bulk-visible special bindings, durable-secret
inventory, protected capability/source metadata, and immutable archive basis,
the restorer constructs one closed
`heterodyne.offline-recovery-pre-unseal-intent.v1` record containing exactly:

```text
type, persona, activation_id, archive_id, generation_record_digest,
manifest_digest, archive_kel_head, new_device_nid, archive_restore_basis,
exposure_preimages, exposure_preimage_set_sha256, created_at,
acknowledged_stale_state_risk, cold_root_signature
```

The archive, KEL, NID, basis, timestamp, and acknowledgement members use the
activation encodings below and are fixed before authority unseal. The complete
`exposure_preimages` array contains one row for every archive-derived or
preexisting persona-authority capability that the pending authority handle
could release. It uses the same class-complete inclusion and fresh-local-key
exclusion rules as the final activation.

`created_at` is a JSON-safe Unix second selected and confirmed by the
independent cold-root signer no later than that signer's current time. At first
observation it may be at most 300 seconds ahead of the verifier's clock; a
future-dated intent cannot open the authority handle. A signer without a
trusted clock uses zero or another conservatively earlier user-confirmed value,
never a host-proposed future time. This timestamp becomes the upper bound for
the later compromise cutoff, so clock uncertainty can only invalidate more
historical authority, not preserve an exposure interval.

Each strictly sorted unique closed row contains exactly:

```text
preimage_id, source_preimage, source_preimage_sha256,
assignment_preimage, assignment_preimage_sha256
```

`source_preimage` is the exact closed
`heterodyne.node-secret-source.v1` object with only `epoch_signature` omitted.
`assignment_preimage` is the exact closed
`heterodyne.node-secret-exposure.v1` `action:"assign"` object with only
`source_record_digest` and `signature` omitted. All IDs, tuple members,
artifact references, issuance times, archived epoch authority, holder NID, and
`transition_id == activation_id` are already final. The two preimage digests
are:

```text
lowercase_hex(SHA256(
  UTF8("heterodyne-offline-recovery-source-preimage-v1") || 0x00 ||
  UTF8(JCS(source_preimage))
))

lowercase_hex(SHA256(
  UTF8("heterodyne-offline-recovery-assignment-preimage-v1") || 0x00 ||
  UTF8(JCS(assignment_preimage))
))
```

`preimage_id` is lowercase-hex SHA-256 of
`UTF8("heterodyne-offline-recovery-exposure-preimage-id-v1")`, a zero byte,
and UTF-8 JCS of
`{source_preimage_sha256,assignment_preimage_sha256}`. Rows sort by decoded
`preimage_id`; duplicate IDs, duplicate source or assignment IDs, duplicate
capability coverage, a tuple/link mismatch, or any field left caller-variable
rejects. The set digest is:

```text
lowercase_hex(SHA256(
  UTF8("heterodyne-offline-recovery-pre-unseal-exposure-set-v1") || 0x00 ||
  UTF8(JCS(exposure_preimages))
))
```

The independent cold root signs SHA-256 of
`UTF8("heterodyne-offline-recovery-pre-unseal-intent-v1")`, a zero byte, and
the UTF-8 JCS record with `cold_root_signature` omitted. The signature is 128
lowercase hexadecimal characters. The complete-record digest is lowercase-hex
SHA-256 of the signed JCS bytes, and Core stores the record create-only at:

```text
keys/core/recovery/offline-pre-unseal-intents/
  <activation-id>/<intent-digest>.json
```

Exact duplicate bytes are idempotent. A nonidentical otherwise-valid intent
for one `(persona,activation_id)` is a collision: every variant remains
conservative evidence, no authority handle may be opened by selecting one, and
the collision uses the same cold-root emergency-reset reason and all-variant
evidence rule as an activation collision.

The signed intent and exact immutable archive bytes become durable before the
pending authority handle is permitted to unwrap, release, or decrypt anything.
Durability of the signed intent is the irreversible exposure boundary even if
the operator cancels, the authority AEAD later fails, the hidden material does
not match its outer commitment, or no final activation is produced. Before
that boundary only clear framing, authenticated ciphertext, bulk plaintext,
and non-authority scratch state may be discarded. A merely unsigned local
journal, a process-memory promise, or release followed by later persistence is
nonconforming.

After the intent is durable, the compartment may exercise but never export the
authority DEK. It authenticates and decrypts each hidden object internally,
then validates its closed schema, every repeated outer identity/binding,
commitment derivation, and exact intent template before releasing that exact
validated material or a narrowly bound signing operation. An AEAD, schema,
identity, commitment, or template mismatch releases no plaintext or signing
capability and zeroizes the attempted result; the already durable intent
remains conservative evidence. An implementation unable to enforce this
validated-release boundary cannot perform offline authority activation.

Only after that validation does the archived epoch sign each exact
`source_preimage`, producing the sole added `epoch_signature`; the resulting
complete source digest fills the corresponding assignment's sole
`source_record_digest`, and the epoch signs that exact assignment. Every other
byte MUST equal the intent template. The restorer then constructs one closed
`heterodyne.offline-recovery-activation.v1` record containing exactly:

```text
type, persona, activation_id, archive_id, generation_record_digest,
manifest_digest, archive_kel_head, new_device_nid, archive_restore_basis,
pre_unseal_intent_digest, provisional_exposure_records,
provisional_exposure_set_sha256, created_at, acknowledged_stale_state_risk,
cold_root_signature
```

`manifest_digest` is lowercase-hex SHA-256 over the exact JCS manifest
including its signature; `archive_kel_head` equals the manifest high-water
KEL; and `acknowledged_stale_state_risk` is exactly `true`.
`pre_unseal_intent_digest` equals the complete signed intent digest. The final
activation's `persona`, `activation_id`, `archive_id`,
`generation_record_digest`, `manifest_digest`, `archive_kel_head`,
`new_device_nid`, `archive_restore_basis`, `created_at`, and
`acknowledged_stale_state_risk` are byte-identical to the signed intent.
The final activation has a complete bijection with that intent's preimage
rows: only the two source/assignment signature fields and the assignment
`source_record_digest` are additions, and every added value verifies as
specified above. A missing/extra completion, altered preimage byte, source-link
substitution, shared-top-level mismatch, or activation without its exact intent
rejects.
`archive_restore_basis` is a closed offline object containing exactly:

```text
archive_id, archive_generation, generation_record_digest, manifest_digest,
finalization_record_digest, artifact_resolution_digest, archive_authority,
opened_recipient_slot, credential_checkpoint_digest,
governed_decrypt_key_bindings_sha256,
historical_decrypt_obligations_sha256, secret_inventory_sha256,
special_authority_bindings_sha256
```

`artifact_resolution_digest` is null or the exact accepted finalized artifact
resolution. `archive_authority` is the exact closed
`{persona,epoch_pubkey,kel_head}` triple. `opened_recipient_slot` is the exact
`{slot_id,slot_sha256}` pair for the ordinary header slot actually opened; it
need not be one of the two required slots, but the restore separately verifies
both required commitments. Every other digest equals the selected allocation,
signed manifest, finalization/resolution, credential high-water, complete
governed-head/binding state `K(C)`, complete historical-obligation frontier,
durable inventory, and special bindings already validated by the ordinary
restore. The repeated
top-level archive fields equal the basis byte for byte. This schema-scoped
offline basis is not the
transfer-grant `archive_restore_basis`; neither closed shape may be parsed as
the other.

Before the activation record is signed, the full-archive candidate creates the complete
ADR-037 source-companion and assign-record set for every archive-derived or
preexisting persona-authority capability that the restore exposes to the new
node. A capability is in this set only when its exact secret/private material
or exercisable persona-authority capability is obtained from an authenticated
archive entry/recipient opening, or when preexisting persona authority is
actually staged or made exercisable by this restore. Its tuple must equal the
exact generic inventory row, special-authority binding, protected capability
record that proves that origin.

The set includes the archived epoch secret and every archive-derived generic
current or historical-decrypt secret. It includes `cold-root` when the restore
can unwrap or otherwise exposes that scalar; if it exposes only the opaque
NIP-49 record, the set instead includes the applicable `core-protected` or
`recovery-wrap` capability under the total class mapping. The set excludes
every `device-signing` clone secret: that material is legal only in a
`clone-device` archive, whose unused authority DEK is destroyed and which
cannot create this pre-unseal intent or activation. Exact cloning follows the
same-NID, no-new-logical-assignment rule above.

The set excludes a freshly generated prospective NID seed, device/publishing
key, SSH authentication key, X25519 recovery recipient key, or
platform-wrapper key when that material was not in the archive and is not
persona authority exposed by the restore. Those fresh local/enrollment
capabilities receive ordinary holder-generated source and assignment records
only after their separate delegation or enrollment is authorized. Merely
creating or using them to stage the recovery does not trigger rotation or
revocation of fresh material.

Each provisional source names `new_device_nid` as holder, repeats the exact
secret identity and instance commitment from its applicable authenticated
generic inventory, special binding, or protected-capability origin above, and
uses the ordinary ADR-037 source shape, which has no
`transition_id`. Its
`artifact_refs` name only independently materialized allocation, manifest,
finalization-or-resolution, checkpoint, active-obligation, pointer, or
governed-decrypt-key-binding records. They cannot embed or refer to the
activation or the enclosing `archive_restore_basis`. Each corresponding assignment names the
exact source digest and holder/tuple and sets its non-null `transition_id` to
the prechosen `activation_id`. Neither record may reference the activation
record or its digest: source/assign bytes are created first, then the
activation commits them, so the graph is acyclic. The activation signature,
not a backwards artifact reference, binds those full records to the complete
archive basis.

`provisional_exposure_records` is the complete strictly sorted unique array of
closed rows containing exactly `record_type`, `record_digest`, and `record`.
`record` is the complete closed source or assignment JCS object and its
lowercase-hex SHA-256 equals `record_digest`. `record_type` is
`secret-source` or `secret-assignment`, in that order, followed by decoded
complete-record digest bytes. `secret-source` requires the embedded record's
exact `type` to be `heterodyne.node-secret-source.v1`; `secret-assignment`
requires `heterodyne.node-secret-exposure.v1` with `action:"assign"`.
Every assignment's exact source is embedded,
and the set contains exactly one source/assign holder pair for every
archive-derived or preexisting persona-authority capability exposed by the
restore unless the ordinary ADR-037 schema requires additional distinct
per-capability records. No freshly generated excluded key may appear. The
digest is exactly:

```text
lowercase_hex(SHA256(
  UTF8("heterodyne-offline-recovery-provisional-exposure-set-v1") || 0x00 ||
  UTF8(JCS(provisional_exposure_records))
))
```

The complete embedded bytes remain mandatory even when an implementation also
indexes them by digest; a digest-only record whose bytes are unavailable keeps
the activation pending and installs nothing.

The cold root signs:

```text
SHA256(
  UTF8("heterodyne-offline-recovery-activation-v1") || 0x00 ||
  JCS(record with cold_root_signature omitted)
)
```

with BIP-340, encoded as 128 lowercase hex. The record is retained under
`keys/core/recovery/offline-activations/<activation-id>/<record-digest>.json`,
where the digest is lowercase-hex SHA-256 of its complete JCS bytes.
Exact duplicate activation bytes are idempotent. Two nonidentical otherwise
valid activation records for the same `(persona,activation_id)` quarantine
every then-unreconciled claimant and its candidate namespace; neither may be
selected by arrival order. Recovery requires a cold-root emergency reset whose
provisional union includes every colliding unreconciled activation array and
retires all of their assignments. An already-reconciled same-ID variant is
proven through accepted audit history and is neither re-added to
`ProvisionalItems` nor re-retired; observing the late collision still forces
emergency reset, and collision never permits an unreconciled branch to be
ignored.

All provisional source/assignment bytes and every restored protected secret
are written beneath:

```text
credential-sync/offline-recovery-candidates/<activation-id>/
```

Within it, source bytes use
`secret-sources/<secret-id>/<record-digest>.json`, assignment bytes use
`secret-exposures/<assignment-id>/<record-digest>.json`, protected archive
entries preserve their manifest path beneath `protected/`, and
`activation.json` is the byte-identical signed activation visibility marker.
No other path can satisfy the candidate inventory.

Cross-store atomicity is not assumed. Before the signed pre-unseal intent is
durable, an implementation may construct, verify, and discard only bulk-visible
or non-authority scratch state. Durability of that signed intent and its exact
immutable archive basis is the first irreversible authority-exposure boundary;
after it, neither cancellation nor failure to produce a completed activation
permits the intent to disappear.

When completed source/assignment and protected candidate bytes exist, the
protected crash journal enters a second monotonic
`secret-bearing-prepare` state before any such byte becomes durable. That state
retains the exact already-durable intent, exact signed activation, every
embedded source/assignment byte, activation-record digest,
`provisional_exposure_set_sha256`, and complete sorted protected inventory.
The implementation then stages the protected candidate bytes inertly beneath
the candidate path and verifies all restored-material bindings. This second
phase cannot replace, weaken, or reset the earlier intent boundary.

Once the intent is durable, crash recovery MUST always preserve it as observed
unreconciled evidence until accepted reconciliation. Once either the completed
prepare state or any protected secret/candidate byte is durable, recovery MUST
additionally finish publication of the signed Core activation record and
byte-identical `activation.json` marker or retain the exact signed activation
and embedded record bytes as an observed unreconciled activation. It MUST NOT
discard, erase, reuse, or forget either evidence layer because the namespace
is incomplete, authority decryption failed, publication failed, a secret was
later erased, or the process crashed. An implementation that can release
authority before durable intent, or durably write a completed protected
candidate without first making its exact signed activation recoverable, is
nonconforming.

A candidate is visible only when both publication markers and every staged
byte are present and exact. An activation/marker with an incomplete namespace
is invalid for installation and exposes no authority, but its prepared signed
activation remains in `ObservedActivations` and holds authority until complete
reconciliation. This is one logical crash-consistent publication of the
source/assignment bytes and protected candidate material, without claiming an
impossible atomic commit across Core and Comms stores. No protected secret is
installed in a live authority namespace. A missing record, set-digest
mismatch, holder/commitment mismatch, install without its records, or
source/assignment write after activation rejects and quarantines the entire
candidate without deleting its evidence.

The commit moves the client only to `offline-recovered`. It may authenticate
and inspect its isolated archive, inspect/edit local working copies, and
prepare unsigned drafts. It MUST NOT exercise restored Core or Comms
authority, expose the candidate namespaces through normal live reads,
issue or finalize an authority-signed recovery backup, publish, mint, sign as
the persona or an agent, delegate, revoke, approve, receipt, rotate, or serve
another recovery node. Cold-root possession and a local device delegation are
not freshness proofs.

Let `ObservedPreUnsealIntents` contain every individually valid, independently
cold-root-signed pre-unseal intent variant durably observed for the persona,
including every intent whose authority opening was cancelled, failed
authentication, revealed mismatched hidden material, crashed, or never
produced an activation. The exact signed intent and immutable archive bytes
must remain available. For one intent `I`, `ReconciledIntent(I)` is true if and
only if all of these facts are reachable on the accepted chain:

1. one accepted, fully receipted transition
   `inventory_basis.offline_recovery_pre_unseal_intents` contains `I`'s exact
   `{activation_id,intent_record_digest,
   exposure_preimage_set_sha256}` row;
2. every preimage row in `I` appears as the exact
   `{intent_record_digest,preimage_id}` origin in the matching transition
   exposure and action; every real assignment completion for `I` observed in
   that transition basis is independently inventoried and retired; and the
   class-complete rotation, replacement, termination, revocation, retained-
   ciphertext/obligation update, or persona migration has accepted; and
3. the result checkpoint and normal-or-gap rollover have accepted. If
   `I.new_device_nid` enters the target roster, a byte-exact valid activation
   linked to `I` must also be inventoried and reconciled and every required
   delivery checkpoint and recovery-role record must accept. Without that
   linked completion, the NID is target-excluded, receives no successor,
   delivery, or role, and the intent is terminalized by cleanup alone.

Define:

```text
UnreconciledPreUnsealIntents =
  ObservedPreUnsealIntents - { I | ReconciledIntent(I) }
```

The next recovery transition inventories the exact strictly sorted unique row
projection of that set in
`offline_recovery_pre_unseal_intents`, ordered by decoded activation ID then
intent digest. Every row and every template byte is reachable in its closure
basis. A missing intent, unavailable template, extra locally invented row, or
digest-only substitute rejects. An already reconciled intent remains accepted
audit history but is not reintroduced. A later valid activation completing
that intent is a new member of `UnreconciledActivations` and must be
reconciled; it does not resurrect or undo the already terminalized intent
items.

For transition closure basis `B`, let `IntentVariants_B(x)` contain every
distinct valid intent with activation ID `x` whose exact bytes are preserved
in `B`, and define:

```text
ActiveIntentCollisionIds_B =
  { x |
      cardinality(IntentVariants_B(x)) >= 2 and
      exists I in IntentVariants_B(x)
        such that I is in UnreconciledPreUnsealIntents
  }
```

`offline_recovery_pre_unseal_intent_collisions` is the complete strictly
sorted projection into closed
`{activation_id,intent_record_digests}` rows, with each digest array sorted by
decoded bytes, unique, and containing every valid variant for that ID.
Every unreconciled digest also has its complete intent-inventory row; a digest
omitted from that inventory must independently satisfy
`ReconciledIntent(I)` and supplies collision evidence only. Exact duplicate
bytes do not collide. One intent and its linked activation sharing an ID are
the expected two phases, not a collision. Nonidentical intent variants, or
nonidentical fully signed activation variants completing one intent, are never
collapsed by template equivalence or arrival order.

Either a nonempty intent-collision projection or the ADR-037 activation-
collision projection forces the same cold-root
`credential_ledger_reset_offline_activation_id_collision` emergency-reset
path. A collision-only reset may preserve every healthy roster member, but it
still creates a fresh generation-zero epoch, config audience, and OAuth
pairwise state. Its `compromise_since` is no later than detection and no later
than the earliest `created_at` among the relevant linked intents for any
unreconciled intent or activation in the collision evidence that plans or
records exposure of the predecessor-current epoch tuple, including an intent
already reconciled before a late activation. Thus a late collision cannot
preserve forged signatures from the interval between an earlier irreversible
intent and detection.

Let `ObservedActivations` contain every individually valid signed activation
variant observed for the persona, including every quarantined collision
variant and every activation retained at the irreversible prepare boundary
even when its candidate namespace or publication markers are incomplete. For
one exact activation `A`, `Reconciled(A)` is true if and only if all of these
facts are reachable on the accepted chain:

1. one accepted, fully receipted transition
   `inventory_basis.offline_recovery_activations` contains `A`'s exact
   `{activation_id,activation_record_digest,
   provisional_exposure_set_sha256}` row;
2. that transition's complete actions and absorbing retirements cover every
   assignment embedded by `A`, every overlapping ordinary/staged assignment,
   every mandatory class rotation, and every required retained-ciphertext
   re-encryption, governed-head/key-binding update, obligation retain/close
   update, and decrypt-only historical replacement assignment; and
3. the transition's result checkpoint and recovery-state rollover have
   accepted. If `A.new_device_nid` is target-included, every required
   post-addition delivery checkpoint and recovery-role reconciliation for it
   has also accepted. If target-excluded, the transition has terminally
   retired all provisional and overlapping assignments and no bootstrap,
   successor assignment, delivery, or role grants authority to that NID.

Define:

```text
UnreconciledActivations =
  ObservedActivations - { A | Reconciled(A) }
```

Only `UnreconciledActivations` appears in a later
`offline_recovery_activations` inventory and contributes to
`ProvisionalItems`. A reconciled activation, its embedded records, and its
absorbing retirements remain byte-identical audit history in the ordinary
authenticated head union, but its retired assignments are not reintroduced
as provisional items. Reobserving exact duplicate bytes preserves the same
reconciled digest. A late nonidentical activation sharing the ID, or any new
activation digest, is unreconciled and immediately holds authority until a
new complete reconciliation.

First synchronization cannot activate the candidate through delegation alone.
The next addition/reset `inventory_basis` contains the complete intent array
and collision projection above plus a complete strictly sorted unique
`offline_recovery_activations` array of closed
`{activation_id,activation_record_digest,provisional_exposure_set_sha256}`
items for the exact row projection of `UnreconciledActivations`, sorted by
decoded activation ID then activation-record digest. Every exact activation
byte and embedded provisional record is available. The basis also contains the
complete ADR-037 activation-collision projection. A missing unreconciled
intent or activation, omitted prepared evidence set, omitted collision
variant, or digest-only unavailable record rejects. An incomplete protected
candidate remains unusable but does not permit either signed evidence layer to
be omitted. Any active intent or activation collision rejects ordinary
addition; an emergency-reset basis is valid only when it includes every
colliding variant and uses the complete unreconciled union for cleanup without
selecting a candidate.

Before the transition can make `ReconciledIntent(I)` or `Reconciled(A)` true,
it copies every exact prepared intent, activation, template, and embedded
record byte into the ordinary authenticated audit namespace. Thus crash
completion can reconcile signed intent evidence even when authority decryption
or protected candidate material never finished, without turning absent secret
bytes into authority or permitting evidence to disappear.

Let `BaseItems` be the canonical conservative assignment items replayed from
the ordinary authenticated head union named by the predecessor
`inventory_basis`. Let `ProvisionalItems` be the deduplicated union of the
normalized source/assignment pairs embedded by every member of
`offline_recovery_activations`. Both use ADR-037's closed
`{assignment_id,assignment_record_digest,source_record_digest}` item and sort
by decoded assignment ID, assignment digest, then source digest.

Let `IntentItems` be the complete deduplicated union of every preimage in each
member of `offline_recovery_pre_unseal_intents`, normalized to the closed
tagged origin
`{secret_class,secret_id,secret_commitment,holder_nid,
intent_record_digest,preimage_id}` and sorted by the ordinary secret-tuple
comparator, canonical NID bytes, decoded intent digest, then decoded preimage
ID. Each tuple and holder is taken from both exact templates and must agree.
No intent item pretends that a source or assignment signature exists.

```text
EffectiveAssignmentItems = dedup(BaseItems union ProvisionalItems)

EffectiveInventoryOrigins =
  AssignmentOrigins(EffectiveAssignmentItems) union
  IntentOrigins(IntentItems)
```

The tagged union preserves every origin even when multiple origins project to
one secret tuple. Exact duplicate assignment items count once; every
nonidentical otherwise-valid assignment variant remains distinct. Each
transition exposure and action gains an exact strictly sorted
`pre_unseal_intent_items` array of closed
`{intent_record_digest,preimage_id}` rows. The exposure's
`assignment_record_digests` and action's `source_assignment_digests` remain
independently complete over all and only real assignment-backed origins; the
intent array is independently complete over all and only co-keyed intent
origins. Either origin array may be empty only when the other is nonempty.
Presence of an intent never excuses omitting or failing to retire a real
assignment. `retirement_record_digests` remains a one-to-one projection only
of real `source_assignment_digests`; accepting the class-complete action
terminalizes its exact intent origins without inventing retirement records.

The predecessor `inventory_basis.exposure_set_sha256` continues to hash
`BaseItems`. Mandatory cleanup, action completeness, holder partitions, and
class-authority selection operate on `EffectiveInventoryOrigins`. The
successor `result_basis.exposure_set_sha256` hashes only the real assignment
frontier obtained after retiring every named real assignment and adding the
real current-successor and historical-decrypt-only assignments. Intent
pseudo-items never enter either exposure-set digest. The separately signed
intent inventory and collision projection make their terminalization
independently provable. Omission of any origin, subset replacement, or a
record/template created after its signed evidence rejects.

If current KEL, repository, checkpoint, and normal-or-gap rollover state are
ancestor/equal and fully available, the transition is an ordinary
`routine-addition` for the fresh NID. Otherwise the cold root must use
ADR-037's `emergency-reset`; a competing/nonancestor state, missing checkpoint,
or unresolved rollover cannot be overwritten by the ordinary path. A
cold-root emergency reset escaping an obligation fork likewise inventories
every branch and creates fresh obligation IDs for the full objectively
retained union.

Either path treats every imported real assignment and every pre-unseal intent
origin as conservative authority-exposure evidence, retires each real
assignment exactly once, terminalizes each intent origin through its one
accepted action, and applies the class-complete ADR-037 action to every
disclosed or planned-to-be-released durable capability. It rotates at least
epoch, config-audience, and OAuth-pairwise state; reencrypts/replaces governed
ciphertext and closes or supersedes every historical obligation and
retention-snapshot/key-binding row needed to rotate a historical key; and
rotates, revokes/reissues, replaces, retires, terminates, or migrates every
other disclosed class exactly as its matrix requires. An intent that can
release the archived cold-root scalar triggers the matrix's persona-migration
condition even when authority decryption later fails; the independent cold-
root signer does not make that scalar safe to expose. Fresh successor
source/assignment records cover only the authorized post-transition holder
set.

Every transition containing an unreconciled intent origin that plans release
of the predecessor-current epoch tuple, or an unreconciled activation origin
that records such exposure, MUST perform a fresh compromise-declaring KEL
rotation. Its `compromise_since` is no later than the minimum `created_at` of
all relevant intents: the unreconciled intent origins plus the exact linked
intent of each relevant activation, including a linked intent already proven
reconciled from accepted audit history.
The cutoff is carried through the required recovery-state rollover and
invalidates every otherwise signer-valid record in the exposure-to-sync
interval. This applies to `routine-addition` as well as emergency reset;
successful later admission of the recovered NID does not weaken it.

If governed ciphertext objectively still requires an old instance after this
cleanup, the action's exact nonempty `historical_decrypt_nids` and
`historical_assignment_digests` create the complete fresh-ID, same-old-tuple,
decrypt-only replacement holder set. Their sources cite the complete
projected-active retain-obligation head set, applicable governed bindings, and
governing artifacts; every imported or prior historical assignment retires
into every projected-active obligation successor's provenance. If the final
dependency closes, the action retires all historical assignments and both
arrays are empty.

For first acceptance only, the cold-root-signed activation and exact archive
basis permit a mathematically valid source/assignment signed under the archived
epoch to enter `ProvisionalItems` even when that epoch has retired. This is a
narrow conservative-accounting exception, not operational source authority.
Every archived-epoch source/assignment imported from an offline activation is
conservative exposure only, even if its key/head happens to equal the
verifier's current canonical Core KEL. It MUST rotate and cannot use ADR-037's
narrow current-epoch adoption exception.

That first-acceptance exception deliberately ignores only historical-authority
eligibility failures caused by KEL-window retirement or the new
`compromise_since` cutoff for the exact byte-complete intent templates. The
verifier still requires raw BIP-340 validity under the intent-bound archived
epoch key; exact source/assignment template completion; exact cold-root
intent/activation signatures and shared top-level equality; archive,
commitment, tuple, holder, and artifact provenance; and every closed schema
check. Cutoff-invalid completed records enter conservative inventory solely so
the accepting transition can retire and rotate them. They never grant
operational authority, sign a successor, satisfy a receipt, or escape the
fresh compromise-declaring rotation.

When a final activation is observed only after its linked intent has already
become `ReconciledIntent(I)`, accepted audit proof of that intent satisfies the
link. The later transition inventories and reconciles only the activation's
new real assignment origins; it does not reintroduce the terminalized intent
items. If both are unreconciled at the candidate's frozen prior checkpoint,
the transition inventories both and the one tuple action includes both exact
origin kinds. A retry producing nonidentical fully signed activation bytes
remains multiple activation variants and follows the collision union even
when every byte omitted by the intent template was the only difference.

The transition must then become canonical in an accepted fully receipted
checkpoint, accept the required epoch rollover closure, complete every
successor delivery checkpoint and roster receipt, recompute the complete
governed-head/binding, current-holder/historical-assignment,
obligation/provenance sets, and finish reconciliation. Only a subsequent
current-state activation installs fresh successor material in live protected
stores and changes the client from `offline-recovered` to `online-current`;
the isolated archived secrets never become live authority.
Erasure, non-use, failure to decrypt later, or claimed destruction of the
offline candidate does not excuse import, retirement, class-complete rotation,
receipts, or reconciliation. Discovery of another valid activation or
provisional record after apparent reconciliation immediately holds authority
and requires a new cleanup transition over the recomputed complete union;
prior delegation, receipts, or local erasure cannot grandfather the omission.
Thus removable media can complete local inspection and editing without
creating a long-lived unrecorded exposure or pretending to solve offline
freshness.

## Recovery-node enrollment over SSH and Tor

### Authorization

The prospective node generates:

- a provisional device NID;
- a dedicated SSH authentication key; and
- an X25519 recovery recipient key.

The ability to approve recovery is a Core-owned durable policy, not an
implicit consequence of device enrollment and not a use of the still-gated
general Control profile. Each recovery node's protected Core policy store
holds a closed
`heterodyne.recovery-approval.authorization.v1` record. Grant IDs are never
reused,
exact duplicate bytes are idempotent, revocation is absorbing, and every
recovery node refuses authority while its local policy chain is unresolved. The
initial scope vocabulary is `recovery.enroll`, `recovery.activate`,
`archive.read`, `archive.write`, `object.read`, `object.write`, and
`authority.read`. `recovery.enroll` is required to approve a prospective node;
`recovery.activate` and `authority.read` are both required before current
epoch authority can be released.

The record lives at
`keys/core/recovery/approvals/<authorization_id>/<record-digest>.json`. Its exact member
names are `type`, `authorization_id`, `persona`, `target_nid`, `scopes`,
`lineage_sequence`, `previous_record`, `issued_at`, `valid_until`, `action`,
`supersedes`, `epoch_pubkey`, `kel_head`, and `signature`; the
`kel_head` object is exactly `{"event_id":"<64 lowercase hex>","seq":<JSON-safe
nonnegative integer>}`. `type` is
`heterodyne.recovery-approval.authorization.v1`; `action` is `grant`,
`renew`, or `revoke`; scopes are sorted, unique, and nonempty. `authorization_id` is
exactly 16 random bytes encoded as 32 lowercase hex. All times and KEL
sequences are JSON-safe nonnegative integers.

Approval policy is a mergeable set of independent authorization-ID lineages.
A root grant uses `lineage_sequence:0` and `previous_record:null`; every
same-ID successor increments by exactly one and names the complete prior
record digest. Exact duplicate bytes are idempotent. Competing nonidentical
roots or successors quarantine only that authorization ID and every grant
that depends on it; unrelated approvals remain usable.

A root grant has `valid_until > issued_at`. A `renew` repeats persona, target,
and exact scopes, names the active predecessor, has `issued_at` strictly before
that predecessor's `valid_until`, has nondecreasing `issued_at`, and strictly
increases `valid_until`. Acceptance is independent of when a verifier receives
the bytes. A lineage for which no such signed renewal exists before the expiry
boundary cannot be revived; expiry regrant uses a fresh ID as described below.
A `revoke` repeats persona, target, and scopes, sets `valid_until:0`, names the
active predecessor, and is absorbing for the ID. Same-lineage renew/revoke
records use `supersedes:[]`.

A fresh root grant uses `supersedes:[]` only when no prior overlapping
`(persona,target_nid,scope)` lineage exists. For ordinary regrant,
`supersedes` is the sorted unique array of every latest terminal head for the
overlapping lineages: the absorbing revoke, or the latest expired grant/renew.
Every nonconflicting overlap must be terminal. After expiry alone, the
then-current epoch may sign the fresh root. After any revoke, the fresh root's
KEL sequence is greater than every named revoke, KEL replay contains an
intervening rotation to a different epoch key, and that post-rotation key signs
it.

A quarantined fork, cutoff-invalid head, or conflicting active overlap has no
unique predecessor that can be revoked. Recovering that exact
`(persona,target_nid,scope)` tuple uses a fresh authorization ID whose
`supersedes` is the complete sorted frontier of every individually valid,
operationally eligible maximal head in every overlapping prior lineage,
including every ratified competing fork branch and every latest terminal
revoke or expired head. `unratified-pre-rotation` evidence is excluded. Each
named head
is either terminal by absorbing revocation/expiry or inactive because of the
fork/cutoff/overlap, and at least one named head MUST be inactive for one of
those conflict reasons; otherwise the ordinary regrant rule applies. The
canonical KEL contains a later rotation to a different epoch key after all
named KEL states, and that current post-conflict key signs the root. The new
head sequence is greater than every named head sequence; each named head is
either an ancestor of the new canonical state or invalidated by its canonical
compromise cutoff. Signer-controlled wall time is audit data and cannot block
this recovery.
Acceptance makes every named lineage terminal for overlap evaluation; rejected
bytes remain audit evidence. An incomplete frontier, still-active
nonconflicting head, extra digest, stale signer, or second nonidentical
resolution root quarantines the attempted recovery.

After one conflict-recovery root is accepted, its required post-conflict KEL
rotation is also an objective arrival-order cutoff for that exact
`(persona,target_nid,scope)` tuple. Every historically signer-valid omitted root,
successor, or descendant whose signing KEL state precedes that rotation and
which does not descend from the accepted recovery root is terminal for
authority/overlap evaluation, regardless of whether it was locally known or
accepted before the recovery. Its bytes remain audit evidence and cannot
reopen the tuple. The resolver MUST include every then-known operationally
eligible maximal candidate; omitting one is producer nonconformance, while
audit-only unratified evidence is never included. A later verifier does not
invalidate the accepted recovery based on arrival order. A competing root or
successor authorized at or after the post-conflict state is not covered by the
cutoff and creates an ordinary new conflict. Stores recompute the terminal
frontier after reconciliation.
If the recovery root is rollover-provisional, the rollover includes it in
`approval_heads`. Otherwise the rollover preserves the complete conflicting
approval frontier and the current post-rollover key may sign the recovery root
against exactly that frontier; the root becomes an ordinary current-authority
update after all existing checks pass.

At most one lineage head may be active for each
`(persona,target_nid,scope)` tuple. Simultaneous active overlap or an
unresolved lineage fork quarantines only the overlapping tuple/IDs, never the
global policy. An unrevoked grant/renew is active while `now < valid_until`,
its accepted signing head remains an ancestor of the current canonical KEL,
no `compromise_since` cutoff invalidates it, and after a later rotation its
head is committed by or reachable from the applicable rollover frontier. New
grant, renew, and revoke records require current-epoch authority under their
named KEL head; after that epoch retires they remain candidates only through
rollover ratification. A cutoff-invalid lineage cannot renew and must be
superseded under post-cutoff authority. A late retired-key root or successor
omitted from the rollover is evidence only and cannot create or reopen an
overlap; a competing current-epoch or ratified record enters the complete
frontier.

Approval authority is the union of the complete nonconflicting active ID set.
Removing a target or scope requires absorbing revokes for every active ID
that contributes it. Grant validation evaluates the complete canonical set,
not merely one caller-supplied ID. “Union” means that any one active lineage
may independently authorize the scopes it contains; scopes from separate IDs
are never conjunctively combined. Every operation and transfer grant MUST name
one exact active approval ID/head that by itself contains the complete required
scope set. Split approvals therefore cannot jointly satisfy
`recovery.activate` plus `authority.read`, or any other multi-scope condition.

The signature is a 64-byte BIP-340
signature encoded as 128 lowercase hex over SHA-256 of
`UTF8("heterodyne-recovery-approval-v1")`, a zero byte, and the JCS object
with `signature` omitted. `record-digest` is lowercase-hex SHA-256 of the JCS
bytes of the complete signed record. Core's protected approval-policy head is
authoritative per authorization ID; the Comms composition mirrors the same
byte-identical lineage set in the encrypted config repository. A withheld
record cannot become active unless it is the exact next canonical lineage
record. A competing successor never gains authority and never stalls
unrelated IDs.

Approval to enroll does not itself make the target a recovery node. The
durable role artifact is a closed
`heterodyne.recovery-node-role.v1` record with exactly:

```text
type, role_id, persona, target_nid, delegation_event_id, recovery_key, server_onion,
server_host_key, lineage_sequence, previous_record, issued_at, action,
supersedes, epoch_pubkey, kel_head, signature
```

`role_id` is 16 random bytes encoded as 32 lowercase hex.
`delegation_event_id` is the 64-lowercase-hex ID of the complete active Core
device-delegation event binding `target_nid` to this exact persona.
`recovery_key` is exactly
`{"algorithm":"X25519","public_key":"<unpadded base64url 32-byte key>"}`.
`server_onion` is exactly
`{"host":"<56 lowercase base32 characters>.onion","port":<1..65535>}`.
`server_host_key` is exactly
`{"algorithm":"ssh-ed25519","public_key":"<unpadded base64url 32-byte key>"}`.
`supersedes` is a sorted unique array of complete record digests.
`epoch_pubkey` is 64 lowercase hexadecimal characters and MUST satisfy
historical signer validation under the closed `kel_head`, be current epoch
authority when produced, and be rollover-ratified after that epoch retires.

Recovery roles are a mergeable set of independent role-ID lineages.
`action` is `grant`, `update`, or `revoke`. Every root grant uses
`lineage_sequence:0` and `previous_record:null`. A first-use root for a target
with no prior accepted role lineage uses `supersedes:[]`; a fresh-ID regrant
for a target with prior accepted role history uses the nonempty `supersedes`
rule below. Each same-ID successor increments by one and names the complete
active predecessor digest. Exact duplicates are idempotent. A competing root
or successor quarantines only that role ID and target, not the persona-wide
policy.

`grant` and `update` are accepted only when the named delegation is canonical,
active, and unrevoked under the record's KEL head at `issued_at`. A later
delegation revocation makes the role inactive but does not remove the record
from deterministic frontier/conflict processing. `update` preserves persona,
role ID, and target NID but may replace
the delegation event ID, recovery key, onion endpoint, or SSH host key; it names the exact active
predecessor and uses `supersedes:[]`. `revoke` repeats the active head's
persona, target, delegation, and endpoint/key values, names it as predecessor, uses
`supersedes:[]`, and is absorbing. A fresh-ID regrant for a target with prior
accepted nonconflicting role history has a nonempty sorted unique
`supersedes` array exactly equal to every latest terminal head for every prior
role ID for that target. A terminal head is either an absorbing role revoke
or a grant/update whose exact named target delegation has a canonical
absorbing revocation; delegation revocation makes that head permanently
inactive for regrant and it cannot be updated or revived. Regrant requires a
later canonical rotation to a different epoch key after every named
role/delegation revocation and is signed by that post-revocation key. A
missing latest terminal head, extra digest, active overlap, or
stale/pre-rotation signer rejects.

When a role target is quarantined by a role-lineage fork, conflicting overlap,
or cutoff-invalid head, no unique predecessor can be revoked. Recovery uses a
fresh role ID whose `supersedes` is the complete sorted frontier of every
individually valid, operationally eligible maximal head for every prior role ID
of that target, including all ratified competing branches and every latest
terminal role or delegation-revoked head. `unratified-pre-rotation` evidence
is excluded. Each named head is either terminal under the ordinary
rule above or inactive because of the fork/overlap/cutoff, and at least one
named head MUST be inactive for one of those conflict reasons; otherwise
ordinary regrant applies. The target has one current canonical active
delegation; the canonical KEL contains a later rotation to a different epoch
key after all named role KEL states and after every canonical
delegation-revocation event/state that makes a named terminal head inactive;
that post-conflict key signs the root. The new head sequence is greater than
every named head sequence and every such delegation-revocation sequence, and
each named head and revocation is either its ancestor or cutoff-invalidated
under canonical fork processing; wall time does not gate recovery. Acceptance
makes all named lineages terminal for target-overlap evaluation. An incomplete
frontier, still-active nonconflicting role, inactive target delegation, stale
signer, or second nonidentical recovery root quarantines the attempt.

After one role conflict-recovery root is accepted, its required post-conflict
KEL rotation is the objective arrival-order cutoff for that exact
`(persona,target_nid)` target. Every omitted historically signer-valid role root,
successor, or descendant signed under a KEL state before that rotation and not
descending from the accepted recovery root is terminal for role/overlap
evaluation, including a late sibling bound to a delegation later revoked by
the recovery sequence. The resolver MUST enumerate every then-known
operationally eligible maximal role/delegation terminal or conflicting head; a
known eligible omission is producer nonconformance and retained audit evidence,
but a late unratified pre-rotation arrival is excluded and does not invalidate
or reopen the accepted root. A competing record authorized at or after the
post-conflict state creates an ordinary new conflict. Stores recompute the
terminal target frontier after reconciliation.
If the recovery root is rollover-provisional, the rollover includes it in
`role_heads`. Otherwise the rollover preserves the complete conflicting role
frontier and the current post-rollover key may sign the recovery root against
exactly that frontier; the root becomes an ordinary current-authority update
after all existing checks pass.

At most one lineage head is active for `(persona,target_nid)`. Overlap or a
fork quarantines role authority for that target only. A valid grant/update
remains active after a later KEL rotation only when its signing head is an
ancestor of the current canonical KEL, no compromise cutoff invalidates it,
its exact head is committed by or reachable from the applicable rollover
frontier, and its exact named target delegation remains active and unrevoked.
Revoking that delegation makes the role inactive immediately, including when
the target is serving rather than acting as the transfer client. New
grant/update/revoke records require current-epoch authority under their named
KEL head and rollover ratification after that epoch retires. A late retired-key
root or successor omitted from the rollover is evidence only and cannot enter
the active frontier; a competing current-epoch or ratified record enters
ordinary conflict processing. A cutoff-invalid role is inactive and cannot
update; it must be revoked/quarantined and freshly granted under post-cutoff
authority. The active-role digest is the complete digest of the unique current
grant/update head.

The record's `epoch_pubkey` signs:

```text
SHA256(
  UTF8("heterodyne-recovery-node-role-v1") || 0x00 ||
  JCS(record with signature omitted)
)
```

with BIP-340 encoded as 128 lowercase hex. Its complete-record digest is
lowercase-hex SHA-256 of its JCS bytes. Core stores it at
`keys/core/recovery/node-roles/<role_id>/<record-digest>.json`; the Comms
composition mirrors the same bytes at
`recovery/node-roles/<role_id>/<record-digest>.json` in the canonical
encrypted config repository. Core's per-ID lineage set is authoritative for a
Core-only claimant; a Comms claimant additionally requires the byte-identical
lineage set to be durable and canonical in the encrypted config repository.
This mirror rule does not make Core depend on Comms. An unresolved fork,
overlap, or revoke is fail-closed for its target and cannot stall unrelated
roles.

Registry prerequisites are:

```text
core.recovery-node.v1 -> core.portable-recovery.v1
core.recovery-node.v1 -> core.onion-service-host.v1
comms.portable-recovery.v1 -> core.portable-recovery.v1
comms.recovery-orchestration.v1 -> comms.portable-recovery.v1
comms.recovery-orchestration.v1 -> comms.double-ratchet.v1
comms.recovery-client.v1 -> comms.recovery-orchestration.v1
comms.recovery-client.v1 -> core.outbound-tor.v1
comms.recovery-provider.v1 -> comms.recovery-orchestration.v1
comms.recovery-provider.v1 -> core.recovery-node.v1
comms.large-object-sync.v1 -> comms.recovery-orchestration.v1
comms.large-object-sync-consumer.v1 -> comms.large-object-sync.v1
comms.large-object-sync-consumer.v1 -> core.outbound-tor.v1
comms.large-object-sync-provider.v1 -> comms.large-object-sync.v1
comms.large-object-sync-provider.v1 -> core.recovery-node.v1
```

Revision 4 allocates the following wire vocabularies in `allocations.json`;
they are not diagnostic conformance reason codes:

```text
slot-type:nip44-v2-secp256k1-adapted-envelope
slot-type:hpke-x25519-device
slot-type:hpke-x25519-bootstrap
slot-type:platform-device-local
slot-type:webauthn-prf-a256kw
slot-type:argon2id-a256kw

role:cold-root
role:epoch
role:device
role:bootstrap
role:repository-bundle
role:core-protected-record
role:protected-metadata-record
role:authority-protected-secret
role:device-clone-secret
role:shared-configuration
role:platform-configuration
role:device-configuration
role:audit-history
role:large-object
role:media

owner:core
owner:comms
owner:control
owner:social
owner:client

platform:android
platform:browser
platform:ios
platform:linux
platform:macos
platform:windows

provider:android-keystore
provider:android-strongbox
provider:apple-keychain
provider:apple-secure-enclave
provider:freedesktop-secret-service
provider:linux-tpm2
provider:pkcs11
provider:webcrypto-indexeddb
provider:windows-cng
provider:windows-dpapi
provider:windows-tpm

archive-abandonment-reason:recovery_archive_cancelled
archive-abandonment-reason:recovery_archive_production_failed
archive-resolution-reason:archive_generation_fork
archive-resolution-reason:archive_artifact_conflict
rollover-gap-reason:rollover_state_unrecoverable
rollover-reference-member:previous-rollover-head
historical-decrypt-obligation-action:retain
historical-decrypt-obligation-action:close

grant-revocation-reason:recovery_grant_cancelled
grant-revocation-reason:recovery_policy_changed
grant-revocation-reason:recovery_role_revoked

transfer-error:transfer_bad_frame
transfer-error:transfer_request_id_conflict
transfer-error:transfer_authorization_inactive
transfer-error:transfer_scope_mismatch
transfer-error:transfer_resource_mismatch
transfer-error:transfer_range_invalid
transfer-error:transfer_length_mismatch
transfer-error:transfer_byte_limit_exceeded
transfer-error:transfer_digest_mismatch
transfer-error:transfer_range_conflict
transfer-error:transfer_target_not_found
transfer-error:transfer_grant_closed
transfer-error:transfer_staging_unavailable
transfer-error:transfer_destination_unrecoverable
```

Revision 4 also adds the closed allocation kind
`governed-decrypt-source-profile`. Its value set is the exact exhaustive list
from the normative Comms governed-decrypt source-profile table, with each
globally unique profile ID owned by its validating family. At minimum, the
already named values include all six
`heterodyne-comms-tier3-wrapped-content-kind-{1,6,16,1063,30023,30402}-v1`
profiles, `heterodyne-comms-config-repository-v1`, and
`comms.large-object-pointer.v1`. The implementation batch must first assign
exact stable IDs to the Tier-3 feed index and descriptor, private claim-ledger
encryption, and every recovery-wrapped or other current governed source
profile, then allocate the complete table. Revision 4 cannot freeze with only
this minimum subset, an implicit profile, a wildcard, or a placeholder ID.

No other value is allocated for those recovery vocabulary kinds in revision
4, and no unallocated string appears in the corresponding signed record,
manifest entry, slot, or transfer frame. The six `slot-type` allocation
entries are schema-bearing, with these exact planned schema paths:

```text
nip44-v2-secp256k1-adapted-envelope -> docs/spec/schemas/recovery/slot-nip44-v2-secp256k1-adapted-envelope.schema.json
hpke-x25519-device -> docs/spec/schemas/recovery/slot-hpke-x25519-device.schema.json
hpke-x25519-bootstrap -> docs/spec/schemas/recovery/slot-hpke-x25519-bootstrap.schema.json
platform-device-local -> docs/spec/schemas/recovery/slot-platform-device-local.schema.json
webauthn-prf-a256kw -> docs/spec/schemas/recovery/slot-webauthn-prf-a256kw.schema.json
argon2id-a256kw -> docs/spec/schemas/recovery/slot-argon2id-a256kw.schema.json
```

Every other allocation above has both schema members null. The implementation
PR creates each named closed schema first, computes `schema_sha256` from its
exact raw bytes, and then writes that digest into the allocation entry; a
placeholder digest is never committed.

The shared ADR-037 revision-4 batch additionally creates this exact Comms
wire-profile/schema binding set:

```text
comms.governed-decrypt-key-binding.v1 -> docs/spec/schemas/comms/governed-decrypt-key-binding-v1.schema.json
comms.historical-decrypt-obligation.v1 -> docs/spec/schemas/comms/historical-decrypt-obligation-v1.schema.json
comms.repository-retention-inventory.v1 -> docs/spec/schemas/comms/repository-retention-inventory-v1.schema.json
```

That same implementation change adds required
`governed_decrypt_key_bindings_sha256` and
`historical_decrypt_obligations_sha256` to the closed
`comms.credential-ledger-checkpoint.v1` schema; adds exact
`historical_decrypt_nids` and `historical_assignment_digests` fields
immediately after `successor_assignment_digests` in
`comms.node-secret-transition-action.v1`; carries the governed-binding digest
through the exact target/inventory/result branches of
`comms.credential-ledger-secret-transition.v1` and through
`candidate_governed_decrypt_key_bindings_sha256` in
`comms.credential-ledger-candidate-abandonment.v1`; adds closed
`offline_recovery_pre_unseal_intents`,
`offline_recovery_activations`,
`offline_recovery_pre_unseal_intent_collisions`, and
`offline_recovery_activation_collisions` arrays to the applicable
ordinary-addition/emergency-reset inventory-basis and reset schemas; adds the
independently complete `pre_unseal_intent_items` origin array to transition
exposures/actions and permits assignment/source arrays to be empty only for an
intent-only tuple; keeps retirement arrays one-to-one only with real
assignments; adds the two obligation-action allocations and the closed
`governed-decrypt-source-profile` kind/table above; creates the closed
repository-retention-inventory schema with exact type const, safe integers,
typed Git/KEL members, canonical RID/ref constraints, and no additional
properties; and computes every raw schema/allocation/profile digest before
freezing the revision. This design
consumes those shared profiles; it does not create a second recovery-owned
spelling.

Revision 4 also creates exactly these recovery wire-profile/schema bindings:

```text
core.recovery-archive-header.v1 -> docs/spec/schemas/recovery/archive-header-v1.schema.json
core.recovery-manifest.v1 -> docs/spec/schemas/recovery/archive-manifest-v1.schema.json
core.recovery-state-rollover.v1 -> docs/spec/schemas/recovery/recovery-state-rollover-v1.schema.json
core.recovery-state-rollover-gap.v1 -> docs/spec/schemas/recovery/recovery-state-rollover-gap-v1.schema.json
core.recovery-archive-generation.v1 -> docs/spec/schemas/recovery/archive-generation-v1.schema.json
core.recovery-archive-generation-resolution.v1 -> docs/spec/schemas/recovery/archive-generation-resolution-v1.schema.json
core.recovery-archive-artifact-resolution.v1 -> docs/spec/schemas/recovery/archive-artifact-resolution-v1.schema.json
core.recovery-archive-finalization.v1 -> docs/spec/schemas/recovery/archive-finalization-v1.schema.json
core.recovery-archive-abandonment.v1 -> docs/spec/schemas/recovery/archive-abandonment-v1.schema.json
core.recovery-device-archive-generation.v1 -> docs/spec/schemas/recovery/device-archive-generation-v1.schema.json
core.recovery-device-archive-finalization.v1 -> docs/spec/schemas/recovery/device-archive-finalization-v1.schema.json
core.recovery-device-archive-abandonment.v1 -> docs/spec/schemas/recovery/device-archive-abandonment-v1.schema.json
core.recovery-device-clone-secret.v1 -> docs/spec/schemas/recovery/device-clone-secret-v1.schema.json
core.recovery-epoch-authority-envelope.v1 -> docs/spec/schemas/recovery/epoch-authority-envelope-v1.schema.json
core.recovery-authority-protected-secret.v1 -> docs/spec/schemas/recovery/authority-protected-secret-v1.schema.json
core.offline-recovery-pre-unseal-intent.v1 -> docs/spec/schemas/recovery/offline-recovery-pre-unseal-intent-v1.schema.json
core.offline-recovery-activation.v1 -> docs/spec/schemas/recovery/offline-recovery-activation-v1.schema.json
core.recovery-approval.v1 -> docs/spec/schemas/recovery/recovery-approval-v1.schema.json
core.recovery-node-role.v1 -> docs/spec/schemas/recovery/recovery-node-role-v1.schema.json
core.recovery-transfer-grant.v1 -> docs/spec/schemas/recovery/transfer-grant-v1.schema.json
core.recovery-transfer-grant-revocation.v1 -> docs/spec/schemas/recovery/transfer-grant-revocation-v1.schema.json
core.recovery-epoch-activation-envelope.v1 -> docs/spec/schemas/recovery/epoch-activation-envelope-v1.schema.json
core.recovery-transfer-frame.v1 -> docs/spec/schemas/recovery/transfer-frame-v1.schema.json
core.recovery-transfer-receipt.v1 -> docs/spec/schemas/recovery/transfer-receipt-v1.schema.json
comms.large-object-pointer.v1 -> docs/spec/schemas/recovery/large-object-pointer-v1.schema.json
```

Each path is created as a closed schema and its raw-file SHA-256 is populated
in `wire-profiles.json` in the same implementation commit. This list is the
complete ADR-038 revision-4 wire-profile batch; adding another profile requires
another registry revision or an amended pre-release ADR before revision 4 is
published.

In that same frozen batch, `core.recovery-manifest.v1` requires
`governed_decrypt_key_bindings_sha256` in the non-null Comms credential
high-water; `core.recovery-authority-protected-secret.v1` requires it in every
generic outer/decrypted identity and record-value binding;
`core.offline-recovery-pre-unseal-intent.v1`,
`core.offline-recovery-activation.v1`, and
`core.recovery-transfer-grant.v1` require it in their distinct closed
`archive_restore_basis` branches; and the durable-inventory branch of the
manifest requires it in every generic row. The gap schema permits
`authenticated-reference` only with `signed-recovery-record` and permits
storage-index/provider metadata only as
`{evidence_class:"audit-only-reference",
evidence_type:"audit-storage-metadata"}`. Raw schema digests and the registry
entry-set digest are recomputed only after these exact changes.

Core accepts approval and transfer records over any already authenticated
local or higher-document path and does not define a carrier. A provider of
`core.recovery-node.v1` must provide `core.onion-service-host.v1`; native
recovery and large-object consumers claim their consumer features with
`core.outbound-tor.v1`, while servers claim the corresponding provider
feature. A client never inherits provider/full-node requirements merely by
consuming the service. A browser cannot claim a native consumer feature
through an unstandardized gateway. The Comms recovery-orchestration feature mirrors
the Core records into the encrypted config repository and makes DR the
standard authenticated delivery path. These features do not open general
Control conformance.

An existing device with active Core delegation and a canonical unrevoked
approval containing every mode-specific authorization below creates a
transfer grant valid for at most eight hours. `recovery.enroll` is required
only for bootstrap; delegated transfer requires the matching read/write
scopes, and authority activation requires `recovery.activate` plus
`authority.read`. The transmitted grant envelope is the closed object:

```json
{
  "grant": {},
  "authorizer_delegation": {},
  "authority_payload": null
}
```

`authorizer_delegation` is the complete active Core kind-31001 NIP-01 event
with exactly `id`, `pubkey`, `created_at`, `kind`, `tags`, `content`, and
`sig`. `authority_payload` is null except for `authority-activation`, where it
is the exact closed HPKE envelope defined below. `grant` is a closed object
with exactly:

```text
type, grant_id, grant_mode, persona, kel_head, authorizer_nid, client_nid,
client_authorization, approval_authorization_id, approval_record_digest,
server_nid, server_role_record_digest, server_onion, server_host_key,
prospective_nid, delegation_intent, client_ssh_key,
client_recovery_key, archive_restore_basis,
scopes, resources, max_bytes, archive_generation,
issued_at, expires_at, authorizer_signature, epoch_signature
```

`type` is `heterodyne.recovery-transfer-grant.v1`; `grant_id` and
`approval_authorization_id` are 16 random bytes encoded as 32 lowercase hex.
`grant_mode` is `bootstrap`, `delegated-transfer`, or
`authority-activation`. `client_nid` is the NID that must prove the bound SSH
key; it may lack an active delegation only in bootstrap mode.
`client_authorization` is the closed object
`{"type":"prospective"|"self"|"approval"|"role",
"authorization_id":null|"<32 lowercase hex>",
"record_digest":null|"<64 lowercase hex>",
"role_record_digest":null|"<64 lowercase hex>"}`.
`prospective` and `self` require all three nullable members null; `approval`
sets the first two to the exact approval lineage/basis record and leaves the
role digest null; `role` sets only the exact complete active role-record
digest. `approval_record_digest` is the exact accepted grant/renew basis in
`approval_authorization_id`'s lineage. `server_role_record_digest` is the
exact active role head for `server_nid`.
`kel_head` is the closed event-ID/sequence object defined above. Persona, KEL
event, and key fingerprints use lowercase hex; NIDs are canonical Ed25519
`did:key` values. `server_onion`, `server_host_key`, and `client_ssh_key` use
the exact closed shapes defined for the role record. When non-null,
`client_recovery_key` is exactly
`{"algorithm":"X25519","public_key":"<unpadded base64url 32-byte key>"}`.
`archive_restore_basis` is null except for `authority-activation`. In that mode
it is a closed object containing exactly:

```text
archive_transfer_grant_id, archive_transfer_grant_envelope_digest,
archive_transfer_grant_mode, archive_id, archive_generation,
generation_record_digest, manifest_digest, finalization_record_digest,
archive_authority, required_epoch_slot,
addition_checkpoint_digest, delivery_checkpoint_digests,
credential_checkpoint_digest, governed_decrypt_key_bindings_sha256,
historical_decrypt_obligations_sha256,
secret_inventory_sha256,
special_authority_bindings_sha256
```

`archive_transfer_grant_mode` is `bootstrap` or `delegated-transfer` and the ID
and envelope digest identify the exact prior grant whose completed receipt
delivered this immutable finalized archive. `archive_authority` is the closed
`{persona,epoch_pubkey,kel_head}` triple equal across its allocation and
manifest. `required_epoch_slot` is the closed
`{slot_id,slot_sha256}` pair for the original required epoch slot committed by
that signed manifest. `delivery_checkpoint_digests` is a nonempty array in
strict canonical checkpoint ancestry order. The checkpoint and digest
equalities governing the remaining members are defined in the activation
ceremony below.

When non-null, `delegation_intent` is an unsigned prospective Core kind-31001 body with
exactly `created_at`, `kind`, `tags`, and `content`. `kind` is 31001,
`content` is empty, and its canonical tag array satisfies the Core base-device
delegation profile for `prospective_nid`; it contains no event ID, pubkey, or
signature. Scopes are sorted and unique and MUST be a subset of the scopes in
the named active approval record. Conditional members are exact:

| Grant mode | Required values |
|---|---|
| `bootstrap` | `client_nid == prospective_nid`; client authorization is `prospective`; prospective NID, delegation intent, and recovery key are non-null and mutually consistent; `archive_restore_basis` is null; exactly one archive resource; `archive_generation` is its positive generation; scopes exactly `["archive.read"]`; named approval contains both `recovery.enroll` and `archive.read`; transmitted `authority_payload` is null |
| `delegated-transfer` | client NID has an active Core delegation; prospective NID, delegation intent, recovery key, and `archive_restore_basis` are null; resources are either exactly one archive or one-or-more objects, never mixed; archive generation is positive only for the archive case and otherwise null; scopes are exactly one of `["archive.read"]`, `["archive.write"]`, `["object.read"]`, or `["object.write"]` and match every resource; client authorization is `self` when client equals authorizer and otherwise names the exact covering active approval or role; transmitted `authority_payload` is null |
| `authority-activation` | client NID equals the active node-role target; client authorization is `role` and references the same active role digest as the authority resource ID; prospective NID and delegation intent are null; recovery key equals the active role key; `archive_restore_basis` is non-null; exactly one authority resource; archive generation equals the basis's positive generation; scopes exactly `["authority.read"]`; the named authorizer approval contains both `recovery.activate` and `authority.read`; transmitted `authority_payload` is non-null |

Every mode requires `server_role_record_digest` to be the complete digest of
the unique active role head whose persona, target NID, onion endpoint, and SSH
host key exactly equal the grant's `persona`, `server_nid`, `server_onion`,
and `server_host_key`, and whose exact target delegation remains canonical,
active, and unrevoked. A role update/revoke, target-delegation revocation, or target-local fork invalidates
every grant bound to the old server head. This server role is distinct from
the client role used for authority activation; the two may be identical only
when a node serves its own transfer.

`approval_record_digest` MUST be an accepted grant/renew in
`approval_authorization_id`'s nonconflicting lineage, target
`authorizer_nid`, cover every required scope, and have `valid_until >=
expires_at`. At evaluation, the current lineage head is that basis or a
non-revoking renew descendant; a revoke, fork, expiry before grant expiry, or
scope/target change invalidates the grant. When client authorization is
`approval`, its authorization ID and record digest obey the same exact basis
rule for the client. When it is `role`, its role digest is the exact active
client-role head.

For bootstrap and authority activation the authorizer may differ from the
client. For delegated transfer, a different client is permitted only when
that client is an active recovery role or has its own durable approval
covering every requested scope and `client_authorization` binds that exact
role record or approval ID; otherwise `client_nid == authorizer_nid` and the
basis is `self`. A later alternate role or approval cannot substitute for the
bound lineage.
One grant has one transfer direction. Read and write authority never share a
grant or a resource bitmap; a peer needing both receives two independently
bounded grants.
Null is the JSON literal and no omitted conditional member is accepted.
`resources` is a sorted unique array of exact
`{class,id,descriptor_sha256,payload_sha256,payload_length}` objects.
`payload_length` is a positive JSON-safe integer. For an archive, `id` is
the archive ID and the two digests cover its immutable payload descriptor and
exact ciphertext-plus-tag stream, and `payload_length` is that immutable
ciphertext stream length. For an object, `id == payload_sha256`,
`descriptor_sha256` is null, and `payload_length` is the complete stored
object length. For an authority envelope, `class` is
`authority`, `id` is the active node-role record digest,
`descriptor_sha256` is null, and `payload_sha256` hashes the exact HPKE
activation-envelope bytes defined below; `payload_length` is the exact byte
length of `UTF8(JCS(authority_payload))`. Resources are sorted by
`(class,id,descriptor_sha256-or-empty,payload_sha256,payload_length)`, with
the first four compared as UTF-8 and length numerically. No
resource wildcard exists. This immutable
payload identity deliberately excludes mutable recipient slots and breaks the
grant/rewrap hash cycle. When non-null, `archive_generation` MUST equal the
signed manifest generation of the sole archive resource. Integers are JSON-safe and
`0 <= issued_at < expires_at <= issued_at + 28800`, and `expires_at` MUST be
no later than the named approval grant's `valid_until`.

At issuance an archive resource MUST resolve to one accepted allocation,
manifest, header, and finalization satisfying the cross-record matrix above;
its descriptor, payload digest, and payload length equal that finalized
artifact. An object resource resolves to one immutable stored object with the
declared digest/length. An authority resource resolves to the exact
already-created envelope in the signed grant. No caller-supplied metadata can
substitute for those canonical bytes.

A completed bootstrap archive grant is eligible to be named later in
`archive_restore_basis` only when that archive's allocation/manifest authority
tuple exactly equals the bootstrap grant's persona, current KEL head, and epoch
key derived from that head and used for its countersignature. A stale tuple may
still be bulk-staged under rollback policy but is permanently ineligible as
that grant's activation basis. A completed delegated archive transfer may be a
basis under the same equality. In either case the later activation grant
revalidates the immutable archive and repeats all basis values; the old grant
does not become an authority credential. This tuple test is necessary, not
sufficient: an initial bootstrap archive produced before the node's accepted
addition/delivery checkpoints is permanently ineligible even if its KEL tuple
has not changed. Only a post-transition archive satisfying the complete basis
and exposure equations below can be named, whether its completed delivery used
a later bootstrap grant or an ordinary delegated-transfer grant.

Before either signature is produced, a process holding the current epoch
authority creates the authority payload, when applicable, and supplies its
exact object in the transmitted envelope. The unsigned signing envelope is
`{"grant":<grant with both signature members omitted>,
"authorizer_delegation":<complete event>,
"authority_payload":<exact object or null>}`. Its authorizer NID signs:

```text
SHA256(
  UTF8("heterodyne-recovery-grant-v1") || 0x00 ||
  JCS(unsigned signing envelope)
)
```

The authorizer signature is 64-byte Ed25519 encoded as unpadded base64url. The
current epoch authority countersigns the same digest with BIP-340 encoded as
128 lowercase hex after validating the authorizer's active delegation and
recovery-approval authority. The two strings populate the grant object before
the complete envelope is hashed or transmitted. The complete envelope,
including the authority payload when present, is registered at the exact
`server_nid` recovery node through an already authenticated path and is not a
standalone bearer token. For an authority resource, the server computes
`UTF8(JCS(authority_payload))` and requires its SHA-256 to equal the sole
resource's `payload_sha256` before staging it; the server never regenerates
that randomized HPKE envelope. This control-plane registration is the sole
authority-payload upload path and does not allocate `authority.put`.

`grant_envelope_digest` is lowercase-hex SHA-256 of the exact JCS bytes of the
complete transmitted envelope. Within one `(persona,server_nid,grant_id)`
tuple, exact duplicate envelope bytes are idempotent and every nonidentical
reuse is a grant-ID conflict. The server permanently quarantines every
conflicting envelope, opens no channel, accepts no stat or stage, and never
chooses by arrival order, signature order, or digest. Revocation of that tuple
applies conservatively to every conflicting claimant, but recovery requires a
fresh random grant ID and complete new signatures. SSH-principal lookup
succeeds only when the tuple resolves to exactly one complete envelope; stage
keys continue to include its complete digest.

At evaluation, `issued_at` may be at most 300 seconds ahead of the server
clock, but clock tolerance never extends `expires_at`.

One predicate, `grant_active(now,state)`, governs channel opening, every stat,
read, put, cancel, and every cached replay. It is true only when:

- both grant signatures and the complete transmitted envelope verify, the
  request reaches the exact server/host key, `issued_at` is within tolerance,
  and `now < expires_at`;
- the grant's KEL key/head is the current accepted persona state, the
  authorizer delegation is active, and its target/scopes match the named
  approval;
- the latest epoch-changing rotation has one unique accepted state rollover
  with its complete normal-or-gap linkage closure, and every retired-epoch
  approval or role basis named by the grant is in or reachable from its
  committed frontier;
- the exact named approval basis and every required client approval/role are
  active under their nonconflicting per-ID lineages, unexpired where
  applicable, unrevoked, ancestor/cutoff-valid, and cover every requested
  scope;
- `server_role_record_digest` is still the exact unique active role head and
  its server NID, onion endpoint, and host key still match the connection, and
  its exact target delegation remains active;
- no signed whole-grant revocation is effective;
- for non-bootstrap modes the client delegation is active; for bootstrap the
  prospective NID, intent, recovery key, and proof remain exact; and
- when `client_authorization` is `approval` or `role`, that exact referenced
  lineage remains active; authority activation has its required one active
  target role, while any other role required by the grant remains active and
  unique; and
- for authority activation, every `archive_restore_basis` equality, completed
  archive-transfer receipt, routine-addition and delivery checkpoint, source/
  assignment exposure, governed-head/key-binding state, active
  historical-obligation and retired-provenance binding, archive inventory, and
  reconciliation gate defined below remains canonical and current.

Any grant expiry, KEL rotation/staleness, delegation revocation, approval
expiry/revocation/fork, bound server/client role update/revocation/fork, or
grant revocation makes the
predicate false immediately. Proof of the bound client SSH key is still
required for each authenticated session. No later paragraph weakens this
predicate.

Archive bootstrap delivery reaches only isolated `bootstrap-validated` bulk
staging. Before the authority DEK may be opened, the prospective NID completes
ordinary Core delegation and ADR-037's `routine-addition` transition. Its
fully receipted accepted checkpoint names the NID in `node_roster`, binds the
mandatory fresh config-audience and OAuth-pairwise successors, and passes every
mandatory/cleanup exposure action. That digest is
`archive_restore_basis.addition_checkpoint_digest`. A pending addition,
unreceipted checkpoint, missing mandatory rotation, or merely local NID record
cannot pass this gate.

After addition acceptance, a separate authorization-record mutation and fully
receipted checkpoint grants any required credential-sync/protected-transfer
authority. Canonical source companion and assignment records are then created
for the current epoch and every current generic secret the new node will use.
For an old instance still required by governed ciphertext, distribution is
only through one accepted ADR-037 transition action whose
`historical_decrypt_nids` contains the exact recovery/decrypt-only holder set
and whose `historical_assignment_digests` contains its complete one-to-one
fresh-ID assignment set. That action retires every old operational or prior
historical assignment, carries the same old secret tuple into the fresh
decrypt-only assignments, binds their sources to the complete projected-active
retain-obligation head set, applicable governed bindings, and governing
artifact/pointer proofs, and adds the assignments to the result exposure
digest. It may add the new node to
`current_holder_lineages`, but it neither replaces active obligation heads or
retired provenance nor authorizes new encryption with the old key. One or more
accepted post-addition checkpoints bind those exact exposures and name the node
as holder.
`delivery_checkpoint_digests` is the complete nonempty canonical-chain-ordered
set of checkpoints needed for those deliveries; every member is strictly
after the addition checkpoint and the final member equals
`credential_checkpoint_digest`. The final checkpoint's digest,
`exposure_set_sha256`, `governed_decrypt_key_bindings_sha256`,
`historical_decrypt_obligations_sha256`, exact retention-snapshot/binding
state `K(C)`, complete maximal obligation frontier, active-retain subset, and
exact generic current-holder/obligation/provenance sets—including each
historical action's `historical_decrypt_nids` and
`historical_assignment_digests` projection—equal the archive high-water and
inventory. Its epoch current-holder set equals the special epoch binding.
`special_authority_bindings_sha256` is:

```text
SHA256(
  UTF8("heterodyne-recovery-special-authority-bindings-v1") || 0x00 ||
  UTF8(JCS(manifest.special_authority_bindings))
)
```

and `governed_decrypt_key_bindings_sha256`,
`historical_decrypt_obligations_sha256`, and `secret_inventory_sha256` equal
their basis and manifest high-water members.
Every remaining archive-basis member equals the exact finalized allocation,
manifest, prior transfer grant/receipt, authority tuple, and committed required
epoch slot. The archive therefore binds state at or after the final delivery
checkpoint and is normally newly produced and finalized after admission. An
archive whose checkpoint, governed-head/binding set, obligation set,
inventory, special epoch holder lineages, or authority tuple predates this
transition is ineligible; later local erasure, promised non-use, or a failed
restore never removes an exposure and cannot excuse a missing source,
assignment, binding, obligation, or retirement record.

Only after those checkpoints and the target recovery-node role are canonical
may the node request an `authority-activation` grant. Its client NID and
recovery key match that role, its named approval contains
`recovery.activate` and `authority.read`, its sole resource is `authority`, and
its complete `archive_restore_basis` passes the equations above. The current
epoch-authority process creates the exact payload, hashes it into the resource,
obtains the device and epoch signatures over the envelope that already
contains the same basis, and registers the complete envelope at the serving
node. Any other ordering or payload substitution fails the transcript or
resource digest check.

The resource bytes are the JCS encoding of this closed HPKE envelope:

```json
{
  "type": "heterodyne-recovery-epoch-activation-envelope-v1",
  "grant_id": "<32 lowercase hex>",
  "role_record_digest": "<64 lowercase hex>",
  "archive_restore_basis_sha256": "<64 lowercase hex>",
  "issued_at": 0,
  "kem": "DHKEM-X25519-HKDF-SHA256",
  "kdf": "HKDF-SHA256",
  "aead": "AES-256-GCM",
  "enc": "<unpadded base64url>",
  "ciphertext": "<unpadded base64url>"
}
```

HPKE base mode uses the role record's X25519 key and encrypts this exact
closed plaintext:

```json
{
  "type": "heterodyne-recovery-epoch-activation-v1",
  "grant_id": "<32 lowercase hex>",
  "persona": "<64 lowercase hex>",
  "role_record_digest": "<64 lowercase hex>",
  "target_nid": "<canonical Ed25519 did:key>",
  "recipient_key": "<unpadded base64url 32-byte X25519 key>",
  "recipient_fingerprint": "<64 lowercase hex>",
  "epoch_pubkey": "<64 lowercase hex>",
  "kel_head": {"event_id": "<64 lowercase hex>", "seq": 0},
  "archive_restore_basis_sha256": "<64 lowercase hex>",
  "issued_at": 0,
  "epoch_secret": "<64 lowercase hex valid secp256k1 scalar>"
}
```

`archive_restore_basis_sha256` is exactly:

```text
SHA256(
  UTF8("heterodyne-recovery-archive-restore-basis-v1") || 0x00 ||
  UTF8(JCS(grant.archive_restore_basis))
)
```

HPKE `info` and AAD are both the JCS bytes of exactly
`{type:"heterodyne-recovery-epoch-activation-v1",grant_id,persona,
role_record_digest,target_nid,recipient_fingerprint,epoch_pubkey,kel_head,
archive_restore_basis_sha256,issued_at}`.
The recipient fingerprint is SHA-256 of the decoded X25519 key. The recipient
rejects unless the outer and plaintext
`grant_id/role_record_digest/archive_restore_basis_sha256/issued_at` values
are identical; those values equal the active transfer grant's exact
`grant_id`, `client_authorization.role_record_digest` (also the sole authority
resource ID), computed archive-restore-basis digest, and `issued_at`.
Plaintext `persona` and `kel_head` equal the grant; `target_nid` equals
`client_nid` and the active client-role target; `recipient_key` equals both
`client_recovery_key.public_key` and that role's recovery key; its decoded
fingerprint is exact; and
`epoch_pubkey` is the exact current BIP-340 key derived from that grant KEL head
and used for its epoch countersignature. The private scalar MUST derive that
same key. Immediately before protected-store installation the recipient
re-evaluates the complete registered envelope and `grant_active(now,state)`,
including current canonical KEL equality, role/delegation activity, approval,
expiry, and revocation. A historical key/head, a changed current head, or any
payload/grant mismatch rejects even if HPKE authentication succeeds. Every
role value and the epoch-countersigned transfer grant bind the complete
envelope digest.

The decrypted scalar is a transient slot-opening capability, not installable
epoch authority. It MUST authenticate and open the archive's complete,
byte-identical original epoch recipient slot named by
`archive_restore_basis.required_epoch_slot`; the slot MUST be one of the
manifest's exact required epoch slots, bind the same current
`archive_authority` tuple, and yield exactly the 64-byte
`DEK || authority_DEK` bundle. A missing, relabeled, substituted, stale, or
non-opening slot rejects the activation and erases the scalar.

Successful slot opening begins a new ordinary full-archive restore from the
immutable archive bytes. The implementation MUST discard every
bootstrap-layer parse object and verdict, reparse the header and signed
manifest, reauthenticate every chunk and entry under the recovered DEK,
validate the complete nonce set and entry/path matrix, open and validate every
special and generic authority envelope under the recovered `authority_DEK`,
recompute the complete durable-secret inventory, governed retention-snapshot
and key-binding state `K(C)`, maximal historical-obligation frontier and
active-retain subset, governed-ciphertext bijection, current-holder lineages,
retired provenance, and checkpoint/exposure equalities, validate the complete
normal-or-gap rollover closure, and repeat the ordinary rollback comparison
against then-current canonical state.
Bootstrap staging is only an immutable byte source: activation never upgrades
`bootstrap-validated`, reuses its hidden-material conclusions, or installs
anything by itself.

Only after that new ordinary restore succeeds in full may one atomic protected
transaction install the current epoch scalar, the archive's validated special
authority material, and every required generic current or historical secret.
The activation scalar may be persisted only in that transaction and only when
it is byte-identical to the epoch material recovered from the special epoch
envelope. The transaction also records the exact restore-basis digest and
ordinary-restore result. Any KEL, rollover, checkpoint, inventory, source,
assignment, governed head, key binding, obligation, provenance, governed
ciphertext, role, approval, archive-authority, archive-generation, manifest,
finalization, or required-slot value that changed since grant issuance makes
`grant_active` false or the ordinary restore stale; the recipient rejects,
installs no durable secret, and erases all transient scalar/DEK bytes. A failed
or unused activation remains an ADR-037 exposure and never licenses removing
its source, assignment, binding, obligation, or retirement records.

Future ordinary archive transfer may instead wrap both DEKs directly to a
newly authorized recipient after the same admission, checkpoint, source,
assignment, and reconciliation gates. That separate two-DEK recipient-slot
path is `delegated-transfer`, not bootstrap promotion or epoch activation, and
still performs a new ordinary restore before installation. The server's read
receipt attests completed delivery, never slot opening or the recipient's
durable commit. `authority.put` is not allocated.

Every epoch rotation first produces and accepts the normal-or-gap state
rollover closure bound to that rotation. The active recovery-node role and
approval sets are then computed from the rollover-ratified frontier plus any
valid current-epoch successors. Before any retained node receives new
authority, its ADR-037 addition/source/assignment/delivery checkpoint and
reconciliation gates must again cover the exact secret set exposed to it.
Only then does the node create a fresh activation envelope and separately
signed transfer grant for each retained role. The complete grant envelope is
registered at an active serving node before that target pulls it; no other
node receives the new epoch scalar. A node does not exercise newly delivered
authority until the matching KEL rotation, normal-or-gap rollover closure,
and ordinary archive restore are canonical. Removing a recovery node is one
fail-closed ceremony: commit its absorbing node-role revoke, rotate the epoch
key, accept the rollover that ratifies that terminal role state, complete the
required ADR-037 reconciliation, and redistribute the new authority only to
retained active roles. Revocation without that rotation, rollover, and
reconciliation does not revoke a copied secret and MUST be reported as
incomplete. If authority was released before a role was durable, before
rollover acceptance, before reconciliation, or to a role omitted from the
accepted frontier, clients revoke the role and rotate again. Old archive
copies and old epoch secrets cannot be clawed back; KEL rotation makes them
non-current.

Revocation is absorbing. A closed
`heterodyne.recovery-transfer-grant-revocation.v1` object contains exactly
`type`, `grant_id`, `persona`, `server_nid`, `revoked_at`, `reason_code`,
`revoker`, and `signature`. `revoker` is exactly
`{"type":"epoch-secp256k1"|"device-ed25519","key":"<canonical key>"}`. The
reason is exactly `recovery_grant_cancelled`, `recovery_policy_changed`, or
`recovery_role_revoked`. The
current epoch key or the original still-active authorizer NID signs SHA-256 of
`UTF8("heterodyne-recovery-grant-revocation-v1")`, a zero byte, and the JCS
object with `signature` omitted. Epoch signatures are 128 lowercase hex;
device signatures are unpadded base64url of exactly 64 bytes. It is delivered
on an authenticated path,
stored by Core under
`keys/core/recovery/grant-revocations/<grant_id>/<digest>.json`, and takes
effect immediately at the target. The Comms composition mirrors it under
`recovery/grant-revocations/<grant_id>/<digest>.json` in the encrypted config
repository for multi-node durability. An
expired, revoked, wrong-server, stale-KEL, or no-longer-authorized grant cannot
open a new channel or continue an existing one.

### Constrained subsystem

The onion SSH service authenticates possession of the bound SSH key and maps
it to the registered grant. The SSH username is exactly
`epoch-recovery:<persona>:<grant_id>` and denotes a logical principal, not an
operating-system user.

The closed transport profile is SSH-2 with:

- `curve25519-sha256` key exchange;
- `ssh-ed25519` server-host and public-key user authentication;
- `aes256-gcm@openssh.com` authenticated encryption;
- no password, keyboard-interactive, host-based, or anonymous authentication;
  and
- no SSH compression.

The only accepted subsystem name is `heterodyne-transfer-v1`; SFTP is not
enabled. Each subsystem frame is:

```text
uint32be(header_length) || JCS(header) || body
```

The header is at most 64 KiB and `body` is exactly `body_length` bytes and at
most 1 MiB. A channel is a concatenated sequence of complete frames; “no
extra channel bytes” means EOF may occur only at a frame boundary. The closed
header shape has exactly:

```json
{
  "version": "heterodyne-transfer-v1",
  "request_id": "<32 lowercase hex>",
  "target_request_id": null,
  "type": "request",
  "operation": "object.read",
  "resource": {
    "class": "object",
    "id": "<64 lowercase hex>",
    "descriptor_sha256": null,
    "payload_sha256": "<same 64 lowercase hex>",
    "payload_length": 1048576
  },
  "offset": 0,
  "length": 1048576,
  "body_length": 0,
  "body_sha256": null,
  "transfer_sha256": "<64 lowercase hex from prior stat>",
  "final": false,
  "status": null,
  "reason_code": null
}
```

`type` is `request`, `response`, `receipt`, or `error`. Operations are
`archive.stat`, `archive.read`, `archive.put`, `object.stat`, `object.read`,
`object.put`, `authority.stat`, `authority.read`, and `cancel`. `resource` is the exact grant
resource object. The scope mapping is closed:

| Operation | Required grant scope |
|---|---|
| `archive.stat` | the grant's sole `archive.read` or `archive.write` direction |
| `archive.read` | `archive.read` |
| `archive.put` | `archive.write` |
| `object.stat` | the grant's sole `object.read` or `object.write` direction |
| `object.read` | `object.read` |
| `object.put` | `object.write` |
| `authority.stat`, `authority.read` | `authority.read` plus active role and `recovery.activate` approval |
| `cancel` | the scope of the targeted operation |

Archive transfer bytes are the complete single-file container, including
magic, header-length prefix, mutable recipient-slot header, and ciphertext.
Object transfer bytes are the complete stored object. Authority transfer bytes
are the complete JCS activation envelope. Zero-length resources are rejected.
Transfer ranges use a fixed 1 MiB grid over those complete bytes and are
deliberately independent of cryptographic chunk boundaries: offsets are
multiples of 1 MiB, every non-final range is exactly 1 MiB, and the final
range is 1 through 1 MiB. A range can contain the archive clear prefix and
header, cross from header into ciphertext, or cross one or more archive/object
cipher chunks. The receiver reassembles the complete resource before parsing
and separately verifies each cryptographic chunk.

Before the first successful stat response, the server establishes one durable
transfer stage for each `(grant_envelope_digest, resource, direction)` tuple.
A read stage materializes the byte-exact source and freezes its positive full
length, bytes, and `transfer_sha256`. For an archive in bootstrap mode, this
includes generating the recipient-specific HPKE bootstrap slot exactly once.
A delegated-transfer archive is served byte-for-byte as already stored and
the active client must possess an existing ordinary recipient slot; this
baseline does not rewrap an archive for an already delegated client. An
authority read uses exactly `UTF8(JCS(authority_payload))` from grant
registration; staging neither creates nor changes its HPKE bytes.

A write stage does not presuppose bytes that the client has not uploaded. It
starts with an empty destination and empty verified-range bitmap and freezes
only the stat request's declared positive complete length and
`transfer_sha256`. As put frames arrive, their verified bytes and bitmap
coverage become durable stage state; a retry may add an absent valid range or
repeat byte-identical accepted bytes but cannot change either the declaration
or an accepted range.

The applicable read source or write declaration and accepted stage state are
frozen across retries, sessions, and stat calls while
`grant_active(now,state)` remains true. Completion blocks new authorization
but does not permit discarding bytes needed for an authorized cached replay.
When the predicate first becomes false, the server stops all work and erases
the stage. A read stage never regenerates a changed archive header under the
same grant/resource, and a write stage never accepts a changed declaration or
conflicting bytes. If the server cannot retain the required read source or
write stage state, it returns `transfer_staging_unavailable` before accepting
the stat or aborts the incomplete resource without promotion. A client
persists the first stat result and rejects any changed length or digest during
resume.

At grant issuance every signed `payload_length` is at most `max_bytes`; the
sum of resource payload lengths is also at most `max_bytes`. Before stat
success, the complete read-source length or declared write length MUST
separately fit `max_bytes`; for an archive this length includes its mutable
header in addition to the signed immutable ciphertext payload.

A read-direction stat request declares no bytes, length, or transfer digest;
the server stages the resource and returns the positive complete transfer
length and its SHA-256. A write-direction stat request instead declares the
positive complete transfer length in `length` and its complete-byte SHA-256
in `transfer_sha256`, with empty body. The server freezes that declaration,
creates the empty write stage, rejects an impossible length or byte limit, and
returns the same values. For object write, declared length/hash exactly equal
resource `payload_length/payload_sha256`. Authority has no write direction.
For archive write, declared length includes magic, prefix, and header and is
greater than the signed immutable ciphertext `payload_length`; after complete
coverage the server requires the reassembled byte length and SHA-256 to equal
the frozen declaration, then requires the parsed header to declare exactly
that payload length and the signed descriptor/ciphertext digests before
promotion or a completion receipt. A changed stat declaration for the same
tuple is a resource mismatch. No read or put frame is accepted before its
matching successful stat.

`request_id` is a fresh random 16-byte value. Except where stated below,
responses echo the request's ID, operation, resource, offset, length, and
`final`. Every nonempty frame body has lowercase-hex SHA-256 in
`body_sha256`. The conditional state table is normative:

| Frame | Required field state |
|---|---|
| read-stat request | read-scope stat; `target_request_id:null`; `offset:0`; `length:0`; `body_length:0`; both hashes null; `final:false`; status/reason null |
| write-stat request | write-scope stat; target null; offset 0; `length` = declared positive complete transfer length; body length 0/body hash null; transfer hash = declared complete-byte SHA-256; `final:false`; status/reason null |
| stat response | target null; offset 0; `length` = frozen complete length; body length 0; body hash null; transfer hash = frozen read-source SHA-256 or write declaration; `final:true`; `status:"ok"`; reason null |
| read request | target null; grid-valid offset/positive length from the prior stat; body length 0/body hash null; transfer hash equals stat; final is exactly `offset+length==complete_length`; status/reason null |
| read response | target null; same range; `body_length==length`; body hash present; transfer hash equals stat; exact final bit; `status:"ok"`; reason null |
| put request | target null; grid-valid range from the prior write stat; `body_length==length`; both hashes present; transfer hash equals the frozen write stat; exact final bit; status/reason null |
| put response | target null; same range; body length 0; `body_sha256` echoes the accepted request-body hash; transfer hash echoes request; exact final bit; `status:"ok"`; reason null |
| completion receipt | target null; echoes the request ID and operation of the data frame that completed full range coverage; offset 0; length = complete resource length; body is the signed receipt; both hashes present; `final:true`; `status:"complete"`; reason null |
| error | echoes the offending request ID, target request ID, operation, resource, range, transfer hash (or null if not yet staged), and exact final bit; body length 0/body hash null; `status:"error"`; allocated reason |
| cancel request | fresh ID; `target_request_id` names an outstanding request in this authenticated session; operation `cancel`; resource equals target resource; offset/length/body length zero; both hashes null; final false; status/reason null |
| cancel response | echoes cancel request ID and target ID; same resource; zero range/body and null hashes; `final:true`; `status:"cancelled"`; reason null |

The only non-null status values are `ok`, `complete`, `cancelled`, and
`error`. Non-error frames always have `reason_code:null`; error reason codes
use the allocated `transfer-error` values above. An error frame is emitted
only when the offending header provides a canonical error-frame echo basis:
`request_id`, `target_request_id`, an allocated `operation`, the exact closed
`resource`, nonnegative integer `offset` and `length`, Boolean `final`, and a
`transfer_sha256` that is either null or a valid 64-lowercase-hex value can
all be represented in the error row above. A missing field, wrong type,
unallocated operation, malformed resource, noncanonical integer or hash, or
otherwise unrepresentable echo value closes the subsystem without an error
frame. This connection-close rule also applies to an invalid length prefix,
unparseable JSON, or non-JCS header. `transfer_bad_frame` is available only
for a closed-table violation after the complete echo basis is representable.
Otherwise the mapping is exact:

| Condition | `reason_code` |
|---|---|
| parseable frame violates the closed field/type/conditional table | `transfer_bad_frame` |
| request ID is reused with different bytes | `transfer_request_id_conflict` |
| grant expired/revoked or required approval/role is inactive | `transfer_authorization_inactive` |
| operation is not covered by the grant's sole direction | `transfer_scope_mismatch` |
| resource is absent from the grant or its immutable identity differs | `transfer_resource_mismatch` |
| offset, length, final bit, or grid is invalid | `transfer_range_invalid` |
| declared/frozen total length conflicts with the resource or completed parsed representation | `transfer_length_mismatch` |
| accepting the first copy would exceed `max_bytes` | `transfer_byte_limit_exceeded` |
| body, complete-transfer, descriptor, payload, or semantic digest fails | `transfer_digest_mismatch` |
| a put range conflicts with bytes already accepted for that range | `transfer_range_conflict` |
| cancel target is unknown, completed, or outside the authenticated session | `transfer_target_not_found` |
| new data is requested for a resource already completed | `transfer_grant_closed` |
| the server cannot create or retain the required frozen stage | `transfer_staging_unavailable` |
| a completed archive write lacks valid applicable rollover state, required-slot commitments, or an ordinary class-sufficient recipient slot the destination can authenticate and open | `transfer_destination_unrecoverable` |

For simultaneously observable conditions, table order is precedence except
that an unrecoverably malformed frame follows the connection-close rule.

A protocol `cancel` cancels only the named outstanding request. Whole-grant
cancellation uses the signed absorbing grant-revocation record, never a frame.
Unknown, completed, or cross-session target IDs return an allocated error.
Requests with duplicate IDs must be byte-identical; a conflicting reuse is an
error.

The server maintains a durable verified-range bitmap per staged resource.
`final:true` means only that a range ends at the declared complete length; it
does not mean all preceding ranges have been served or accepted. An
out-of-order final range therefore remains incomplete, emits no receipt, and
does not close the resource. Completion occurs only when the union of verified
grid ranges covers every byte exactly once from offset zero through the
declared length.

The receiver parses a completed archive and requires its descriptor and
ciphertext digests to equal the immutable grant resource. For an object,
`transfer_sha256 == resource.payload_sha256`; the same equality is required
for an authority envelope. For a recipient-rewrapped archive the complete-file
transfer digest normally differs from the immutable payload digest in the
grant. A byte range is charged once by
`(direction,resource,offset,length,body_sha256)`; the server atomically
reserves the charge before I/O so parallel sessions cannot exceed
`max_bytes`.

Writes are staged; object writes are content-addressed while archives retain
their random ID and immutable payload identity. Repeating the same verified
range is idempotent; conflicting bytes reject the resource. The server
promotes an archive or object only after every range, declared complete
length, complete transfer digest, and the resource's semantic digests verify.
If the archive's named KEL state includes an epoch rotation, the destination
also requires the applicable unique normal-or-gap latest rollover closure,
every recursively linked normal rollover or gap base/skipped/repair member,
and every referenced head to validate from the archive or its canonical
recovery store. Missing, conflicting, or unresolved rollover/gap state leaves
the staged archive nonpromoted and returns
`transfer_destination_unrecoverable`.
Before archive promotion, the destination server MUST also authenticate and
open at least one ordinary recipient slot in the uploaded header using a key
it currently controls under its active recovery role and protected-key
boundary. A bootstrap slot is not an ordinary slot and cannot satisfy this
check. For `full`, that opening MUST yield the exact 64-byte
`DEK || authority_DEK` bundle and both keys MUST successfully authenticate
the encrypted entry stream and epoch-authority envelope under the full-archive
equality matrix. It MUST then verify that the uploaded header contains both
complete byte-identical slots committed by the signed manifest's exact
cold-root/epoch `required_recipient_slots` array. Opening the destination's
added ordinary slot does not excuse a stripped, relabeled, or substituted
required slot. For `device-local` or `clone-device`, the opening MUST yield
the bulk DEK needed to authenticate the encrypted entry stream; any supplied
but unused authority DEK follows the mandatory destruction rule. For
`clone-device`, the server also verifies that the manifest's required array is
nonempty, every entry has a closed ordinary slot type/role shape and is not a
forbidden platform-local or bootstrap type, the signed producer commitment
verifies, and every complete committed slot remains byte-identical in the
uploaded header. Loss-of-host independence and the original self-test are
producer-conformance facts; `archive.put` does not claim to re-prove them
without the user's separate portable-device, hardware, or passphrase secret.
The destination may use its own added ordinary slot for archive authentication
while health still requires the user to exercise a committed clone path. For
`device-local`, the required array MUST be exactly empty. The server erases all
transient unwrapped key bytes after validation. Missing, malformed,
unauthenticated, or class-insufficient destination key material returns
`transfer_destination_unrecoverable`, performs no promotion, and emits no
completion receipt. The server neither treats a bootstrap-only wrap as
durable destination recovery nor silently creates an unapproved replacement
slot. An empty clone commitment, forbidden clone slot type, or missing or
mismatched required-slot commitment returns the same error and leaves the
staged copy nonpromoted.
After a read response makes verified read coverage complete (including
`authority.read`), or after complete write coverage is verified and promoted,
the server emits exactly one
per-resource completion receipt with the closed JCS shape:

```text
type, server_nid, grant_id, resource, operation, direction, length,
transfer_sha256, completed_at, signature
```

`type` is `heterodyne.transfer-receipt.v1`; `direction` is `read` or `write`
and agrees with `operation`. The server NID signs SHA-256 of
`UTF8("heterodyne-transfer-receipt-v1")`, a zero byte, and the JCS object with
`signature` omitted, using Ed25519 encoded as unpadded base64url of exactly
64 bytes. The receipt's JCS bytes are the body of the `receipt` frame and are
covered by `body_sha256`. A bootstrap client accepts delivery only after
receiving and verifying the read receipt and locally verifying complete byte
coverage. While `grant_active(now,state)` is true, a byte-identical replay of any
previously accepted read request returns the same range from the frozen staged
bytes without recharging; once generated, the identical cached receipt
accompanies every such replay. A lost response on one parallel session can
therefore be recovered after server-side completion without reopening
authority or changing bytes. Every following replay has the same predicate.
The server likewise retains
every accepted put request and response while that predicate is true. A
byte-identical replay of any previously accepted put returns the identical cached put response without
recharging or re-promoting; once write completion has occurred, the identical
cached write receipt accompanies every such replay. Thus loss of the put
response or write-completion receipt remains recoverable after atomic
promotion. Conflicting request bytes still fail.

It prohibits interactive shell, arbitrary exec, filesystem browsing,
arbitrary filesystem writes, PTY allocation, TCP/Unix-socket forwarding, X11
forwarding, and SSH-agent forwarding. Bounded
`archive.put` and `object.put` are permitted only for an already delegated
device or recovery peer holding the corresponding durable approval and grant;
a prospective bootstrap node remains read-only. The client pins the onion
address and SSH host key from the grant.

The recovery node rewraps the archive DEK to the prospective node's recovery
recipient. Neither the plaintext DEK nor a plaintext epoch secret appears on
the transfer protocol; the separately authorized HPKE activation envelope
carries only the transient scalar that can open the exact already-committed
required epoch slot. It does not directly install authority. The server
handles the transient archive key bundle within its protected key boundary,
copies only the bulk DEK into the bootstrap plaintext, and erases both
transient keys after rewrapping. The grant expires after eight hours and may
be revoked sooner. Idempotent,
key-bound range retries are
allowed during its lifetime, share one monotonic byte counter, and cannot
exceed the bound by opening parallel sessions. A completion receipt closes
only its resource. The grant closes to new data authorization after every listed
resource has a completion receipt, or immediately on signed whole-grant
revocation, expiry, or approval/role revocation. “Closes” rejects new data
requests but permits any byte-identical previously accepted read or put replay
and the applicable cached receipt above only while
`grant_active(now,state)` remains true. The server re-evaluates that complete
predicate before every replay; false stops cached disclosure as well as new
work. An interrupted incomplete resource may resume only under the same
predicate.

After `bootstrap-validated` bulk staging, the new node completes ordinary
delegation, the fully receipted ADR-037 routine-addition checkpoint with its
mandatory config-audience and OAuth-pairwise rotations, a separate
authorization checkpoint, all source/assignment deliveries, and
reconciliation. Only after its durable recovery role and post-transition
archive basis are canonical may it receive epoch activation. That scalar must
open the basis's exact required epoch slot and drive a new ordinary full
restore; activation alone installs nothing. Merely downloading the archive
grants no publishing, delegation, recovery-node, or epoch authority.

Recovery nodes create their own current archive locally or receive an
encrypted archive through `archive.put`. Existing authorized devices upload
large objects with `object.put`; recovery nodes replicate immutable stored
bytes to one another under separate bounded grants. No put operation accepts
plaintext key material, overwrites a content-addressed object, or authorizes
deletion. Garbage collection remains driven by canonical repository
reachability and the future repo-relay storage profile.

## Large-object profile

### Thresholds and storage budget

For each persona on each node:

- the default managed-storage budget is exactly `5 * 2^30` bytes;
- the default Radicle-eligible per-object threshold is exactly
  `100 * 2^20` bytes;
- the warning threshold is exactly `1 * 2^30` bytes; and
- an exact `64 * 2^20`-byte default reserve is kept for KEL, revocation, credential-ledger,
  status, and other security-critical records.

These are configurable policy defaults, not network hard limits. Available
space is the minimum of configured remaining budget and physical filesystem
free space. Managed storage includes live public, private, config, and keys
repositories; retained recovery archives; managed large-object ciphertext;
and client-managed audit, observability, log, and cache data. It excludes
operating-system overhead and user-controlled offline copies outside the
client store. The 64 MiB reserve is inside the 5 GiB budget. The client warns
when available space drops below 1 GiB and stops nonessential writes before
they would consume the reserve.

The accounting ledger counts each retained Git pack/object, archive, or
content-addressed stored object once by its actual stored byte length, plus
ordinary managed file lengths; filesystem block slack and operating-system
metadata are handled by the separate physical-free-space check. An object of
exactly 100 MiB remains Radicle-eligible; a larger one uses the pointer
profile. No warning occurs at exactly 1 GiB remaining. A nonessential write is
refused if it would leave less than the 64 MiB reserve. Security-critical
writes may consume the reserve down to the actual hard limit and fail closed
if durable persistence is impossible. The client never silently evicts
authoritative objects. Cache eviction requires a declared policy and another
authorized recovery source or backup.

This is a local client/recovery-node safety default and simulated policy
conformance surface. It does not define remote repo-relay admission, tenant
quota, retention, namespace, or garbage-collection behavior reserved for the
future repo-relay server/storage ADR.

### Pointer and transfer

An object above the configured Radicle threshold is stored in the recovery
large-object store only when its pointer is in a Tier 2 private repository or
a Tier 3/config protected branch. At the object's ordinary repository path,
the Git blob is exactly:

```text
HETERODYNE-LARGE-OBJECT-V1\n || JCS(pointer) || \n
```

with no other bytes. The closed pointer has:

```json
{
  "type": "heterodyne-large-object-v1",
  "object_id": "<64 lowercase hex SHA-256 of complete stored bytes>",
  "plaintext_length": 1048577,
  "stored_length": 1048609,
  "media_type": "application/octet-stream",
  "role": "media",
  "chunk_plaintext_bytes": 1048576,
  "chunk_digests": [
    "<64 lowercase hex SHA-256 of stored chunk 0>",
    "<64 lowercase hex SHA-256 of stored chunk 1>"
  ],
  "encryption": {
    "profile": "aes-256-gcm-chunked-v1",
    "object_nonce_id": "<64 lowercase hex>",
    "key_id": "<allocated protected-branch key id>",
    "wrapped_dek": "<unpadded base64url>",
    "audience_dependency": {
      "secret_class": "tier3-audience",
      "secret_id": "<class-valid lowercase hex>",
      "instance_commitment": "<64 lowercase hex>"
    },
    "object_dek_dependency": {
      "secret_class": "object-dek",
      "secret_id": "<64 lowercase hex>",
      "instance_commitment": "<64 lowercase hex>"
    }
  },
  "recovery_nodes": [
    {
      "nid": "<canonical node NID>",
      "onion": {"host": "<v3 onion hostname>", "port": 22},
      "host_key": {
        "algorithm": "ssh-ed25519",
        "public_key": "<unpadded base64url 32-byte key>"
      }
    }
  ]
}
```

`role` is an allocated lowercase ASCII identifier; `media_type` is a
lowercase registered media type or null. Recovery-node hints are sorted by
NID, onion hostname, port, and host-key bytes. They are discovery hints, not
authorization; a valid transfer grant is still required. The chunk-digest
array is nonempty and ordered by increasing chunk index. Empty large objects
are not encoded by this profile.

For a Tier 2 pointer, `profile` is `none`, stored bytes are plaintext,
`plaintext_length == stored_length`, and `object_nonce_id`, `key_id`, and
`wrapped_dek`, `audience_dependency`, and `object_dek_dependency` are null.
Non-final stored chunks are exactly 1 MiB; the final
chunk is 1 byte through 1 MiB. This preserves Tier 2's stated trust boundary:
every allowed seeder can read the object.

For a Tier 3 or protected config pointer, `profile` is
`aes-256-gcm-chunked-v1`; the producer generates a random 32-byte object DEK
and random 32-byte `object_nonce_id`. Plaintext chunks follow the same
1 MiB/final rules. The 96-bit nonce is:

```text
0x48444c4f || uint64be(chunk_index)
```

where `HDLO` is the domain marker. AAD is the UTF-8 encoding of:

```text
heterodyne-large-object-chunk-v1|<object_nonce_id>|<index>|<chunk_plaintext_length>|<final>
```

where `chunk_plaintext_length` is the current chunk's length, not the complete
object length, with the same canonical integer/final encodings as archive
chunks. Each stored
chunk is AES-256-GCM ciphertext followed by its 16-byte tag. Non-final stored
chunks are therefore 1 MiB + 16 bytes. `object_id` hashes the concatenation of
stored chunks, and each `chunk_digests` member hashes exactly one stored chunk,
never plaintext.

The immutable chunk AAD deliberately excludes the mutable audience `key_id`.
Audience rotation rewraps the same object DEK without invalidating stored
ciphertext.

For either profile, `chunk_count = ceil(plaintext_length / 1048576)` and the
array length must equal `chunk_count`. For the encrypted profile,
`stored_length = plaintext_length + 16 * chunk_count`; for `none`, it equals
`plaintext_length`.

The Tier 3/config protected branch's 32-byte audience key derives a KEK with HKDF-SHA256:
IKM is the audience key, salt is decoded `object_nonce_id`, info is
`UTF8("heterodyne-large-object-kek-v1|"+key_id)`, and output length is 32.
RFC 3394 AES-KW wraps the object DEK; `wrapped_dek` therefore decodes to
40 bytes. The pointer containing that wrapper remains inside the private,
config, or Tier 3 protected branch. Audience-key rotation either retains the
authorized old key or atomically republishes a pointer with the same stored
object and a newly wrapped DEK. Retaining the old key is permitted only when
the authorized audience is unchanged. Removing or losing any prior key holder
MUST publish the new wrapper, cease all new use of the old audience key, and
apply the credential secret-transition rules; copied old pointers/ciphertext
remain readable and are never described as retroactively revoked.

The two dependency objects are non-null for the encrypted profile.
`audience_dependency.secret_class` is exactly `config-audience` for a config
branch or `tier3-audience` for a Tier 3 branch; its `secret_id` equals
`encryption.key_id`, and its commitment equals the canonical source/exposure
tuple for that exact audience instance. `object_dek_dependency` has exact class
`object-dek`, a 64-lowercase-hex secret ID, and the canonical commitment of the
generated object DEK. Both tuples must resolve through the authenticated
source/exposure state at the governing checkpoint.

For each noncurrent dependency tuple, the authenticated pointer/branch profile
deterministically emits exactly its corresponding governed locator row: a
noncurrent `audience_dependency` emits the `git-blob` row for the exact
encrypted pointer/wrapped-DEK blob, while a noncurrent
`object_dek_dependency` emits the `large-object` row for the exact stored
ciphertext bytes. It emits both distinct rows only when both tuples are
noncurrent, never one multi-key row. Their different locator preimages produce
different binding IDs when bindings are needed. If both keys become
historical, `G(C)` contains both rows and requires one active obligation
coverage item for each tuple. Omitting an applicable row, adding a row for a
still-current dependency, swapping the tuples, binding both rows to one key,
or collapsing them because they arise from one logical pointer rejects.

Tier 1 public content has no grant-dependent pointer in this baseline. It
remains within the configured Radicle threshold so an anonymous public client
can retrieve it through the ordinary public repository. Public objects above
that threshold require a separately specified optional public-object carrier;
clients do not silently publish an inaccessible SSH-only pointer. SSH and Tor
protect private transport but are not substitutes for Tier 3 object
encryption.

The constrained subsystem transfers fixed complete-resource ranges that may
cross stored cipher-chunk boundaries. The receiver reassembles the object,
then verifies every exact stored chunk and `object_id` before making it
visible. Observability data and audit logs are private by default.

## Platform recommendations

The wire format is platform-independent. Implementations should use:

- Apple Keychain and Secure Enclave where available;
- Android Keystore, preferring hardware-backed or StrongBox keys where
  supported;
- Windows CNG/TPM, with DPAPI as a local fallback;
- freedesktop Secret Service or an explicitly detected TPM/PKCS#11 provider
  on Linux; and
- non-extractable WebCrypto keys persisted in IndexedDB for browser-local
  wrappers.

These facilities protect small wrapping secrets, not bulk repositories.
Device-bound facilities are never the only full-recovery path. A browser
cannot claim hardware-backed storage merely because a `CryptoKey` is
non-extractable.

## Standards anchors

The normative integration must pin its exact use of:

- [NIP-44 v2](https://github.com/nostr-protocol/nips/blob/master/44.md) for
  the cryptographic primitives and encoding reused by the explicitly adapted,
  non-NIP-01 cold-root and epoch recipient envelope;
- [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785.html) for JCS,
  [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final) for GCM,
  and [RFC 3394](https://www.rfc-editor.org/rfc/rfc3394.html) for AES-KW;
- [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html) for HKDF,
  [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html) for HPKE, and
  [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html) for Argon2id;
- [WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/#prf-extension) and
  [CTAP 2.2](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html)
  for hardware-authenticator PRF slots; and
- [RFC 4252](https://www.rfc-editor.org/rfc/rfc4252.html),
  [RFC 4253](https://www.rfc-editor.org/rfc/rfc4253.html), and
  [RFC 4254](https://www.rfc-editor.org/rfc/rfc4254.html) for SSH
  authentication, transport, and the constrained subsystem;
- [RFC 8731](https://www.rfc-editor.org/rfc/rfc8731.html) for
  `curve25519-sha256`, [RFC 8709](https://www.rfc-editor.org/rfc/rfc8709.html)
  for `ssh-ed25519`, and
  [RFC 5647](https://www.rfc-editor.org/rfc/rfc5647.html) together with
  [RFC 9212](https://www.rfc-editor.org/rfc/rfc9212.html) for SSH AES-GCM.

## Conformance

Revision 4 allocates:

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

Minimum vectors cover:

- exact header, descriptor, ciphertext digest, chunk nonce/AAD, manifest,
  conditional BIP-340/Ed25519 manifest signatures, path mapping,
  generation/finalization/abandonment records for persona and device chains,
  pending/finalized freshness, entry ordering, and successful multi-chunk
  round trip;
- full and both device-class header, manifest, allocation, finalization, and
  abandonment equality, including exact persona/delegation binding,
  cross-persona, cross-allocation, cross-class, and header/manifest transplant
  rejection; full vectors additionally bind one exact allocation/manifest
  authority/manifest-high-water/authority-envelope/decrypted-secret/finalization
  persona, epoch key, and KEL head through rollback comparison;
- `protocol_context` semantic closure for revision 4, including the exact
  registry `entry_set_sha256`, byte-identical selected document
  `artifact_manifest_path`/`artifact_set_sha256` pairs and recursive dependency
  closure, complete claimed-feature prerequisite closure, and exact
  configuration-owner/schema authorization; plus unsupported-archive handling,
  never local downscoping, for a wrong registry or artifact-set digest,
  mismatched artifact path/digest pair, a missing required dependency, feature,
  or owner, an unsupported or unprovided extra one, owner/schema without its
  governing document, and signed context reduction that attempts to make an
  otherwise required entry optional;
- exact revision-4 allocations of
  `rollover-gap-reason:rollover_state_unrecoverable`,
  `rollover-reference-member:previous-rollover-head`, and the
  `retain`/`close` historical-decrypt-obligation actions; the closed
  `core.recovery-state-rollover-gap.v1` and
  `comms.governed-decrypt-key-binding.v1` and
  `comms.historical-decrypt-obligation.v1` and
  `comms.repository-retention-inventory.v1` wire-profile bindings and schema
  digests; the closed `governed-decrypt-source-profile` allocation kind and
  exhaustive owner-bound source-profile table; the required
  `governed_decrypt_key_bindings_sha256` and
  `historical_decrypt_obligations_sha256` checkpoint schema members; and
  rejection of an unallocated value, wrong schema path/digest, missing profile
  entry, stale checkpoint schema, or profile outside the signed
  registry/artifact closure;
- exact `heterodyne.governed-decrypt-key-binding.v1` closed shape,
  deterministic typed-locator binding ID, authority transcript, complete
  digest, canonical config path, and accepted-predecessor to artifact-`A` to
  optional-binding-`K` to repository-inventory-`R` to obligation-`O` to
  transition-`T` to checkpoint-`C` to receipts dependency order; exact `K(C)`
  `{repository_inventory_records,governed_heads,binding_records}` derivation
  from checkpoint-authenticated inventory cuts and retention snapshots,
  including complete conflict variants and the
  `heterodyne-governed-decrypt-key-binding-set-v1` digest; no `K(C)` change
  for current-key posts; and atomic snapshot/binding updates for retirement,
  retained-set change, re-encryption, deletion, or close. Positives cover both
  an authenticated profile with an embedded tuple and one requiring the exact
  signed binding, plus a mixed-owner cut producing one head row per distinct
  selected-profile owner. Negatives cover an unmarked ciphertext, missing/extra/late
  or conflicting binding, binding for no enumerated dependency, hidden/extra
  snapshot or dependency, wrong tuple/locator/ID/authority/signature/path,
  artifact/binding/inventory/obligation cycle, unallocated/wrong-owner source
  profile, missing/extra/mismatched projected head owner, zero or multiple
  otherwise-unembedded tuples offered to one binding fallback,
  validator-selected tuple, changed `K(C)` during receipt collection, a new
  transition-bound `K`/`R`/`O`/dependent proof in parentless `B`, transition
  signing before complete proof bytes, an intermediate commit before
  direct-child `T`, a record naming `T`'s commit OID, or lexical Git tree order
  treated as dependency order. A positive carrier co-commits those finalized
  records in `T` under logical dependency/signing order even when their
  canonical paths sort differently;
- exact `heterodyne.repository-retention-inventory.v1` genesis, successor,
  emergency-merge, signature, complete-record digest, canonical path,
  deterministic ref ID, typed SHA-1/SHA-256 scan heads, row sorting, absorbing
  retirement, and complete maximal frontier. Positives cover initial
  config/private registration, monotone head advance, registering and fully
  scanning a new private ref before governed use, rotation that discovers its
  retained dependency, descendant-tree re-encryption or deletion followed by
  obligation close while the ancestor commit remains audit residue, a
  current-key post that does not mutate `K(C)`, exact ordinary config-key-
  acceptance, including no-dependency rotation/addition/removal with changed
  inventory/`K(C)`/governed-binding digest but byte-identical governed heads,
  binding records, and obligation digest, and emergency complete-`V_old`
  deregistration with complete
  closure basis, same-CAS old-ref deletion, and ancestor-only audit evidence
  without later ref scan, and an emergency record that
  parents and merges every competing inventory branch. Emergency convergence
  positives cover active/active, active/retired, retired/retired, and same-head/
  different-retired variants of one semantic row in both Git object formats:
  the resolution head orders every distinct variant head as its exact direct-
  parent set, its scanned exact tree gives every marked artifact locator one exact
  preserve/reencrypt-or-replace/delete-and-close disposition, fresh H*-based
  locators/bindings replace old-head forms, `G(B)=O(B)`, and the signed reset
  selects the retirement result without making ancestor history governed
  content. A retired config outcome includes a separate active config row.
  A branch-only newly registered row is preserved from the union even when
  every other parent lacks it. Config-row convergence uses the exact bound
  `heterodyne-config-retention-resolution-v1` multi-parent grammar while
  ordinary config history remains linear. A current-on-A/retired-on-B and a
  current-on-A/different-current-on-B vector both classify the A ciphertext
  through cross-branch `Current_I` as conservative rather than omitting it.
  A legitimate same-locator two-embedded-tuple profile with only one tuple
  noncurrent preserves pairwise accounting, while conflicting fallback
  bindings `L->t1`/`L->t2` clean both candidates before accepting one
  independently validated fresh H* result binding; the rejected candidate is
  terminal audit evidence and receives no active result obligation.
  Negatives cover omission of a prior private RID/ref or preexisting
  dependency, omission of a branch-only row outside `V_old`, governed content
  on an unregistered ref, wrong/non-config/premature deregistration,
  partial-variant or different-ref emergency subtraction, incomplete logical-tree closure,
  missing old-ref deletion, a missing conflict
  frontier member, arrival-order selection, ordinary retired-row drop/
  reactivation/advance, emergency resolution missing or adding a parent, wrong
  SHA-1/SHA-256 parent ordering, a non-common-descendant or unscanned merge,
  parent-local currentness used to omit a cross-branch historical dependency,
  singular-tuple selection for an embedded multi-tuple locator, omitted
  conflicting binding candidate or unavailable candidate bytes, fresh
  fallback binding without unique profile/ciphertext validation, an active
  obligation for a rejected candidate, a result pair absent from authenticated
  result bytes/binding, path
  collision or branch artifact without total disposition, silent
  ancestor-only disappearance, wrong signed retirement result, missing active
  config replacement, reused old-head locator/binding, missing fresh H*
  binding, post-reset `G(B) != O(B)`, later advance of retired H*, scan-head
  regression, an unbound config merge, wrong/extra/unsorted config parents,
  ordinary multi-parent config commit, wrong resolution message, RID/ref alias,
  format/ID mismatch,
  self-reference/cycle, a stale predecessor `K(C)` digest across mandatory
  config-row replacement, any other unchanged `K(C)` despite inventory drift,
  archive
  omission, treating an ancestor-only or loose object as a current dependency,
  ignoring an explicitly frozen retention ref, and acceptance of post-cut
  old-key content. A positive late pre-cut branch remains audit evidence but
  is excluded by the accepted reset cutoff rather than reopening H*;
- exact `heterodyne.historical-decrypt-obligation.v1` root/retain/update/close
  lineage, authority transcript, complete digest, sequence-bearing config
  path, accepted-transition projection, complete maximal
  `{obligation_id,lineage_sequence,action,record_digest}` frontier including
  close and competing branches, active-retain subset, and domain-separated
  checkpoint digest; both exact Git-blob and large-object ciphertext locator
  forms with typed SHA-1 and SHA-256 `repository_head`/`git_blob_oid` objects,
  exact object-format agreement and nested-field sorting, and a preexisting
  authenticated artifact/pointer or key-binding tuple;
  complete source/assignment/retirement provenance; two disjoint obligations
  for one secret tuple; objective `G(C)=O(C)` derivation; every target-roster
  receipt independently reproducing the same frontier and
  governed-ciphertext bijection; and cold-root emergency-reset fork escape
  into fresh IDs over the complete branch union. Vectors propagate the
  independently recomputed governed-binding digest and the separately
  projected obligation digest through manifest high-water, transition
  target/inventory/result bases, null-transition preservation,
  candidate abandonment, same-key audit, emergency reset, exact-tip CAS,
  archive restore bases, receipt, and reconstruction. Negatives cover a fork in an
  ordinary checkpoint, nonmaximal/omitted competing/close frontier item,
  retain after close or closed-ID reuse, wrong signer/transition, uncovered
  retained ciphertext, obligation without ciphertext, duplicate coverage,
  wrong owner/head/ref/path/blob/object/digest/length, a bare/mixed-format or
  wrong-length typed Git OID, artifact created after or referring to its
  binding/obligation/checkpoint, obligation-only secret-tuple
  derivation, incomplete or wrong provenance, premature close, mutation
  during receipts, incomplete reset branch union, and erasure/non-use offered
  as closure;
- Comms durable-secret semantic closure from one accepted credential
  checkpoint: exact sorted-inventory derivation from the complete live source
  and conservative exposure state; equality of `owner`, `secret_class`,
  `secret_id`, `instance_commitment`, `lifecycle`, canonical `record_value`,
  complete plural `current_holder_lineages`,
  `historical_obligation_record_digests`,
  `retired_provenance_lineages`, `credential_checkpoint_digest`,
  `governed_decrypt_key_bindings_sha256`, and
  `historical_decrypt_obligations_sha256` across generic inventory, outer
  envelope, repeated decrypted fields, high-water, and restore basis;
  one-to-one `entry_path`/`entry_sha256` binding to the exact
  generic `authority-protected-secret` entry; and exact entry/path owner and
  allocated owner/class-schema agreement. Positive vectors cover a current
  secret with multiple staged/competing per-holder lineages, a
  historical-decrypt secret with multiple active obligations, complete
  retired provenance, and exact fresh-ID
  `historical_decrypt_nids`/`historical_assignment_digests` holder
  replacement—including one NID represented by a retired old assignment and a
  live decrypt-only assignment, sources binding every active obligation, and
  each active obligation successor receiving the retired lineage—and final
  close retiring the complete live historical set; plus empty historical
  arrays only for `current`. Negatives
  cover omitted or subset current holders, a source without its assignment,
  wrong or unrecorded new holder, reuse of an old assignment ID or stale
  source lacking the complete active-obligation/binding/artifact refs,
  provenance omitted from one of multiple active obligations, operational or new
  encryption use of a decrypt-only assignment,
  missing/extra/inactive obligation, empty historical obligation or provenance
  array, wrong provenance/retirement, arbitrary old source, historical arrays
  on `current`, missing/extra inventory or generic entry, wrong owner, entry
  transplant, non-bijective record mapping, canonical-locator substitution or
  collision, unallocated class, excluded device/session material, and wrong
  `checkpoint_digest`, `credential_checkpoint_digest`,
  `governed_decrypt_key_bindings_sha256`,
  `historical_decrypt_obligations_sha256`, `exposure_set_sha256`,
  `secret_inventory_sha256`, `entry_sha256`, or recomputed
  `instance_commitment`, including transplant of a historical entry across two
  distinct `K(C)` states with the same obligation digest;
- the total ADR-037 class mapping, with positive category/schema/lifecycle
  vectors for all special, generic, protected-nonsecret, clone-only, and
  forbidden classes; exact two-row cold-root/epoch
  `special_authority_bindings` with their complete source identities;
  rejection of a special/generic duplicate, a forbidden private capability,
  a generic Core-only secret, or a class assigned another category/schema;
  and the exact special-plus-generic authority-DEK nonce set, including
  12-byte unpadded-base64url nonce and ciphertext-plus-16-byte-tag encodings,
  exact entry bounds, producer collision resampling, and pre-decryption
  rejection of duplicate or malformed nonces;
- `standalone` versus `network-assisted` semantic completeness, including one
  valid declared omitted `large-object` stored-byte ID; rejection of a
  `standalone` archive with nonempty `external_objects`, an undeclared
  omission, a declared ID that is not omitted governed large-object
  ciphertext, or omission of any repository, configuration, history,
  protected metadata, normal-or-gap rollover member, gap base/skipped/repair
  KEL event, rollover-reference-evidence byte, frontier byte, special binding,
  current-holder record, governed retention-snapshot head or signed key-binding
  record, active obligation/provenance record, governed pointer/locator
  metadata, `authority-protected-secret`, or durable-secret inventory entry;
  and
- bootstrap noninterpretation of authority-protected secrets: successful
  bulk-layer authentication and manifest binding of the outer-envelope bytes,
  inventory, commitments, and ciphertext digests reaches only
  isolated `bootstrap-validated` bulk staging, while authority AEAD and
  hidden-material checks remain explicitly unresolved; an outer-valid but
  inner-invalid secret remains non-authoritative under bootstrap and rejects
  under a later ordinary restore. Negatives cover treating unavailable hidden
  material as absent, matched, schema-valid, installed, or authority-bearing;
  moving required policy/finality metadata behind authority ciphertext;
  allowing any live repository/config read; reusing a bootstrap parse object
  or verdict; or enabling authority operations before the complete activation
  ceremony;
- exact closed state-rollover shape, BIP-340 transcript, complete-record
  digest, Core path, and byte-identical Comms mirror; inception without a
  rollover; first-rotation empty `previous_rollover_heads`, successive exact
  predecessor links, a linked competing-predecessor frontier, and a
  three-rotation recursively closed chain; exact closed
  `heterodyne.recovery-state-rollover-gap.v1` shape, cold-root signature and
  digest, Core path, byte-identical Comms mirror, inception/last-rollover base,
  canonical nonempty skipped-rotation chain, compromise repair rotation and
  cutoff, complete unrecoverable-digest arrays, authenticated-reference rows
  backed only by exact `core.recovery-state-rollover.v1` bytes and the
  `previous-rollover-head` semantic member, rejection of another
  profile/member or a substring/lookalike match, storage-index/provider
  metadata represented only as explicit audit-only rows, exact
  digest-projection and evidence-byte set, exact six frontier-array hashes,
  and one repairing rollover's gap/base equality; full generation,
  signed-manifest, terminal, and per-scope finalized-fallback frontiers
  (including pending manifest conflicts and resolution-selected closure);
  approval and role frontiers with preserved local conflicts;
  rollover-provisional repair inclusion versus
  ratified-conflict-then-current repair; valid current-epoch successors after
  ordinary rollover; and base-only plus repair-provisional eligibility after
  a gap;
- exact `archive_freshness_chains`/`archive_generation_heads` bijection and
  complete decreasing finalized fallback chains, including an empty array
  when no finalized allocation is reachable and exact `F3,F2,F1`
  allocation/manifest/finalization/optional-resolution closure. Vectors cover
  selection of `F3`, accepted abandonment or cutoff of `F3` falling back to
  `F2`, then invalidation of `F2` falling back to `F1`; and an earlier
  finalized allocation followed respectively by a greater pending allocation,
  a greater abandoned allocation, a maximal unresolved manifest or terminal
  conflict, and an unresolved maximal generation fork. Negatives cover a
  missing, extra, duplicate, or misordered fallback; omitted earlier
  finalization; wrong scope head; and any manifest, terminal, finalization, or
  artifact-resolution mismatch;
- wrong prior/new key or head, nonadjacent or noncanonical rotation, wrong
  signature, nonmaximal/extra/duplicate head, wrong/omitted/extra/duplicate
  predecessor link, unavailable linked or frontier bytes, cutoff-invalid head,
  known-lineage empty-array producer nonconformance, competing rollovers, and
  missing-rollover restore-pending behavior; gap negatives cover a nonunique
  base, hidden available ordinary/conflict rollover, missing or extra skipped
  rotation, broken key/head chain, late cutoff, reused epoch key, wrong
  frontier hash, wrong or competing gap, ordinary predecessor mixed with a
  gap, a second rollover citing one gap, unavailable gap bytes, missing/extra
  evidence, digest/evidence projection mismatch, wrong evidence hash/path/
  class, a storage index or provider assertion classified as authenticated,
  unsigned bytes called a signed recovery record, audit-only evidence treated
  as candidate validity, a fully available rollover hidden as a reference, and
  attempted operational use of a skipped-key record or late skipped
  rollover. A
  standalone multi-rotation archive with only the latest rollover, but a
  missing intermediate normal record, gap record, skipped/repair KEL event,
  reference-evidence byte, or referenced head, remains `restore-pending`;
  arrival-order-equivalent vectors reject omitted backdated retired-key roots,
  successors, manifests, and terminals without reopening the accepted snapshot
  or becoming directly eligible at a later rotation;
- independent `device-local` and `clone-device`
  per-`(persona,NID,backup_class)` generation chains, exact persona/NID path
  derivation, exact clone-secret payload and path, optional publishing-secret
  inclusion, explicit concurrent-copy and reduced-assurance behavior, unchanged
  same-NID logical holder/source/assignment state, and rejection of
  pre-unseal/activation records for either device class;
- allocation-fork resolution for root and non-root predecessors, selected and
  null outcomes, rejected-evidence retention, required post-conflict epoch
  rotation, exact BIP-340 transcript/encoding/digest/path, resolution
  `created_at`, complete frozen root/non-root conflict frontiers, omitted-third
  branch producer-audit failure with arrival-order-independent terminal
  classification, deterministic late pre-rotation candidate retention and
  rejection, transitive `P -> A -> A2` versus `P -> B` terminalization and
  high-water recomputation, first-acceptance current KEL validation, and
  competing-resolution halt;
- same-allocation manifest, conflicting-finalization,
  conflicting-abandonment, and finalization-versus-abandonment detection and
  artifact resolution, including exact derived conflict kinds, complete
  selected/rejected set equations, finalized and abandoned outcomes, rejected
  and late-candidate evidence retention, post-resolution freshness/repair,
  generation-chain noninterference, and competing cold-root-resolution halt,
  plus nonconflicting recipient-slot-only header rewraps and immutable-header
  variant conflicts, permanent device-fork quarantine, canonical ancestry-or-cutoff
  processing, old-NID revocation, and fresh-NID generation-one restart;
- tampered header, slot, chunk, final flag, digest, duplicate path, traversal,
  undeclared bytes, and resource exhaustion;
- cold-root and epoch NIP-44-v2-derived adapted envelopes, including rejection
  as NIP-44/NIP-01 events, exact primitive/encoding vectors, ordinary
  bulk/authority bundle opening, bootstrap bulk-only opening, and
  Core-protected installation of restored authority;
- device X25519 binding, byte-exact bootstrap binding, key-ID-preserving
  rewrap, platform-local labeling, WebAuthn PRF, and passphrase wrappers;
- required full cold-root/epoch slot set, nonempty self-tested clone-device
  non-device-local commitment, device-local-only empty commitment, risky
  device-local warning, and rejection of missing, platform-local-only,
  malformed, substituted, or rewrap-stripped required clone slots;
- default fresh-device restore and explicit clone-device restrictions;
- Git bundle/RID/head/KEL validation and rollback warning;
- standalone, network-assisted, online-current, restore-pending,
  non-authoritative bootstrap-validated, and cold-root offline-recovered
  restore states, including unavailable-authority-DEK deferral, every
  available full-binding equality, missing/conflicted/unresolved latest or
  intermediate normal-or-gap rollover deferral, and refusal to install
  archived authority in a live namespace;
- exact `heterodyne.offline-recovery-pre-unseal-intent.v1` and
  `heterodyne.offline-recovery-activation.v1` shapes, signatures, domains,
  paths, random 32-hex activation ID, complete offline
  `archive_restore_basis`, and fresh NID creation. Positives require an
  independently available cold-root signer, bulk-only or compartmentalized
  combined-slot opening, complete bulk-derived exposure templates, durable
  intent plus immutable archive before authority-handle release, trusted-time
  and conservative-zero timestamp paths, nonexportable authority-DEK
  validated release, and a strict
  bijection in which a completed activation adds only the source signature,
  assignment source digest/signature, and its intent digest. They cover exact
  completeness over full-archive-derived or preexisting persona authority,
  excluding every clone/device-signing secret and fresh
  NID/device/publishing, SSH, X25519-recipient, and platform-wrapper key.
  Negative pre-unseal cases include no independent signer, a combined slot
  without compartmentalization, authority release before durable intent,
  a signer- or verifier-future `created_at` and host-proposed future time when
  the signer lacks a trusted clock,
  missing/extra/wrong-provenance templates, altered template bytes or
  source-link substitution, any shared-top-level intent/activation mismatch,
  raw authority-DEK export or hidden plaintext/signing release before complete
  inner validation, archived cold-root release mislabeled as opaque,
  any intent/activation for `device-local` or `clone-device`, clone material in
  a full activation, a changed same-NID logical assignment under exact cloning,
  and an unrecorded new holder. Cancellation, operator abort, failed authority
  AEAD, hidden-commitment mismatch, and crash after intent but before
  activation all retain the exact intent as unreconciled evidence.
- two-boundary crash vectors distinguish discardable bulk/non-authority scratch
  before intent, irreversible signed intent, and the later completed
  `secret-bearing-prepare`. After completed prepare, recovery finishes
  activation publication or preserves the exact signed activation/embedded
  records as well. Incomplete candidates install nothing. Exact state vectors
  cover `ObservedPreUnsealIntents`, `ReconciledIntent(I)`,
  `UnreconciledPreUnsealIntents`, `ObservedActivations`, `Reconciled(A)`, and
  `UnreconciledActivations`; exact intent/activation inventories and separate
  collision projections; and copying every evidence byte into accepted audit
  closure before terminalization.
- origin-accounting vectors derive `BaseItems` and `ProvisionalItems` only from
  real assignments, derive complete `IntentItems`, and form the tagged
  `EffectiveInventoryOrigins` union. Exposure/action assignment and intent
  arrays are independently exact; intent presence cannot omit a co-keyed real
  assignment; retirement remains one-to-one only with actual assignments; and
  predecessor/result exposure-set digests never hash pseudo-assignments.
  Positives cover an intent-only failed opening, simultaneous intent plus
  activation rotating one tuple once, target inclusion only with linked
  activation, target-excluded terminal cleanup, and a late activation after
  its intent was already reconciled without resurrecting the intent item.
- collision vectors distinguish exact duplicate idempotence, two nonidentical
  intents, and two nonidentical fully signed activations completing one
  template. They preserve all variants without arrival-order selection, treat
  a linked intent/activation as noncolliding, route either active collision
  only through cold-root emergency reset, and cover a reconciled variant plus
  late same-ID variant while inventorying only unreconciled evidence.
  Ordinary and emergency first-sync positives perform every class-complete
  rotation/replacement/revocation/termination or persona migration, retained-
  ciphertext/binding/obligation/historical-assignment update, checkpoint,
  receipt, rollover, delivery, and role gate. Any predecessor-current epoch
  intent/activation origin forces a fresh compromise-declaring rotation with
  cutoff no later than the earliest relevant linked intent time, including an
  already reconciled intent and routine addition; signatures in the exposure-
  to-sync interval reject. A positive inventory-only vector admits an exact
  raw-valid archived-epoch completion that is authority-invalid under that
  cutoff, then retires it; negatives reject a bad raw signature, altered
  template, or any operational use. Further negatives cover delegation-only
  bypass, archived-epoch adoption, erasure/non-use as excuse, live reads or
  authority-bearing backup issuance while offline-recovered, and activation
  before every gate;
- valid, expired, revoked, wrong-target, wrong-key, bearer-only, scope-widened,
  and noncanonical recovery grants;
- mergeable approval lineages covering grant, renew, revoke, pre-expiry
  renewal, post-expiry fresh-ID authorization, post-revocation epoch rotation,
  current-epoch successors, retired-head rollover ratification, omitted
  retired-record rejection, compromise cutoff, per-ID and tuple fork
  isolation, and complete mixed terminal-plus-conflict recovery frontiers;
- mergeable role lineages covering grant, update, revoke, target-local fork
  isolation, current-epoch successors, retired-head rollover ratification,
  omitted retired-record rejection, compromise cutoff, and fresh-ID
  post-revocation rotation, delegation-revoked terminal heads, exact ordinary
  superseding regrant, and complete mixed terminal-plus-conflict recovery
  frontiers whose post-conflict rotation and rollover follow every bound
  delegation revocation;
- exact transfer-grant binding to the approval ID and record digest, the
  client's approval and role basis, and the server role record digest, NID,
  onion endpoint, and SSH host key, including invalidation on role update,
  revocation, or fork, plus byte-identical grant-ID replay and quarantine of a
  nonidentical collision under the globally unique
  `(persona,server_nid,grant_id)` key;
- the complete bootstrap-to-activation ceremony: a completed bootstrap or
  delegated archive transfer with exact then-current archive/KEL/epoch tuple;
  bootstrap bulk staging only; ordinary delegation; an accepted fully
  receipted ADR-037 `routine-addition` checkpoint naming the new NID and its
  mandatory fresh config-audience and OAuth-pairwise successors; a separate
  authorization checkpoint; complete current-holder source/assignment
  exposure for current secrets and exact
  `historical_decrypt_nids`/`historical_assignment_digests` decrypt-only
  exposure for historical secrets; exact governed retention-snapshot/binding
  state and digest; exact maximal-obligation frontier/digest and active-retain
  subset; and complete retired provenance;
  post-addition delivery
  checkpoints and reconciliation; a newly produced/finalized post-transition
  archive; durable node role; and an exact closed `archive_restore_basis`. The activation
  envelope binds the basis digest in its outer object, plaintext, HPKE
  info/AAD, grant signatures, and immutable resource; its transient scalar
  opens only the original byte-identical required epoch slot, yields the exact
  two-DEK bundle, and drives a newly parsed ordinary restore before one atomic
  protected install. Negatives cover a pretransition or stale archive/current
  tuple, absent mandatory rotation/checkpoint/source/assignment/binding/
  obligation/provenance/delivery, omitted activation-target holder, wrong
  governed-binding or obligation-set digest, erased or promised-unused
  exposure, substituted required slot,
  one-DEK result, bootstrap-verdict reuse or upgrade, activation-only
  installation, scalar/special-epoch mismatch, intervening state change, and
  failure to erase transient keys. A separate successful ordinary two-DEK
  delegated-transfer restore confirms that it is not activation or bootstrap
  promotion;
- epoch redistribution after normal-or-gap rollover and ADR-037
  reconciliation, incomplete removal without rotation/rollover/reconciliation,
  absorbing role revocation, ratified retained-role selection, and linked
  post-rotation regrant;
- SSH host-key pinning and refusal of every prohibited subsystem or channel;
- every transfer frame state, canonical error echo for a representable bad
  frame, connection close for every unrepresentable echo basis, read/write
  completion receipt, byte-stable rewrapped resume, lost read/put/receipt
  replay after completion, and fixed transfer ranges crossing cipher-chunk
  boundaries;
- resumable archive, authority, and object reads with exact semantic and
  transferred-byte integrity checks, plus archive-write rejection when the
  destination cannot authenticate and open an ordinary class-sufficient
  recipient slot, including bootstrap-only and full-archive one-DEK negative
  cases, a full two-DEK success case, clone empty/forbidden/stripped required
  slot failures, and clone destination-added-slot success with all committed
  user slots retained;
- signed immutable resource payload lengths, direction-aware read/write stat,
  empty declaration-bound write staging, object total-length equality, archive
  complete-transfer versus ciphertext length, put-before-stat and
  changed-declaration rejection, maximum-byte and length-mismatch rejection,
  and exact bitmap, final whole-transfer hash, and semantic completion;
- 5 GiB, 100 MiB, 1 GiB, and critical-reserve boundary behavior; and
- Tier 1 no-pointer, Tier 2 plaintext, Tier 3/config encrypted, audit, and
  observability pointer confidentiality, including the exact embedded
  audience/object-DEK dependency tuples and deterministic two-row
  Git-pointer/large-object `G(C)` expansion when both keys are historical;
  positive audience-only historical retention with exactly the Git-blob row,
  object-DEK-only historical retention with exactly the large-object row, and
  simultaneous audience/object-DEK retention with two distinct obligations;
  plus an applicable-row omission, still-current-key extra row, tuple
  substitution/swap, two-row collapse, and validator-chosen multi-tuple
  fallback negatives; and
- Core-only portable recovery, offline Comms composition, onion provider, and
  Tor-native network consumer feature-prerequisite claims.

## Non-goals

This design does not:

- expose a general remote shell;
- make a recovery node a Tor relay;
- require every full node to hold epoch authority;
- put cold-root material on every recovery node;
- make WebAuthn credentials portable across arbitrary RP IDs;
- treat a USB mass-storage device as a hardware authenticator;
- clone active ratchet state;
- guarantee discovery of a newer offline backup; or
- replace the future repo-relay server/storage conformance ADR.
