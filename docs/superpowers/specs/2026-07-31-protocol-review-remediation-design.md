# Protocol Review Remediation Design

**Date:** 2026-07-31
**Status:** Approved for implementation planning
**Protocol owners:** Core, Comms, Control, and Social
**Registry target:** revision 4
**Decision record:** ADR-037

## Goal

Resolve the accurate findings from the 2026-07-30 Opus, GLM 5.2, and
Antigravity reviews against the current protocol family, without treating
stale, false, or already-gated findings as defects.

The remediation makes the prepared 0.5.0 family internally consistent,
replaces generator-self-consistency with executable validation where security
depends on a verdict, and records the user's pre-1.0 mutability rule. It does
not open the incomplete Control conformance gate or add a membership-private
Tier 3 transport.

## Review method and disposition

The reviews targeted commit `e02bdee`. The current baseline is `07e46d7`,
which already integrates ADR-035 and ADR-036 and registry revision 3. Each
finding was checked against current normative text, accepted ADRs, generated
artifacts, and focused executable tests. Disagreement between reviewers was
resolved using repository evidence rather than reviewer consensus.

### Confirmed or partially confirmed

| Area | Disposition |
|---|---|
| KEL fixtures and vectors | Current inception bytes omit the required owner stamp and rotation fixtures use the obsolete array content. Existing byte-exact vectors therefore pin invalid 0.5.0 bytes, and the symbolic KEL set lacks an executable replayer. Correct in place under the pre-1.0 rule and add semantic replay. |
| Node advertisement | `kind:31010` proof bytes bind `repo_head`, but the event does not carry it. Add the tag as the issuance-time possession snapshot required by ADR-026. |
| Tier 3 metadata | Content is encrypted, but clear recipient tags, roster events, and reusable key identifiers expose membership and changes. Correct confidentiality claims and UI/threat language; do not invent a private-membership carrier in this remediation. |
| JWK proof profile | The generator enforces the algorithm/key-type mappings, but normative prose and metadata-member handling are incomplete. Define one closed Core profile, tighten the generator to it, and add negative vectors. |
| Witness-free rotation | `strategy:none` with threshold zero makes hot-key rotation unilateral and fork acceptance ambiguous. Prohibit it; witness-free personas use `committed`. |
| Registry semantics | Historical governing-revision pins are intentional, but Core does not define them clearly and the release feature vocabulary cannot distinguish provided from required features. Add a feature catalog and split release-manifest fields. |
| HKDF and NIP-44 | Positional notation is ambiguous. Label IKM, salt, info, and length and state that the result substitutes for the NIP-44 conversation key. |
| Status-list compression | Canonical recompression is not required by draft-21 and rejects interoperable encodings. Accept every valid signed ZLIB-wrapped DEFLATE stream. |
| Persona linkage | Core's absolute unlinkability statement conflicts with Social's explicit dual-signed relationship assertion. Add a narrow, user-authorized exception. |
| Credential-node loss | The authoritative node set and permanent-loss recovery are undefined. Add normal synchronized removal and a cold-root-authorized emergency ledger-generation reset. |
| DNS rebinding | Resolution is validated but the connection is not bound to the validated address. Pin each hop to its validated public address while preserving hostname verification. |
| Double Ratchet erasure | The acceptance boundary is not explicit. Make state advancement and consumed-key erasure one atomic commit before releasing plaintext. |
| Claims and OIDC | Equal-time attenuation is incorrectly rejected, empty nonce can be accepted, and Comms verification order differs from ADR-034. Fix all three and add precedence vectors. |
| Claim owner stamp | Claim and revocation bodies use `comms_version` despite Core's `spec_version` rule. Rename the field while preserving registry revision 2 as the allocation pin. |
| Stale Matrix artifacts | Active fixtures and vectors still claim retired room-secret and private-broadcast behavior. Remove them from the current corpus and add precise partial-supersession notes to historical ADRs. |
| Coverage gaps | Add byte-exact credential-ledger, ATProto, repository-finality, root-freshness, raw-event-binding, and security-boundary vectors. |
| Verifier independence | Regeneration compares the generator with itself. Require an executable replayer or an explicit evidence class for every normative vector. |
| Registry hygiene | Allocate NIP-42 `kind:22242`; retain already allocated upstream list kinds with explicit purpose. |
| Current integration regression | Repair Social's Matrix capability fixture so it uses registry revision 3, current feature identifiers, and `implementation_role`. |
| Failure language | Replace impossible delivery-success deadlines with initiation deadlines plus retry obligations; replace exact English UI strings with structured, localizable outcomes. |

### Rejected, stale, or intentionally deferred

| Finding | Disposition |
|---|---|
| ADR-035/036 are unintegrated | Stale on current main. No remediation. |
| `previous_index` lacks vectors | False; valid and mismatch vectors already exist. |
| `repo_unreachable` and `repo_causally_behind` are unregistered reason codes | False; they are normalized repository-state descriptions, not conformance reason codes. |
| `tuple_hash` is unused | False; confirmation rumor IDs commit to it and later hashes commit to those IDs. |
| Capability bootstrap must advertise registry digest | Not required; bootstrap and conformance reports have different schemas and purposes. |
| Unprefixed profile identifiers are invalid | No normative naming rule exists. Leave profile IDs stable and apply the new convention only to feature IDs. |
| Repo-relay server/storage conformance is missing silently | Already an explicit pre-conformance blocker. Keep it gated for its dedicated future ADR. |
| Control is accidentally claimable | False; the general ADR-030 gate remains explicitly closed. Keep it closed. |
| Current re-anchor recovers cold-root compromise | False. Clarify that current re-anchor recovers infrastructure loss only; cold-root compromise requires persona migration until a precommitted recovery policy exists. |
| Add optional witness approval after compromise | Insufficient unless mandatory policy was precommitted. Defer stronger cold-root recovery. |
| Add membership-private Tier 3 distribution now | Defer as a separate optional protocol because the current key distribution cannot hide membership by merely hashing identifiers. |
| Finish MLS migration now | Intentionally incomplete and outside this remediation. |

## Pre-1.0 artifact policy

Protocol behavior, schemas, registry entries, and conformance vectors remain
mutable throughout `0.x`. A current `0.x` corpus is authoritative for its
declared document combination, but its vector identifiers and bytes are not
immutable until 1.0.

Release records still preserve the exact digest of every published `0.x`
artifact set so an implementation can identify what it tested. Archived
0.4.0 bytes remain historical evidence and are not restamped. The mutability
rule permits correcting the current 0.5.0 KEL vectors in place; it does not
permit silently changing a published artifact without changing its release
record and documenting the change.

## Core corrections

### KEL validity and replay

Every current inception event retains its canonical NIP-01 `created_at`,
contains exactly one `["spec_version","core/0.5.0"]` tag, and satisfies the
existing tag-order and signature rules. Every current rotation retains its
canonical timestamp and uses the exact compact object with its actual ordered
receipt array:

```json
{"spec_version":"core/0.5.0","receipts":[...]}
```

The array is empty only for a ceremony whose valid canonical receipt set is
empty. Rotation timestamps remain the authority-window and compromise-cutoff
boundaries defined by Core; they are not normalized to zero.

The KEL generator gains an independent replay boundary that parses exact
`nip01_raw`, verifies BIP-340 signatures, enforces sequence and prior-digest
continuity, verifies receipt weights, materializes accepted state, and returns
the exact fork, stall, and rejection result. Current symbolic `keri/*` vectors
are replaced by executable vectors or explicitly classified non-wire evidence.

The same parser rejects a missing stamp, malformed timestamp, obsolete bare
array content, divergent raw bytes, signature mismatch, sequence
discontinuity, prior-digest mismatch, and insufficient/invalid receipts.
Replay does not reject an otherwise valid ambiguous successor merely because
it competes: it returns the exact stalled/duplicity state and applies Core's
repo-carried canonicality rule.

### Rotation rule

`strategy:none` is valid only when the prior accepted state has witness
threshold at least one and the new branch satisfies that threshold. A
witness-free or threshold-zero persona rotates only with
`strategy:committed`. A threshold-zero `strategy:none` event is rejected
before candidate selection. It may be retained as non-authoritative evidence
of an attempted fork, but it does not stall a valid committed successor.
Competing individually valid `strategy:committed` successors continue to
stall under the ordinary duplicity rule.

### Node-advertisement possession proof

`kind:31010` adds exactly one canonical:

```text
["repo_head", "<40-lowercase-hex-git-oid>"]
```

The NID proof continues to bind the RID, node identity, single endpoint, expiry,
and `repo_head`. The head is the canonical head observed when the
advertisement was issued. It need not remain the newest head after later
pushes, but the advertised endpoint must serve an object graph containing it
until the advertisement expires. A consumer rejects a missing, duplicate,
mismatched, or malformed head. A successful fetch proving that the served
graph excludes the advertised head rejects the advertisement. Transport
unavailability is a retryable or provisional availability state and does not
claim that graph exclusion was proved.

### Public-JWK proof profile

The normative closed profile tightens and makes explicit the current verifier:

- `OKP` with `crv:Ed25519` uses `alg:EdDSA`;
- `EC` with `crv:P-256` uses `alg:ES256`;
- `RSA` with a modulus of at least 2048 bits uses `alg:RS256`;
- the protected JWS header is the closed object `{"alg":"<allowed
  algorithm>"}`: `alg` is its sole member, must be present, and must match the
  JWK type exactly; every additional protected-header member is rejected; and
- the JWK member allowlist is `{kty,crv,x,alg,use,key_ops,kid}` for OKP,
  `{kty,crv,x,y,alg,use,key_ops,kid}` for EC, and
  `{kty,n,e,alg,use,key_ops,kid}` for RSA.

Required thumbprint members are present and canonical. The four metadata
members are optional; when present, `alg` must match the protected algorithm,
`use` is exactly `sig`, `key_ops` is exactly `["verify"]`, and `kid` is exactly
the RFC 7638 thumbprint. Every other member, including private or remote-key
metadata, is rejected. `none`, MAC/HS algorithms, `oct`, wrong curves, weak
RSA, and algorithm/key-type mismatch are also rejected.

The proof is verified only after the RFC 7638 thumbprint and typed-key binding
are validated.

### Exact raw-event verification

Where an artifact supplies `nip01_raw`, the verifier parses and hashes those
exact bytes. It must not reconstruct a convenient serialization from parsed
fields. Exposed parsed fields, event ID, signature, and raw sibling bytes must
all agree before the event is used.

## Registry revision 4

Revision 4 adds six allocation containers:

- `features.json`, for claimable behavior and prerequisites;
- `allocations.json`, for smaller closed vocabularies such as recovery slot
  types, roles, owners, platforms, and providers;
- `wire-profiles.json`, for byte/schema profiles that are not Nostr kind
  profiles; and
- `diagnostic-fields.json`, for profile-relative JSON Pointers used by
  pre-schema diagnostic precedence; and
- `kat-sources.json`, for authenticated immutable upstream known-answer
  provenance; and
- `validators.json`, for executable conformance tooling.

Each is a closed JCS object containing exactly `registry_revision:4` and one
array named `features`, `allocations`, `wire_profiles`,
`diagnostic_fields`, `kat_sources`, or `validators`.

A feature entry contains exactly:

```text
feature_id, owner_document, first_version, status, description, prerequisites
```

`feature_id` matches
`^[a-z][a-z0-9-]*(\.[a-z0-9-]+)+\.v[1-9][0-9]*$`; owner is `core`, `comms`,
`control`, or `social`; status is `active`, `reserved`, `gated`, or `retired`;
and prerequisites are sorted and unique. The feature array is strictly
increasing by UTF-8 `feature_id`; duplicate IDs reject. Every prerequisite
resolves in the same catalog, self-dependencies and cycles reject, and a
cross-document edge must already be permitted by the family DAG.

An allocation entry contains exactly:

```text
allocation_id, allocation_kind, value, owner_document, first_version,
status, spec_ref, schema_path, schema_sha256, description
```

`allocation_kind` is `slot-type`, `role`, `owner`, `platform`, `provider`,
`reset-reason`, `dr-termination-reason`, `archive-resolution-reason`,
`archive-abandonment-reason`, `grant-revocation-reason`,
`rollover-gap-reason`, `rollover-reference-member`,
`historical-decrypt-obligation-action`,
`governed-decrypt-source-profile`, or `transfer-error`;
`allocation_id` is exactly `<allocation_kind>:<value>`. `schema_path` and
`schema_sha256` are both null for an atomic token and both non-null when the
allocation has a closed body schema. Arrays sort by
`(allocation_kind,value)` UTF-8 bytes and reject duplicate IDs or duplicate
kind/value pairs.

A wire-profile entry contains exactly:

```text
profile_id, owner_document, first_version, status, spec_ref,
schema_path, schema_sha256, description
```

A diagnostic-field entry contains exactly:

```text
profile_id, generation_pointer, roster_pointer
```

`profile_id` resolves to exactly one wire profile or globally unique nested
Nostr kind profile. Each pointer is either null or one RFC 6901 JSON Pointer
relative to that profile's validator input after any Nostr event-content
extraction. At least one pointer is non-null. Entries sort by unsigned UTF-8
`profile_id`, duplicates reject, and every pointer must resolve in the
profile's closed schema when the member is present.

A KAT-source entry contains exactly:

```text
source_id, canonical_uri, upstream_project, immutable_revision, source_sha256,
owner_document, first_version, status, description
```

`source_id` follows the feature-ID lexical form but is globally unique within
this catalog. `canonical_uri` is an HTTPS URI directly naming one upstream
raw JSON object at an immutable commit, release, RFC, or standards-draft
revision; floating branch, `latest`, redirector, and owner-controlled generated
artifact URLs reject. `immutable_revision` is the exact upstream commit,
release, RFC, or draft revision visible in that URI. `source_sha256` is the
raw response-body digest. Registry construction MUST fetch that exact URI with
redirects disabled, require authenticated HTTPS to the named authoritative
external upstream project, and verify the raw digest; an unverifiable or
Heterodyne-controlled upstream is ineligible for independent KAT evidence.
Entries are strictly
increasing by unsigned UTF-8 `source_id`; duplicate URI/revision/digest tuples
reject. A later upstream byte change requires a new source ID; the old entry
is not edited. Runtime conformance may use the authenticated vendored bytes
offline after matching this catalog.

A validator entry contains exactly:

```text
validator_id, profile_ids, operations, runner_protocol, status,
implementation_family, provenance_manifest_path, provenance_manifest_sha256,
operation_contracts, bundle_manifest_path, bundle_manifest_sha256, description
```

Wire profiles are strictly increasing by UTF-8 `profile_id`, validators are
strictly increasing by UTF-8 `validator_id`, and a duplicate identifier in
either array rejects. A profile ID is globally unique across `wire_profiles`
and every nested `kinds[].profiles[]` entry; a cross-catalog collision rejects
rather than relying on lookup order.
`kind_profiles` is a virtual catalog keyed by that globally unique nested
`profile_id`; its authenticated entry bytes are the enclosing profile object
inside the selected `kinds` live/history array, not a separate
`kind_profiles.json` file.
In revision 4 every nested kind-profile entry contains exactly:

```text
profile_id, owner, discriminator, stamping, first_version, status,
schema_scope, schema_path, schema_sha256
```

`schema_scope` is null, `decoded-content`, or `complete-event`.
`schema_scope/schema_path/schema_sha256` are either all null or all non-null.
A non-null schema binds exact raw bytes as elsewhere in this registry. A profile used by
`schema-only` evidence, an executable validator, or a diagnostic-field
mapping MUST have a non-null pair. `decoded-content` means the base NIP-01
event has already passed exact raw-event, kind, ID, signature, and tag
validation and the profile schema receives only the authenticated parsed
content value; `complete-event` receives the complete authenticated event
carrier, including any required `nip01_raw`. Revision-aware validation leaves
the six-member nested profile objects in history revisions 1 through 3
unchanged rather than synthesizing these members into their digest inputs.
`status` for allocations, profiles, KAT sources, and validators is `draft`, `stable`, or
`frozen`, matching the existing registry lifecycle. A `spec_ref` is one
qualified family anchor. A schema or bundle path is repository-relative and
has no empty, `.` or `..` component; its digest is lowercase-hex SHA-256 of
the exact file bytes. `validator_id` is one ASCII path component of at most
64 bytes matching `^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$`; parsing and canonical
re-encoding MUST reproduce the exact input bytes. Its
`bundle_manifest_path` is not merely any safe path: it is exactly
`docs/spec/validators/<validator_id>/<bundle_manifest_sha256>/bundle-manifest.json`,
where both interpolated components are their already-validated canonical
forms. The raw file at that path hashes to `bundle_manifest_sha256`; a path
alias, alternate filename, digest-directory mismatch, or catalog/runtime-root
disagreement rejects. Validator `profile_ids` is strictly increasing,
duplicate-free, and nonempty; every item resolves unambiguously to a
wire-profile entry or globally unique nested `kinds.json` profile ID.
Validator `operations` is a sorted unique nonempty
subset of `consume`, `produce`, `replay`, `roundtrip`, and `validate`.
`runner_protocol` is exactly `heterodyne-vector-validator-stdio-v1`.
`operation_contracts` is a nonempty array of closed objects containing exactly
`profile_id`, `operation`, `input_schema_path`, `input_schema_sha256`,
`result_schema_path`, `result_schema_sha256`, and `assurance`. `assurance` is
exactly `semantic` or `cryptographic`; an operation that verifies, derives,
decrypts, encrypts, signs, hashes into an identifier/commitment, or otherwise
makes a security decision from cryptographic bytes is `cryptographic`. The
contract array is strictly increasing by
the UTF-8 tuple `(profile_id,operation)` and has no duplicate pair. Every
contract profile appears in `profile_ids`, every contract operation appears
in `operations`, and those two arrays equal the respective unique projections
of the contract array; an advertised profile/operation combination exists
only when that exact pair has a contract. Schema paths obey the same safe-path
rule as wire schemas, and each digest is lowercase-hex SHA-256 of the exact
schema file bytes.

`implementation_family` is a stable lowercase ASCII identifier for one
independently maintained code lineage, not a build name. The provenance path
is exactly
`docs/spec/validators/<validator_id>/<bundle_manifest_sha256>/implementation-provenance.json`;
its raw digest equals `provenance_manifest_sha256`, it is listed as
`non-oracle-support` in the bundle manifest, and its bytes are exact UTF-8 JCS
of one closed `heterodyne-implementation-provenance-v1` object containing
exactly `type`, `artifact_kind`, `implementation_family`,
`source_repository`, `source_revision`, `source_files`, `build_recipe`,
`toolchain_components`, `operation_lineage`, and
`cryptographic_components`.
`artifact_kind` is `validator-bundle` here and `vector-generator` for the
fixed generator provenance below.
The family equals the catalog entry. `source_repository` is an authenticated
HTTPS repository origin and `source_revision` is an immutable
commit or release revision within it.
`source_files` is the complete strictly path-sorted array of closed
`{path,sha256}` entries for every regular implementation source, build
description, and lockfile used to produce the module, excluding only generated
bundle files and the provenance file itself; every entry is reproducible from
that revision. `build_recipe` is a closed
`{path,sha256,entrypoint,args,environment_path,environment_sha256}` object
naming one listed recipe file, its raw digest, a canonical entrypoint within
that file, a fixed array of UTF-8 arguments, and one other listed closed build
environment manifest plus its raw digest. `toolchain_components` is a strictly name/source-sorted complete
array of closed
`{name,source_uri,immutable_revision,sha256}` entries for every compiler,
linker, runtime, code generator, binary utility, sysroot, and transitive native
library available to the build. The environment manifest is exact JCS of this
same byte-identical `toolchain_components` array plus the fixed locale,
timezone, filesystem ordering, environment
variables, and sandbox policy; it provides no network, clock, randomness,
ambient filesystem, or undeclared executable. `cryptographic_components` is a
strictly algorithm/source-sorted array of closed
`{algorithm,project,source_repository,immutable_revision,source_sha256}`
entries covering every direct or transitive implementation of a cryptographic
primitive used by any advertised operation. Omitting, repackaging, vendoring,
or statically linking a component does not remove it from this inventory.
`operation_lineage` is a strictly
`(profile_id,operation)`-sorted complete array of closed objects containing
exactly `profile_id`, `operation`, `decision_source_files`, and
`transcript_source_files`. The pair set equals the artifact's advertised or
generated executable operation set. Each source-file array is sorted and
unique, contains closed `{path,sha256}` entries that byte-identically resolve
in `source_files`, and is complete for the selected operation:
`decision_source_files` covers every replay, state-transition, comparison, and
verdict/reason path, while `transcript_source_files` covers every
canonicalization, serialization, domain-separation, identifier, signature
transcript, and expected-result construction path. Their union is nonempty.
Build-dependency tracing and source review establish completeness; hiding
shared logic behind a wrapper, generated file, generic helper, or unlisted
transitive library invalidates provenance.

Provenance is eligible only after an independent verifier performs the pinned
hermetic build from the exact authenticated revision, source-file bytes,
recipe, lockfiles, and toolchain/environment components. For a validator, the
rebuild MUST reproduce byte-for-byte every `entrypoint` and
`non-oracle-support` bundle file other than the provenance file itself; the
resulting raw digests MUST equal the already authenticated bundle manifest.
The verifier then reconstructs the provenance and bundle-manifest bindings and
requires the catalog version/root/digests to match. A claimed family/source
file paired with an unreproducible or different Wasm binary is invalid even
when both files hash correctly in isolation.

Every registry profile schema, validator input/result schema, and
evidence-bound contract schema resolves transitively and offline within the
selected owner/dependency artifact closure. After resolving a relative
reference against the containing schema's current base URI under the pinned
JSON Schema dialect, every non-fragment document URI in `$ref` or another
dialect reference keyword MUST equal exactly one `$id` declared in a regular
`schema`-role file from that closure. Every such file and raw digest is
therefore pinned by one authenticated artifact set. `$id` values are unique
across the closure; a duplicate ID, missing target, non-schema-role target,
mutable or network-fetched target, artifact-root escape, or resolution outside
the closed owner/dependency graph rejects. Fragment-only references stay
within their already selected schema resource. Reference cycles use the
pinned dialect's ordinary evaluation semantics rather than ad hoc expansion.
The dialect metaschema URI is mapped to the implementation's byte-pinned local
metaschema for that declared dialect and is never fetched. For executable
validator contracts, the harness resolves and evaluates that canonical schema
closure before and after module execution. No schema file is duplicated under
or exposed through the module's read-only bundle preopen, so a canonical
dependency `$id` has one artifact identity and no runtime resolver obtains
ambient filesystem or network authority.

Revision 4 changes `manifest.json` to registry schema `2.0.0`. The
`history/4.json` entry is a closed object containing exactly these sorted
arrays:

```text
allocations, diagnostic_fields, features, kat_sources, kinds, reason_codes,
security_invariants, validators, wire_profiles
```

`entry_set_sha256` is lowercase-hex SHA-256 over the UTF-8 JCS serialization
of that exact object. The live catalog arrays MUST JCS-equal the corresponding
history arrays. Historical revisions 1 through 3 retain their original
three-member entry-set shape and original digests; a revision-aware loader
selects the history schema and never synthesizes empty revision-4 arrays into
an old digest input. Release manifests pin the exact revision and
`entry_set_sha256`.

Release manifests replace the ambiguous `features` member with:

- `provided_features`: features whose behavior the document defines; and
- `required_features`: feature-level prerequisites supplied by dependency
  documents.

Both arrays are sorted, unique, and resolve in the pinned feature catalog.
Document-version dependencies remain authoritative for the family DAG.
Feature requirements refine optional/profile dependencies and do not create a
new document dependency.
Each provided feature's `owner_document` MUST equal the release manifest's
document. Each required feature MUST be owned by a declared document
dependency and MUST appear in that dependency release's `provided_features`.
For a release with `conformance_status:"conformant"`, every provided or
required feature MUST have catalog status `active`. An
`incomplete-draft` release MAY list its own `gated` features in
`provided_features` so its draft surface remains explicit, but that listing
does not make them claimable; no release may place a `gated` feature in
`required_features`. `reserved` and `retired` entries never appear in either
array. The two arrays are disjoint. The transitive prerequisite closure of every
provided feature is complete: same-document prerequisites also appear in
`provided_features`, while cross-document prerequisites appear in
`required_features` and are provided by the exact dependency release. A
catalog entry's `first_version` MUST be a qualified version whose document
prefix equals `owner_document`; malformed or cross-owner first-version values
reject.

Release-manifest schema `2.0.0` also adds exactly
`artifact_manifest_path`, `artifact_set_sha256`, and
`superseded_artifact_sets`. The referenced artifact manifest is a closed JCS
object:

```json
{
  "qualified_version": "comms/0.5.0",
  "provided_features": ["comms.double-ratchet.v1"],
  "required_features": ["core.nostr-relay-read.v1"],
  "registry": {
    "revision": 4,
    "entry_set_sha256": "<64 lowercase hex>"
  },
  "dependencies": [
    {
      "qualified_version": "core/0.5.0",
      "artifact_manifest_path": "docs/spec/releases/artifacts/core/0.5.0/<digest>.json",
      "artifact_set_sha256": "<64 lowercase hex>"
    }
  ],
  "files": [
    {
      "path": "docs/spec/heterodyne-comms.md",
      "role": "normative-document",
      "sha256": "<raw-file SHA-256>"
    }
  ]
}
```

`provided_features` and `required_features` obey the release rules above. For
the current top-level artifact pair they MUST JCS-equal the owner release
manifest arrays. For a superseded pair they are the immutable historical
feature claims and are validated against that artifact's self-contained
registry/dependency context rather than today's current arrays.

`registry` contains exactly `revision` and `entry_set_sha256`. For the current
top-level artifact pair it MUST JCS-equal the registry pin in the owner release
manifest. For a selected superseded pair, `qualified_version` still MUST equal
the owner release qualified version, but the self-contained historical
registry revision/digest is verified against that immutable history entry
rather than compared to the current release pin. `dependencies` is a strictly
increasing, unique array by UTF-8 `qualified_version`. For the current
top-level artifact pair it has exactly one closed object for every entry in
the owner release's document-version dependency map and no others, and each
qualified version equals that declared dependency version. For a superseded
owner artifact its immutable dependency array is the historical authority and
is not compared to today's owner dependency map. In both cases each dependency
path/digest pair MUST be either the referenced dependency release record's
current top-level pair or one exact member of its append-only
`superseded_artifact_sets`; the selected manifest is then verified recursively.
A Core artifact manifest therefore uses an empty dependency array;
Comms, Control, and Social commit the exact dependency corpora against which
their owner bytes were validated. Dependency artifact manifests recursively
commit their own declared dependency contexts. Recursive expansion also
produces one closed map from `qualified_version` to the exact
`{artifact_manifest_path,artifact_set_sha256}` pair used in the closure. If a
qualified version is reached through more than one dependency path, every path
MUST select the byte-identical pair; a direct dependency and a transitive
dependency cannot select current and superseded artifacts, or two different
superseded artifacts, for the same qualified version. Any mismatch invalidates
the owner artifact before schema or validator resolution, even if the selected
corpora happen not to expose a duplicate `$id`.

Feature satisfaction is evaluated in that exact artifact context. For every
current or superseded owner pair, each `required_features` member MUST appear
in `provided_features` of the exact selected direct-dependency artifact
manifest that owns it, not merely in that dependency release's current
metadata. Every selected dependency recursively satisfies the same rule and
the feature prerequisite closure against its own selected pairs. Thus a
current owner artifact cannot select an older superseded dependency corpus
that predates a feature the owner requires; current-release metadata never
upgrades the capabilities of selected historical bytes.

`role` is `normative-document`, `schema`, `vector`, `validator-bundle`, or
`normative-support`. Entries are strictly increasing by UTF-8 path and unique;
paths are safe repository-relative paths, and every raw file digest verifies.
The referenced artifact-manifest path and every listed file resolve to regular
files beneath the same verified repository root. Symlinks, hardlinks,
junctions, sparse aliases, device/special files, lexical or resolved escapes,
and any path whose resolved bytes are not the repository-published object at
that exact relative path reject. Hashing a host-external target through an
in-repository alias is never an artifact corpus. These checks occur before
digest or recursive dependency validation and apply identically to current
and superseded artifact sets.
The set includes the owner document, every schema it owns, every normative
vector whose `owner_document` names it, and every validator/support file needed
by those vectors. It excludes ADRs, research, the release manifest itself, the
artifact manifest itself, and the independently pinned registry.

Artifact-manifest bytes are exactly `UTF8(JCS(object))` with no extra bytes.
`artifact_set_sha256` is lowercase-hex SHA-256 of those exact bytes, and
`artifact_manifest_path` is
`docs/spec/releases/artifacts/<document>/<version>/<artifact_set_sha256>.json`.
The path digest, release member, and bytes MUST agree. A published manifest at
that content-addressed path is never overwritten or deleted.
`superseded_artifact_sets` is a strictly digest-sorted unique array of exact
`{artifact_manifest_path,artifact_set_sha256}` objects for every previously
published artifact set under the same qualified `0.x` version; it is empty
before the first replacement and never loses an entry. Exactly the top-level
pair is current. Thus mutable pre-1.0 bytes remain distinguishable without
pretending that the allocation-genesis registry revision freezes behavior.
Because the artifact-set digest covers both the registry pin and exact
dependency artifact-set map, a superseded owner artifact retains the complete
family corpus against which it was tested.

Revision 4 names the existing bare Comms features:

```text
comms.key-claims.v1
comms.private-claim-ledger.v1
comms.oidc-jwt-projection.v1
comms.token-status-list-draft-21.v1
comms.double-ratchet.v1
```

Revision 4 also allocates these Comms-owned reason codes:

```text
credential_generation_missing
credential_ledger_persona_mismatch
credential_generation_stale
credential_checkpoint_invalid
credential_reset_invalid
credential_roster_empty
credential_checkpoint_stale_kel
```

Revision 4 also allocates these exact Comms-owned obligation action values:

```text
historical-decrypt-obligation-action:retain
historical-decrypt-obligation-action:close
```

The revision-4 `diagnostic_fields` array contains exactly these generation
and roster mappings; null is an actual JSON null:

| Profile ID | `generation_pointer` | `roster_pointer` |
|---|---|---|
| `comms.credential-sync-authorization-record.v1` | `/credential_ledger_generation` | null |
| `heterodyne-comms-key-claim-nostr-bip340-v1` | `/credential_ledger_generation` | null |
| `heterodyne-comms-key-claim-radicle-ed25519-v1` | `/credential_ledger_generation` | null |
| `heterodyne-comms-key-claim-jwk-jws-v1` | `/credential_ledger_generation` | null |
| `comms.claim-ledger-record.v1` | `/credential_ledger_generation` | null |
| `comms.oidc-issuance-record.v1` | `/credential_ledger_generation` | null |
| `comms.oidc-signing-jwk.v1` | `/credential_ledger_generation` | null |
| `comms.oidc-id-token.v1` | `/credential_ledger_generation` | null |
| `comms.oauth-access-token-rfc9068.v1` | `/credential_ledger_generation` | null |
| `comms.heterodyne-assertion-jwt.v1` | `/credential_ledger_generation` | null |
| `comms.status-list-token-draft-21.v1` | `/credential_ledger_generation` | null |
| `comms.credential-ledger-checkpoint.v1` | `/generation` | `/node_roster` |
| `comms.credential-ledger-emergency-reset.v1` | `/new_generation` | `/new_roster` |

The three Nostr key-claim pointers are relative to the decoded closed content
object after the event profile has authenticated and parsed it. Every other
pointer is relative to the complete profile input. No validator guesses a
pointer from an object's apparent shape.
Each of those three nested key-claim profiles has
`schema_scope:"decoded-content"`,
`schema_path:"docs/spec/schemas/comms/key-claim-v1.schema.json"`, and
`schema_sha256` equal to the raw-file SHA-256 of that exact schema. The three
proof profiles share content syntax but retain distinct event/proof
discriminators and validators.

Those values are diagnostic conformance outcomes only. Reason precedence is
exact. For an otherwise parseable affected artifact, two targeted checks run
before general closed-schema validation. Omission of the required generation
member at the profile's allocated JSON Pointer yields
`credential_generation_missing`; only if that member is present does a
recognizable checkpoint/reset roster array with zero items yield
`credential_roster_empty`. Thus an artifact with both defects deterministically
reports `credential_generation_missing`. A present generation
with the wrong JSON type, a non-array roster, an unknown object shape, or any
other schema/signature defect retains the existing generic
schema/cryptographic reason. After that general validation, precedence is
persona mismatch, stale/wrong generation, stale KEL, checkpoint invalid, then
reset invalid. A pending but structurally valid transition is a state, not a
rejection reason.
The signed reset wire value is instead exactly one of these allocations from
`allocations.json`:

```text
reset-reason:credential_ledger_reset_node_loss
reset-reason:credential_ledger_reset_offline_activation_id_collision
```

Revision 4 allocates no other reset-reason value. Node loss takes precedence
when both an unavailable old-roster node and an offline intent- or
activation-ID collision are present; the collision-only reason can never
disguise a roster loss.

Revision 4 also adds `governed-decrypt-source-profile` to the closed
`allocation_kind` enum. Its value set is the exact exhaustive list in the
Comms governed-decrypt source-profile table; each globally unique profile ID
is owned by the family document that validates and expands it, and the table
binds that ID to its allowed secret classes and deterministic locator/tuple
expansion. It includes all six Tier-3 wrapped-content profiles, Tier-3 feed
index and descriptor profiles, config-repository encryption, private
claim-ledger encryption, every recovery-wrapped profile capable of retaining
governed ciphertext, and `comms.large-object-pointer.v1`. Revision 4 cannot
freeze with a placeholder, wildcard, implicit profile, missing current
spelling, unknown value, or wrong owner. Profiles that cannot produce a
governed dependency are absent and cannot expand repository scans.

The combined ADR-037/ADR-038 revision-4 batch includes these directly affected
wire-profile/schema bindings; ADR-038's complete Core recovery list remains
the authority for its other profiles:

```text
core.offline-recovery-pre-unseal-intent.v1 -> docs/spec/schemas/recovery/offline-recovery-pre-unseal-intent-v1.schema.json
core.offline-recovery-activation.v1 -> docs/spec/schemas/recovery/offline-recovery-activation-v1.schema.json
comms.repository-retention-inventory.v1 -> docs/spec/schemas/comms/repository-retention-inventory-v1.schema.json
comms.credential-ledger-checkpoint.v1 -> docs/spec/schemas/comms/credential-ledger-checkpoint-v1.schema.json
comms.credential-ledger-checkpoint-receipt.v1 -> docs/spec/schemas/comms/credential-ledger-checkpoint-receipt-v1.schema.json
comms.credential-ledger-removal-observation.v1 -> docs/spec/schemas/comms/credential-ledger-removal-observation-v1.schema.json
comms.credential-ledger-candidate-abandonment.v1 -> docs/spec/schemas/comms/credential-ledger-candidate-abandonment-v1.schema.json
comms.credential-ledger-staging-ref-cleanup.v1 -> docs/spec/schemas/comms/credential-ledger-staging-ref-cleanup-v1.schema.json
comms.credential-ledger-config-key-bootstrap-recipient-array.v1 -> docs/spec/schemas/comms/credential-ledger-config-key-bootstrap-recipient-array-v1.schema.json
comms.credential-ledger-emergency-reset.v1 -> docs/spec/schemas/comms/credential-ledger-emergency-reset-v1.schema.json
comms.credential-ledger-reset-recipient-array.v1 -> docs/spec/schemas/comms/credential-ledger-reset-recipient-array-v1.schema.json
comms.node-secret-source.v1 -> docs/spec/schemas/comms/node-secret-source-v1.schema.json
comms.node-secret-exposure.v1 -> docs/spec/schemas/comms/node-secret-exposure-v1.schema.json
comms.governed-decrypt-key-binding.v1 -> docs/spec/schemas/comms/governed-decrypt-key-binding-v1.schema.json
comms.historical-decrypt-obligation.v1 -> docs/spec/schemas/comms/historical-decrypt-obligation-v1.schema.json
comms.credential-ledger-secret-transition.v1 -> docs/spec/schemas/comms/credential-ledger-secret-transition-v1.schema.json
comms.node-secret-transition-action.v1 -> docs/spec/schemas/comms/node-secret-transition-action-v1.schema.json
comms.double-ratchet-session-termination.v1 -> docs/spec/schemas/comms/double-ratchet-session-termination-v1.schema.json
comms.credential-ledger-lost-generation-path.v1 -> docs/spec/schemas/comms/credential-ledger-lost-generation-path-v1.schema.json
comms.config-repository-git-structure.v1 -> docs/spec/schemas/comms/config-repository-git-structure-v1.schema.json
```

The reset-recipient-array schema includes its closed HPKE body, plaintext, and
context shapes rather than allocating an open nested envelope. The
implementation creates each closed schema first and records its exact raw-file
SHA-256 in `wire-profiles.json`; no placeholder digest is published.
The repository-retention schema closes the signed frontier, target/basis,
semantic-ref, typed scan-head, and retirement fields; its validator enforces
target activation, maximal-parent completeness, scan-cut ancestry, the exact
emergency `H*` direct-parent/tree reconciliation exception, and enlarged
`K(C)` projection.
The emergency-reset schema's closed `reason` enum contains exactly the two
allocated reset reasons, its `offline_recovery_activation_collisions` member
and `offline_recovery_pre_unseal_intent_collisions` members use their closed
row shapes, and its conditional branches require nonempty node-loss arrays
versus empty collision-only loss/removal arrays plus at least one nonempty
collision projection. The secret-transition schema adds both intent arrays
and both collision-evidence arrays to its closed `inventory_basis`, adds
`pre_unseal_intent_items` to every closed exposure, and its action schema adds
the byte-identical field. Its executable cross-record validator resolves
`target.reset_id`, requires byte-identical reset evidence, recomputes
`ObservedPreUnsealIntents`, `ReconciledIntent(I)`, `ActiveIntentCollisionIds_B`,
`ObservedActivations`, `Reconciled(A)`, both exact unreconciled inventories,
and both collision projections, and permits empty emergency `removed_nids`
only for a valid collision-only reset. The activation schema requires
`pre_unseal_intent_digest`, validates the exact template-completion bijection,
and rejects activation without its signed durable intent. Schema validation
alone never turns a claimed collision or origin into evidence.
The config-repository Git profile has
`schema_scope:"decoded-git-object"`: its executable validator authenticates
the exact raw commit/tree bytes and projects the closed header, message, mode,
and pathname fields into that schema. Its commit schema has exactly the
ordinary zero/one-parent `heterodyne-config-v1` branch and the
one-or-more-parent `heterodyne-config-retention-resolution-v1` branch. The
latter's cross-record validator requires the exact config-class emergency `H*`,
decoded-OID-sorted complete variant-parent set, and all repository-inventory,
`L(S)`/`Bound_I`/`D(S)`/`U(S)`/`ResultPairs(H*)`/`Current_B`, reset,
checkpoint, and receipt predicates above. Schema-valid
projection without byte-exact raw parsing and cross-record validation is not
conformance.

Revision 4 also catalogs these already-normative, non-kind
generation-bearing profiles in `wire-profiles.json`, creating a closed schema
where one does not yet exist:

```text
comms.credential-sync-authorization-record.v1
comms.claim-ledger-record.v1
comms.oidc-issuance-record.v1
comms.oidc-signing-jwk.v1
comms.oidc-id-token.v1
comms.oauth-access-token-rfc9068.v1
comms.heterodyne-assertion-jwt.v1
comms.status-list-token-draft-21.v1
```

`allocations.json` also adds
`dr-termination-reason:persona_node_removed` and
`dr-termination-reason:candidate_material_retired`; the peer-tombstone schema
admits exactly those two reason values in revision 4.

Existing dotted Core, Comms, Control, and Social feature IDs remain. Control
lists `comms.double-ratchet.v1` as required rather than provided. Revision 4
requires the Comms release manifest to list `comms.double-ratchet.v1` in
`provided_features`, so Control's requirement has one exact provider.
Every Control-owned feature has catalog status `gated` in revision 4 and the
Control 0.5.0 release remains `conformance_status:"incomplete-draft"`; its
`provided_features` enumerate those gated draft surfaces without opening the
general ADR-030 gate. No other family release may require them.
Revision 4
also allocates upstream NIP-42 `kind:22242`, ADR-038's recovery features and
prerequisites, every recovery slot/body profile, and every role/owner/platform
or provider token used by those closed schemas. ADR-037 and ADR-038 are a
joint registry batch: ADR-037 is not accepted unless ADR-038 is accepted, and
the revision-4 history entry is not written with only one decision's
allocations.

Vector schema `2.0.0` adds required `registry_sha256`,
`allocation_catalog_revision`, `allocation_catalog_sha256`,
`registry_allocations`, and `evidence` members, plus conditional
`validator_operation`.
The vector's `registry_revision` remains the historical governing-registry pin
carried by the current 0.5.0 envelope, and `registry_sha256` is the exact
history entry-set digest for that revision. For a Nostr kind or nested kind
profile it also authenticates allocation genesis as checked below. It does not
claim non-kind `wire_profiles` allocation genesis, because history revisions
1 through 3 had no such catalog; those profiles are authorized by the explicit
revision-4 allocation-catalog pin, their `first_version`, and the selected
owner artifact set. The historical pin is not an immutable
behavioral snapshot: current `0.x` behavior is identified by `owner_version`
and the selected current or append-only superseded artifact-set digest for that
version.
`allocation_catalog_revision` independently
selects the later complete symbol catalog used to resolve every identifier
named by the current envelope; it is 4 for this migration, and
`allocation_catalog_sha256` is that history entry-set digest.
`registry_allocations` is a sorted unique array of closed objects:

```json
{"catalog": "<catalog>", "id": "<canonical identifier>"}
```

`catalog` is `allocations`, `diagnostic_fields`, `features`, `kat_sources`, `kinds`,
`kind_profiles`, `reason_codes`, `security_invariants`, or `wire_profiles`.
For `kinds`, `id`
is the canonical unsigned decimal kind without leading zeroes; for every
other catalog it is the exact allocation identifier. Entries sort by UTF-8
`catalog` then `id`. Every protocol allocation directly used by input,
expected output, profile, or exact rejection reason MUST be listed and resolve
in `allocation_catalog_revision`. Validator IDs do not appear here because
they are tooling rather than historical protocol authority.
For a selected Nostr kind or nested kind profile, the historical
kind/profile-allocation pin is also validated, not merely
digest-authenticated. When the history schema at `registry_revision` contains `kinds`,
that exact kind and selected nested profile MUST exist in the pinned history
entry; its immutable allocation identity and owner/profile fields MUST match
the later catalog view. A profile introduced in revision 3 therefore cannot
claim revision 1. Catalog types absent from an old history schema, plus later
diagnostic reasons and semantic invariants, resolve only through the explicit
allocation catalog and are not backfilled into history 1–3. For a non-kind
wire profile, `registry_revision` authenticates only the vector's declared
historical registry context; it makes no allocation-genesis claim. That
profile's identity, ownership, `first_version`, schema, and behavior resolve
from the revision-4 allocation catalog plus the selected owner artifact set.
For `executable`, `cryptographic-known-answer`, or `schema-only` evidence,
`validator_operation` is required. It is `produce` when `direction` is `produce`,
`roundtrip` when direction is `round-trip`, and one of `consume`, `replay`, or
`validate` when direction is `consume`. It MUST equal `evidence.operation` and
be permitted by the selected validator where one executes. For
`documented-nonwire`, `validator_operation` is absent.

Operation semantics are closed:

- `produce` independently derives the complete expected semantic result and
  every emitted wire artifact from `/input` and its explicit deterministic
  pins. Before returning, the same independent entrypoint validates each
  emitted artifact against the selected profile. Merely validating a supplied
  artifact cannot satisfy a produce vector.
- `consume` parses and verifies the supplied candidate artifact/context and
  returns the complete verdict and normalized state.
- `replay` consumes the ordered history/state supplied by `/input`, performs
  the profile state transition from genesis or the explicit starting
  checkpoint, and returns the complete verdict and terminal state. It is
  permitted for a consume-direction vector only when the governing `spec_ref`
  defines ordered replay.
- `roundtrip` independently produces the artifact from semantic input, then
  consumes those exact produced bytes through the selected profile and returns
  both the artifact and normalized terminal result.
- `validate` performs the selected profile's isolated schema, signature,
  digest, or cryptographic validation and returns its complete verdict. It is
  permitted for a consume-direction vector only when isolated validation is
  the behavior under test; it cannot substitute for semantic consume or
  replay.

For a reject case the selected operation executes normally until the exact
failure and returns its allocated reason; a validator may not short-circuit
from the vector ID. A catalog entry advertising several operations implements
each of these contracts separately.

Every current normative vector upgrades to schema `2.0.0`, including vectors
whose allocation-genesis revision remains 1, 2, or 3. That envelope upgrade
does not restamp the wire's genesis pin: all current protocol symbols resolve
against the explicitly pinned revision-4 catalog, while the current owner
document and release artifact set govern behavior. This is necessary for
legacy revision-1–3 vectors that already carried feature literals before a
feature catalog existed; history is not backfilled or mutated. Evidence
resolves through `evidence.catalog_revision`, which MUST equal the vector's
`allocation_catalog_revision` and digest for schema 2.0.0.

## Comms corrections

### Tier 3 honesty

Tier 3 promises content confidentiality. It does not promise sender,
recipient, audience-membership, membership-change, timing, or volume privacy.
Clear `p` tags, roster events, and `key_id` linkage are named residual
metadata. Clients must disclose that boundary before a user treats a Tier 3
audience as membership-private.

### Cryptographic notation and erasure

The audience-key derivation labels `IKM`, `salt`, `info`, and output length
and states that its 32-byte output replaces the NIP-44 conversation key.
NIP-44 nonce expansion, padding, encryption, and authentication remain
unchanged. A retransmission may reuse identical ciphertext; a new encryption
intent must not reuse a nonce under the same derived key.

On Double Ratchet receive, decryption, ratchet-state advancement, persistence
of the new state, and cryptographic deletion of the consumed message key form
one crash-consistent acceptance commit. After recovery from a crash, the old
key is unavailable and the same message cannot be released twice. Plaintext is
not returned to application code or durable storage before that commit
succeeds. This is a key-unavailability requirement, not a claim that a storage
medium can be physically erased. Skipped-key retention follows the pinned
nostr-double-ratchet profile and is not silently replaced by an invented
limit.

### Claims and OIDC

Claim and revocation bodies use `spec_version:"comms/0.5.0"`. Their
`registry_revision:2` member remains the profile's genesis allocation pin.

Attenuation accepts equal time bounds when all authority dimensions are
preserved or narrowed and `remaining_depth` decreases correctly. OIDC rejects
an empty expected or presented nonce even when the two empty strings compare
equal. Verification precedence follows ADR-034: structural and cryptographic
validity, KEL and chain authority, time/audience/subject, repository state,
revocation, proof, and finally local trust/release policy.

### Status-list compression

An issuer should use deterministic level-9 ZLIB-wrapped DEFLATE for stable
producer fixtures. A verifier authenticates the signed token and mirror digest
and then accepts any standards-compliant ZLIB-wrapped DEFLATE encoding that
decompresses to the valid status bytes. It never recompresses and compares a
local encoding as a condition of acceptance.

### Credential-ledger node loss

The encrypted config repository allocates sixteen closed JCS record profiles:

```text
credential-sync/checkpoints/<generation>/<sequence>-<digest>.json
credential-sync/checkpoint-receipts/<checkpoint-digest>/<node-nid-sha256>-<receipt-digest>.json
credential-sync/removal-observations/<transition-id>/<node-nid-sha256>-<observation-digest>.json
credential-sync/candidate-abandonments/<candidate-checkpoint-digest>/<abandonment-digest>.json
credential-sync/staging-ref-cleanups/<staging-config-key-id>/<cleanup-digest>.json
credential-sync/config-key-bootstraps/<generation>/<sequence>-<digest>.json
credential-sync/resets/<new-generation>-<digest>.json
credential-sync/reset-recipients/<new-generation>-<digest>.json
credential-sync/secret-transitions/<generation>/<sequence>-<digest>.json
credential-sync/secret-sources/<secret-id>/<digest>.json
credential-sync/secret-exposures/<assignment-id>/<digest>.json
credential-sync/governed-decrypt-key-bindings/<binding-id>/<digest>.json
credential-sync/historical-decrypt-obligations/<obligation-id>/<lineage-sequence>-<digest>.json
credential-sync/secret-transition-actions/<transition-id>/<digest>.json
credential-sync/dr-terminations/<transition-id>/<digest>.json
credential-sync/lost-generation-data/<prior-generation>/<path-sha256>/<index-digest>.json
```

Every generation, sequence, and other numeric path component in this section
uses the shortest unsigned ASCII decimal form: exactly `0` or
`[1-9][0-9]*`. A parser rejects signs, leading zeroes, whitespace, alternate
digits, overflow beyond the JSON-safe integer range, and any spelling whose
parse-and-re-encode bytes differ; the resulting integer MUST equal the bound
record member before lookup or acceptance.

The `secret-sources/<secret-id>` component is exactly 32 lowercase hex for a
`config-audience` record and 64 lowercase hex for every other secret class;
the parser may provisionally accept only those two lengths and MUST then
require exact class/member/path equality after decoding the record.

The `governed-decrypt-key-bindings/<binding-id>` component is exactly 64
lowercase hexadecimal characters and MUST equal the domain-separated
locator-derived `binding_id` recomputed from the parsed closed record. The
filename digest equals lowercase-hex SHA-256 of the complete signed JCS bytes.

Every record schema fixes its `type` member with JSON Schema `const`; a parser
never infers a record class from its path or shape:

| Record | Exact `type` |
|---|---|
| checkpoint | `heterodyne.credential-ledger.checkpoint.v1` |
| checkpoint receipt | `heterodyne.credential-ledger.checkpoint-receipt.v1` |
| removal observation | `heterodyne.credential-ledger.removal-observation.v1` |
| candidate abandonment | `heterodyne.credential-ledger.candidate-abandonment.v1` |
| staging-ref cleanup | `heterodyne.credential-ledger.staging-ref-cleanup.v1` |
| emergency reset | `heterodyne.credential-ledger.emergency-reset.v1` |
| secret source | `heterodyne.node-secret-source.v1` |
| secret exposure assignment/retirement | `heterodyne.node-secret-exposure.v1` |
| governed decrypt key binding | `heterodyne.governed-decrypt-key-binding.v1` |
| historical-decrypt obligation | `heterodyne.historical-decrypt-obligation.v1` |
| secret transition | `heterodyne.credential-ledger.secret-transition.v1` |
| transition action | `heterodyne.node-secret-transition-action.v1` |
| Double Ratchet termination | `heterodyne.double-ratchet-session-termination.v1` |
| lost-generation path index | `heterodyne.credential-ledger.lost-generation-path.v1` |

The two bootstrap artifacts are bare closed arrays and therefore have no
top-level `type`; their encrypted plaintext and HPKE context objects carry the
exact literals defined below.

`heterodyne.credential-ledger.checkpoint.v1` contains exactly `type`,
`persona`, `generation`, `sequence`, `previous_checkpoint`, `record_set_digest`,
`node_roster`, `config_head`, `config_key_id`, `config_key_sha256`,
`pairwise_secret_sha256`, `exposure_set_sha256`,
`config_bootstrap_recipients_digest`,
`governed_decrypt_key_bindings_sha256`,
`historical_decrypt_obligations_sha256`, `secret_transition_digest`,
`generation_transition`,
`epoch_pubkey`, `kel_head`, `created_at`, and `epoch_signature`.
`previous_checkpoint` is null only at generation inception. Digests are
32-byte lowercase hex. `config_head` is the closed object
`{"object_format":"sha1"|"sha256","oid":"<lowercase hex>"}`; `oid` is exactly
40 hexadecimal characters for `sha1` and 64 for `sha256`. Rosters are
nonempty, sorted, unique arrays of canonical node NIDs, and numeric fields are
JSON-safe nonnegative integers. An empty roster always rejects; ordinary
removal cannot remove the final node. `config_head` is the canonical config-repository
snapshot being acknowledged immediately before the commit that stores this
checkpoint; it never names a commit containing itself.
`config_key_id` is 16 random bytes encoded as exactly 32 lowercase hexadecimal
characters and is the active config-branch key identifier. It is inserted
verbatim into `refs/heads/enc/<config_key_id>` and every credential path; a
producer and verifier MUST parse the fixed hex, decode 16 bytes, re-encode, and
require byte-for-byte round-trip equality before ref/path construction. `/`,
`.`, `@{`, `.lock`, controls, Unicode, alternate case, and every variable-length
or noncanonical spelling are therefore impossible.
Despite their historical field names, `config_key_sha256` and
`pairwise_secret_sha256` are not bare secret hashes. Each is the exact
`heterodyne-node-secret-instance-v1` domain-separated
`instance_commitment` defined below with `commitment_kind:"secret-bytes"` and
respectively `secret_class:"config-audience"` or
`secret_class:"oauth-pairwise"` over the exact 32-byte secret.
Every roster receipt is valid
only after that node decrypts the named branch, verifies both key
commitments, replays the source/exposure records at `config_head`, and
recomputes the exact `exposure_set_sha256`. It also replays the complete
historical-decrypt-obligation lineages and governed retained-ciphertext state
at that same head, establishes the exact bijection defined below, and
recomputes `governed_decrypt_key_bindings_sha256` and
`historical_decrypt_obligations_sha256`.
`exposure_set_sha256` is the domain-separated mergeable-set digest defined
below. A checkpoint with null `secret_transition_digest` evaluates the
conservative set at `config_head` under the canonical accepted-transition set.
A checkpoint with a non-null transition digest applies exactly that named
independently valid pending transition—routine rotation, addition, removal, or
reset—to the set at `result_basis.config_head` and carries that projected
digest; every roster node verifies the same projection before receipt.
Checkpoint acceptance makes that one projection ordinary accepted state
atomically. No other pending transition affects the digest.
`governed_decrypt_key_bindings_sha256` is the complete retention-snapshot and
binding-set digest `K(C)` defined below. It is evaluated at the same exact
config/result-basis projection and recomputed before every receipt.
`historical_decrypt_obligations_sha256` is the separately domain-separated
mergeable-set digest defined below. It uses the same projection boundary: a
checkpoint with null `secret_transition_digest` evaluates the complete
maximal frontier `F(C)` at `config_head`, including close and competing
branches even though a competing maximum rejects ordinary acceptance; a
checkpoint with a non-null transition digest applies only that exact
independently valid transition's retain/close records to the obligation state
at `result_basis.config_head`. Every receipt recomputes the resulting
governed-ciphertext equation and digest before it counts.
`config_bootstrap_recipients_digest` is non-null exactly for the
generation-zero/sequence-zero checkpoint and for any successor whose
`config_key_id` differs from its predecessor. It is null otherwise. On an
emergency reset it equals the reset's `bootstrap_recipients_digest`; genesis
and every routine config-key transition use the receipt-only bootstrap array
below.
`secret_transition_digest` is non-null on every config-key change, including
routine rotation, roster addition/removal, and emergency reset, and names the
canonical complete transition record defined below. It is null otherwise.
At candidate acceptance, every roster NID MUST have one active, durable,
unforked Core delegation under the checkpoint's accepted KEL state. A receipt
counts only when its signer delegation was active at `observed_at` and remains
active at candidate acceptance; a revoked, expired, provisional, or fork-only
NID cannot join a roster or satisfy a receipt.
The three legal continuity forms are:

```text
generation 0, sequence 0:
  previous_checkpoint = null
  generation_transition = null

sequence greater than 0:
  previous_checkpoint = digest of sequence - 1 in the same generation
  generation_transition = null

generation greater than 0, sequence 0:
  previous_checkpoint = null
  generation_transition = digest of the staged independently valid
                          reset candidate
```

Every other combination rejects. The epoch signature is 64 bytes encoded as
128 lowercase hex and covers:

```text
SHA256(
  UTF8("heterodyne-credential-ledger-checkpoint-v1") || 0x00 ||
  JCS(checkpoint with epoch_signature omitted)
)
```

`epoch_pubkey` is 32 bytes encoded as 64 lowercase hex and `kel_head` is
exactly `{"event_id":"<64 lowercase hex>","seq":<JSON-safe nonnegative
integer>}`. A verifier replays that accepted KEL head and requires the named
epoch key to be current at `created_at`; `created_at` must not precede the
accepted KEL event's effective time. More importantly, when a checkpoint is a
candidate for first acceptance, its key and KEL head MUST exactly equal the
verifier's current accepted persona key and head after normal fork,
compromise-cutoff, and freshness processing. A historically valid but
superseded key therefore cannot create a new accepted checkpoint merely by
backdating. A later rotation does not erase an already accepted checkpoint
from audit history, but credential authority is held after rotation until an
ordinary successor signed under the new current head is canonical and fully
receipted.

`checkpoint_digest` is lowercase-hex SHA-256 over the JCS bytes of the complete
checkpoint including `epoch_signature`.

Genesis and every routine config-key transition use one closed receipt-only
`heterodyne.credential-ledger.config-key-bootstrap-recipient-array.v1`.
It is stored at
`credential-sync/config-key-bootstraps/<generation>/<sequence>-<digest>.json`,
where `<digest>` is lowercase-hex SHA-256 of the complete JCS array, and the
checkpoint's `config_bootstrap_recipients_digest` equals that digest. The
array is strictly ordered by unsigned UTF-8 bytes of `nid` and contains
exactly one closed entry for every candidate-roster NID:

```text
nid, delegation_event_id, recovery_key, nid_proof, enc, ciphertext
```

Before proposal, each recipient supplies a fresh X25519 recovery key and its
Ed25519 NID signs the domain-separated JCS object containing exactly
`persona`, `generation`, `sequence`, `config_head`, `config_key_id`,
`config_key_sha256`, `nid`, and `recovery_key`. The delegation, proof, key
encoding, recipient fingerprint, HPKE suite, `enc`, ciphertext, and
one-entry-per-NID validation rules are identical to the reset bootstrap below,
with domain `heterodyne-credential-config-bootstrap-recipient-v1`.
The exact HPKE plaintext is:

```text
{type:"heterodyne-credential-config-key-bootstrap-v1", persona, generation,
 sequence, config_head, config_key_id, config_key_sha256,
 config_audience_key}
```

and the exact context is the same object without `config_audience_key`, with
type `heterodyne-credential-config-key-bootstrap-context-v1`, plus
`recipient_nid` and `recipient_fingerprint`. Plaintext and context use their
exact JCS UTF-8 bytes; the audience key is unpadded base64url of exactly
32 bytes. Neither object contains the checkpoint digest or array digest, so
the checkpoint can commit the already-complete array without a cycle.
The recipient recomputes `config_key_sha256` with the exact
domain-separated config-audience instance-commitment construction, never a
bare SHA-256 of the decoded audience key.

The candidate checkpoint and array may travel over authenticated DR, local
IPC, or offline media before the encrypted branch is active. A recipient
first verifies the checkpoint signature/current KEL, roster, array digest,
delegation, NID proof, and HPKE context; it decrypts only to inspect the exact
candidate branch and does not issue a receipt until the branch, commitments,
authorization set, and exposure projection all verify. This possession gives
no publishing, minting, synchronization, serving, or other operational
authority. The exact candidate plus every roster receipt must become
canonical first. Each recipient erases its fresh X25519 recovery private key
immediately after its successful checkpoint receipt and before normal
authority resumes. This is the sole pre-receipt config-key delivery mechanism
for genesis and routine rotation, addition, or removal; emergency reset uses only its
cold-root-bound reset array below.

`record_set_digest` uses exactly the already-defined
`predecessor_ledger_digest` algorithm from Comms credential sync. Its set is
the union of every credential-sync grant or revoke record that is reachable
from `config_head` and individually structurally, cryptographically, persona-,
KEL-, repository-, and generation-field-valid. It includes expired grants,
every revoke tombstone, and retained records from prior generations. Current
time, current delegation status, operational revocation outcome, and equality
to the current ledger generation do not filter this audit set. Checkpoints,
receipts, resets, claim-ledger records, JWTs, Status List Tokens, and repository
metadata are excluded. Records under
`credential-sync/lost-generation-audit/` are also categorically excluded even
when their copied signed bytes would be valid in the operational authorization
namespace; that namespace contributes only to `lost_audit_set_digest`.

For each included complete signed record:

```text
record_bytes  = UTF8(canonical_compact_json(record))
record_digest = lowercase_hex(SHA256(record_bytes))
```

Byte-identical records collapse to one; distinct byte strings with the same
digest invalidate the candidate. Distinct records sort by:

```text
(
  decoded authorization_id bytes,
  UTF8(target_nid) bytes,
  issued_at integer,
  action_rank,
  decoded record_digest bytes
)
```

where grant rank is zero and revoke rank is one. Byte comparisons are unsigned
lexicographic and integers compare numerically. Then:

```text
record_digest_array =
  canonical_compact_json([record_digest(record_0), ..., record_digest(record_n)])
record_set_digest =
  lowercase_hex(SHA256(UTF8(record_digest_array)))
```

The empty-set digest is therefore SHA-256 of the two UTF-8 bytes `[]`.
Implementations use one implementation for `record_set_digest` and
`predecessor_ledger_digest`.

Each roster node acknowledges the exact checkpoint with a
`heterodyne.credential-ledger.checkpoint-receipt.v1` containing `type`,
`checkpoint_digest`, `node_nid`, `observed_at`, and `signature`. The node's
Ed25519 NID signs:

```text
SHA256(
  UTF8("heterodyne-credential-ledger-checkpoint-receipt-v1") || 0x00 ||
  JCS(receipt with signature omitted)
)
```

The signature is 64 bytes encoded as unpadded base64url. The receipt
filename component is lowercase-hex SHA-256 of the canonical NID's UTF-8
bytes; `receipt_digest` is lowercase-hex SHA-256 of the JCS bytes of the
complete signed receipt. Checkpoint and reset path digests use the identical
complete-signed-JCS rule. A checkpoint is fully receipted only when every node
in its roster has a valid receipt. Two distinct valid receipts by one node are
audit evidence but still count as one roster acknowledgement only when both
name the same checkpoint.

Routine removal additionally requires one closed
`heterodyne.credential-ledger.removal-observation.v1` from every removed NID.
It contains exactly:

```text
type, persona, transition_id, transition_digest, checkpoint_digest,
source_ref_head, staged_ref, staged_head, node_nid, observed_at, signature
```

`staged_ref` is exactly `refs/heads/enc/<new-config-key-id>` and `staged_head`
is the typed Git head for candidate root `C`. `source_ref_head` equals the
transition inventory basis; the two complete-record digests name the exact
routine-removal transition and candidate checkpoint. The removed NID verifies
the accepted predecessor and old ref, the transition authority/signature and
its own membership in `removed_nids`, its exclusion from the target roster and
bootstrap array, the candidate checkpoint's exact transition/target binding,
and the signed staging-ref publication. It does not decrypt the candidate
branch or receive its config key.

The NID signs:

```text
SHA256(
  UTF8("heterodyne-credential-ledger-removal-observation-v1") || 0x00 ||
  JCS(observation with signature omitted)
)
```

with 64-byte Ed25519 encoded as unpadded base64url. `observation_digest` is
lowercase-hex SHA-256 of complete signed JCS and equals the filename component;
the NID path component is the lowercase-hex SHA-256 of canonical NID UTF-8.
Observation commits descend from `C`. Candidate acceptance requires exactly
one valid observation per `removed_nids` member and no others. This one record
type verifies the NID signature and delegation at the exact accepted
predecessor KEL/delegation state, even when the transition's independently
bound Core revocation is already canonical by `B` and therefore predates
`observed_at`. That historical-key exception authorizes only acknowledgement
of this exact already-signed transition/checkpoint/staged ref; it cannot
authorize a receipt, grant, publication, successor state, or any other
post-revocation act. `observed_at` is no earlier than signed publication of
exact `C` and no later than candidate acceptance. Acceptance nodes decrypt
`C` and verify that the checkpoint/transition bytes whose digests were
observed are the exact bytes in the candidate lineage. These post-`C`
observations are acceptance conditions and are not referenced by the
transition or checkpoint, avoiding a digest cycle. A missing observation makes
the path permanent loss and requires emergency reset.

An unaccepted successor does not remain a candidate forever merely because a
recipient withholds a receipt. While the predecessor is still the current
accepted checkpoint, the current epoch authority may issue one absorbing
`heterodyne.credential-ledger.candidate-abandonment.v1` containing exactly:

```text
type, persona, predecessor_checkpoint, candidate_checkpoint_digest,
candidate_transition_id, candidate_transition_digest,
candidate_ref, candidate_head, abandonment_ref, abandonment_basis_head,
partial_acceptance_record_set_sha256, candidate_exposure_records,
candidate_governed_decrypt_key_bindings_sha256,
candidate_historical_decrypt_obligations_sha256,
abandoned_at, epoch_pubkey, kel_head, epoch_signature
```

`candidate_transition_id` and `candidate_transition_digest` are both null for
a successor with no secret transition and otherwise name its exact complete
transition. `candidate_ref` and `abandonment_ref` are exact signed
repository-relative config refs; each head is the closed typed Git head used
elsewhere. For a config-key transition, `candidate_ref/head` equal the staged
new-key ref and its exact current append-only partial-acceptance tip descending
from `C`, while `abandonment_ref` is the still-authoritative old-key ref. For a
same-key ordinary successor, both refs are the active config ref and
`candidate_head` is that exact current ref tip descending from `C`, reaching
the checkpoint and its currently available receipt records. It may also reach
a later security-critical write that made acceptance impossible; such a write
is preserved in the abandonment basis rather than rolled back.
`abandonment_basis_head` is the exact current target of `abandonment_ref`,
reaches the accepted predecessor and every security-critical write already
accepted there, and, for a config-key transition, reaches
`candidate_transition.inventory_basis.source_ref_head`.
`partial_acceptance_record_set_sha256` is
`lowercase_hex(SHA256(UTF8("heterodyne-partial-acceptance-record-set-v1") ||
0x00 || UTF8(JCS(items))))`, where `items` is the complete strictly
record-type/digest-sorted array of closed
`{record_type,record_digest,node_nid}` entries for every valid checkpoint
receipt and removal observation reachable from `candidate_head`.
`record_type` is exactly `checkpoint-receipt` or `removal-observation`;
the former sorts first, then decoded digest bytes, then canonical NID UTF-8
bytes. Duplicate complete record digests reject.

`candidate_exposure_records` is the complete strictly ordered unique array of
closed `{record_type,record_digest}` objects for every node-secret source and
`action:"assign"` exposure record newly reachable at the candidate
checkpoint's exact `config_head` relative to its accepted predecessor's
operational config state. `record_type` is exactly `secret-source` or
`secret-assignment`, in that order, followed by decoded digest bytes. Inherited
byte-identical records, later writes after the checkpoint, retirements, and
other record classes are excluded. Every listed assignment's exact source is
listed or was already accepted in the predecessor; every newly reachable
source/assignment is listed. The verifier derives the array independently from
the two named states. This binds ordinary null-transition exposure additions
even when a same-key candidate is later abandoned.
`candidate_historical_decrypt_obligations_sha256` equals the candidate
checkpoint's field and is independently recomputed from its exact
`config_head`, including the complete `G(C) = O(C)` equation, active
projection, full maximal frontier `F(C)`, governed locators/key bindings, and
retired provenance. It equals the predecessor
digest only when the candidate makes no exact projected obligation-state
change. A transition-bound retain/close projection or governed-ciphertext
change cannot be hidden by retaining the predecessor value.

`candidate_governed_decrypt_key_bindings_sha256` separately equals the
candidate checkpoint's field and is independently recomputed as `K(C)` from
that exact `config_head`, including the complete retention-snapshot head set,
every reachable canonical binding-record frontier row, and every conflict
variant. It equals the predecessor digest only when the candidate makes no
exact governed-snapshot or binding-frontier change. Neither candidate digest
may absorb, substitute for, or omit the other.

The named checkpoint/transition MUST have been an otherwise-valid successor of
`predecessor_checkpoint` when staged, MUST still be unaccepted, and MUST have
no successful canonical acceptance transition. For a config-key candidate, a
signed candidate tip may already contain the complete receipt/observation set
yet remain unaccepted because the old-ref half of its acceptance CAS can no
longer succeed; that inert complete tip may be abandoned. A later reachable
security-critical write may have invalidated acceptance but no other
staging-time defect is excused. `predecessor_checkpoint` MUST still be the current accepted
checkpoint. `abandoned_at` is a JSON-safe nonnegative integer no
earlier than the candidate checkpoint and transition creation times.
`epoch_pubkey/kel_head` are the exact current accepted epoch state at first
acceptance. That key signs:

```text
SHA256(
  UTF8("heterodyne-credential-ledger-candidate-abandonment-v1") || 0x00 ||
  JCS(record with epoch_signature omitted)
)
```

using BIP-340 encoded as 128 lowercase hexadecimal characters. The
`abandonment_digest` and path component are lowercase-hex SHA-256 of complete
signed JCS. The directory component is the record's exact
`candidate_checkpoint_digest`, so a same-key candidate with null transition
members has the same unambiguous path grammar.

The record becomes canonical only through one signed-ref compare-and-swap
that freezes the exact partial-evidence tip. For a config-key transition the
atomic signed multi-ref CAS requires
`candidate_ref == candidate_head` and
`abandonment_ref == abandonment_basis_head`, leaves the candidate ref fixed,
and advances the abandonment ref to a direct child containing the record.
For a same-key candidate, where those names identify one ref and
`candidate_head == abandonment_basis_head`, the CAS advances that exact tip to
a direct child containing the abandonment. In either form the validator
recomputes `partial_acceptance_record_set_sha256` from the complete valid
receipt/observation set reachable from the compared candidate tip and
recomputes `candidate_exposure_records` from the predecessor and candidate
checkpoint config states. It also recomputes the candidate governed-binding
and historical-obligation digests and governed-ciphertext equation at that
same exact head. A
mismatch, an invalid or out-of-roster record, or a second observation for one
removed NID rejects the abandonment.

The candidate-ref append CAS and abandonment CAS are linearly ordered. If an
append wins first, the proposed abandonment's compared head and partial-set
digest are stale and the authority must rebuild it over the new tip. If
abandonment wins first, no later acceptance record may append. For a
config-key transition the old-ref advance also makes the candidate's
source-ref acceptance CAS fail; for a same-key candidate, acceptance replay
treats the reachable abandonment before any complete acceptance head as
terminal. If acceptance wins first, abandonment fails.
Exact duplicate bytes are idempotent; a later nonidentical abandonment has no
additional effect. Once canonical, abandonment is absorbing, the record is
never removed from the accepted audit chain, and the abandoned successor no
longer counts in the one-candidate rule. Its staged ref, protected candidate
key, source/assignment, governed-decrypt-key-binding, and
historical-obligation records, governed-ciphertext projection, and partial
receipts remain inert evidence. A retain or close
record whose transition never accepts cannot change the predecessor's active
obligation set.
A source/assignment tuple for the epoch key that is independently current
under the canonical Core KEL is the sole exception to “inert”: abandonment
cannot undo that already accepted KEL authority. It remains conservative
exposure/accounting state under the epoch-adoption rule below, while the
abandoned config checkpoint and every other staged capability remain
non-authoritative.
A later candidate MUST start from the post-abandonment authoritative head and
copy the abandonment record into its parentless generation. For a config-key
abandonment it also includes that staging ref in `signed_ref_map`, includes
every staged exposure in the mandatory cleanup set except the exact safe
current-epoch adoption tuple, retires each included assignment, reconciles any
adopted epoch tuple under the singleton rule, and later applies staging-ref
cleanup. For a same-key abandonment there is no nonactive staging ref or
candidate key to clean. Instead the next transition MUST include every
`secret-assignment` in `candidate_exposure_records` in its mandatory cleanup
set: the exact current canonical epoch tuple may be safely adopted under the
singleton rule, and every other assignment is retired. A desired non-epoch
capability is recreated as a fresh successor source/assignment rather than
adopting the abandoned ordinary assignment. The source records and absorbing
retirements remain on the active audit chain; staging-ref cleanup is neither
required nor permitted for this same-key case.

If current epoch authority is unavailable or competing candidates prevent an
ordinary abandonment from becoming canonical, the existing cold-root reset
escape is the sole alternative. Its complete inventory includes every pending
candidate/staging ref; accepted reset terminalizes every unaccepted candidate
from the last common checkpoint and closes all of their conservative
exposures. A cold-root reset and an epoch abandonment cannot both win: their
old-ref/inventory compare-and-swap ordering makes the later construction
rebuild from the already canonical outcome. No timestamp or local
“abandoned” flag supersedes these signed transitions.

Retiring every staged assignment, or safely adopting the exact current epoch
subset, does not by itself delete its inert encrypted ref. Cleanup uses one closed
`heterodyne.credential-ledger.staging-ref-cleanup.v1` containing exactly:

```text
type, persona, staging_config_key_id, staging_ref, staging_head,
staging_transition_id, staging_transition_digest, staging_baseline_head,
terminalization,
accepted_transition_id, accepted_transition_digest,
accepted_checkpoint_digest, active_ref, active_basis_head,
staging_storage_object_set_sha256, inherited_audit_set_digests,
opaque_object_manifest, opaque_object_manifest_sha256,
safe_record_copies, safe_record_set_sha256, assignment_record_digests,
adopted_epoch_assignment_digests,
retirement_record_digests, cleaned_at, epoch_pubkey, kel_head,
epoch_signature
```

`staging_config_key_id` is the exact 32-lowercase-hex config-key ID and
`staging_ref` is exactly
`refs/heads/enc/<staging_config_key_id>`. `staging_head` is the exact inert
head still present in the current signed-ref map. `active_ref/head` name the
current accepted encrypted config ref and its exact head.
`staging_transition_id/digest` identify the exact unaccepted config-key
transition that created the staging generation, and `staging_baseline_head`
equals that transition's `inventory_basis.config_head`. The staging transition
cannot have a successful acceptance transition; its frozen candidate tip may
nevertheless contain a complete receipt/observation set whose old-ref CAS
failed.
`terminalization` is a closed object containing exactly `kind`,
`record_digest`, and `acceptance_head`. `kind` is
`candidate-abandonment` or `emergency-reset`. In the former case,
`record_digest` names the exact canonical absorbing abandonment for the staging
candidate and `acceptance_head` is the signed-ref head whose accepted CAS first
made that record reachable; `staging_head` MUST equal that abandonment's
frozen `candidate_head`. In the latter case, `record_digest` names an exact
accepted cold-root emergency reset, `acceptance_head` is that reset's complete
acceptance head, and the reset's closed signed-ref inventory contains this
exact `staging_ref == staging_head` and explicitly terminalizes this
unaccepted candidate under the emergency-reset rule below. No timeout, failed validation,
local flag, ref absence, or merely newer checkpoint is a terminalization fact.
For either kind, replay proves that the terminalization CAS won before cleanup,
that a candidate-acceptance CAS did not win first, and that accepting this
candidate from its old basis is permanently impossible under the append-only
signed-ref state machine.
`accepted_transition_id/digest` and `accepted_checkpoint_digest` identify the
later accepted transition that retired every exposure reachable from the
staging generation except an exact safely adopted current-epoch subset.

Cleanup never republishes decrypted arbitrary or secret-bearing candidate
content. In particular, an
abandoned candidate may contain a fresh but compromised OIDC pairwise secret,
bootstrap ciphertext, bearer credential, or arbitrary configuration secret;
none of those plaintext bytes or their bare hashes may be copied beneath the
current config key. The exact closed safe signed-record allowlist below is the
sole decrypted-copy exception. Before erasing the candidate key, the verifier instead
walks the exact raw Git object closure from the parentless candidate basis
through `staging_head`. It authenticates every object with the named repository
object format and constructs one complete strictly ordered
`opaque_object_manifest`, with only the authenticated inherited-subtree
elision defined below. Each closed entry contains exactly:

```text
object_type, object_id, raw_sha256, paths, disposition,
audit_path, audit_sha256, inherited_audit_set_digests
```

`object_type` is `commit`, `tree`, or `blob`; `object_id` has the exact
typed-head object format and canonical lowercase length; `raw_sha256` hashes
the exact raw Git object body, excluding the Git type/length framing.
`paths` is the sorted unique complete set of canonical tip or historical-tree
paths through which the object is reachable and is empty only for a commit.
The empty string is the sole root-tree sentinel and may appear only as the
sole path for a root tree; blob paths are nonempty.
Entries sort by object-type rank (`commit`, `tree`, `blob`) and then decoded
object-ID bytes. A missing reachable object outside a valid elided subtree, an extra object, a history escape
past the candidate's parentless basis, a symlink, gitlink, nonregular blob
mode, unsafe path, object-ID mismatch, or two raw bodies for one ID rejects.
`staging_storage_object_set_sha256` is
`lowercase_hex(SHA256(UTF8("heterodyne-staging-storage-object-set-v1") ||
0x00 || UTF8(JCS(opaque_object_manifest))))`, with every disposition and
`audit_sha256` already populated; `opaque_object_manifest_sha256` is
lowercase-hex SHA-256 of exact UTF-8 JCS of that same array.

The top-level `inherited_audit_set_digests` is the sorted unique complete set of prior
accepted complete cleanup-record digests whose logical audit namespaces are
present in the candidate; each such signed record binds both its opaque-object
and safe-record sets. Before cleanup, the retained candidate
key partitions each logical namespace under
`credential-sync/staging-ref-audit/`. A namespace is inherited only when every
file is a byte-identical member of exactly one already accepted cleanup set and
the namespace has no omission or addition. A namespace that is prospective
but unaccepted, spoofed, mutated, incomplete, or otherwise unreferenced is
ordinary non-inherited candidate material: it grants no audit status, is never
logically promoted, and its complete raw tree/blob closure is opaque-copied.
Such a namespace cannot cause cleanup rejection merely by using the audit
prefix; an attempt to classify nonidentical bytes as an accepted inherited set
rejects that classification. A blob reachable exclusively through
authenticated inherited audit paths
has `disposition:"inherited-reference"`, null `audit_path/audit_sha256`, and
the exact sorted nonempty subset of prior cleanup digests that prove those
paths in its `inherited_audit_set_digests`; its redundant candidate-key
re-encryption need not survive. A tree whose complete subtree and every
reachable path lie exclusively inside one or more authenticated inherited
audit namespaces uses the same disposition and exact proving digest subset;
its redundant body and descendant object entries are elided as one
authenticated subtree reference. A tree that also reaches any non-audit path
or any unaccepted/prospective audit namespace,
including each mixed ancestor from the repository root to the audit namespace,
cannot be elided. Every commit, every mixed/non-audit tree, and every blob
reachable through at least one non-audit or unaccepted/prospective audit path has
`disposition:"opaque-copy"`, an empty `inherited_audit_set_digests` array, and is copied
without decryption to exactly
`credential-sync/staging-ref-audit/<staging-config-key-id>/<staging-head-token>/objects/<object-type>/<object-id>.bin`.
That file's logical bytes are the candidate repository's exact raw object body,
not the plaintext inside an encrypted config blob, and `audit_sha256` hashes
those copied bytes. `staging-head-token` is canonical
`<object-format>-<lowercase-object-id>`. The active basis MUST reach every
opaque-copy path and no unlisted path in that object-set directory. Thus the
non-inherited candidate ciphertext and structural history remain inspectable,
while elided redundant inherited re-encryptions remain committed by their tree
IDs, raw hashes, and prior signed cleanup digests rather than byte-copied.
Destruction of the candidate audience key makes retired secret plaintext
unavailable to future roster members. Prior audit subtrees are referenced
rather than nested or recopied, so repeated cleanup adds one new audit
namespace plus references instead of copying every prior tree body.

Cold replay still needs the non-secret signed control records that prove the
exposure and retirement sets. `safe_record_copies` is the complete strictly
record-digest-sorted array of closed
`{profile_id,record_digest,source_path,audit_path,audit_sha256}` entries for
every schema-valid and, where the profile is directly signed, signature-valid
checkpoint, receipt, removal observation,
candidate abandonment, cleanup, reset, source, assignment/retirement,
repository-retention inventory, governed-decrypt key binding,
historical-decrypt obligation, transition, action, Double Ratchet
termination, ADR-038 offline-recovery pre-unseal intent or activation, or
lost-generation index
reachable from the staging lineage and not already byte-identically reachable
from `active_basis_head` outside this cleanup's exact reserved
`credential-sync/staging-ref-audit/<staging-config-key-id>/<staging-head-token>/`
namespace. A record found only inside that reserved destination remains novel,
MUST be listed, and MUST be reachable at its exact `audit_path`; a record
reachable byte-identically elsewhere in the active basis is omitted. The
reserved namespace is therefore excluded from the “already reachable” side
rather than making B's recovered copy erase its own provenance. The allowlist is
exact; bootstrap plaintext/ciphertext,
wrapped key material, bearer/token bytes, arbitrary configuration, and an
unknown record type are never safe copies. Each safe record is decrypted while
the candidate key exists, revalidated under its allocated closed schema, and
copied as its exact JCS bytes (exact signed JCS for every directly signed
profile) to
`credential-sync/staging-ref-audit/<staging-config-key-id>/<staging-head-token>/records/<record-digest>.json`.
No record whose `source_path` lies inside an unaccepted/prospective audit
namespace enters this array; that entire namespace remains opaque candidate
material even if one decrypted file happens to resemble an allowlisted record.
An unsigned lost-generation index enters only when its exact path, path/index
digests, and opaque-variant bytes all verify and it is reachable from the exact
closure-basis `B` bound by an otherwise-valid signed reset, transition, and
candidate checkpoint. No free-standing unsigned index is allowlisted.
The record digest and `audit_sha256` are recomputed, a record/path collision
rejects, and `safe_record_set_sha256` is
`lowercase_hex(SHA256(UTF8("heterodyne-staging-safe-record-set-v1") || 0x00 ||
UTF8(JCS(safe_record_copies))))`. These copies convey audit evidence only and never
reactivate a source, assignment, candidate, or authorization.

`assignment_record_digests` is the sorted unique complete conservative
assignment set attributable to that staging generation.
`adopted_epoch_assignment_digests` is empty unless the singleton rule adopts
the exact current canonical epoch tuple; when nonempty it equals that tuple's
complete assignment subset, every member is byte-identically reachable from
the new active basis, and its KEL/holder/competition checks are repeated at
cleanup acceptance. `retirement_record_digests` is the exact one-to-one
accepted retirement set for
`assignment_record_digests - adopted_epoch_assignment_digests`; no other
assignment may escape retirement.
An empty or incomplete object manifest, safe-record set when a safe record is
present, assignment set, or required retirement set rejects. Verification requires only
the retained candidate key and raw candidate ref, never the retired
`staging_baseline_head` audience key. The complete opaque object commitment,
nonrecursive inherited references, and safe-record set are audit preservation;
they do not make the abandoned candidate or any copied authorization record
authoritative.

The current accepted epoch key/head signs the ordinary BIP-340
domain-separated JCS transcript under
`heterodyne-credential-ledger-staging-ref-cleanup-v1`; `cleanup_digest` is
lowercase-hex SHA-256 of complete signed JCS and is the filename component.
The record becomes canonical only in one atomic signed multi-ref
compare-and-swap that requires `active_ref == active_basis_head` and
`staging_ref == staging_head`, advances `active_ref` to a direct child
containing the cleanup record, and deletes only that exact inert
`staging_ref`. The active basis MUST reach the accepted checkpoint,
transition, every retirement, every adopted epoch assignment, and every
copied audit byte before the CAS.
The ref MUST be nonactive and the exact terminalization proof above MUST remain
canonical. A mismatch, newly advanced staging ref, incomplete
retirement/adoption partition,
noncanonical terminalization, or concurrent transition fails without deleting
or erasing anything.

Until that cleanup CAS succeeds, the ref remains in `signed_ref_map` and
`staging_heads`, its protected candidate key remains decryptable, and future
transitions continue to inventory it even after its assignments are retired
or an exact epoch subset is adopted.
After success the cleanup record and its one new audit namespace are durable on
the active ref, the deleted ref is absent from later maps, and the protected
staging key may be erased. Later parentless generations preserve prior audit
namespaces byte-identically and carry their set digests without recopying them
inside a new namespace. A
cleanup racing a transition whose inventory includes the ref changes that map
and forces the transition to rebuild; if the transition accepts first, cleanup
must rebuild from the newer active basis. Exact replay of an already accepted
cleanup is idempotent and never deletes a reused or different ref.

Checkpoint acceptance is a closed chain state machine:

For every genesis, ordinary, roster-change, and reset checkpoint,
acceptance-time replay MUST prove that no credential-sync authorization record
and no node-secret source, assign, retirement, or transition-action record
and no governed-decrypt key binding, historical-decrypt obligation, governed
retained-ciphertext locator, or obligation provenance record changed after
the checkpoint's exact `config_head` and before the canonical head containing
its complete receipt set. Any such mutation in that interval invalidates the
candidate and requires a new checkpoint from the newer head.
Revocation and other security-critical writes are never blocked merely to
preserve a candidate. This invariant is universal; the specialized rules below
only add constraints.

Every checkpoint also enforces two universal singleton identities after
applying only its exact accepted transition projection. First, the operational
`oauth-pairwise` assignments resolve to exactly one
`(secret_id,instance_commitment)` tuple, every operational holder source names
that tuple, and its commitment equals `pairwise_secret_sha256`. An
exposure-only or null-transition successor may add another holder assignment
only for that same tuple and MUST keep the predecessor checkpoint commitment
unchanged. Introducing a different pairwise tuple or commitment requires a
non-null secret transition that includes every predecessor and competing
pairwise assignment, retires them atomically, and establishes exactly one
successor tuple. Thus a fully receipted exposure-only checkpoint cannot create
a second pairwise identity or silently change the commitment.

Second, exactly one operational `epoch` tuple equals the canonical Core KEL's
current `(epoch_pubkey,kel_head.event_id,kel_head.seq)` identity and the
checkpoint's epoch fields. Every operational current-epoch holder source and
assignment names that same tuple. Noncurrent epoch assignments remain
historical conservative exposure only. Adding a holder for the unchanged
canonical tuple may use a separately accepted exposure checkpoint, but a
different epoch identity requires its cold-root-authorized KEL rotation,
transition accounting, and singleton closure. A null-transition record,
competing source, or checkpoint field cannot manufacture another current
epoch. These checks run for genesis, same-key successors, config-key
transitions, and emergency reset before receipts count.

- Before genesis, credential-plane synchronization and minting are held.
  Genesis is the unique generation-zero/sequence-zero checkpoint with no
  predecessor, a nonempty roster, and the record set computed from its
  pre-checkpoint `config_head`. It becomes accepted only at a canonical config
  head from which the checkpoint and valid receipts from every genesis-roster
  node are reachable.
- An ordinary successor names the currently accepted checkpoint, stays in the
  same generation, increments sequence by exactly one, has a null generation
  transition, and computes its record set from its own pre-checkpoint config
  head. Its predecessor must already be canonical and fully receipted. The
  successor becomes accepted only when it and every candidate-roster receipt
  are reachable from one canonical config head.
- An exposure-only ordinary successor keeps the roster and authorization
  record set byte-identical and advances `exposure_set_sha256` to include
  newly staged source/assign records. The corresponding secret or capability
  is not delivered or enabled until that successor is fully receipted.
- An ordinary successor with null `secret_transition_digest` also keeps
  `governed_decrypt_key_bindings_sha256` and
  `historical_decrypt_obligations_sha256` byte-identical. Creating, updating,
  or closing an obligation, or changing any retention snapshot, governed
  decrypt-key binding, or governed retained-ciphertext dependency, requires
  the exact non-null transition whose
  inventory/result/target projection binds that change and a fully receipted
  successor checkpoint.
- A roster addition or synchronized removal is an ordinary successor with the
  config-key transition below. It starts from a fully receipted predecessor;
  addition rotates before delivery to the new NID, and removal cannot omit an
  unreachable prior node through this path. The authorization record set
  remains byte-identical.
- An emergency reset successor follows the separate cross-generation rules
  below.

At most one non-identical valid, unaccepted, and unabandoned successor of an
accepted checkpoint may be a candidate. Competing genesis records,
same-predecessor successors, or canonical heads stall checkpoint advancement
and all credential-plane authority until one exact candidate is established,
an epoch-signed abandonment becomes canonical, or a cold-root reset starts
from the last common fully receipted checkpoint.
The greatest accepted checkpoint determines `current_generation`, and its
`node_roster` is the exact “currently configured persona full nodes” set used
by Comms credential-sync convergence. Once a reset is accepted, nodes omitted
by its new roster no longer participate in the all-node reachability rule;
nodes still in the accepted roster remain mandatory.

Every full node maintains a durable, append-only exposure index derived from
canonical Core keys-store records and every canonical Comms distribution,
wrap, ACL, session, endpoint, and credential record. Recording exposure is
part of the same crash-consistent commit that gives a node a long-lived secret
or decryption capability. The pre-0.5 migration scans current protected state
and refuses node removal until every discovered capability has a source
record. The index covers at least:

```text
cold-root, epoch, device-signing, agent-signing, core-protected,
config-audience, tier3-audience, claim-ledger-audience, object-dek,
double-ratchet, radicle-access, oauth-signing, oauth-pairwise,
bearer-credential, ssh-client, ssh-host, recovery-wrap,
onion-service-identity, tls-serving
```

Those are closed `secret_class` values for this profile. “Exposure” means the
node possessed, hosted, cached, or could unwrap the material; claimed local
erasure does not remove an exposure.

The index is a mergeable set of independently identified, epoch-signed
`heterodyne.node-secret-exposure.v1` assignment lineages. Every record
contains exactly:

```text
type, persona, assignment_id, action, holder_nid, secret_class,
secret_id, secret_commitment,
source_profile, source_record_digest, transition_id, supersedes,
issued_at, authority, signature
```

`assignment_id` is 16 random bytes encoded as 32 lowercase hex. There is
exactly one distinct `assign` record per assignment ID; collision or competing
assign bytes prevent operational use of every competing variant but do not
remove any variant from recovery inventory. Every otherwise-valid complete
assign digest is treated as a separate conservative exposure lineage and must
be retired by a record whose `supersedes` names that exact digest. The
collision is audit evidence, cannot stall unrelated assignments, and cannot
block emergency removal.
An ordinary `assign` record has null `transition_id` and `supersedes`, and its
exact holder/source tuple MUST be committed atomically with the source record
that gives the holder the capability. A successor assignment staged by any
config-key transition has a non-null transition ID, null `supersedes`, and,
unless it is the exact current-Core-epoch accounting exception below, remains
operationally non-authoritative until that exact transition becomes accepted,
but it enters the conservative exposure set as soon as it is canonical. A `retire`
record repeats the assign's persona, assignment ID, holder, class, secret
identity/commitment, and source fields, names the governing transition ID, and
sets `supersedes` to the assign record digest. It is a pending proposal while
the transition is pending: the old assignment remains exposed and the staged
successor remains unusable but exposed. Retirement becomes absorbing, and
successor assignments gain operational authority, except for the narrow
current-Core-epoch accounting rule below, atomically with acceptance of the
exact referenced checkpoint/reset. If the candidate is abandoned or
invalidated, later replay continues to count both the old assignment and
every staged/delivered successor assignment as exposures; another transition
must retire material no longer wanted. Two different transitions can never
both become accepted for one assignment.
The ADR-038 offline candidate use below also carries a non-null
`transition_id`, but that value names its prechosen activation ID rather than
an accepted credential transition. The isolated namespace and cold-root
activation binding distinguish that form; source/assignment signatures and a
local install never make it operational or accepted.

The narrow epoch exception separates Core authority from Comms accounting.
When an epoch source/assign tuple's public key, event ID, KEL head, source
signature, and accepted cold-root-authorized rotation all agree with the
verifier's exact current canonical Core KEL, that epoch key is current because
of the KEL event, not because of the config candidate. Its canonical
source/assign records immediately describe a current conservative exposure
even if their non-null `transition_id` later names an abandoned config
candidate. Credential-plane authority nevertheless remains held until a
fully receipted checkpoint under that current epoch head reconciles the
exposure set. No other secret class, noncurrent epoch key, or merely proposed
KEL event receives this exception.

`authority` is the closed `{signer_type,signer,kel_head}` object used by the
transition profile. An assign uses `signer_type:"epoch"` and exactly matches
its source companion's current epoch key/head. A retire uses the exact
authority selected from the containing transition's complete action set under
the rule below: ordinary non-authority maintenance uses the current epoch,
while epoch/Core-protected/recovery-wrap closure and emergency recovery use
the cold root and name the bound current or fresh recovery KEL head. A
cold-root retire never requires an unavailable prior epoch secret. The signer
produces BIP-340 over SHA-256 of
`UTF8("heterodyne-node-secret-exposure-v1")`, a zero byte, and JCS with
`signature` omitted. First acceptance validates the mode-appropriate current
authority and requires `issued_at` no earlier than the assign and governing
KEL event.

Existing source wire profiles are not extended with exposure metadata.
Instead, every acquisition first creates one generic closed
`heterodyne.node-secret-source.v1` companion record containing exactly:

```text
type, persona, secret_class, secret_id, instance_commitment, holder_nid,
commitment_kind, source_kind, artifact_refs, issued_at, epoch_pubkey,
kel_head, epoch_signature
```

For `secret_class:"config-audience"`, `secret_id` is exactly the associated
16-byte `config_key_id` encoded as 32 lowercase hex. For every other class it
is a random 32-byte value encoded as 64 lowercase hex and generated once for
the capability instance before any holder receives it. Parsers select the
length from `secret_class`, decode and re-encode exactly, and reject every
cross-class length or ID mismatch. All holders of one shared
key/session/capability use the same ID and commitment in separate source
records. Transition action `secret_id`/`successor_id` and every exposure
assignment use that same class-conditional encoding. `commitment_kind` is
`secret-bytes` or `capability-jcs`.
`instance_commitment` is lowercase-hex SHA-256 of
`UTF8("heterodyne-node-secret-instance-v1")`, a zero byte,
`UTF8(secret_class)`, a zero byte, `UTF8(commitment_kind)`, a zero byte, and
either the exact secret/private-key bytes or `UTF8(JCS(capability_object))`.
`secret-bytes` is required only for the fixed-width config, Tier 3,
claim-ledger, object-DEK, OAuth-pairwise, and recovery-wrap symmetric secrets,
and for the exact bearer-token bytes; bearer material MUST have at least
128 bits of entropy.

Every other class uses `capability-jcs` with one exact closed object:

```text
cold-root, epoch:
  {algorithm:"secp256k1",public_key}
device-signing, agent-signing:
  {algorithm:"Ed25519"|"secp256k1",public_key,purpose:"nid"|"publishing"|"agent-publishing"}
core-protected:
  {record_id,protected_value_sha256}
double-ratchet:
  {session_id,local_nid,local_delivery_pubkey,
   local_delivery_delegation_event_id,remote_persona,remote_nid,
   remote_delivery_pubkey,remote_delivery_delegation_event_id}
radicle-access:
  {rid,nid,permissions,grant_record_digest}
oauth-signing:
  {jwk_thumbprint,public_jwk_sha256}
ssh-client, ssh-host:
  {algorithm,public_key}
onion-service-identity:
  {hostname}
tls-serving:
  {spki_sha256}
```

Public keys use the profile's canonical raw/base64url representation;
fingerprints/digests are 64 lowercase hex, NIDs/RIDs/onion names use their
canonical protocol forms, and `permissions` is a sorted unique nonempty array.
For `device-signing`, Ed25519 is permitted only with purpose `nid` and
secp256k1 only with purpose `publishing`; `agent-signing` is secp256k1 with
purpose `agent-publishing`. Certificate renewal under the same TLS key
therefore does not change the secret instance; certificate digests remain in
artifact refs and rotation proofs.
This avoids provider-specific private-key encodings such as PEM, DER, expanded
Ed25519 state, or hardware handles. No class admits both commitment kinds.

`source_kind` is
`canonical-artifact` or `local-protected-state`. `artifact_refs` is a sorted
unique array of closed `{profile_id,record_digest}` objects; it is nonempty for
`canonical-artifact` and may be empty only for a local TLS/onion/SSH private
key, cached ratchet state, pairwise secret, object DEK, or other protected
state with no pre-existing portable source record. The current epoch key signs
SHA-256 of `UTF8("heterodyne-node-secret-source-v1")`, a zero byte, and JCS
with `epoch_signature` omitted. Current KEL state verifies before acceptance.
Its complete-record digest is the filename digest.
Every `artifact_refs` array in this section is ordered first by the unsigned
UTF-8 bytes of `profile_id` and then by decoded `record_digest` bytes;
duplicates of the exact closed pair reject.

The exposure assign record's `source_profile` is exactly
`comms.node-secret-source.v1`; its secret class, ID, commitment, holder NID,
source digest, issuance key/head, and time MUST equal that companion record.
Creating the companion plus assign record is one crash-consistent commit;
ordinary delivery/enabling follows only after the fully receipted checkpoint
gate below. A transition-staged successor may be delivered only after `B`,
`T`, and the candidate checkpoint are validated and the signed staging ref at
`C` is durable, solely so its holder can verify state and issue a receipt; the
canonical staged assign makes that delivered material an exposure
immediately, while operational use still waits for atomic transition
acceptance. Existing source schemas, including the pinned upstream Double Ratchet
wire, need not gain fields. Replay to a named exposure-set basis therefore
produces one interoperable conservative set when parameterized by the
canonical accepted-transition set: every canonical assign is included until
an accepted transition makes its retirement effective. Pending transitions
can add exposure but never remove it, and no node-local database encoding is
hashed. A distribution without its canonical source companion and assign
record is invalid and cannot grant authority.
The complete record is signed over SHA-256 of
`UTF8("heterodyne-node-secret-exposure-v1")`, a zero byte, and its JCS object
with `signature` omitted. Record digests are lowercase-hex SHA-256 of complete
signed JCS.

Comms owns the canonical source records and mergeable exposure set at the
encrypted-config paths above. A full node may keep an opaque protected local
mirror in Core's keys repository, but that mirror neither changes the
canonical set nor makes Core interpret Comms-only secret classes. A Comms
capability is usable only after its source/assign records are canonical in the
encrypted config repository and a fully receipted checkpoint binds the
resulting `exposure_set_sha256`. Ordinary non-bootstrap remote delivery waits
for that fully receipted exposure checkpoint. The config-key candidate
bootstrap above and the transition-staged receipt-only exception require the
complete candidate state before delivery; receipts follow, and operational
use waits for atomic checkpoint or transition acceptance. For a
holder-generated local secret, generation and
commitment may precede the checkpoint but serving, session use, or authority
remains disabled until acceptance. A partition may delay a new long-lived
capability but cannot create a usable post-checkpoint exposure that is absent
when every old node is later lost. Core-only profiles remain independent; the
Comms full-node composition records their exposure when it grants Core
material to a Comms credential node.

The pre-0.5 migration creates companion source and assign records under the
current epoch for every extant capability before ordinary authority resumes;
it does not rewrite the historical source artifact. An implementation that
cannot bind every discovered capability to this canonical set cannot
complete removal or reset.

Historical decryption does not create an exception to that exposure
inventory. For every retired secret instance that remains able to decrypt
governed ciphertext, every node that currently holds, can unwrap, or is
transition-staged to receive that instance has one complete live or staged
source/assign lineage in the ordinary `exposure_set_sha256`. The separately
retired provenance below proves how the former operational assignments ended;
it never substitutes for the current holder exposure set. In ADR-038
composition, `current_holder_lineages` is the nonempty exact complete array
of closed
`{holder_nid,assignment_id,source_record_digest,assignment_record_digest}`
rows derived from those live/staged assignments,
`historical_obligation_record_digests` is the exact complete active
obligation-head digest set whose secret tuple matches the archived entry, and
`retired_provenance_lineages` is the exact complete retired lineage set
defined below. The checkpoint and archive high-water digest separately commit
the complete `F(C)`, including close and competing heads; those inactive or
quarantined frontier records remain audit evidence rather than source-identity
members. A nonempty `current_holder_lineages` array says who can
currently decrypt the instance; it does not make a
`historical-decrypt` lifecycle `current`. A historical key with an omitted current holder, or a
current holder represented only by retired provenance, rejects the checkpoint
and every archive derived from it.

#### Governed decrypt key bindings

A governing ciphertext or pointer profile MUST independently mark its bytes
as an encrypted decrypt dependency. When that authenticated profile does not
itself embed the exact decrypt-secret tuple, the config repository carries one
closed `heterodyne.governed-decrypt-key-binding.v1` record containing exactly:

```text
type, persona, binding_id, retained_ciphertext, secret_class, secret_id,
instance_commitment, issued_at, authority, signature
```

`retained_ciphertext` is one exact closed locator row with the same shape,
typed-Git requirements, sorting semantics, and byte commitments used by
historical obligations below. `binding_id` is deterministically:

```text
binding_id =
  lowercase_hex(SHA256(
    UTF8("heterodyne-governed-decrypt-key-binding-id-v1") || 0x00 ||
    UTF8(JCS(retained_ciphertext))
  ))
```

The complete record is stored at:

```text
credential-sync/governed-decrypt-key-bindings/
  <binding-id>/<record-digest>.json
```

The path ID, recomputed locator ID, complete record, and lowercase-hex SHA-256
record digest must agree. Exact duplicate bytes are idempotent. Two
nonidentical otherwise-valid records for one `(persona,binding_id)` quarantine
the ID and reject every obligation/checkpoint that depends on that locator;
arrival order never selects a tuple.

`issued_at` is a JSON-safe nonnegative integer. `authority` is the exact closed
`{signer_type,signer,kel_head}` object selected by the governing class and
owner at artifact creation. An ordinary binding uses the exact current epoch
authority. A binding reconstructed as part of an emergency reset uses the
reset's exact cold-root authority and bound current or fresh recovery KEL
head. The selected authority BIP-340-signs:

```text
SHA256(
  UTF8("heterodyne-governed-decrypt-key-binding-v1") || 0x00 ||
  UTF8(JCS(record with signature omitted))
)
```

and `signature` is 128 lowercase hexadecimal characters. First acceptance
checks the exact authority mode, KEL ancestry, signature, and compromise
cutoff.

The repository universe used for governed-decrypt validation is itself a
signed monotonic record. The closed
`heterodyne.repository-retention-inventory.v1` profile contains exactly:

```text
type, persona, inventory_sequence, previous_records,
basis_checkpoint_digest, target_generation, target_sequence,
repository_refs, issued_at, epoch_pubkey, kel_head, epoch_signature
```

Genesis has sequence zero, empty `previous_records`, null basis, and
`(target_generation=0,target_sequence=0)`. A successor's sequence is one
greater than its maximum parent and
`previous_records` is the complete maximal valid frontier of closed
`{inventory_sequence,record_digest}` rows sorted by numeric sequence then
decoded digest. An ordinary successor has one parent and names its accepted
predecessor checkpoint; a cold-root emergency successor names every competing
maximal parent and the accepted last-common checkpoint. Its target tuple is
the one immediate candidate checkpoint that may activate it. A record becomes
effective only at that exact target/basis and remains effective through
descendants until a targeted successor replaces it. Stale, skipped, future, or
mismatched targets never activate.

The complete signed record is stored at:

```text
credential-sync/repository-retention-inventories/
  <inventory-sequence>-<record-digest>.json
```

Its closed schema is
`docs/spec/schemas/comms/repository-retention-inventory-v1.schema.json`.
`repository_refs` is a nonempty sorted unique array of closed rows:

```text
repository_ref_id, repository_class, repository_rid, ref_name,
object_format, retired, scan_head
```

Class is `config`, `private`, or `public`; `scan_head` is the exact typed Git
object matching `object_format`. The semantic ID is:

```text
lowercase_hex(SHA256(
  UTF8("heterodyne-repository-retention-ref-id-v1") || 0x00 ||
  UTF8(JCS({repository_class,repository_rid,ref_name,object_format}))
))
```

Rows sort by class, RID, and full ref-name UTF-8, object-format ASCII, then
decoded ID. Every ordinary single-parent successor retains every predecessor
semantic row. An active scan head remains equal or advances to a Git
descendant; it may become retired only at an equal-or-descendant final head.
Retirement is ordinarily immutable and absorbing. A new row names an already
materialized fully scanned head before that ref can carry governed use.
Ordinary accepted state has exactly one active config row. The config row's
`scan_head` is a strict ancestor of the commit first containing the inventory
record, preventing self-reference.

For candidate checkpoint `C`, `EffectiveRefs(C)` is the complete set of every
`repository_refs` row variant in the activated maximal inventory frontier after
these successor rules; conflicting variants remain distinct and reject
ordinary acceptance. Rows present only in signed ancestor records are
authenticated audit history, not effective registrations.

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

A cold-root emergency successor contains the union of every semantic row
present in `EffectiveRefs` of any maximal parent plus valid new rows. Absence
from another branch is never deletion. A prior valid config deregistration
suppresses a row only when it is absent from every maximal parent's
`EffectiveRefs`. A branch-only row or one unique shared variant must be
preserved, ordinarily advanced, or explicitly retired at an
equal-or-descendant cut; omission rejects.

After first forming that complete union, emergency config-key acceptance may
subtract exactly `V_old`, the complete variant set for the one old active
`config` semantic identity whose ref name is
`refs/heads/enc/<old-config-key-id>` and whose current signed target is
`inventory_basis.source_ref_head`. Every maximal-parent variant of that
semantic identity is in `V_old`. Reset `K(I)`, closure basis `B`, and
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

Only a semantic row with two or more present parent variants that disagree on
`scan_head` or `retired` and is outside a valid `V_old` terminal deregistration
uses convergence. It emits one replacement with the
same semantic ID and newly materialized resolution head `H*`. The raw Git
commit at `H*` has a complete direct-parent set containing every distinct
variant scan head, sorted by decoded OID, and no other parent; if variants
share a head and differ only on `retired`, that head is its sole parent.
`H*`'s exact tree is the pre-materialized reconciled cut scanned by the reset,
while every parent tree remains immutable audit history.

The replacement's retired value equals the reset's explicit signed result, not
a local merge choice. A retired resolved config row requires a separate fully
scanned active config row in the same inventory. This is the sole permitted
advance from or reactivation of a retired variant and requires every maximal
parent inventory variant in `previous_records`, every variant head as an exact
direct parent of `H*`, and reset `K(I)` plus class-complete actions accounting
for the complete cross-branch `L(S)`, `D(S)`, `U(S)`, and
`ResultPairs(H*)` sets below.

For conflicted row `S`, first derive the cross-branch physical-locator,
candidate-tuple, and key-state universes:

```text
L(S) =
  union(all allocated, authenticated, marked decrypt-dependency artifact
        locators in every parent variant exact tree, regardless of whether
        the artifact's key is parent-locally current)

Bound_I(locator) =
  complete set of every tuple embedded by an allocated authenticated source
  profile plus every tuple in every individually valid signed-binding variant
  for that locator across all parent K(I) branches, including all conflicts

D(S) = { (locator,tuple) |
         locator in L(S) and tuple in Bound_I(locator) }

Current_I(tuple) =
  every complete applicable parent key-state projection exists and agrees
  tuple is the same sole current instance, and no parent retires, competes
  with, or names a different-current instance for it

L(S) =
  preserved_at_H_star disjoint-union
  reencrypted_or_replaced disjoint-union
  deleted_and_closed

U(S) = { (locator,tuple) in D(S) |
         not Current_I(tuple) }

ResultPairs(H*) =
  complete set of authenticated (fresh_H_star_locator,tuple) pairs embedded
  by allocated source profiles in H* or, where the profile cannot embed the
  tuple, named by exactly one nonconflicting fresh result binding whose tuple
  is independently supported by actual H* profile/ciphertext validation

Current_B(tuple) =
  the ordinary post-reset unique-current predicate replayed from projected
  result B after every class action; true only when the complete applicable
  result projection names tuple as one nonconflicting current instance with
  no retirement, competition, or different-current instance
```

Missing applicable state or any disagreement, retirement, competition, or
different-current instance makes the tuple conservatively noncurrent. Missing
bytes for any required binding candidate keep reset pending. Every physical
locator in `L(S)`, including both sides of a path/content collision, appears
in exactly one disposition; a unanimously current locator cannot vanish.
Ancestor reachability is not a disposition.

Class-complete cleanup and provenance account for every pair in `D(S)`, not
one selected binding winner. Every old candidate pair, including every pair
in `U(S)`, terminally maps exactly once to an identical semantic tuple at a
fresh H*-based locator in `ResultPairs(H*)`, a reencrypted or replaced
artifact, a binding-candidate-resolved-and-closed audit outcome, or a
deleted-and-closed outcome. Legitimate multiple tuples embedded by one source
profile therefore remain multiple result pairs; conflicting unembedded
bindings do not become multiple active results merely because they were
observed.

A fresh nonconflicting fallback result binding is accepted only after every
conflicting candidate is accounted and actual profile/ciphertext validation
independently supports one unique result tuple. Otherwise the affected
candidate is replaced, deleted, or retained only as closed audit evidence;
arrival order, digest order, and local candidate selection cannot choose a
winner. Every `(locator,tuple)` in `ResultPairs(H*)` for which
`Current_B(tuple)` is false gets the required fresh binding, where the source
profile does not embed the tuple, and active historical-decrypt obligation
because its locator commits `repository_head`.
Rejected conflict candidates remain cleanup/audit evidence, not active
obligations. The transition closes or replaces every old-head obligation and
produces `G(B) = O(B)`. Reused old-head locators/bindings, an unaccounted
candidate, a selected candidate tuple, or missing candidate bytes reject.

After acceptance the ordinary absorbing/equal-or-descendant rules resume. No
ordinary successor, selected digest, non-common descendant, missing or extra
direct parent, unscanned merge tree, branch-only omission, or incomplete
disposition may use this exception.

A scan covers the exact recursive tree selected by each cut in
`EffectiveRefs(C)`, not ancestor commit trees or loose local objects.
Historical ciphertext absent from that tree is audit residue unless retained
under an explicitly registered frozen ref. Thus a descendant tree can
reencrypt/delete a dependency and permit an obligation close without
pretending the ancestor commit vanished. All target-roster nodes authenticate
each effective RID/ref, signed ref, authorization, object format, ancestry, and
exact immutable scan cut. A validly deregistered config ref is validated
through its ancestor record and accepting transition/CAS instead and is not
fetched or scanned. Post-cut old-key content is noncanonical.

The current epoch BIP-340-signs SHA-256 of
`UTF8("heterodyne-repository-retention-inventory-v1")`, a zero byte, and the
JCS record without `epoch_signature`; emergency uses the fresh reset epoch and
activates only with that reset checkpoint. Historical signer, KEL ancestry,
rollover, and compromise-cutoff rules apply.

At checkpoint/config head `C`, `K(C)` is the closed object containing exactly:

```text
repository_inventory_records, governed_heads, binding_records
```

`repository_inventory_records` is the complete activated maximal inventory
frontier retained through `C`, using the exact frontier-row comparator above.
Each row dereferences one valid signed record and its complete ancestor graph.
Every maximal conflict variant is included. Conflict rejects ordinary
checkpoint acceptance; emergency reset starts from the last common checkpoint
and complete branch union, then creates one fresh inventory record parenting
every maximal variant.

`governed_heads` is the complete sorted unique set of closed
`{owner,repository_rid,ref_name,repository_head}` rows derived from
`EffectiveRefs(C)`. For every active or retired cut, validators scan each
noncurrent marked dependency under its one registry-selected authenticated
source profile and emit exactly one row for each distinct allocated `owner`
produced by those locator expansions. `repository_head` is that typed scan
cut. A mixed-owner cut emits multiple rows; a cut without a noncurrent
dependency emits none. Rows sort by owner, RID, and full ref-name UTF-8, then
object-format ASCII and decoded OID. A fallback binding's retained-ciphertext
`owner` must equal the selected source-profile owner; missing, extra, or
mismatched head-owner projections reject. They are frozen retention snapshots.
Current-key posts do not alter them; a retained-set change advances the
inventory cut and projects the snapshot through the same transition.

For every exact retained head, validators expand only the closed allocated
governed-decrypt source profiles. `binding_records` is the complete sorted
unique `{binding_id,record_digest}` frontier for every required deterministic
binding, including conflict variants. A binding for no dependency enumerated
by the governed heads is extra and rejects. The checkpoint field remains:

```text
governed_decrypt_key_bindings_sha256 =
  lowercase_hex(SHA256(
    UTF8("heterodyne-governed-decrypt-key-binding-set-v1") || 0x00 ||
    UTF8(JCS(K(C)))
  ))
```

The unchanged domain commits the enlarged object; an unchanged digest with
inventory-frontier or scan-cut drift rejects. Every receipt independently
fetches and authenticates every named ref/cut, scans it, expands the closed
profile table, and recomputes the complete inventory, snapshot, binding, and
conflict frontiers.

Every accepted config-key transition activates the mandatory targeted
inventory successor that deregisters the exact old active config-ref row and
registers the new fully scanned active row. Its `result_basis`, target, and
successor checkpoint MUST bind `governed_decrypt_key_bindings_sha256`
recomputed from successor `K(C)`. `repository_inventory_records`, `K(C)`, and
that digest therefore change even when there is no noncurrent decrypt
dependency and `governed_heads` and `binding_records` remain byte-identical.
The historical-obligation digest remains byte-identical unless an exact
obligation action changes its complete frontier. This is the permitted
non-null inventory-only advance; it does not broaden the following null
transition exception.

A null transition may change this digest only when one targeted inventory
successor registers a fully scanned ref or advances an existing scan cut,
introduces no noncurrent decrypt dependency, and leaves `governed_heads` and
`binding_records` byte-identical. `repository_inventory_records` still changes
and therefore so does `K(C)`. Every other null transition preserves both
governed-decrypt digests byte-identically; an ordinary current-key post alone
does not create an inventory successor.

The artifact exists at authenticated head `A`; any required binding record
`K` is materialized after its locator exists and before inventory record `R`;
`R` names only preexisting scan heads. Obligation `O`, transition `T`,
checkpoint `C`, and receipts follow:

```text
accepted predecessor -> artifact A -> optional binding K ->
repository inventory R -> obligation O -> transition T -> checkpoint C ->
receipts
```

An embedded tuple omits `K`. These arrows are logical record dependency and
signing order, not canonical Git tree-entry order and, for a config-key
transition, not necessarily distinct commits. Closure basis
`B = result_basis.config_head` remains the parentless new-key root and the new
active config row's pre-inventory `scan_head`. Every artifact and scan head
preexists `R`. A required `K` is either already reachable at an independently
authenticated pre-inventory head or, when its locator commits `B` and
embedding it in `B` would self-reference, first carried in direct-child commit
`T`. That commit may atomically carry finalized `K`, `R`, `O`,
every `O`-dependent source/assignment/retirement and transition-action record,
reset where applicable, and the transition, but their bytes and signatures are
produced in dependency order and none names `T`'s commit OID. Result and
target digests project those records. New transition-bound `K`/`R`/`O` and
dependent proof records are not placed in `B`; copied predecessor audit
records remain there.

No artifact, scan head, or binding depends on `R` or a descendant. `R`
references only its accepted basis and parent inventory frontier. An unmarked
ciphertext, late/conflicting binding, unregistered ref, scan-cut mismatch,
tuple/locator mismatch, or obligation as sole tuple source rejects. All
artifacts, inventory records/frontiers/cuts, bindings, and obligations remain
in closure, receipt replay, reset inventory, portable archive, candidate
audit, and exact-tip/CAS drift checks.

The Comms archive high-water and every Core archive/restore-basis carrier of
`governed_decrypt_key_bindings_sha256` inherit this enlarged `K(C)` without a
second digest. A standalone archive preserves every inventory frontier and
ancestor record, registered repository bundle and exact ref/scan cut, Radicle
identity/signed-ref proof, governed snapshot, source-profile marker, binding,
locator, obligation, and provenance dereference needed to recompute it.
Network-assisted archive mode may externalize only already-declared large
object ciphertext, never repository-inventory or scan evidence. Manifest,
generation, finalization/abandonment, offline intent/activation,
transfer-grant, restore comparison, and normal-or-gap rollover schemas all
reject an unchanged digest when the inventory frontier or scan cut changes.

#### Historical-decrypt obligations

A retained ciphertext that still needs a retired secret is canonical Comms
credential state, not an implementation-local reason to keep an arbitrary old
key. The closed record type
`heterodyne.historical-decrypt-obligation.v1` contains exactly:

```text
type, persona, obligation_id, lineage_sequence, previous_record, action,
secret_class, secret_id, instance_commitment, retained_ciphertexts,
retired_provenance_lineages, transition_id, issued_at, authority, signature
```

`obligation_id` is 16 fresh random bytes encoded as 32 lowercase hexadecimal
characters. A root has `lineage_sequence:0`, `previous_record:null`, and
`action:"retain"`. Every successor increments the sequence by exactly one and
names the lowercase-hex SHA-256 digest of the complete immediately preceding
signed JCS record. `action` is `retain` or `close`. A retaining head has a
nonempty `retained_ciphertexts` array. A closing head has an exactly empty
array, repeats the complete identity, and is absorbing. Every successor's
`retired_provenance_lineages` is a superset of its predecessor and adds
exactly any assignment retirements made effective by its transition; no
prior row may disappear or change. Exact duplicate bytes are idempotent.
Nonidentical roots or successors quarantine that obligation ID and make every
checkpoint that names either competing head unacceptable. Different
nonconflicting IDs may cover disjoint ciphertext rows for the same
`(persona,secret_class,secret_id,instance_commitment)` tuple. Exact duplicate
coverage of one governed decrypt dependency is invalid under `G(C) = O(C)`;
disjoint coverage is additive rather than an obligation-ID conflict.
An emergency reset cannot discard or choose one competing branch. It preserves
the complete maximal frontier, retires every exposure associated with every
branch, reconciles the objective governed-ciphertext set, and, only when
retention remains necessary, creates one fresh obligation ID whose complete
retained/provenance sets are the verifier-derived union. A closed obligation
never reopens; any later retention uses a fresh ID.

Only a class whose ADR-038 portable mapping permits
`historical-decrypt` may use a retaining obligation. `lineage_sequence` and
`issued_at` are JSON-safe nonnegative integers, successor `issued_at` never
decreases, and `transition_id` is exactly 32 lowercase hexadecimal
characters. A retaining root names the exact accepted credential-ledger
secret transition that retired the old capability assignments while
preserving governed ciphertext that requires this instance. A retaining
update names the accepted transition that changed the complete retained
artifact set without authorizing new encryption under the old key. A close
names the accepted transition that reencrypted or removed every remaining
governed dependency. The identity fields equal every source, assignment,
retirement, archive-inventory, and encrypted-material binding for that
instance. `authority` is the exact closed
`{signer_type,signer,kel_head}` object selected by that transition's complete
class/authority rule. The selected epoch or cold root signs:

```text
SHA256(
  UTF8("heterodyne-historical-decrypt-obligation-v1") || 0x00 ||
  UTF8(JCS(record with signature omitted))
)
```

using BIP-340 encoded as 128 lowercase hexadecimal characters. Historical
signer validation, accepted-transition binding, KEL ancestry, and compromise
cutoff all apply. The complete-record digest is lowercase-hex SHA-256 of the
complete signed JCS bytes. It equals the filename digest at:

```text
credential-sync/historical-decrypt-obligations/
  <obligation-id>/<lineage-sequence>-<record-digest>.json
```

The path ID, shortest unsigned decimal sequence, parsed record members, and
complete digest must agree before lineage replay.

`retained_ciphertexts` is strictly sorted and unique by every member in the
listed order. Each closed row contains exactly:

```text
storage_class, owner, repository_rid, repository_head, ref_name, path,
git_blob_oid, object_id, ciphertext_sha256, ciphertext_length
```

`storage_class` is `git-blob` or `large-object`; `owner` is the allocated
family owner governing the encrypted data. Repository RID, canonical
repository head, full ref name, slash-normalized repository-relative path,
and Git blob object ID are non-null and identify the exact ciphertext blob or
the exact governing large-object pointer. `repository_head` and `git_blob_oid`
are each the closed object
`{object_format:"sha1"|"sha256",oid}`. Their `object_format` values are
identical; a `sha1` OID is exactly 40 lowercase hexadecimal characters and a
`sha256` OID exactly 64. A bare OID string, mixed repository formats, or
length/format mismatch rejects. For `git-blob`, `object_id` is null and
`ciphertext_sha256`/`ciphertext_length` cover exactly the Git blob content
bytes. For `large-object`, `object_id` is non-null, equals the lowercase-hex
SHA-256 of the complete retained stored bytes, equals `ciphertext_sha256`,
and `ciphertext_length` is their exact positive length; the repository fields
and `git_blob_oid` identify the exact canonical pointer governing those bytes.
`object_id`, when non-null, and `ciphertext_sha256` are exactly 64 lowercase
hexadecimal characters. Every length is a JSON-safe positive integer, and no
mutable alias, caller-selected local path, or plaintext semantic name may
replace these exact locators.
The exact row comparator expands the listed object members: compare
`storage_class`, `owner`, and `repository_rid` by UTF-8 bytes; then
`repository_head.object_format` by ASCII and its decoded `oid` bytes; then
`ref_name` and `path` by UTF-8 bytes; then
`git_blob_oid.object_format` by ASCII and its decoded `oid` bytes; then
`object_id` with null before a non-null decoded digest; then decoded
`ciphertext_sha256`; then numeric `ciphertext_length`. Equality under that
full comparator is a duplicate and rejects.
The named `repository_head`, ref, pointer/blob, and stored object MUST already
exist, authenticate, and bind the exact ciphertext bytes before the obligation
record is signed. That artifact head is an ancestor of or an independently
bound co-equal repository head in the later checkpoint. It never names the
config commit containing the obligation, the transition commit, the candidate
checkpoint, or any descendant, so the construction is strictly
artifact `A` -> inventory `R` -> obligation record `O` ->
transition/checkpoint. Under the config-key co-commit rule, finalized `R` and
`O` records may first appear in transition carrier `T`, but neither names
`T`'s commit OID, so they cannot form a self-referential
config/checkpoint-head cycle.

`retired_provenance_lineages` is a nonempty strictly sorted unique array of
closed rows containing exactly:

```text
holder_nid, assignment_id, source_record_digest,
assignment_record_digest, retirement_record_digest
```

Rows sort by canonical holder-NID UTF-8 bytes, decoded assignment ID, then
decoded source, assignment, and retirement digests. Each row dereferences one
exact valid source companion, one exact otherwise-valid assign variant, and
the accepted absorbing retirement that supersedes that assignment. All
repeat the obligation's persona, secret class, ID, commitment, and holder;
each retirement is effective through the obligation's named transition or an
accepted predecessor transition. The array is the complete retired provenance
for this retained instance, including every competing assignment variant that
was individually retired. An unretired holder belongs in the ordinary
exposure set and ADR-038 `current_holder_lineages`, never in this array.
Claimed erasure, non-use, local loss, or an unavailable source byte is not a
retirement and cannot remove a row.

At candidate checkpoint head `C`, every verifier independently derives
`G(C)`, the complete set of governed retained decrypt dependencies. Each
element is:

```text
(persona, secret_class, secret_id, instance_commitment,
 <complete retained_ciphertexts row>)
```

and is obtained from every canonical repository/blob and large-object pointer
reachable under `C` and the checkpoint's bound repository heads whose bytes
still require a noncurrent secret. The verifier also derives `O(C)` by
replaying every obligation lineage reachable from `C`, applying only the
checkpoint's exact accepted-transition projection, selecting each unique
nonconflicting maximal `retain` head, and expanding its ciphertext array with
the same secret tuple.

The tuple in each `G(C)` member comes only from the authenticated
ciphertext/pointer profile or the unique nonconflicting
`heterodyne.governed-decrypt-key-binding.v1` record already canonical at the
pre-obligation binding head. That evidence independently binds
`secret_class`, `secret_id`, and `instance_commitment`. The obligation may
repeat that tuple, but it can never supply, alter, or be the sole evidence for
it. A profile or binding that authenticates only ciphertext location and not
the decrypt-secret tuple cannot contribute a governed item. Acceptance
also expands an authenticated encrypted ADR-038 large-object pointer into two
distinct items when both dependencies are noncurrent: the `git-blob`
pointer/wrapped-DEK ciphertext locator binds the exact config- or
Tier-3-audience tuple, while the `large-object` stored-byte locator binds the
exact object-DEK tuple. The pointer profile embeds both complete tuples, or
each distinct locator requires its own locator-derived binding. One logical
pointer can therefore produce two obligations without overloading one binding
ID. Omitting, swapping, or collapsing either item rejects.

Acceptance requires the exact set equation:

```text
G(C) = O(C)
```

Each nonconflicting obligation ID has one maximal head, and every `G(C)`
dependency row is covered by exactly one active retain record. Multiple
active IDs for one secret tuple are valid only when their coverage rows are
disjoint. A retained governed ciphertext without an active obligation, an
obligation row without matching retained ciphertext, duplicate coverage, a wrong
digest/length/locator, a missing or substituted provenance member, or an
active obligation for a fully eliminated dependency rejects the checkpoint.
A `close` successor is valid only when every ciphertext row named by that
lineage's preceding retain head is absent from independently derived `G(C)`.

Let `L_C(o)` be the accepted or exactly projected records for obligation ID
`o`, and let `max(L_C(o))` be its unique valid greatest
`lineage_sequence` record whose `previous_record` chain reaches the unique
root without omission. Then the active state is exactly:

```text
Active(C) = {
  max(L_C(o)) |
  max(L_C(o)).action = "retain"
}
```

A missing predecessor, sequence gap, competing maximum, or successor of an
absorbing close makes the active projection undefined and rejects the
checkpoint. It does not make the ambiguous bytes disappear from the committed
state. Let `F(C)` be the complete maximal frontier across every valid branch,
including every unique retain head, every close head, and every competing
maximum. It is the strictly ordered unique array of closed
`{obligation_id,lineage_sequence,action,record_digest}` items, sorted by
decoded obligation ID, numeric lineage sequence, explicit action rank
(`retain` before `close`), then decoded complete-record digest. The checkpoint
field is exactly:

```text
historical_decrypt_obligations_sha256 =
  lowercase_hex(SHA256(
    UTF8("heterodyne-historical-decrypt-obligation-set-v1") || 0x00 ||
    UTF8(JCS(F(C)))
  ))
```

This is a domain-separated mergeable-set digest: complete record digests
commit every locator and provenance row, and the complete frontier prevents a
close or competing branch from being omitted merely because it grants no
active authority. Deterministic lineage replay separately selects the sole
active retain head per nonconflicting ID. Every checkpoint and every
target-roster receipt recomputes `G(C)`, `O(C)`, `Active(C)`, `F(C)`, the
digest, every obligation and key-binding signature, predecessor link,
available ciphertext digest and locator, and provenance dereference. Any
governed-ciphertext, key-binding, obligation, source, assignment, or
retirement mutation after the candidate's exact `config_head` and before its
complete receipt head invalidates the candidate and requires reproposal.

A retain or close record `O` is finalized after its governing inventory
record `R` and before its noncyclic transition is signed; it binds the
prechosen `transition_id`, not the transition record digest. Under the
config-key co-commit rule, `R`, `O`, the citing transition action, and the
transition may first appear together in direct-child carrier `T`, in that
logical record signing order. The transition action cites the obligation
record as an independently materialized proof when old ciphertext remains or
ceases to require the key. The transition, its `inventory_basis`, its
`result_basis`, its target, the checkpoint, and every acceptance/ref-CAS
replay all bind the corresponding predecessor and projected obligation-set
digests. No same-head write, candidate abandonment, reset inventory,
source-basis reconstruction, or exact-tip append may change an obligation
record, governed locator/key binding, or its source/assignment/retirement
proof while retaining an unchanged basis digest.

#### ADR-038 offline-recovery candidate exposure

Before an offline `backup_class:"full"` restore unwraps, releases, decrypts
with, or otherwise exercises any persona-authority capability, it creates a Core-owned
`heterodyne.offline-recovery-pre-unseal-intent.v1` record. The client first
chooses a fresh `new_device_nid` and a fresh random 16-byte `activation_id`
encoded as 32 lowercase hexadecimal characters. Before intent durability it
may obtain only the bulk DEK, authenticate the bulk stream, and validate
bulk-visible material. A combined-bundle recipient slot is eligible for
offline authority recovery only through a cryptographically compartmentalized
opener that returns the bulk DEK while retaining the authority DEK as a
non-exportable, non-decrypting pending handle. If that separation cannot be
proven, the client permits bulk-only inspection and cannot perform offline
authority activation through the combined slot.

The pre-unseal signer is a cold-root capability available independently of the
archive being opened, for example on separate hardware or USB media. A
cold-root scalar first recovered from that same archive cannot authorize its
own pre-unseal evidence. Without an independent signer, the client remains
read-only, bootstrap-validated, and restore-pending until an online recovery
device authorizes the operation. The closed intent contains exactly:

```text
type, persona, activation_id, archive_id, generation_record_digest,
manifest_digest, archive_kel_head, new_device_nid, archive_restore_basis,
exposure_preimages, exposure_preimage_set_sha256, created_at,
acknowledged_stale_state_risk, cold_root_signature
```

Its archive fields and closed `archive_restore_basis` have the exact meanings
and shape specified below for the final activation, and
`acknowledged_stale_state_risk` is exactly true. `exposure_preimages` is
complete over every archive-derived or preexisting persona-authority
capability that the pending authority handle could release, using the final
activation's exact inclusion and exclusion rules. Each row is closed and
contains exactly:

```text
preimage_id, source_preimage, source_preimage_sha256,
assignment_preimage, assignment_preimage_sha256
```

`source_preimage` is the exact closed
`heterodyne.node-secret-source.v1` object that will be materialized after
unseal, with only `epoch_signature` omitted. `assignment_preimage` is the
exact closed `heterodyne.node-secret-exposure.v1` `assign` object that will be
materialized after unseal, with only `source_record_digest` and `signature`
omitted. Every identifier, capability tuple, artifact reference, time,
archived authority, holder NID, and other byte is final in the preimage;
`transition_id == activation_id`. Their digests are:

```text
source_preimage_sha256 =
  lowercase_hex(SHA256(
    UTF8("heterodyne-offline-recovery-source-preimage-v1") || 0x00 ||
    UTF8(JCS(source_preimage))
  ))

assignment_preimage_sha256 =
  lowercase_hex(SHA256(
    UTF8("heterodyne-offline-recovery-assignment-preimage-v1") || 0x00 ||
    UTF8(JCS(assignment_preimage))
  ))

preimage_id =
  lowercase_hex(SHA256(
    UTF8("heterodyne-offline-recovery-exposure-preimage-id-v1") || 0x00 ||
    UTF8(JCS({source_preimage_sha256,assignment_preimage_sha256}))
  ))
```

Rows are strictly sorted by decoded `preimage_id` and unique.
Duplicate preimage IDs, source or assignment IDs or preimage digests,
capability instances, tuple/link mismatches, or any caller-variable field
reject. The set digest is exactly:

```text
exposure_preimage_set_sha256 =
  lowercase_hex(SHA256(
    UTF8("heterodyne-offline-recovery-pre-unseal-exposure-set-v1") || 0x00 ||
    UTF8(JCS(exposure_preimages))
  ))
```

The independent cold root BIP-340-signs:

```text
SHA256(
  UTF8("heterodyne-offline-recovery-pre-unseal-intent-v1") || 0x00 ||
  UTF8(JCS(record with cold_root_signature omitted))
)
```

The signature is 128 lowercase hexadecimal characters. The intent record
digest is lowercase-hex SHA-256 of its complete signed JCS bytes. The
create-only Core path is:

```text
keys/core/recovery/offline-pre-unseal-intents/<activation-id>/<intent-digest>.json
```

`created_at` is a JSON-safe nonnegative integer. Before signing, the
independent signer confirms that it is no later than the signer's trusted
current time. First observation permits at most 300 seconds of positive
verifier clock skew. If the signer has no trusted clock, it uses zero or a
conservatively earlier user-confirmed value; it never accepts a future value
proposed by the archive-opening host. This signature-bound rule prevents a
future-dated intent from weakening either compromise cutoff.

Exact duplicate bytes are idempotent. Two nonidentical individually valid
signed intent variants for one `(persona,activation_id)` are an intent
collision: all variants remain evidence and no handle is selected by arrival
order. A byte-identical intent and the one final activation that references
its exact digest are two phases of one recovery, not a collision.

The exact signed intent and immutable archive basis MUST be durable before the
authority handle can unwrap, release, or decrypt any authority material. This
intent durability is the irreversible evidence boundary even if the user
cancels, authority AEAD validation fails, a hidden artifact mismatches, or no
activation is ever produced. Before it, clear framing, authenticated
ciphertext, bulk plaintext, and non-authority scratch may be discarded. An
unsigned journal, a process-local promise, or release followed by persistence
does not satisfy the boundary.

After intent durability, the pending compartment may unwrap the authority DEK
internally but MUST keep it non-exportable. It AEAD-decrypts each hidden object
inside the compartment and validates the closed hidden schema, every repeated
outer identity, commitment, provenance/template binding, and archive equality
before releasing that exact validated material or performing a bound signing
operation with it. A mismatch produces zero output and zeroizes the DEK and
temporary plaintext; the durable intent remains exposure evidence. An
implementation that can export a raw authority DEK or unvalidated plaintext,
or cannot enforce validate-before-release, cannot perform offline authority
activation.

Every later Core recovery archive, portable safe copy, and Comms audit closure
whose authenticated basis reaches this operation preserves all signed intent
variants, their exact archive basis and preimages, and any linked activation
bytes. Archive manifest/profile schemas treat the create-only intent path as a
closed signed recovery-record class, never as optional scratch or a
deduplicated replacement for activation evidence. Archive finalization,
artifact resolution, safe-copy classification, and cold replay all fail closed
on an omitted variant or changed intent-to-activation link.

ADR-038's Core-owned
`heterodyne.offline-recovery-activation.v1` record is the sole narrow case in
which the ordinary Comms source and assignment schemas may describe a locally
installed recovery candidate before current network state is known. Its closed
record contains exactly:

```text
type, persona, activation_id, archive_id, generation_record_digest,
manifest_digest, archive_kel_head, new_device_nid, archive_restore_basis,
pre_unseal_intent_digest, provisional_exposure_records,
provisional_exposure_set_sha256, created_at, acknowledged_stale_state_risk,
cold_root_signature
```

`activation_id` is 16 fresh random bytes encoded as 32 lowercase hexadecimal
characters and is chosen before any provisional source or assignment is
created. `archive_restore_basis` is the closed object containing exactly:

```text
archive_id, archive_generation, generation_record_digest, manifest_digest,
finalization_record_digest, artifact_resolution_digest, archive_authority,
opened_recipient_slot, credential_checkpoint_digest,
governed_decrypt_key_bindings_sha256,
historical_decrypt_obligations_sha256, secret_inventory_sha256,
special_authority_bindings_sha256
```

Every member equals the immutable archive artifact actually opened.
`finalization_record_digest` and `artifact_resolution_digest` follow
ADR-038's exact mutually applicable finality rules; neither is a caller hint.
The checkpoint, governed-binding, and historical-obligation digests equal the
archive's signed Comms high-water state. The activation's original top-level archive,
generation, manifest, and KEL members equal their basis projections.
`acknowledged_stale_state_risk` is exactly true. This schema-scoped offline
basis is not ADR-038's transfer-grant `archive_restore_basis`; neither closed
shape may be parsed as the other.

Only after durable intent and successful validated compartment release does
the offline full-archive restorer create one ordinary
`heterodyne.node-secret-source.v1` companion and one
`heterodyne.node-secret-exposure.v1` assign record for every ADR-037
capability that is archive-derived or preexisting and that the restored NID
possessed, hosted, cached, or can unwrap under the existing exposure
definition. Coverage is class-complete rather than limited to epoch or
ADR-038 generic-secret entries. If the NID can unwrap the cold-root secret,
`cold-root` is exposed; an opaque NIP-49 record that it cannot unwrap is
represented by the applicable `core-protected` or `recovery-wrap` capability
instead. Every `device-signing` clone secret is excluded because it is legal
only in `backup_class:"clone-device"`, which has no persona authority DEK and
cannot produce a pre-unseal intent or activation.
ADR-038's exact clone flow creates no new logical holder, source companion, or
assignment: both physical installations deliberately remain the same
protocol-indistinguishable NID, so the existing assignment is unchanged and
the signed clone lineage plus mandatory warning carry the available audit
evidence. A separately accountable holder uses fresh-NID enrollment.

The provisional set excludes freshly generated prospective device/NID, SSH
authentication, X25519 recipient, and platform-wrapper keys that were never
in the archive and are not yet persona authority. Once authorized, those
fresh keys use the ordinary holder-generated enrollment source/assign path,
not the offline-activation exception. A fresh device key is not rotated merely
because a restore occurred; only archive-derived or preexisting capability
material disclosed by restore enters mandatory cleanup. Every current or
historical secret, repository capability, endpoint credential, protected
wrapper, and other durable archive-derived or preexisting capability made
available by the restore is otherwise treated identically.

Each provisional assignment has
`transition_id == activation_id`, repeats the restored NID as holder, and
names its exact companion source digest. The source schema is unchanged and
has no `transition_id`; it is bound by the assignment's source digest plus
exact holder/secret-tuple equality and by the activation's complete
source/assignment array and namespace. Both records are otherwise schema-valid
and signed under the archive's exact epoch key/head. First-acceptance
validation ignores only present-day KEL-window or compromise-cutoff authority
ineligibility for an exact archived-epoch template completion. It still
requires raw BIP-340 verification under the archived epoch public key,
byte-exact intent-template completion, both cold-root signatures,
archive/KEL/provenance and source-link agreement, closed schemas, and complete
set/bijection validation. A raw-invalid signature, changed template, wrong
archive authority, or provenance mismatch rejects. A pair passing this narrow
exception enters conservative accounting only and never gains operational
authority or signs a later action. The records and
restored protected material are written only beneath this isolated
encrypted-config namespace:

```text
credential-sync/offline-recovery-candidates/<activation-id>/
```

Within it, source bytes use
`secret-sources/<secret-id>/<record-digest>.json`, assignment bytes use
`secret-exposures/<assignment-id>/<record-digest>.json`, protected archive
entries preserve their manifest path beneath `protected/`, and
`activation.json` is the byte-identical signed activation visibility marker.
No other path can satisfy the candidate inventory. No record at those paths is
evaluated as an operational source or assignment, and copying the same bytes
to an ordinary operational path is invalid without the later accepted
cleanup/reissuance transition. Path activation ID, assignment transition ID,
holder, source digest, secret tuple, archive authority, and archive-basis
values must agree.

`provisional_exposure_records` is the complete strictly ordered unique array
of closed `{record_type,record_digest,record}` rows for those exact records.
`record` is the complete closed source or assignment JCS object and its
lowercase-hex SHA-256 equals `record_digest`. `record_type` is
`secret-source` or `secret-assignment`, in that order, then rows sort by
decoded record digest. `secret-source` maps only to embedded
`type:"heterodyne.node-secret-source.v1"`; `secret-assignment` maps only to
embedded `type:"heterodyne.node-secret-exposure.v1"` with
`action:"assign"`. Every assignment's companion source appears in the
array, and the set contains exactly one source/assign holder pair for every
disclosed capability instance unless the ordinary source/exposure schema
requires additional distinct per-capability records. The complete embedded
bytes remain mandatory even when an implementation also indexes them by
digest; a digest-only substitute or missing indexed copy leaves recovery
pending and can never be treated as an absent exposure. Its digest is exactly:

```text
provisional_exposure_set_sha256 =
  lowercase_hex(SHA256(
    UTF8("heterodyne-offline-recovery-provisional-exposure-set-v1") || 0x00 ||
    UTF8(JCS(provisional_exposure_records))
))
```

The cold root signs:

```text
SHA256(
  UTF8("heterodyne-offline-recovery-activation-v1") || 0x00 ||
  UTF8(JCS(record with cold_root_signature omitted))
)
```

with BIP-340, encoded as 128 lowercase hexadecimal characters. The record is
retained at
`keys/core/recovery/offline-activations/<activation-id>/<record-digest>.json`,
where the digest is lowercase-hex SHA-256 of its complete JCS bytes.

After authority release, the archived epoch signs each exact source preimage
by adding only `epoch_signature`. The resulting complete source-record digest
fills the matching assignment preimage's `source_record_digest`; the archived
epoch then signs that assignment by adding only `signature`. Every other byte
MUST exactly equal its intent template. The final activation's
`pre_unseal_intent_digest` is the exact complete signed intent digest, and its
provisional array is an exact bijection with the intent preimage array.
`persona`, `activation_id`, `archive_id`, `generation_record_digest`,
`manifest_digest`, `archive_kel_head`, `new_device_nid`,
`archive_restore_basis`, `created_at`, and
`acknowledged_stale_state_risk` are byte-identical across both signed records.
A missing or extra record, any changed shared field, any byte changed beyond
the two signatures and source-digest link, a substituted intent, or an
activation without its exact intent rejects.

Construction is deliberately acyclic. Intent preimages may cite only
independently materialized allocation, manifest,
finalization-or-resolution, checkpoint, active-obligation, pointer, or
key-binding records. They cannot cite an intent, activation, reset,
transition, checkpoint candidate, or the enclosing `archive_restore_basis`.
The completed source and assignment records cannot cite the enclosing intent
or activation. The dependency direction is therefore preexisting artifact to
intent to completed source/assignment and activation to later transition; no
record points backward.

The producer stages every completed provisional record, protected archive
entry, and byte-identical signed `activation.json` inertly behind a protected
crash journal or equivalent invisible namespace. Once any completed source,
assignment, or activation becomes durable, crash recovery MUST finish
publication or preserve its exact bytes as additional evidence linked to the
already durable intent. A candidate is visible only when the Core activation,
candidate marker, and every staged byte are present and exact. An incomplete marker
installs nothing, but neither it nor an absent activation permits removal of
the intent evidence. There is no cross-store atomic-commit assumption.

Exact duplicate activation bytes are idempotent. Two nonidentical valid
activation records for one `(persona,activation_id)` remain an activation
collision even when both reference valid intent variants; every then-
unreconciled activation and completed provisional record is quarantined.
Likewise, an active intent collision or activation collision forces the
cold-root `emergency-reset` path; `routine-addition` may reconcile only a set
with neither kind of active collision.

Let `ObservedPreUnsealIntents` contain every individually valid, signed, durable
pre-unseal intent variant observed for the persona, including every
quarantined collision variant and every intent for which authority release
never completed. For an exact intent `I`, `ReconciledIntent(I)` is true if and
only if all of these facts are reachable on the accepted chain:

1. one accepted, fully receipted transition
   `inventory_basis.offline_recovery_pre_unseal_intents` contains `I`'s exact
   `{activation_id,intent_record_digest,exposure_preimage_set_sha256}` row;
2. each of `I`'s preimages appears in the exactly matching exposure and action
   `pre_unseal_intent_items` arrays, and every completed source/assignment pair
   derived from `I` that was observed by that transition's frozen inventory
   basis also appears as its actual assignment origin and has exactly one
   absorbing retirement;
3. all class-complete actions and rotations, retained-ciphertext and
   obligation updates, result checkpoint, and ADR-038 recovery-state rollover
   required by those intent origins have accepted; and
4. delivery and recovery-role reconciliation occur only if an exact valid
   final activation linked by `pre_unseal_intent_digest` was observed by that
   transition and its NID is in the target roster. If no linked activation
   existed, or its NID was target-excluded, that NID receives no bootstrap,
   successor assignment, delivery, or role and cannot join through the
   intent-only evidence.

Define:

```text
UnreconciledPreUnsealIntents =
  ObservedPreUnsealIntents - { I | ReconciledIntent(I) }
```

These predicates, like activation reconciliation below, are frozen against
the chain ending at `prior_checkpoint`. A final activation first observed
after its intent was reconciled is new unreconciled evidence: it enters
`UnreconciledActivations`, and every newly observed completed assignment is
inventoried and retired in a new transition. Earlier intent reconciliation
never licenses omission. Conversely, an intent and its exact linked activation
may be reconciled together by one transition without forming a collision.

For closure basis `B`, let `IntentVariants_B(x)` be every distinct,
individually valid signed intent with activation ID `x` whose exact bytes are
observed by the ceremony and preserved in `B`. Define:

```text
ActiveIntentCollisionIds_B =
  { x |
      cardinality(IntentVariants_B(x)) >= 2 and
      exists I in IntentVariants_B(x)
        such that I is in UnreconciledPreUnsealIntents
  }
```

`offline_recovery_pre_unseal_intent_collisions` is the complete strictly
sorted unique projection into closed
`{activation_id,intent_record_digests}` rows. Rows sort by decoded activation
ID; each digest array is decoded-digest-sorted, unique, has at least two
members, and contains every valid observed variant for that ID. Every named
digest resolves in `B` to byte-identical signed intent bytes for the same
persona and activation ID. Exact duplicate bytes collapse to one digest.
Every unreconciled digest has its exact full row in
`offline_recovery_pre_unseal_intents`; an omitted digest is valid only when
`ReconciledIntent(I)` is independently proven. A fully reconciled historical
collision with no unreconciled member is not active.

Let `ObservedActivations` contain every individually valid signed activation
variant observed for the persona, including every quarantined collision
variant. Record-level validity means its closed schema, signature, archive
basis, exact linked intent, template completion, and embedded bytes verify; an
incomplete or missing external candidate namespace still installs nothing but
cannot make that otherwise-valid signed record disappear from
`ObservedActivations`. For an exact activation row `A`,
`Reconciled(A)` is true if and only if all of these facts are reachable on the
accepted chain:

1. one accepted, fully receipted transition
   `inventory_basis.offline_recovery_activations` contains `A`'s exact
   `{activation_id,activation_record_digest,
   provisional_exposure_set_sha256}` row;
2. that transition's complete actions and absorbing retirements cover every
   assignment embedded by `A`, every overlapping ordinary/staged assignment,
   and, only when the linked intent was in
   `UnreconciledPreUnsealIntents` at the frozen
   `prior_checkpoint`, the same inventory contains its exact intent row and
   every exact intent origin linked by
   `A.pre_unseal_intent_digest`; if that intent was already reconciled, its
   accepted audit proof satisfies the link and only the newly observed
   activation assignments re-enter origin accounting and retirement; the same
   actions also cover every mandatory class rotation and required
   retained-ciphertext re-encryption and obligation retain/close update; and
3. the transition's result checkpoint and ADR-038 recovery-state rollover have
   accepted; and
4. if `A.new_device_nid` is in the target roster, every required post-addition
   delivery checkpoint and recovery-role reconciliation for that NID has
   accepted. If it is target-excluded, the reset bootstrap, successor
   assignments, delivery checkpoints, and recovery-role records contain no
   grant or recipient for that NID, while the transition has terminally retired
   every provisional and overlapping assignment embedded by `A`. Target
   exclusion is therefore a complete reconciliation outcome, not an obligation
   to admit an unavailable collision claimant.

Define:

```text
UnreconciledActivations =
  ObservedActivations - { A | Reconciled(A) }
```

For one candidate, `Reconciled(A)`, `ReconciledIntent(I)`, and both
unreconciled sets in its inventory and collision equations are frozen against
the accepted chain ending at `prior_checkpoint`, before applying any effect of
that candidate. Candidate acceptance cannot retroactively erase its own input
collision evidence.

For one transition closure basis `B`, let `Variants_B(x)` be the set of
distinct, individually valid activation records with activation ID `x` whose
exact bytes are observed by the ceremony and preserved in `B`. Define:

```text
ActiveCollisionIds_B =
  { x |
      cardinality(Variants_B(x)) >= 2 and
      exists A in Variants_B(x) such that A is in UnreconciledActivations
  }
```

`offline_recovery_activation_collisions` is the complete strictly sorted unique
projection of `ActiveCollisionIds_B` into closed
`{activation_id,activation_record_digests}` rows. Rows sort by decoded
activation ID. Each digest array contains the decoded-digest-sorted unique
complete record digests of every member of `Variants_B(activation_id)` and has
at least two entries. Every digest resolves in `B` to byte-identical,
schema-valid, cold-root-signed activation bytes for the same persona and
activation ID. Exact duplicate bytes collapse to one digest and do not form a
collision.

An exact valid intent plus an activation that names its digest does not add a
second variant to either collision projection. A nonidentical signed
activation record remains an activation variant and can collide regardless of
whether its referenced intent is shared with or differs from another
activation variant.

Every unreconciled evidence digest has its exact full activation row in
`offline_recovery_activations`. A collision-evidence digest absent from that
inventory is valid only when `Reconciled(A)` is independently provable from the
accepted chain. Such a reconciled digest proves the collision but contributes
nothing to `ProvisionalItems`, transition action source sets, or retirement
sets. Omitting an active collision ID or observed digest, adding an unrelated
digest, or treating a historical fully reconciled collision with no
unreconciled member as active rejects the projection.

Only the exact row projection of `UnreconciledActivations` appears in a later
`offline_recovery_activations` inventory and contributes to
`ProvisionalItems`. A reconciled activation, its embedded records, and its
absorbing retirements remain byte-identical audit history under the ordinary
authenticated head union, but its retired assignments are not reintroduced
as provisional items. Reobserving exact duplicate bytes preserves the same
reconciled digest. A late nonidentical activation sharing the ID, or any new
activation digest, is unreconciled and immediately holds authority until a
new complete reconciliation.

Local installation, successful signature validation, a fresh Core delegation,
claimed non-use, or later local erasure never makes these records operational
and never removes the recorded exposure. When current KEL, repository,
checkpoint, and normal-or-gap rollover state are ancestor/equal and fully
available, reconciliation may use `routine-addition` for the fresh NID.
Otherwise it requires cold-root `emergency-reset`; a competing or
nonancestor state, missing checkpoint, or unresolved rollover cannot be
overwritten by the ordinary path. This is the offline path: the fresh NID is
not required to have been a holder in the archived online checkpoint.

On first synchronized recovery, the next accepted `routine-addition` or
`emergency-reset` transition includes the
complete sorted union of every observed unreconciled intent and activation,
including every unreconciled variant from either collision projection, every
intent template, and every completed provisional set in the mandatory
inventory. Already-reconciled variants are proven through accepted audit
history and are not repeated. It retires every actual provisional assignment
and every overlapping ordinary or staged assignment while rotating the epoch,
config audience, OAuth pairwise secret, and every other durable capability
named by an intent origin, whether or not authority release progressed far
enough to produce an assignment. An epoch tuple from an offline intent or
activation MUST rotate and is never eligible for the narrow current-Core-epoch
adoption exception, even when its public key happens to equal the verifier's
current KEL key. A disclosed cold-root scalar triggers persona migration
rather than a fake same-persona rotation. A retained ciphertext dependency
must be re-encrypted under a fresh instance and its obligation closed or
replaced consistently; if any class-complete rotation, retirement,
reissuance, or obligation update cannot finish, authority remains held.

The fresh epoch then completes ADR-038's normal-or-gap recovery-state rollover
closure. The target roster completes the ordinary config candidate and every
full checkpoint receipt. For each target-included recovered NID it also
completes fresh successor source/assignment exposure, post-addition delivery,
and archive/recovery-role reconciliation before that node may exercise
publishing, minting, delegation, revocation, serving, or recovery authority. A
target-excluded collision claimant instead receives no successor or role and
is terminally reconciled by complete cleanup. A fresh delegation alone is
insufficient. An intent-only NID can never join. The accepted chain retains the
offline intent, any linked activation, provisional records, and absorbing
retirements as non-authoritative audit evidence. A newly discovered intent,
activation, or completed provisional record after reconciliation immediately
holds authority again and requires another complete cleanup, receipt,
rollover, and reconciliation cycle; prior cleanup never licenses silently
dropping late evidence.

This cutoff rule applies to routine addition as well as emergency reset. For
each transition, let `CurrentEpochOfflineEvidence` be every unreconciled intent
origin in its frozen inventory that plans release of the exact
predecessor-current epoch tuple, plus every unreconciled activation origin that
completes that tuple. The evidence time for a linked activation is its exact
intent's `created_at`, including an already-reconciled intent proven through
accepted audit history. Revision 4 has no activation-without-intent legacy
fallback. If this set is nonempty, the transition MUST use a
fresh compromise-declaring cold-root KEL rotation whose canonical
`compromise_since` is no later than the minimum evidence time and the first
detection boundary. The transition target, result checkpoint, and ADR-038
normal-or-gap rollover all bind that new KEL head and cutoff. Any signature
under the predecessor-current epoch with an effective time in the compromised
interval is rejected under the ordinary cutoff rules. A routine path cannot
adopt the old current epoch or omit this cutoff merely because no collision
exists.

A config-key generation change is bound to one
`heterodyne.credential-ledger.secret-transition.v1` record containing exactly:

```text
type, transition_id, persona, mode, prior_checkpoint, added_nids, removed_nids,
target, inventory_basis, result_basis, exposures, outcomes,
created_at, authority, signature
```

`transition_id` is 16 random bytes encoded as 32 lowercase hex. `mode` is
`routine-key-rotation`, `routine-addition`, `routine-removal`, or
`emergency-reset`; both NID arrays are sorted and unique. Key rotation has
both arrays empty and an unchanged roster. Addition has a nonempty
`added_nids`, empty `removed_nids`, and every added NID absent from the prior
roster. Routine removal has nonempty `removed_nids`, empty `added_nids`, and
every removed NID in the prior roster. Emergency reset may add explicitly
authorized NIDs. Its `removed_nids` is nonempty for
`credential_ledger_reset_node_loss` and empty for
`credential_ledger_reset_offline_activation_id_collision`; the associated reset
record and collision evidence must satisfy the mutually exclusive predicates
below. In every mode,
`target.new_roster == (prior_roster - removed_nids) union added_nids`;
overlap rejects. Every roster addition MUST rotate the config key rather than
deliver the currently active key to a not-yet-accepted node.
`target` contains exactly:

```text
generation, sequence, new_roster, config_key_id, config_key_sha256,
pairwise_secret_sha256, exposure_set_sha256,
governed_decrypt_key_bindings_sha256,
historical_decrypt_obligations_sha256, epoch_pubkey, kel_head, reset_id,
epoch_rotation_event_id
```

All integers, rosters, key commitments, and KEL values have the checkpoint
encodings above. In every routine mode `reset_id` is null;
`epoch_rotation_event_id` is null only when the epoch key is unchanged and
otherwise names the target KEL event. In emergency mode `reset_id` is the
32-lowercase-hex reset ID, sequence is zero, and
`epoch_rotation_event_id` is non-null. The config-audience action's successor
ID/commitment MUST equal `target.config_key_id/config_key_sha256`. When an
OAuth-pairwise action is required, its successor commitment MUST equal
`target.pairwise_secret_sha256`; otherwise that target commitment equals the
prior checkpoint unchanged. An epoch action MUST name
`target.epoch_rotation_event_id` and commit the private key deriving
`target.epoch_pubkey`. Every action's authorized NID set is derived from the
target roster plus the governing audience/role policy, never from an
independent caller list.

`inventory_basis` is the closed object
`{config_head,source_ref_head,staging_heads,recovered_heads,
offline_recovery_pre_unseal_intents,
offline_recovery_pre_unseal_intent_collisions,
offline_recovery_activations,offline_recovery_activation_collisions,
same_key_candidate_audit,
signed_ref_map,signed_ref_map_sha256,exposure_set_sha256,
governed_decrypt_key_bindings_sha256,
historical_decrypt_obligations_sha256}`. Every head has the checkpoint's
typed Git object shape.
`source_ref_head` is the exact signed-ref target of the currently authoritative
`refs/heads/enc/<old-config-key-id>` at staging time; it is distinct from the
pre-checkpoint `config_head` and MUST reach the currently accepted checkpoint
and its complete receipt set. `staging_heads` is the complete set of all other
signed `refs/heads/enc/<key-id>` targets that contain delivered but not yet
accepted source/assignment records. Each value is the exact current signed-ref
tip, including every append-only partial receipt/observation commit already
published for that candidate; an earlier `C` or stale partial tip is not an
inventory of that ref. `recovered_heads` is empty in routine
mode and contains the exact additional available old-roster heads examined by
an emergency ceremony.

`offline_recovery_pre_unseal_intents` is normally empty. When a routine
addition or emergency reset reconciles offline evidence, it is the complete
strictly sorted unique array of closed
`{activation_id,intent_record_digest,exposure_preimage_set_sha256}` rows,
ordered by decoded activation ID and decoded intent digest. It contains
exactly the row projection of `UnreconciledPreUnsealIntents`; every signed intent,
archive-basis artifact, and exact preimage row is available and copied into
`B`. A missing observed variant or preimage, digest substitution, or invented
row invalidates the basis.

`offline_recovery_pre_unseal_intent_collisions` has the exact closed
`ActiveIntentCollisionIds_B` projection above. It is empty in every routine
mode. In emergency mode it is complete and may be empty only when the reset is
justified by node loss or by a nonempty activation-collision projection. Every
named intent variant, including reconciled evidence-only history omitted from
the intent inventory, is reachable in `B`; only unreconciled intent rows add
intent origins to cleanup.

`offline_recovery_activations` is normally empty. When
a routine addition or emergency reset reconciles one or more ADR-038 offline
recoveries, it is the complete strictly sorted unique array of closed
`{activation_id,activation_record_digest,provisional_exposure_set_sha256}`
rows, ordered by decoded activation ID and then decoded activation-record
digest. It contains exactly the row projection of
`UnreconciledActivations`, including every unreconciled quarantined
nonidentical record that reuses an ID; no arrival-order winner is selected.
Each complete activation and every
embedded source/assignment record in its signed provisional array are
available to the ceremony and copied into `B`; the set digest and every
embedded record digest are recomputed. Omitting an observed activation
variant, omitting any signed provisional record, substituting a digest-only
row, or adding a locally invented row invalidates the basis. Those
assignments join the transition's mandatory cleanup inventory but never the
predecessor operational exposure set.
`offline_recovery_activation_collisions` has the exact closed shape and
`ActiveCollisionIds_B` projection above. It is empty in every routine mode. In
emergency mode it is the complete active-collision projection and may be empty
only when node loss or a nonempty intent-collision projection independently
justifies the reset. The reset record carries byte-identical copies of both
collision projections. A collision-only reset requires at least one of them
to be nonempty. Every named activation byte, including a reconciled historical
variant omitted from `offline_recovery_activations`, is reachable in `B`;
only the unreconciled activation inventory contributes provisional assignment
cleanup.
`same_key_candidate_audit` is null in routine mode and in emergency mode when
the active source ref has no unaccepted same-key candidate. Otherwise it is
the closed object containing exactly:

```text
predecessor_checkpoint, candidate_checkpoint_digest,
accepted_basis_head, candidate_head, candidate_exposure_records,
candidate_governed_decrypt_key_bindings_sha256,
candidate_historical_decrypt_obligations_sha256,
opaque_object_manifest, opaque_object_manifest_sha256,
safe_record_copies, safe_record_set_sha256
```

The checkpoint digests, candidate-exposure array, governed-binding digest, and
historical-obligation digest have the exact candidate-abandonment definitions
above.
`candidate_governed_decrypt_key_bindings_sha256` equals the candidate
checkpoint field and is independently recomputed as complete `K(C)` from that
candidate's exact config head; it cannot inherit the predecessor digest when
the candidate changes a retention snapshot or binding frontier.
`candidate_historical_decrypt_obligations_sha256` equals the candidate
checkpoint field and is independently recomputed from that candidate's exact
config head; it cannot inherit the predecessor digest when the candidate
projects a retain or close. `accepted_basis_head` is the
canonical signed-ref head containing the fully receipted predecessor;
`candidate_head` equals the exact current `source_ref_head`, descends from that
basis, reaches the unaccepted checkpoint and every signed partial receipt, and
has no successful acceptance or abandonment transition. The two manifest
arrays reuse the staging-cleanup object and safe-record grammars, validation
rules, and digest domains, with destination root
`credential-sync/reset-candidate-audit/<reset-id>/<candidate-checkpoint-digest>/`.
They cover the complete raw Git object closure rooted at `candidate_head`,
including `accepted_basis_head` and every tree/blob reachable in that bounded
commit range but never traversing a parent before the accepted basis, plus
every newly reachable safe record, including the checkpoint, all partial
receipts, security-critical writes, source/assign records,
governed-decrypt-key-binding records, and historical-obligation records.
Old-active-key ciphertext and canonical nonsecret commit/tree structure
remain opaque raw objects; arbitrary plaintext is never promoted.
The reset transition and reset record carry byte-identical objects, and
closure-basis `B` reaches every named copied byte before either is signed.
These copies are non-authoritative audit evidence and are categorically
excluded from operational record/exposure-set evaluation. This audit
classification does not neutralize an independently authoritative monotonic
revocation, retirement, or security reduction found in the suffix: emergency
replay also preserves such a record byte-identically at its canonical
operational path and applies its ordinary effect. The audit copy alone can
never grant or resurrect authority.
Every `secret-assignment` in this object's `candidate_exposure_records` is an
emergency transition mandatory-cleanup item regardless of holder or null
transition ID. The exact canonical current-epoch tuple may use the narrow
adoption rule; every other assignment is retired, and any desired capability
is represented by a fresh reset successor.

For emergency mode it is specifically the sorted, deduplicated union of every
additional signed config/staging head supplied by each retained old-roster
node, excluding heads already represented by `config_head`,
`source_ref_head`, or `staging_heads`. Before signing its sequence-zero
checkpoint receipt, each retained old-roster node MUST enumerate every signed
encrypted head, every complete source/assignment/retirement and
governed-decrypt-key-binding/historical-obligation record it holds, every
governed retained-ciphertext locator, and every non-credential logical path
state reachable from those heads,
verify every head is represented in that union, and verify every reachable
record/path state is copied byte-identically into `B` or the lost-generation
audit/data namespace as applicable. Its ordinary receipt over the checkpoint digest is
also its attestation of that complete local-inventory check. Refusal, an
unavailable claimed-retained node, or any omitted local head keeps the reset
pending; a coordinator cannot classify a reachable retained node as
unavailable merely to suppress its evidence.

`signed_ref_map` is the persisted preimage used for cold replay. Before
transition construction, the producer chooses a fresh config-key ID that is
different from every config-key ID named by any existing active or inert
signed `refs/heads/enc/*` ref. The corresponding
`refs/heads/enc/<new-config-key-id>` ref MUST be absent. An ID collision or
present candidate ref discards that ID; the producer chooses a new random ID
and rebuilds the transition rather than excluding or overwriting the existing
ref. The repository then resolves every existing signed
`refs/heads/enc/*` ref into a closed `{ref,head}` entry. `ref` is the exact
repository-relative ref name, entries are strictly increasing by unsigned
UTF-8 `ref`, and duplicate names reject. The old active ref entry's head MUST
equal `source_ref_head`; the head projection of every other entry MUST exactly
equal `staging_heads` under the ordering below. The candidate ref remains
absent and therefore is not an entry in this pre-candidate map.
The old active ref MUST be the sole signed encrypted ref whose reachable Git
object graph intersects the old active generation. Every other existing
active or inert staging ref starts at its own parentless generation root and
has a reachable graph disjoint from `source_ref_head`'s reachable graph; an
equal head, shared ancestor, or any other old-generation alias rejects
transition construction. Such an alias cannot be silently omitted or left
behind by the acceptance CAS. Processing remains fail closed until a separate,
independently authorized and audited signed-ref cleanup removes the alias, at
which point the producer reconstructs the complete map from current refs.
`signed_ref_map_sha256` is:

```text
lowercase_hex(SHA256(
  UTF8("heterodyne-credential-signed-ref-map-v1") || 0x00 ||
  JCS(entries)
))
```

The stored array MUST JCS-equal those exact entries and its digest must match.
The map is an optimistic-concurrency inventory, not a substitute for signed
ref verification. A new, deleted, renamed, or advanced noncandidate encrypted
ref after this digest is signed invalidates the candidate.
For an emergency reset, its accepted transition CAS compares every inventoried
staging ref to that exact current partial tip and thereby terminalizes it. If
a partial-record append wins first, the reset inventory is stale and must be
rebuilt; if reset acceptance wins first, no later append can succeed.
When `same_key_candidate_audit` is non-null, the same CAS also requires
`source_ref_head == same_key_candidate_audit.candidate_head` and verifies that
`B` already reaches the exact bound audit copies. A same-key append or
security write that wins first changes that head and forces complete audit and
reset reconstruction before the old ref may be deleted. When the reset
inventory uses config deregistration, that same deletion terminalizes exactly
complete `V_old`; missing variant accounting or subtraction of another
semantic identity rejects.

Both head arrays are sorted first by unsigned UTF-8 bytes of `object_format`
and then by decoded `oid` bytes; a duplicate exact typed head rejects. In
emergency mode, `config_head` equals the last-common checkpoint's config head.
The ordinary authenticated head union is the deduplicated union of
`config_head`, `source_ref_head`, every `staging_head`, and every
`recovered_head`. Because a capability was never usable until its
source/assign records reached every configured node, and every pre-receipt
delivery is durably staged as required below, that union is complete for valid
pre-loss exposure; a record visible only on an unavailable node's
noncanonical fork never granted operational authority.

For a basis, replay every complete source/assign lineage reachable from that
ordinary head union under the KEL state at first acceptance. Pending
retirements do not remove assignments. Every otherwise-valid competing assign
digest remains a separate conservative item. Each such unretired lineage is a
conservative exposure item whether or not it ever acquired operational
authority. Each normalized item is the closed object
`{assignment_id,assignment_record_digest,source_record_digest}`, sorted by
decoded assignment ID, then decoded assignment/source digests. Define:

```text
BaseItems =
  dedup(canonical conservative items replayed from the ordinary head union)

ProvisionalItems =
  dedup(normalized source/assignment pairs embedded by every
        inventory_basis.offline_recovery_activations member)

EffectiveInventoryItems = dedup(BaseItems union ProvisionalItems)

IntentItems =
  dedup({secret_class,secret_id,secret_commitment,holder_nid,
         intent_record_digest,preimage_id}
        derived from both exact templates for every preimage in every
        inventory_basis.offline_recovery_pre_unseal_intents member)

EffectiveInventoryOrigins =
  sorted_unique(
    {"origin_type":"assignment",secret_class,secret_id,secret_commitment,
     holder_nid,assignment_id,
     assignment_record_digest,source_record_digest}
      for every item in EffectiveInventoryItems
    union
    {"origin_type":"pre-unseal-intent",secret_class,secret_id,
     secret_commitment,holder_nid,intent_record_digest,preimage_id}
      for every item in IntentItems
  )
```

Every embedded assignment contributes its exact normalized item and requires
its embedded companion source. Assignment-origin tuple and holder fields are
derived from that exact pair and must agree. Exact byte-identical items count
once.
Every nonidentical otherwise-valid assignment-record variant sharing an
assignment ID remains a distinct conservative item, including every variant
from the unreconciled colliding activation IDs present in the inventory.
Sorting and deduplication use the normalized item comparator above, never
arrival order. Both intent templates must project the same tuple and holder.
`IntentItems` sorts by the ordinary secret-tuple comparator, canonical
holder-NID bytes, decoded intent digest, then decoded preimage ID.
`EffectiveInventoryOrigins` sorts by that tuple/holder prefix, explicit origin
rank (`assignment` before `pre-unseal-intent`), and the corresponding
assignment or intent suffix comparator. The tagged shapes are closed; an
intent origin is not a synthetic assignment and has no assignment ID,
source-record digest, or assignment-record digest.

An exact linked activation may contribute both its
actual assignment origin and its intent origin; both are retained and
co-keyed, not deduplicated across origin types. The predecessor exposure-set
digest is:

```text
lowercase_hex(SHA256(
  UTF8("heterodyne-node-exposure-set-v1") || 0x00 ||
  JCS(BaseItems)
))
```

`inventory_basis.exposure_set_sha256` MUST equal that hash of `BaseItems`;
offline intent or activation evidence does not rewrite the archived
predecessor digest.
Endpoint, Core, session, wrapper, and credential sources are represented by
those canonical assignments, not an implementation-local database.
Transition `exposures`, mandatory-cleanup/action completeness, holder
partitions, class-authority selection, and all no-omission checks operate on
`EffectiveInventoryOrigins`. Holder partitions and retirements project only
its actual assignment origins; class action and rotation completeness project
all origins.

The same head union and exact accepted-transition projection replay every
historical-decrypt-obligation lineage and independently derive every governed
retained-ciphertext locator and complete retention-snapshot/binding frontier.
In routine mode,
`inventory_basis.governed_decrypt_key_bindings_sha256` MUST equal the
predecessor checkpoint's independently recomputed `K(C)` digest. In emergency
mode it is the same domain-separated digest over `K(I)`, the complete
repository-inventory maximal frontier and ancestor graph, registered ref/scan
cuts, retention-snapshot set, and binding-record union recovered from every
named config, source, staging, recovered, same-key-candidate, and unreconciled
offline basis. It includes conflicting inventory and binding variants, so
emergency reconciliation cannot erase ambiguity by selecting an arrival-order
winner. The exact transition projects `K(I)` to nonconflicting `K(B)` only
through a fresh signed inventory record parenting the complete maximal
inventory frontier and by preserving, replacing, or removing only the
registered cuts, snapshots, and bindings whose governed dependencies it
actually changes.
In routine mode,
`inventory_basis.historical_decrypt_obligations_sha256` MUST equal the
predecessor checkpoint's recomputed `F(C)` digest. In emergency mode it is
instead the same domain-separated digest over `F(I)`, the complete maximal
frontier replayed from the union of `config_head`, `source_ref_head`, every
staging/recovered head, the exact same-key candidate audit, and every
unreconciled offline archive basis. `F(I)` retains every close and competing
branch and may be a conservative superset of the accepted predecessor
frontier; it is reset inventory, not an ordinarily acceptable active
projection. The reset action set reconciles it to fresh nonconflicting
obligation IDs in `F(B)`. A config-head, ref, recovered-head,
offline-candidate, governed-key-binding, obligation, retired-provenance, or
governed-locator change without the corresponding inventory digest change
invalidates the basis.

`result_basis` is exactly
`{config_head,exposure_set_sha256,
governed_decrypt_key_bindings_sha256,
historical_decrypt_obligations_sha256}`.
Its config head is closure-basis commit `B` below. Its digest is computed from
the actual-assignment frontier `EffectiveInventoryItems` plus the projected
atomic effect of this transition: every `assignment_record_digest` named by an
exposure is retired and every staged current-successor or
historical-decrypt-only assignment is added. Intent origins determine required
cleanup but never enter predecessor or result exposure-set hash preimages as
pseudo-assignments. Actions, source companions, and retirement records
determine and prove the projected assignment set, but the digest preimage
contains only exact conservative assignment items.
For a config-key transition, this projection consumes the independently
validated `T`-local `K`/`R`/`O`, dependent proof, and action records even
though `result_basis.config_head` remains `B`; their presence in `T` does not
make them preexisting accepted state.
Transition/checkpoint fields bind the other proof digests separately. The
result governed-binding digest is independently derived as `K(B)` after
applying this transition's exact targeted inventory successor and
retention-snapshot/binding changes, and equals the transition target and
successor checkpoint field.
Operational activation remains a distinct accepted-transition state; it is
not inferred from membership in this conservative set. The projected set has
no unretired item whose holder is excluded from the target roster.
The result's historical-obligation digest is independently computed after
applying every exact retain/close record governed by this transition to the
predecessor obligation lineages, re-deriving `G(B) = O(B)`, and forming the
new complete `F(B)`. It equals the transition target and successor checkpoint field.
An obligation record absent from the action proof set, a ciphertext change
without its transition-bound lineage successor, or a target/result/checkpoint
digest mismatch rejects before receipts.
`exposures` is strictly increasing and unique by
`(secret_class,secret_id,secret_commitment)`. Every entry contains exactly
`secret_class`, `secret_id`, `secret_commitment`, `holder_nids`,
`assignment_record_digests`, and `pre_unseal_intent_items`.
`pre_unseal_intent_items` is a strictly sorted unique array of closed
`{intent_record_digest,preimage_id}` rows using the `IntentItems` comparator.
`assignment_record_digests` is exactly the complete set of unretired
conservative assign-record digests for that secret tuple, including
transition-staged, operationally non-authoritative, and competing variants;
`holder_nids` is exactly the corresponding complete holder set. Those two
assignment-derived arrays are independently complete, sorted, and unique, and
may both be empty only when the tuple has no real assignment origin.
`pre_unseal_intent_items` is independently exact and may be empty only when
the tuple has no intent origin. Every exposure has at least one origin. When
both origin types exist, all co-keyed origins appear; neither array can be
selectively suppressed by the presence of the other.

Every mode's exposure array contains the sorted union of its mode-mandatory
tuples and the complete cleanup set. The cleanup set contains every inventory tuple
with at least one holder excluded from the target roster, every tuple with an
unretired assignment staged by a transition that is not accepted in the
authoritative checkpoint chain at inventory time, and every tuple containing
a competing assign variant, plus every tuple with an unreconciled intent
origin. Inclusion is not caller-selective: if one origin makes a tuple
eligible, the entry contains every actual assignment and intent origin for
that tuple. The transition retires each actual assignment exactly once; intent
origins receive no retirement record. Removal and emergency modes thereby
close every conservative exposure
held by any target-excluded NID, including a proposed NID from a failed
addition that was never a predecessor-roster member. Routine key rotation has
the current `config-audience` tuple as its mandatory minimum. Routine addition
has the current `config-audience` and `oauth-pairwise` tuples as its mandatory
minimum, ordered by the general comparator, because both secrets rotate before
the proposed node receives candidate state. Either routine mode also includes
the complete cleanup set; those mandatory minima are not exact-only arrays.
When either offline intent or activation inventory is nonempty, the cleanup
set additionally contains every tuple named by every preimage or provisional
assignment, plus every overlapping operational or staged tuple for the same
restored capability. No holder, intent origin, or class may be omitted merely
because release failed before a signed assignment existed, the provisional
assignment was never operational, or restored bytes were later erased.

`oauth-pairwise` and `epoch` are singleton capability classes and close as a
class, not as unrelated tuples. If any `oauth-pairwise` tuple is included by a
mandatory, cleanup, or maintenance rule, the exposure array MUST also include
the exact currently operational tuple committed by the predecessor checkpoint.
Every old, failed-candidate, or competing pairwise tuple is retired, every
pairwise action names one byte-identical fresh successor ID and commitment, and
the transition contains exactly one complete successor-assignment set for that
new singleton. The target and successor checkpoint name that same commitment;
no prior pairwise tuple remains unretired.

For `epoch`, the verifier first resolves the exact current canonical Core KEL
key/head and the complete exposure tuple for that key. A current-epoch tuple is
exempt from the “unaccepted transition” cleanup trigger only when all of its
assignments bind that exact KEL event, have no competing variant, and name only
holders authorized by the target recovery-role policy. When it is safe and the
predecessor checkpoint still names an older epoch, every noncurrent epoch tuple
is included and each `kel-rotation` action converges on that already current
tuple and its already accepted KEL rotation event; the current tuple itself is
not retired. If the current tuple has an excluded holder, a competing variant,
or any other unsafe assignment, it is included too and the cold root performs
one further canonical rotation to a fresh epoch tuple. In either case all epoch
actions in the transition name one byte-identical successor ID, commitment,
public key, event ID, and KEL head, and all non-successor epoch assignments are
retired. A transition cannot select a convenient older tuple or create two
current epoch singletons.

Routine key rotation may additionally include an explicit maintenance set of
otherwise ordinary unretired tuples held only by retained authorized NIDs.
Each such extra tuple is authority-selected in the signed transition, includes
its complete conservative assignment set, and has the class-valid
rotation/revoke-reissue/termination/retirement action and independently
canonical expiry, withdrawal, replacement, or user-maintenance artifact
required by the action matrix. A bare desire to shrink the inventory is not
proof. The maintenance set is the only caller-selected addition; it cannot
omit any mode-mandatory or cleanup tuple, and no other mode admits an
unclassified extra. This provides an accepted path for an expired bearer,
withdrawn endpoint, retired service, or ordinary retained-holder key rotation
without first misclassifying the holder as removed or the assignment as
anomalous.

`outcomes` has exactly one entry for each exposure tuple and no other entry,
in the same order. Each contains exactly `secret_class`, `secret_id`,
`old_commitment`, `disposition`, `successor_id`, and `proof_digests`.
`old_commitment` equals the exposure's `secret_commitment`. `disposition` is
`rotate`, `terminate`, `revoke-reissue`, `retire`, or
`persona-migration-required`. `successor_id` is non-null exactly for
`rotate` and `revoke-reissue`; it is null for `terminate`, `retire`, and
`persona-migration-required`. `proof_digests` is a nonempty sorted unique
array of canonical
`heterodyne.node-secret-transition-action.v1` record digests. The
class-specific completion rules below determine the only valid disposition
and proof set; a syntactically complete but ineffective outcome rejects.

Each transition-action record contains exactly:

```text
type, persona, transition_id, action_kind, secret_class, secret_id,
old_commitment, disposition, successor_id, successor_commitment,
excluded_nids, authorized_nids, source_assignment_digests,
pre_unseal_intent_items,
retirement_record_digests, successor_assignment_digests,
historical_decrypt_nids, historical_assignment_digests,
artifact_refs, created_at, authority, signature
```

`artifact_refs` is a sorted unique nonempty array of closed
`{profile_id,record_digest}` objects; every profile resolves in the selected
artifact/catalog corpus and every exact record is canonical and valid.
An action may reference only independently materialized, noncyclic proof
artifacts finalized before the action is signed: old source/assignment
records, pending retirements, current-successor and historical-decrypt-only
source/assignment records, wraps, delegations/revocations, endpoint or
repository changes, and an independently complete termination/tombstone
carrier, plus an independently complete historical-decrypt retain/close record
when the transition preserves or eliminates governed ciphertext under the old
instance. Existing proofs may already be reachable at closure basis `B`; under
the config-key co-commit rule a new governing inventory `R`, dependent
obligation `O`, every `O`-dependent source/assignment/retirement proof, and
the citing action may first appear together in `T`, but are finalized and
signed in that dependency order before the transition is signed. The action
MUST NOT reference the enclosing transition, this
candidate's reset, checkpoint, bootstrap-recipient array, checkpoint receipt,
transition commit `T`'s OID, or any digest whose own bytes depend on the action
or transition digest. The transition target and the candidate acceptance
rules separately require the exact checkpoint, bootstrap commitment, and
final signed-ref update. A table entry's “canonical artifact effect” is the
complete acceptance condition, not a claim that every named effect appears in
`artifact_refs`.
`source_assignment_digests` is exactly the exposure entry's complete unretired
conservative assignment set for the old secret in
`EffectiveInventoryItems`, including staged, operationally non-authoritative,
competing, retained-holder, target-excluded-holder, and unreconciled offline
provisional variants. `pre_unseal_intent_items` JCS-equals the exposure
entry's independently complete intent-origin array. All co-keyed origins must
appear even when one activation completes an intent. When both offline arrays
are empty, `EffectiveInventoryItems` equals the ordinary predecessor exposure
replay and the intent array is empty.
`retirement_record_digests` is a one-to-one set of canonical `retire`
successors for the complete actual assignment set only. Intent origins are
not assignments, receive no retirement records, and nevertheless require the
same class-complete action, successor/termination effect, checkpoint, and
rollover gates. Thus both assignment arrays are empty exactly for an
intent-only exposure, while `pre_unseal_intent_items` remains nonempty. For
`rotate` or
`revoke-reissue`, successor fields are non-null, the successor ID and
commitment differ from the old values, `successor_assignment_digests` is
exactly the complete canonical staged assignment set projected to become
active for `authorized_nids` at atomic transition acceptance, and no excluded
NID appears. It is not required to be active beforehand. For `terminate` or
`retire`, or `persona-migration-required`, all successor members are null and
all successor-assignment arrays are empty as required by the schema.
For an `epoch` action adopting the already current canonical Core KEL tuple,
`successor_assignment_digests` instead names that tuple's complete already
current assignment set under the exact exception above; its records are copied
byte-identically into `B` and remain active rather than being restaged or
retired. This is the only action allowed to name an already active successor.

`historical_decrypt_nids` is a sorted unique array of canonical NIDs, and
`historical_assignment_digests` is a sorted unique array ordered by decoded
digest bytes. They are both empty unless the projected result `G(B) = O(B)`
contains at least one active retain obligation for this action's exact old
`(secret_class,secret_id,old_commitment)` tuple. Because the action retires
the complete old assignment set, they are both nonempty when such an
obligation remains. `historical_decrypt_nids` is exactly the target-roster
recovery/decrypt-only holder set authorized by the governing class policy;
it is not inferred from convenience or local possession. It may overlap
`authorized_nids`, but neither array implies membership in the other.

Each historical digest names one newly staged `action:"assign"` record with a
fresh assignment ID, this exact `transition_id`, the same old `secret_id` and
commitment, and one holder in `historical_decrypt_nids`; the set is a complete
one-to-one holder projection. Every such assignment names a current,
nonretired source companion for the same holder and old tuple. That source is
newly staged or already canonical under the current epoch, and its
`artifact_refs` bind the complete projected-active retain-obligation head set
for the tuple plus every applicable governed-decrypt key binding and governing
artifact/pointer proof. A prior source that lacks those references cannot be
reused. The current epoch, or the fresh canonical recovery epoch in emergency
mode, signs the source and assignment under the ordinary source/exposure
rules.

All old operational and prior historical assignments in
`source_assignment_digests` retire atomically and populate the
`retired_provenance_lineages` of every projected-active obligation record for
the tuple. The new historical
assignments enter `result_basis.exposure_set_sha256` atomically with
transition acceptance, alongside any distinct fresh-current successor
assignments. They authorize only decrypting the exact `G(B)` locator rows
covered by the cited projected-active obligations and applicable key-binding
records. They are barred
from new encryption, signing, delegation, minting, serving, or any other
authority. A later transition that closes the final matching obligation
includes and retires the complete historical assignment set and leaves both
historical arrays empty. Offline-recovery cleanup follows the same rule:
disclosed historical material is rotated or reencrypted where possible, and
any still-required old instance survives only through this explicit
decrypt-only replacement assignment.

`authorized_nids` is the exact class-specific post-transition
holder/authority set. `excluded_nids` is exactly the exposure entry's
`holder_nids` set difference `authorized_nids`; `excluded_nids` and
`holder_nids` intersect `authorized_nids` are a disjoint partition of the
complete old holder set. `authorized_nids` may additionally contain newly
authorized successor holders that were not old holders, as in routine
addition. Thus a proposed NID from a failed addition is excluded when it is
not in the new authorized set even though it never appeared in
`removed_nids`.

The action's `old_commitment` MUST equal every named old source companion and
assign record. Its `successor_commitment` MUST equal every named staged
successor source companion and assignment. Conflicting commitments under one
secret ID form separate conservative exposure tuples; no implementation may
select the convenient variant.

`action_kind`, disposition, and successor cardinality are selected by this
closed matrix. A conditional row chooses `rotate` or `revoke-reissue` exactly
when the protected service or capability remains after removal; it chooses
`retire` exactly when that service or capability is withdrawn and its
canonical retirement artifact is final.

| Secret class | Required action kind | Allowed disposition and successor | Canonical artifact effect |
|---|---|---|---|
| `cold-root` | `persona-migration` | `persona-migration-required`; no successor | explicit migration record; no successor under this persona |
| `epoch` | `kel-rotation` | `rotate`; exactly one successor | one accepted cold-root-authorized rotation and new-secret assignments only to retained recovery roles |
| `device-signing`, `agent-signing` | `delegation-revocation` | `revoke-reissue` with exactly one successor if its role remains; otherwise `retire` | canonical Core revoke and any replacement delegation/key assignment |
| `core-protected`, `recovery-wrap` | `wrapper-replacement` | `rotate` with exactly one successor if the protected item remains; otherwise `retire` | new wrapper/slot or final retired archive/protected-record generation excluding removed holders |
| `config-audience` | `audience-key-rotation` | `rotate`; exactly one successor | canonical new key epoch, complete retained-roster wraps, checkpoint, and prior-epoch retirement |
| `tier3-audience`, `claim-ledger-audience` | `audience-key-rotation` | `rotate` with exactly one successor if the audience remains; otherwise `retire` | canonical new key epoch and complete retained-recipient wraps, or final audience/data retirement |
| `object-dek` | `object-key-replacement` | `rotate` with exactly one successor if the object remains; otherwise `retire` | canonical new pointer/ciphertext generation or permanent object retirement |
| `double-ratchet` | `ratchet-termination` | `terminate`; no successor field | canonical old-session termination at every retained persona holder plus the peer tombstone below; any fresh invite/session is a separately identified capability |
| `radicle-access` | `repository-access-revocation` | `revoke-reissue` with exactly one successor if access is reassigned; otherwise `retire` | canonical per-RID read/write ACL transition excluding removed NIDs |
| `oauth-signing`, `oauth-pairwise` | `credential-revocation` | `rotate`; exactly one successor | canonical issuer/status rotation and replacement assignment |
| `bearer-credential` | `credential-revocation` | `revoke-reissue` with exactly one successor if the relationship remains; otherwise `retire` | canonical credential/client revocation and optional reissuance |
| `ssh-client`, `ssh-host`, `onion-service-identity`, `tls-serving` | `endpoint-identity-replacement` | `rotate` with exactly one successor if the endpoint remains; otherwise `retire` | canonical credential retirement, optional replacement assignment, and updated endpoint advertisement |

`recovery-wrap` never uses ADR-038 `historical-decrypt`. A still-current
protected item is rewrapped under the fresh successor; otherwise its old
wrapper and archive/protected-record generation retire. Archive recipient
slots remain independently recoverable through their archive-specific
wrappers and cannot create an unrepresentable retained dependency outside the
closed governed `git-blob`/`large-object` locator grammar.

For every class that permits ADR-038 `historical-decrypt`, an action that
retires the operational instance while any governed ciphertext remains also
references the exact `retain` obligation head and proves the projected
obligation-set digest. If the transition re-encrypts or retires the last such
ciphertext, it references the exact absorbing `close` successor. Keeping the
retired key for current authorized historical holders still requires their
complete ordinary source/assign lineages in `exposure_set_sha256`; an
obligation never licenses an unrecorded key copy.

The action record uses the same closed `authority` object and BIP-340 signing
selection as the containing transition. It signs SHA-256 of
`UTF8("heterodyne-node-secret-transition-action-v1")`, a zero byte, and JCS
with `signature` omitted. Its digest is SHA-256 of complete signed JCS. The
transition outcome's disposition/successor MUST exactly equal its action
record; multiple proof records are permitted only when the table requires
distinct canonical artifacts, and their source/retirement/successor sets MUST
be byte-identical.

`persona-migration-required` is a terminal abort state, not a successful
secret transition. Its signed action and transition may be retained as audit
evidence, but no `result_basis`, candidate checkpoint, receipt set, reset, or
signed-ref switch may treat that outcome as satisfied. Credential,
publishing, recovery, and encryption authority for the affected persona
remains held while the client creates a new persona and explicit migration
attestations. The otherwise general “one valid outcome per exposure” rule
therefore excludes this disposition from transition acceptance.

`ratchet-termination` always cites one closed
`heterodyne.double-ratchet-session-termination.v1` record containing exactly:

```text
type, persona, transition_id, old_session_id, local_nid, remote_persona, remote_nid,
local_delivery_pubkey, local_delivery_delegation_event_id,
remote_delivery_pubkey, remote_delivery_delegation_event_id,
source_assignment_digests, removed_holder_nids, retained_holder_nids,
invalidated_at, successor_session_ids, nid_revocation_digests,
retained_receipts, peer_tombstone, peer_delivery_event, authority, signature
```

Holder arrays and successor IDs are sorted and unique; either holder array may
be empty subject to the exact partition below. `old_session_id`, `local_nid`,
`local_delivery_pubkey`, `local_delivery_delegation_event_id`,
`remote_persona`, `remote_nid`, `remote_delivery_pubkey`,
`remote_delivery_delegation_event_id`, and `source_assignment_digests` exactly equal the Double
Ratchet capability object and the transition action's exact complete
unretired conservative assignment set, including every
staged/non-authoritative/competing variant. `removed_holder_nids` is exactly
that exposure holder set minus the action's `authorized_nids`, and
`retained_holder_nids` is exactly its intersection with `authorized_nids`;
together they are a disjoint partition of the complete holder set. Each
delivery key is a raw 64-lowercase-hex secp256k1
publishing key whose named canonical Core delegation binds it to the
corresponding NID and persona; a session is replaced when either delegated
delivery key changes. Define `termination_base_digest` as lowercase-hex SHA-256
of the JCS termination record with `retained_receipts` replaced by `[]` and
the outer `signature` omitted. Each closed retained receipt contains exactly
`termination_base_digest`, `nid`, `observed_at`, and `signature`. Its Ed25519
NID signs SHA-256 of
`UTF8("heterodyne-dr-session-termination-receipt-v1")`, a zero byte, and JCS
of the first three fields. The receipt's base digest MUST equal the recomputed
value. Receipts are strictly ordered by unsigned UTF-8 `nid`, with exactly one
valid receipt per retained holder and no other receipt.
`nid_revocation_digests` is exactly the canonical Core revocation set for
those `removed_holder_nids` whose NID or delegated delivery-key authority
remains current and is required by the class action to be revoked. An
excluded, never-admitted proposed NID with no operational delegation is still
bound and retired above but does not force unrelated global NID revocation.
Omitting a still-current required revocation or adding an unrelated
revocation rejects. Continuing communication has fresh, different successor
session IDs and matching separately identified source/exposure assignments;
otherwise the successor array is empty.
The transition authority signs:

```text
SHA256(
  UTF8("heterodyne-dr-session-termination-v1") || 0x00 ||
  JCS(complete termination record with signature omitted)
)
```

using the authority suite selected below. `signature` is the resulting
64-byte BIP-340 signature encoded as 128 lowercase hexadecimal characters.
`termination_record_digest` is lowercase-hex SHA-256 over the exact JCS bytes
of the complete signed record. It MUST equal both the
`credential-sync/dr-terminations/<transition-id>/<termination-record-digest>.json`
path component and the transition action's corresponding `record_digest`.

`peer_tombstone` is the closed object containing exactly:

```text
type, spec_version, persona, transition_id, old_session_id, local_nid,
remote_persona, remote_nid,
local_delivery_pubkey, local_delivery_delegation_event_id,
remote_delivery_pubkey, remote_delivery_delegation_event_id,
invalidated_at, successor_session_ids, reason, epoch_pubkey, kel_head,
epoch_signature
```

Its type is `heterodyne.double-ratchet-peer-tombstone.v1` and
`spec_version` is exactly `comms/0.5.0`. Its `persona`,
`transition_id`, `old_session_id`, `local_nid`, `local_delivery_pubkey`,
`local_delivery_delegation_event_id`, `remote_persona`, `remote_nid`,
`remote_delivery_pubkey`, `remote_delivery_delegation_event_id`,
`invalidated_at`, and `successor_session_ids` exactly equal the corresponding
enclosing termination members. `reason` is `persona_node_removed` exactly
when the termination's complete old holder set intersects the enclosing
transition's exact `removed_nids`; this remains true when the same tuple also
contains cleanup-only variants. It is `candidate_material_retired` exactly
when that intersection is empty, including a target-excluded holder from a
failed addition that never became a predecessor-roster node. This prevents an
abandoned-candidate cleanup from falsely claiming a persona node was removed.
Any reason/mode/holder mismatch rejects. The
current post-transition epoch key produces a 64-byte BIP-340 signature,
encoded as 128 lowercase hexadecimal characters, over:

```text
SHA256(
  UTF8("heterodyne-dr-peer-tombstone-v1") || 0x00 ||
  JCS(peer_tombstone with epoch_signature omitted)
)
```

`peer_delivery_event` is the closed audit carrier containing exactly
`event`, `nip01_raw`, `seal`, and `rumor`. `event/nip01_raw` are the complete
outer gift-wrap event and exact NIP-01 signing-array string. `seal` contains
exactly `event` and sibling `nip01_raw`; `rumor` contains exactly its parsed
unsigned `event` and sibling `nip01_raw`. Each raw string hashes to the exposed
ID and parses to byte-identical exposed fields; the two ciphertext layers MUST
decrypt to those exact seal and rumor event bytes. Thus the termination digest
binds the exact signed outer and seal bytes and never reconstructs a Nostr
signing input from parsed fields.

The carried event is one complete NIP-59 persistent gift wrap. Its
authenticated rumor has `kind:1061`, `pubkey` equal to `epoch_pubkey`,
`created_at` equal to `invalidated_at`, tags exactly
`[["p","<remote_delivery_pubkey>"],["heterodyne","dr_peer_tombstone"]]`, and
content equal to the exact JCS `peer_tombstone`; its NIP-01 ID is present but
its signature is absent as NIP-59 requires. The `kind:13` seal has empty tags,
is NIP-44-v2 encrypted to `remote_delivery_pubkey`, and is signed by the
tombstone epoch key. This kind-13 seal is the sole narrow exception to Core's
otherwise universal `kel_head` tag on epoch-signed Heterodyne events because
NIP-59 requires empty seal tags; the exact KEL head and signature are bound
inside the encrypted epoch-signed tombstone, and this exception authorizes no
other unstamped epoch use. The outer `kind:1059` event uses a fresh random
one-time key, has exactly one `["p","<remote_delivery_pubkey>"]` tag, and wraps
the seal with NIP-44 v2. Wrapper timestamps follow NIP-59 privacy
randomization; the signed inner `invalidated_at` remains authoritative. Both
`p` values are the raw 32-byte lowercase-hex public key, never its bech32
`npub` encoding. The receiver validates the named delegation at the session's
accepted setup/update KEL head; revocation after setup does not make a
last-known key unusable for this one-way warning.
Revision 4 allocates nested profiles
`heterodyne-comms-double-ratchet-peer-tombstone-rumor-v1` on kind 1061 and
`heterodyne-comms-double-ratchet-peer-tombstone-v1` on kind 1059. The
termination schema validates the complete carrier recursively.
The new `kinds.json` base entry for 1061 has
`allocation_authority:"heterodyne"`, `base_schema_owner:"comms"`,
`status:"draft"`, and `first_version:"comms/0.5.0"`; its sole initial profile
is the rumor profile above with owner `comms`, stamping false,
`first_version:"comms/0.5.0"`, draft status,
`discriminator:"content.type=heterodyne.double-ratchet-peer-tombstone.v1"`,
`schema_scope:"complete-event"`, and
`schema_path:"docs/spec/schemas/comms/double-ratchet-peer-tombstone-rumor-v1.schema.json"`;
its `schema_sha256` is that raw file's digest.

The existing kind-1059 invite-response nested entry retains discriminator
`wire:nostr-double-ratchet@0.0.138;kind=1059`, owner `comms`, stamping false,
`first_version:"comms/0.5.0"`, draft status, and null schema
scope/path/digest. The new tombstone entry has owner `comms`, stamping false,
`first_version:"comms/0.5.0"`, draft status, exact discriminator
`wire:nip59;rumor-kind=1061;rumor-content.type=heterodyne.double-ratchet-peer-tombstone.v1`,
`schema_scope:"complete-event"`,
`schema_path:"docs/spec/schemas/comms/double-ratchet-peer-tombstone-gift-wrap-v1.schema.json"`,
and `schema_sha256` equal to that raw file's digest. The discriminator is
evaluated only after successful NIP-59 unwrap; it cannot be guessed from the
opaque outer content.
For these two profiles, the 1061 complete-event schema input is the closed
`{event,nip01_raw}` unsigned-rumor carrier and the 1059 complete-event schema
input is the exact four-member `peer_delivery_event` carrier above. The latter
schema recursively checks the decrypted seal and rumor raw bytes and the
signed tombstone; a caller that supplies only the opaque outer event has not
yet completed profile validation.

Revision 4 catalogs upstream NIP-59 kind 13 with
`allocation_authority:"nostr"`, `base_schema_owner:"nostr"`,
`status:"draft"`, `first_version:"comms/0.5.0"`, and exactly `profiles:[]`.

The complete event is constructed and bound into the termination/action before
transition acceptance but is broadcast immediately after the atomic signed-ref
acceptance to every relay used for the old session and every current
kind-10050 NIP-17 DM relay of the remote persona. Current NIP-65 read relays
may be tried only as an additional fallback. A conforming peer unwraps it,
validates the outer event, seal, epoch-signed tombstone and point-in-time KEL,
the exact remote delivery key/NID/session recipient binding, and deduplicates by
`(persona,old_session_id,transition_id)`. It MUST reject every later
old-session message after first valid observation. A fresh authenticated
session or offline channel may additionally carry the same complete event.
The peer does not fetch or validate the sender's private config-repository
transition; `transition_id` is correlation data at that boundary. Sender-side
acceptance separately proves that the identical tombstone/event is bound by
the termination, action, transition, and accepted checkpoint.
Retries continue until acknowledged or local policy expires; an external peer
acknowledgement is recorded when available but cannot block persona-side
invalidation. Until acknowledgement, the UI reports that the remote peer may
still accept attacker-authored old-session traffic. No internal receipt or
NID revocation is claimed to erase that delivery-bound residual risk. The
transition-authority signature above binds the complete termination record.

Tombstone KEL verification is point-in-time: `epoch_pubkey` MUST have been
current at `invalidated_at` under the exact named `kel_head`; that head must
remain an ancestor of the receiver's canonical KEL, and no applicable
`compromise_since` cutoff may invalidate the signature. A later ordinary
epoch rotation does not make an asynchronously delivered tombstone stale.

This is unilateral persona-side invalidation: after its transition accepts,
no retained node decrypts, sends, or releases plaintext under the old session.
An external counterparty that never held persona state is not a required
receipt signer. The action's nonempty `artifact_refs` MUST include the
canonical complete termination-record digest; that record recursively binds
the exact peer delivery carrier and retained-holder receipts. Canonical NID
revocations and any fresh invite/session records are additional independent
artifact refs when applicable.

`authority` contains exactly `signer_type`, `signer`, and `kel_head`.
Authority selection is derived from the complete action set, not merely from
the transition mode. `signer_type` is `cold-root` for every emergency reset
and for every routine transition whose complete mandatory, cleanup, and
maintenance action set contains an `epoch`, `core-protected`, or
`recovery-wrap` exposure or otherwise changes who may exercise recovery
authority. It is `epoch` for every other routine transition. A
`cold-root` exposure still yields only `persona-migration-required` and can
never be accepted as a transition.

If an `epoch` action is present, the action artifact MUST be one exact
canonical cold-root-authorized KEL rotation. The action's successor key, the
transition target's `epoch_rotation_event_id`, `epoch_pubkey`, and `kel_head`,
and the accepted rotation event's ID, new epoch key, and post-rotation KEL head
MUST all agree. If no `epoch` action is present, the target's epoch fields
follow the conditional unchanged/rotation rules above; a recovery-wrapper
change does not silently claim an epoch rotation. Every action, retirement,
termination, and transition signature in one transition uses the same selected
authority object. Thus a routine addition or key rotation whose cleanup set
contains recovery-authority material is cold-root-authorized just like a
removal with the same action set. The corresponding BIP-340 key
signs SHA-256 of
`UTF8("heterodyne-credential-secret-transition-v1")`, a zero byte, and the
JCS object with `signature` omitted; the 64-byte signature is 128 lowercase
hex. First acceptance requires the signer/head to be the current accepted
authority and every proof record to be canonical. The complete-record digest
is lowercase-hex SHA-256 of its JCS bytes.

Completion is fail-closed and class-specific:

- every config, Tier 3, and private claim-ledger audience-key epoch the node
  could read is rotated, wrapped only to the retained authorized set, and
  advances its normal key/checkpoint record; claim-ledger reader removal also
  removes that NID's claim-ledger Radicle access, advances the dedicated
  ledger audience-key checkpoint, and retires prior ciphertext. Old
  ciphertext remains readable to a former key holder and the UI states that
  non-retroactive limit;
- every Double Ratchet session whose state the node held is terminated on all
  retained peers, its old state is made unusable, and any continuing
  relationship bootstraps a fresh session ID and root state to retained or
  replacement NIDs. Generation invalidation alone is not post-compromise
  recovery;
- device/agent signing keys, bearer credentials, OAuth issuer/status keys,
  client credentials, SSH credentials, and Radicle read/write authority for
  every affected public, private, config, claim-ledger, and object repository
  are revoked or rotated and reissued only where still authorized;
- every cached object DEK, protected-branch/object wrap, recovery recipient
  slot, archive DEK, Core protected-record wrapper, or other key the node could
  unwrap is rotated and rewrapped to the retained set, or the corresponding
  ciphertext/archive/object generation is retired and replaced. Previously
  distributed ciphertext or archives remain readable under copied old keys;
- every copied Tor onion-service identity, SSH host key, HTTPS/TLS key, and
  OIDC serving key is retired or rotated. Replacement onion identities get a
  new `.onion` address, and canonical recovery-role, endpoint, relay, and
  issuer advertisements are updated before clients use them; and
- epoch exposure requires a cold-root-authorized KEL rotation. If the
  inventory cannot exclude exposure of the cold-root private key itself, no
  transition can restore the persona's assurance: authority operations stop,
  the outcome is `persona-migration-required`, and the client guides creation
  of a new persona plus explicit migration attestations. An emergency reset
  or epoch rotation MUST NOT be presented as curing possible cold-root
  compromise.

Transition staging has one non-self-referential, non-retaining Git shape.
Source-basis commit `A` is `inventory_basis.config_head`, the exact logical
inventory basis (the selected current data head in a routine transition and
the last-common pre-checkpoint head in emergency mode). The distinct
`inventory_basis.source_ref_head` is the actual expected old encrypted-ref
tip used by the atomic compare-and-swap below. Closure-basis commit `B` is
`result_basis.config_head`, the parentless root of the distinct
`refs/heads/enc/<new-config-key-id>` generation. Neither `A` nor any commit
reachable only from the old encrypted ref is an ancestor of `B`, and `B`'s
tree references no ciphertext encrypted under the old key.

Every commit and tree that may become reachable from a signed
`refs/heads/enc/*` ref first passes the closed
`comms.config-repository-git-structure.v1` profile. A commit has exactly
one `tree` header, exactly zero or one `parent` header as required by this state
machine, then one author and one committer header in that exact order. Both
identity/time payloads are
`Heterodyne Protocol <noreply@heterodyne.invalid> 0 +0000`. There are no
optional or continuation headers, and the exact message bytes are
`heterodyne-config-v1\n`. Merge commits are forbidden. A tree contains only
exact raw mode `100644` regular blobs or exact raw mode `40000` subtrees.
Entry names are strictly canonical-Git-byte-ordered and unique within each
tree, and the complete path grammar dictates whether each entry is a blob or
subtree. Every reconstructed root-relative pathname
is either the exact output of a normative family path template with all
variable components independently validated by that template, or
`config-data/<path-token>.bin`, where `path-token` is 64 lowercase hexadecimal
characters encoding
`HMAC-SHA256(path_index_key,
UTF8("heterodyne-config-logical-path-v1") || 0x00 || UTF8(logical_path))`.
Here `config_audience_key` is the exact key that encrypts blobs on the signed
ref containing the tree, and `path_index_key` is
`HKDF-SHA256(IKM=config_audience_key, salt=32 zero bytes,
info=UTF8("heterodyne-config-path-index-key-v1"), L=32)`.
`logical_path` is strict UTF-8 NFC, contains no empty, dot, or dot-dot segment,
and is present only inside the encrypted config blob; a user-supplied label,
filename, hostname, or other free text never appears in a Git pathname.
Normative templates may expose only their fixed literals and components that
their schemas classify as public protocol identifiers; arbitrary or
secret-bearing names use the HMAC form.
Two distinct normalized logical paths yielding one token, or a token whose
decrypted blob's allocated closed owner schema does not derive the same
normalized logical path, rejects before publication.

The exact commit-body grammar, with the bracketed parent line present only for
a nonroot commit and each `\n` one byte, is:

```text
tree <canonical-tree-oid>\n[parent <canonical-parent-oid>\n]author Heterodyne Protocol <noreply@heterodyne.invalid> 0 +0000\ncommitter Heterodyne Protocol <noreply@heterodyne.invalid> 0 +0000\n\nheterodyne-config-v1\n
```

The sole second commit branch is the exact config-class emergency `H*`
retention-resolution grammar:

```text
tree <canonical-tree-oid>\nparent <variant-head-oid-1>\n[one parent <variant-head-oid-N>\n line for each remaining distinct variant head]author Heterodyne Protocol <noreply@heterodyne.invalid> 0 +0000\ncommitter Heterodyne Protocol <noreply@heterodyne.invalid> 0 +0000\n\nheterodyne-config-retention-resolution-v1\n
```

All OIDs use the repository's declared object format and exact lowercase
length. Brackets are notation and never serialized. The resolution grammar
has one or more unique parent headers whose OIDs are sorted by decoded bytes
and equal the complete distinct variant-head set required by `H*`; tree is
first, then exactly those parents, then the fixed author and committer. It uses
the same canonical tree modes, ordering, and path rules.

This second branch is legal only when the commit is the exact config-class
`H*` named by a cold-root emergency repository-inventory resolution whose
complete maximal parent frontier, direct-parent set, `U(S)` disposition,
signed result, `K(I)`, class actions, bindings, obligations, exposure cleanup,
reset, checkpoint, and receipt predicates all verify. It is never an ordinary
config merge. Every `heterodyne-config-v1` commit retains the zero-or-one
parent grammar.

This profile is verified before candidate delivery or signed-ref publication.
It makes commit metadata and exposed tree paths machine-canonical nonsecret
structure. Arbitrary configuration values and their semantic names remain
inside candidate-key-encrypted blob bodies. Consequently an opaque cleanup
manifest's `paths` and copied commit/tree bodies disclose no user-controlled
secret-bearing metadata. A noncanonical identity, timestamp, message, header,
parent count/order/set, mode, tree order, public-path component, HMAC path
token, unbound resolution message, or plaintext logical name makes the
candidate invalid rather than something cleanup preserves under the active
key.

`B` materializes the complete decrypted predecessor logical tree byte for byte,
including non-Comms and non-credential configuration, except only the exact
paths whose prior values this transition explicitly retires or replaces.
No unrelated configuration or private payload may disappear merely because
the config key changes. Within that tree it preserves the complete predecessor
authorization set and complete append-only credential-control audit namespace:
all accepted checkpoint, receipt, removal-observation, candidate-abandonment,
staging-ref-cleanup, reset, bootstrap, source, assign, retire,
repository-retention inventory, governed-decrypt key binding,
historical-decrypt obligation, offline-recovery pre-unseal-intent,
offline-recovery activation, transition, action, and DR-termination records
required to
cold-replay the accepted
chain. For every non-ancestor staging/recovered head that this
transition terminalizes and makes eligible for later ref cleanup, `B`
materializes the complete prospective staging-cleanup audit byte set: every raw
commit and mixed/non-inherited tree object body, every non-inherited raw
encrypted blob body including an unaccepted/prospective audit namespace,
every already accepted inherited-audit namespace, and every independently safe
signed control-record copy required by the exact cleanup profile above. The
producer and each verifier derive the complete prospective
`opaque_object_manifest`, inherited-digest set, and safe-record array before
acceptance; the later cleanup record carries those arrays and digests after it
can bind the accepted checkpoint. This includes colliding or no-longer-active evidence.
In emergency mode, `B` also materializes every byte named by a non-null
`inventory_basis.same_key_candidate_audit` under its deterministic reset audit
namespace before the reset/transition are signed. This source-ref suffix is
required even though it is an ancestor of the old active tip and therefore is
not a `staging_head` or `recovered_head`. It preserves the unaccepted
checkpoint, partial records, security writes, exposure delta, and candidate
governed-binding/historical-obligation state without promoting their logical
effects.
No arbitrary or secret-bearing logical candidate blob is decrypted into this
audit set; arbitrary content remains exact candidate- or old-source-key
ciphertext. The
closed safe-record allowlist is the sole decrypted-copy exception. A recovered
record not independently authoritative under this transition may appear only
at its exact reserved audit path, never at an operational path; the exact
current-epoch adoption rule is the sole exception and is bound separately by
the adopted-assignment set. Omitting a required object, safe record, manifest
entry, or final audit path invalidates `B` before the later transition can
accept. By `B`, the candidate has materialized every independently noncyclic
pending retirement and staged successor source/assignment needed for
`result_basis.exposure_set_sha256` that does not depend on a new obligation,
plus every artifact, scan head, retention snapshot, and binding input that
must preexist the targeted inventory successor. A non-self-referential record
that already predates this candidate may be copied into `B`; an independently
authenticated input remains at its bound pre-inventory head, and any
candidate-new binding `K` follows the direct-child rule. That rule materializes
this candidate's new `K`/`R`/`O`, every `O`-dependent
source/assignment/retirement record, every transition-action record, and the
transition in dependency order; result-basis digests project their effects.
When any offline intent,
activation, or collision array is nonempty, it also preserves every signed
intent and activation named by those arrays, each immutable archive basis,
every intent preimage, every unreconciled completed source/assignment, the
exact intent-to-activation link, and each absorbing cleanup retirement for an
actual assignment. Reconciled collision variants remain audit-only and do not
repopulate intent, provisional, or retirement sets. It excludes this
candidate's new `K`/`R`/`O`, dependent proof, transition, reset, checkpoint,
and receipt records: the first group through reset lives in `T`, while
checkpoint and receipts live in `C` and its descendants. Copied predecessor
audit records remain excluded from `record_set_digest` exactly as their
original record classes were.

Continuity is authenticated by the signed transition's exact complete
`inventory_basis`, including its signed-ref-map, exposure-set,
governed-binding, historical-obligation, offline-intent, and offline-activation
digests, plus the exact `result_basis` `B` and all three projected set digests,
never by Git ancestry. A
verifier reconstructs both complete sets, the governed-ciphertext equation, and
the prior fully-receipted checkpoint chain from the named heads and rejects a
missing byte-identical record, unexplained addition, or assignment to a
removed NID.

Emergency construction restores operational logical state only from the
latest authenticated accepted lineage at `source_ref_head`, falling back to
the last-common `A` when no later accepted source state exists. A value or
deletion found only in a staging/recovered head is never promoted merely
because several non-authoritative copies agree. The ceremony may decrypt such
heads while their keys are available to compare state and extract the safe
signed control-record allowlist, but every differing arbitrary
non-credential variant is preserved only as its exact stored config-blob
ciphertext under
`credential-sync/lost-generation-data/<prior-generation>/<path-sha256>/`.
`path-sha256` is lowercase-hex SHA-256 of the strict relative nonsecret storage
path's UTF-8 bytes. For arbitrary configuration this path is the canonical
`config-data/<path-token>.bin` form above, not a decrypted user label or
original local filename; protocol-templated paths remain subject to the
public-component rule. The directory contains exactly one exact-JCS
`heterodyne.credential-ledger.lost-generation-path.v1` index containing
exactly `type`, `persona`, `prior_generation`, `path_sha256`, `logical_path`,
and `variants`. Persona/generation equal the reset and directory components;
`logical_path` carries that nonsecret storage path and the path digest is
recomputed from it. A secret-bearing semantic name remains only inside the
candidate-key ciphertext.

Each variant contains exactly `origin_heads`, `state`, `storage_object_id`,
`content_sha256`, and `content_path`. There is one variant per distinct
`(state,storage_object_id,content_sha256)` value, with the complete origin-head
set unioned into it; `state` is `deleted` or `present`. A deleted variant has
all three storage/content members null. A present variant has the exact typed
Git blob object ID, a 64-lowercase-hex digest of the raw stored ciphertext
body, and `content_path`
exactly
`credential-sync/lost-generation-data/<prior-generation>/<path-sha256>/<object-format>-<object-id>.bin`;
that safe typed-object path contains the exact candidate-key-encrypted blob bytes
whose SHA-256 equals `content_sha256`. It never contains decrypted logical bytes
or a bare plaintext hash. Variants sort first by state rank (`deleted` before
`present`), then by the ordinary typed-object comparator, then by decoded
content digest bytes, treating deleted nulls as empty byte strings. The
typed-object comparator is the checkpoint typed-head comparator applied to the
blob's `{object_format,oid}` pair.
`origin_heads` is nonempty, sorted by the ordinary typed-head comparator, and
duplicate-free. Duplicate variant keys, a raw file not named by exactly one
present variant, an object-ID/body mismatch, or two byte strings for one
digest rejects.

`index-digest` is lowercase-hex SHA-256 of the exact JCS index and equals the
`.json` filename. The directory, index, and opaque variants are the only
allowed members at that path. Index and opaque variant bytes are bound by parentless `B`,
the signed transition result, reset, and accepted checkpoint. They never enter
`record_set_digest` or grant authority. A later explicit user resolution writes
an ordinary post-reset config change only if the user supplies the retired
audience key or completes resolution before its authenticated erasure; the
protocol does not retain such a key merely to make opaque audit ciphertext
recoverable. No coordinator silently chooses among conflicting preferences,
publishes candidate plaintext to future roster members, or discards the
authenticated ciphertext evidence.

A direct child `T` contains any new binding `K`, targeted inventory successor
`R`, transition-bound obligation `O`, `O`-dependent
source/assignment/retirement records, every transition-action record, the
signed transition, and, in emergency mode, the signed reset. Producers
finalize and sign those records in their logical dependency order before
constructing `T`; canonical
Git tree-entry order does not alter that order, and no record names `T`'s
commit OID. A direct child `C` of `T` contains the candidate checkpoint and
the applicable bootstrap-recipient array; the checkpoint names `T` as its
`config_head`. Receipt commits descend from `C`. These objects may be
exchanged privately but confer no operational authority. Before any
pre-receipt config-key delivery, a signed-ref update MUST create
`refs/heads/enc/<new-config-key-id>` at `C` with an atomic absent-to-`C`
compare-and-swap while retaining the old active ref. A non-absent result is an
ID collision: no existing ref is advanced or overwritten, the candidate is
abandoned, and a fresh ID and rebuilt transition are required.
For a same-key successor, the initial candidate publication instead advances
the exact active ref from its accepted basis to `C`; the accepted checkpoint
does not change until the complete-acceptance rule below succeeds.
In a routine transition, every currently accepted roster node MUST fetch and
verify that exact signed `C`, the transition's complete pre-candidate signed-ref
map, and the bootstrap array before an added NID receives the config key.
Every retained old-roster node then decrypts the candidate branch, installs
the candidate key in protected storage, and issues its ordinary checkpoint
receipt before delivery of any other successor secret. Removed nodes attest
only observation of the encrypted signed ref and never receive the new key.
The candidate ref and bootstrap ciphertexts are append-only replicated state,
not producer-local scratch.

Except for genesis's create-only complete-head path below, every valid
checkpoint receipt or removal observation becomes durable only through an
append to that signed candidate ref. The append is a signed
compare-and-swap from the exact current candidate tip to one direct child whose
tree preserves every prior byte and adds a nonempty set of previously absent,
byte-identical signed records at their canonical paths; deletion, replacement,
an unrelated path change, or a merge rejects. For a config-key candidate the
same atomic operation also requires the old active ref still equal the
transition's `inventory_basis.source_ref_head`. For a same-key candidate it
compares and advances the one active/candidate ref and requires no canonical
abandonment reachable from the compared tip.

Before append, every receipt must validate for the exact candidate checkpoint
and a target-roster NID. Multiple distinct valid receipts from one target NID
are retained as audit evidence and collapse to one acknowledgement for
completeness. Every observation must validate for the exact routine-removal
transition/checkpoint and one `removed_nids` member; exactly one observation
per removed NID is permitted. An outsider, wrong checkpoint/transition,
duplicate observation, invalid signature/delegation, path mismatch, or any
other record rejects the entire append. Concurrent appenders are linearly
ordered: a losing record is retried byte-identically in a new direct child of
the then-current canonical tip. A record left on an orphan or side branch does
not count. After every successful append, replay recomputes the exact
partial-acceptance record-set digest defined by the abandonment profile and
recomputes the candidate's exact governed-binding and historical-obligation
digests and `G(C) = O(C)` equation, including every governed-decrypt key
binding, at the unchanged candidate `config_head`. No append is
permitted after canonical abandonment or complete acceptance. The
append also replays the universal acceptance interval and rejects if a
security-critical mutation has already invalidated the candidate; for a
config-key candidate the exact old-ref comparison detects that mutation, and
for a same-key candidate replay of the compared tip detects it.

In emergency mode the cold-root ceremony persists the signed reset,
transition, exact `C`, bootstrap array, and a cold-root- or active
recovery-slot-encrypted copy of the candidate config key in at least one
independent portable-recovery location before distributing any other
successor secret. Every new-roster node installs the candidate key in
protected storage before issuing its checkpoint receipt. In every mode a
node erases the one-use X25519 private key only after the candidate config key
and exact signed staging head are durably retained. It keeps that protected
candidate key/head until the transition accepts or, for an inert candidate
whose assignments were later retired or narrowly adopted as the current epoch,
the authenticated staging-ref cleanup CAS above succeeds. Losing the only
decryptable copy sooner is a fail-closed recovery error.

That exact candidate lineage appears in every later `staging_heads` set until
the candidate accepts or its exact authenticated staging-ref cleanup succeeds;
accepted retirement alone does not remove it. A failed candidate remains an
inert, signed staging ref;
its key is burned for operational reuse but retained under protection for
audit/recovery, and its ref cannot be deleted merely because the candidate
failed or its assignments retired. Only the cleanup profile above may delete
it after complete retirement/adoption partitioning and opaque audit copying. An unavailable or
undecryptable staging head makes later
removal/reset fail closed rather than dropping a possible exposure.

The complete acceptance head is the current append-only candidate tip or one
direct child of it produced under the same append rules. It descends from `C`,
reaches the candidate checkpoint, and has a nonempty valid receipt set for
every target-roster NID. Distinct valid duplicate receipts remain reachable
but count once per NID. For routine removal it also reaches exactly one valid
removal observation from every `removed_nids` member and no observation from
any other NID. No invalid or otherwise extraneous acceptance record may be
reachable. Candidate
acceptance and later cold replay MUST derive their complete receipt and
observation sets only from records reachable from that head; an orphan,
side-branch, missing acknowledgement/observation, extra observation, or
out-of-scope acceptance record rejects.

Acceptance is the first verified signed-ref compare-and-swap that atomically
requires the candidate ref to equal the exact current partial tip,
requires the complete set of noncandidate encrypted refs and heads to still
hash to `inventory_basis.signed_ref_map_sha256`,
requires the predecessor and projected
`governed_decrypt_key_bindings_sha256` and
`historical_decrypt_obligations_sha256` values to recompute exactly from the
compared source/result heads,
requires `refs/heads/enc/<old-config-key-id>` still equal the transition's
exact `source_ref_head`, advances
`refs/heads/enc/<new-config-key-id>` from that compared partial tip to the
complete acceptance head when a final direct-child append is needed (or leaves
it at that same already-complete tip), activates the successor inventory that
deregisters exactly the ordinary old config row or the emergency transition's
complete `V_old` under the rules above, and deletes the old ref. The only
permitted map changes are that exact candidate-ref advance
and old-ref deletion in the same atomic update. Any new or changed competing
staging ref or old-ref advance, including a revocation, source/assignment,
governed-key-binding, obligation, provenance, or governed ciphertext write,
invalidates the candidate;
the producer must select the newer source ref, rebuild `B`, and recollect
receipts. Failure leaves the old ref/checkpoint authoritative and the new ref
durably inert. Because the new ref has no old-generation ancestor and carries
the complete logical audit copy, deleting the old ref makes old ciphertext
unreachable from the new generation without losing validation evidence,
subject to the existing cooperative-erasure limitation.

For a same-key successor, the signed-ref CAS that appends the final missing
acceptance record requires the one active/candidate ref to equal the exact
partial tip and advances it to the direct-child complete head. That successful
CAS is acceptance; an already-complete current tip was therefore accepted by
the append that produced it and needs no no-op transition. It deletes no ref
and permits no unrelated tree or signed-ref-map change. A reachable
abandonment and acceptance cannot both win because both compare the same
partial tip.

Genesis uses the same receipt boundary without `A`, transition, or reset. Its
initial `enc/<config-key-id>` branch starts at a parentless root `G` containing
the complete initial logical config tree, initial
authorization/source/exposure records, and the initial OIDC pairwise secret
with its canonical source/assignment records. It also contains the complete
initial historical-obligation lineages and governed ciphertext state, normally
both empty for a new persona but mandatory for a pre-0.5 migration that keeps
retired ciphertext. The genesis checkpoint binds the independently recomputed
governed-binding and obligation digests. The genesis bootstrap opens the
branch containing that pairwise secret; it does not place the secret in the
clear header or outside config encryption. Child `C` contains the
checkpoint and genesis bootstrap array and names `G` as `config_head`;
receipts descend from `C`. The first signed-ref publication occurs only at
the complete receipt-bearing head; before that first publication, receipt
commits are exchanged as a privately authenticated linear candidate chain and
the one create-only signed-ref CAS requires the chosen complete head. Genesis
therefore has no signed partial-tip abandonment state.

At first candidate acceptance, replay from `B` through exact transition
carrier `T` MUST find exactly the finalized `K`/`R`/`O`, dependent
source/assignment/retirement proofs, action records, reset where applicable,
and transition bytes named by the projected target/result digests: a missing,
extra, or substituted member rejects. Replay strictly after the checkpoint's
exact `config_head = T` through the canonical receipt-bearing head MUST find
no later assignment or capability source for a removed NID, no later
key-binding/obligation/provenance/governed-ciphertext mutation, and no later
mutation or competing variant of an action/proof named by the transition. Any
such record invalidates the candidate and restarts closure from a newer
source-ref/inventory basis and closure-basis commit. Pending retirement records
from the invalidated transition remain non-effective, so they cannot launder
an exposure out of the next inventory.

The transition record and every proof it names MUST be reachable from the
checkpoint's exact `config_head`; its source/exposure records MUST be durable
under the named canonical Comms heads, and every retain/close record and
governed locator/key binding needed by its obligation projection MUST be
reachable and valid. The checkpoint's `secret_transition_digest` MUST equal the complete
record digest. The transition stays pending and credential,
publishing, recovery, and new encryption authority remain held until every
exposure has a valid outcome and the checkpoint atomically activates the
pending retirements and current-successor/historical-decrypt assignments.

Cross-record equality applies to every routine mode, not only removal.
`prior_checkpoint` is the exact complete-record digest of the currently
accepted, fully receipted predecessor. The target generation equals the
predecessor generation; target sequence equals predecessor sequence plus one;
and target roster, config-key ID/commitment, pairwise-secret commitment,
exposure-set digest, governed-decrypt-key-binding-set digest,
historical-decrypt-obligation-set digest, epoch public key, and KEL head
exactly equal the corresponding successor-checkpoint members.
`target.reset_id` is null in every
routine mode and is not a checkpoint member. A non-null
`target.epoch_rotation_event_id` equals the canonical rotation event ID and
the successor checkpoint's `kel_head.event_id`; a null value means no epoch
rotation action. The checkpoint carries the resulting epoch key/head, not a
separate rotation-event member. Target and `result_basis` exposure,
governed-binding, and historical-obligation digests are respectively
identical. The transition path's
generation and sequence components equal those target/checkpoint values, and
its digest component equals lowercase-hex SHA-256 of the complete signed
transition. The successor's `secret_transition_digest` is that digest and its
`config_head` is exact transition commit `T`, the direct child of `B`.
Its `config_bootstrap_recipients_digest` equals the exact routine bootstrap
array digest. Every entry's NID proof, HPKE plaintext, and context bind the
target/checkpoint generation, sequence, key ID, and key commitment; their
`config_head` equals the successor checkpoint's exact `config_head`, transition
commit `T`. The array's one-entry-per-NID set equals the complete target
roster. Any mismatch rejects before a receipt is counted.

Routine key rotation starts from a fully receipted checkpoint, preserves the
roster and authorization set byte-identically, increments sequence by one, and
uses `mode:"routine-key-rotation"`. Its mandatory exposure/outcome is rotation
of the current config-audience capability to the fresh key committed by the
target; it additionally closes every tuple in the complete cleanup set and any
explicitly proven maintenance set above. The pairwise-secret commitment remains
unchanged exactly when that complete set has no `oauth-pairwise` action;
otherwise the action's fresh successor commitment, transition target, and
successor checkpoint are identical and clients perform the ordinary pairwise
reissuance warning. The epoch key/KEL head remain unchanged and the target's
rotation-event member is null exactly when the complete set has no `epoch`
action; otherwise the
cold-root-authorized action, canonical KEL rotation, target
`epoch_rotation_event_id/epoch_pubkey/kel_head`, and successor checkpoint's
derived `kel_head.event_id` plus epoch key/head all match under the general
rule above. Thus cleanup or maintenance is never made impossible by the
mode-specific defaults. Its mandatory config-row inventory successor follows
the general non-null inventory-only rule: target, result, and checkpoint bind
`governed_decrypt_key_bindings_sha256` newly recomputed from successor `K(C)`.
`governed_heads` and `binding_records` remain byte-identical unless an exact
transition-bound binding/snapshot action changes governed ciphertext, and
`historical_decrypt_obligations_sha256` remains byte-identical unless an exact
obligation action changes the complete frontier.

Routine addition also starts from a fully receipted checkpoint, increments
sequence by one, preserves the authorization set, uses
`mode:"routine-addition"`, and rotates both the config key and OIDC
pairwise-sub secret before any added NID receives the candidate config key.
Its exposures/outcomes therefore include both the `config-audience` and
`oauth-pairwise` successors; `B` contains only the fresh inactive pairwise
secret and canonical source/assignment records, and the target/checkpoint
commit its digest. Clients warn that existing pairwise subjects change and
require relying-party reissuance. `added_nids` is exactly successor roster
minus predecessor roster; `removed_nids` is empty. This mode also closes every
tuple in the complete cleanup set, including a secret delivered by a prior
failed addition to a proposed NID that never joined the roster. The config-bootstrap
recipient array covers the complete successor roster because every member
receives the new key, and the staged source/assign set includes one assignment
for each successor-roster holder. The successor is authoritative only after
all old and added roster members receipt the candidate. A failed addition
therefore exposes neither the active old config key nor the active old
pairwise secret to the proposed node. Its mandatory config-row inventory
successor follows the general non-null inventory-only rule: target, result,
and checkpoint bind `governed_decrypt_key_bindings_sha256` newly recomputed
from successor `K(C)`. `governed_heads` and `binding_records` remain
byte-identical unless exact binding/snapshot records change governed
ciphertext, and `historical_decrypt_obligations_sha256` remains byte-identical
unless exact obligation actions change the complete frontier.
Offline-recovery cleanup that reencrypts a governed ciphertext necessarily
carries those records and binds the recomputed `K(C)` and complete frontier
digests.

An added NID either has no active credential-sync grant at the predecessor
basis or is an already-authorized durable holder whose complete prior secret
exposures are present in `inventory_basis`. In the first case it receives no
credential-sync grant or protected keys-repository transfer while the roster
candidate is pending: the config bootstrap is its sole secret-bearing
admission path. After roster acceptance, a separate authorization-record
mutation and ordinary fully receipted checkpoint may grant credential sync;
only then may protected key transfer begin. In the second case promotion
causes no new transfer, and all material it already held remains in the
conservative inventory. This rule does not imply that every ordinary
credential-sync device must be a full-node roster member.

Normal node removal starts from a fully receipted checkpoint. Every configured
node therefore proves the same generation, sequence, record-set digest, and
config head before the epoch-signed reduced-roster checkpoint is proposed.
That successor increments sequence by one and carries the byte-identical
authorization record set; roster change and authorization-record mutation do
not share one checkpoint transition.
Its transition uses `mode:"routine-removal"`,
`prior_checkpoint` equal to that accepted predecessor's digest,
`removed_nids` exactly equal to predecessor roster minus successor roster,
and `inventory_basis.config_head` equal to source-basis commit `A` above.
Its `target` generation, sequence, roster, config key ID/commitment,
pairwise-secret commitment, exposure-set digest, governed-binding digest,
historical-decrypt-obligation digest, epoch key, and KEL head exactly equal
the successor checkpoint; the three set digests also equal their respective
`result_basis` fields. Its reset ID is null and its epoch-rotation event field
follows the conditional rule above. The mandatory config-row inventory
successor follows the general non-null inventory-only rule: the governed-
binding digest is newly recomputed from successor `K(C)`. `governed_heads`
and `binding_records` are byte-identical to the predecessor unless exact
binding/snapshot records change governed ciphertext, and the obligation digest
is byte-identical unless exact obligation actions change the complete
frontier; the closure basis independently satisfies the resulting
`G(B) = O(B)`.
The transition path's generation and sequence components equal the successor
checkpoint's generation and sequence, and its digest component equals the
complete transition digest. The successor's `secret_transition_digest` names
that same digest and its `config_head` is direct child `T` of `B`.
The reduced roster becomes authoritative only when that successor is
canonical and fully receipted by every node in its new roster; until then the
old roster remains the convergence roster but credential-plane transfer and
minting are held. Acceptance-time replay MUST prove that no credential-sync
authorization record changed after the candidate's `config_head`; a grant or
revoke committed while receipts accumulate invalidates the candidate and
requires a new checkpoint from the newer head. Revocation and other
security-critical writes are never blocked merely to preserve a candidate.

Every roster removal also completes the closed secret transition above. At a
minimum that revokes the removed node's Core NID delegation and hosted
delegated keys, removes its per-repository Radicle authority, rotates the
config audience key, OIDC pairwise-sub secret, private-claim-ledger audience
epoch, every affected Tier 3 audience epoch and object/recovery wrapper,
terminates affected DR sessions, and retires or rotates affected transport and
serving credentials. The new config branch carries the complete predecessor
authorization set and wraps the new config key only to the reduced roster.
The checkpoint binds the fresh config/pairwise commitments and the complete
transition digest; clients warn that pairwise subjects change and require
relying-party reissuance. If the removed node held epoch authority, its
recovery role is revoked and the Core epoch key rotates before the new
checkpoint; possible cold-root exposure instead invokes persona migration.
The ordinary predecessor-digest continuity rule applies because every
old-roster node is available for this path.

Permanent node loss or an active offline intent- or activation-ID collision uses
`heterodyne.credential-ledger.emergency-reset.v1`, containing exactly:

```text
type, reset_id, persona, prior_generation, new_generation,
last_common_checkpoint, old_roster, new_roster, unavailable_nodes,
prior_config_key_id, new_config_key_id, new_config_key_sha256,
prior_pairwise_secret_sha256, new_pairwise_secret_sha256,
lost_audit_set_digest, same_key_candidate_audit,
offline_recovery_pre_unseal_intents,
offline_recovery_pre_unseal_intent_collisions,
offline_recovery_activations, offline_recovery_activation_collisions,
exposure_set_sha256,
governed_decrypt_key_bindings_sha256,
historical_decrypt_obligations_sha256, secret_transition_digest,
epoch_rotation_event_id, new_epoch_pubkey, new_kel_head, compromise_since,
bootstrap_recipients_digest, created_at, reason, cold_root_signature
```

The reset is stored at the path above and signed with BIP-340 over SHA-256 of
`UTF8("heterodyne-credential-ledger-emergency-reset-v1")`, a zero byte, and
the JCS object without `cold_root_signature`; the signature is exactly
64 bytes encoded as 128 lowercase hex. `reason` is exactly
`credential_ledger_reset_node_loss` or
`credential_ledger_reset_offline_activation_id_collision`.
`new_generation` must equal `prior_generation + 1`; the old roster must equal
the fully receipted checkpoint's roster; and the new roster is nonempty,
sorted, and unique.

The reason-specific predicates are mutually exclusive:

- `credential_ledger_reset_node_loss` requires `unavailable_nodes` to be a
  nonempty exact subset of `old_roster`, removes exactly those NIDs from the new
  roster, retains every other old-roster NID, and may add newly commissioned
  replacements.
- `credential_ledger_reset_offline_activation_id_collision` requires
  `unavailable_nodes == []`, at least one nonempty exact
  `offline_recovery_pre_unseal_intent_collisions` or
  `offline_recovery_activation_collisions` projection, and
  `old_roster` to be a subset of `new_roster`. It may preserve the roster
  exactly or add explicitly authorized NIDs, but collision ordering never
  selects one. Every addition still needs the ordinary current or co-committed
  cold-root delegation, reset-recipient proof, bootstrap, and receipt.

If any old-roster node is unavailable, the node-loss reason is mandatory even
when collision evidence is also present. A collision-only reset with a removed
old-roster NID, or a node-loss reset with an empty unavailable set, rejects.

For a collision-only reset, define `CurrentEpochCollisionExposures` as the
union of:

- unreconciled intent variants named by
  `offline_recovery_pre_unseal_intent_collisions` whose exact source and
  assignment preimages plan release of the predecessor-current epoch tuple
  committed by `last_common_checkpoint`; and
- unreconciled activation variants named by
  `offline_recovery_activation_collisions` whose embedded provisional source
  and assignment set resolves to that same epoch public key, KEL event ID, and
  KEL sequence.

Each intent's signed `created_at` precedes authority release. Every activation
must resolve its linked intent and uses that earlier intent time; activation
time is never a substitute. When the set is nonempty:

```text
collision_epoch_exposure_cutoff =
  min(E.created_at for E in CurrentEpochCollisionExposures)
```

The reset's `compromise_since` MUST be no later than both that cutoff and the
operator's first collision-detection boundary. When the set is empty, it must
still be no later than the detection boundary. A reconciled historical variant
does not move this new cutoff backwards: its prior accepted reconciliation
already rotated or retired its exposure, and it remains collision evidence
only. A variant that claims the current tuple without the exact preimage or
completed source, assignment, checkpoint, and KEL bindings does not enter the
set; it instead invalidates the evidence.
`last_common_checkpoint` is the digest of an already committed, fully
receipted checkpoint, not a digest supplied for the first time by the reset.
This is the independently authenticated evidence that makes fabrication
detectable.

Emergency reset treats every unavailable full node and every unreconciled
intent- or activation-collision claimant as potentially hostile.
Before the reset transition can be accepted, cold-root recovery MUST:

1. derive and complete the closed secret-exposure transition for every
   unavailable node and every unreconciled collision intent or activation,
   including
   revocation/rotation of all affected hosted signing keys, audience keys, DR
   sessions, repository and bearer credentials, object and recovery wrappers,
   and endpoint identity keys;
2. commit a cold-root-authorized Core epoch rotation to a fresh key with the
   reset's `compromise_since`, no later than the operator's loss-detection
   boundary for node loss or the collision bounds above for a collision-only
   reset, and make that KEL head canonical;
3. generate a fresh random 32-byte config audience key and distinct random
   16-byte config key ID, distribute the key only to `new_roster` through the
   reset-bound bootstrap profile below, and
   generate a fresh 32-byte OIDC pairwise-sub secret inside the new branch,
   then remove every actually unavailable NID from Radicle read/write
   authorization; and
4. create the new `enc/<new_config_key_id>` branch, retire the prior encrypted
   branch in one signed-ref transition, and preserve the old branch only as
   cooperatively scrubbed ciphertext that former key holders may retain,
   while materializing the exact non-authoritative same-key candidate audit
   suffix required by `inventory_basis.same_key_candidate_audit`.

`prior_config_key_id` equals the last-common checkpoint value.
`new_config_key_id` differs, and `new_config_key_sha256` commits the new key.
`secret_transition_digest` names the canonical emergency-mode transition
whose `prior_checkpoint`, removed-NID set, and inventory basis match this
reset. The reset's `same_key_candidate_audit` JCS-equals the transition
inventory member; null is valid only when no unaccepted same-key candidate is
reachable from the exact source-ref tip. Its
`offline_recovery_pre_unseal_intents` JCS-equals the complete transition
intent inventory member and contains exactly the unreconciled projection. Its
`offline_recovery_pre_unseal_intent_collisions` JCS-equals the complete active
intent-collision projection and may include reconciled evidence-only variants.
Its
`offline_recovery_activations` JCS-equals the complete transition inventory
member and contains exactly the unreconciled projection, not reconciled
same-ID history. Its `offline_recovery_activation_collisions` JCS-equals the
transition's complete active-collision projection and binds every observed
same-ID digest, including any already-reconciled evidence-only variant. Its
`target` reset ID, generation-zero sequence, new roster, config key
ID/commitment, pairwise-secret commitment, exposure digest,
governed-binding digest, historical-decrypt-obligation digest, and epoch
key/KEL head exactly equal this reset; every corresponding candidate-checkpoint
member also equals them. The target's epoch rotation event equals the reset
member and the checkpoint KEL head's event ID. The checkpoint binds the reset
ID indirectly and unambiguously through
`generation_transition == reset_digest`; it has no `reset_id` or separate
rotation-event member. Its
`removed_nids` is exactly `old_roster - new_roster`, which equals
`unavailable_nodes`, and `added_nids` is exactly
`new_roster - old_roster`. Thus both removal arrays are nonempty for node loss
and both are empty for a collision-only reset. The transition is stored at
`credential-sync/secret-transitions/<new_generation>/0-<digest>.json`, and
the digest component equals its complete-record digest. Any possible
cold-root exposure halts this reset in favor of persona
migration before a new generation can be accepted.
The prior pairwise commitment equals the last-common checkpoint,
`new_pairwise_secret_sha256` differs and commits the fresh secret, and the
sequence-zero checkpoint binds that new value. Existing pairwise `sub` values
therefore change after reset; clients warn relying parties and reissue
credentials rather than allowing a former node to correlate future subjects.
`epoch_rotation_event_id` equals the new canonical KEL event ID;
`new_epoch_pubkey` and `new_kel_head` exactly equal that event's accepted
post-rotation key and closed event-ID/sequence head, the transition target, and
the sequence-zero checkpoint's epoch key/KEL head.
`compromise_since` remains mandatory for both reset reasons. It is a JSON-safe
nonnegative integer no later than that rotation's `created_at` and MUST equal
the rotation event's sole canonical
`["compromise_since","<decimal>"]` tag value; absence, duplication, or mismatch
rejects the reset. It additionally satisfies the exact
`CurrentEpochOfflineEvidence` and `CurrentEpochCollisionExposures` cutoffs
above. A collision-only reset does not downgrade this compromise-declaring
epoch rotation merely because the prior roster remains healthy. The new epoch
and config keys are never wrapped to an unavailable or target-excluded
collision NID. Receipt of the
sequence-zero checkpoint proves each new-roster node decrypted the new branch
and verified the key commitment. Any missing revoke, old access-list member,
old-key wrap, noncanonical rotation, or partial signed-ref transition keeps
the reset pending and all credential authority held.

`reset_id` is 16 random bytes encoded as 32 lowercase hexadecimal characters.
Reset bootstrap does not call the held ordinary credential-sync hook. Before
the reset is signed, every new-roster node supplies one fresh X25519 recovery
key and an Ed25519 NID proof over:

```text
SHA256(
  UTF8("heterodyne-credential-reset-recipient-v1") || 0x00 ||
  JCS({persona,reset_id,new_generation,nid,recovery_key})
)
```

The reset ceremony verifies a current or co-committed cold-root-authorized NID
delegation for each recipient. It creates a sorted array with exactly one
closed entry per `new_roster` NID:

```text
nid, delegation_event_id, recovery_key, nid_proof, enc, ciphertext
```

`recovery_key` is
`{"algorithm":"X25519","public_key":"<unpadded base64url 32-byte key>"}`;
`delegation_event_id` is exactly the 64-lowercase-hex NIP-01 event ID of that
current or co-committed delegation. Entries are strictly increasing by the
UTF-8 bytes of `nid`; duplicates reject. `nid_proof` is 64-byte Ed25519
encoded as unpadded base64url. `enc` and `ciphertext` are unpadded base64url;
`enc` decodes to exactly 32 bytes. They carry RFC 9180 HPKE base-mode
DHKEM(X25519,HKDF-SHA256)/HKDF-SHA256/AES-256-GCM values. The plaintext is the
closed object
`{type:"heterodyne-credential-reset-config-key-v1",persona,reset_id,
new_generation,new_config_key_id,new_config_key_sha256,config_audience_key}`
where the key is unpadded base64url of exactly 32 bytes.
`plaintext_bytes = UTF8(JCS(plaintext_object))`; decryption rejects any byte
sequence that is not that exact JCS encoding. The recipient
fingerprint is lowercase-hex SHA-256 of the decoded 32-byte X25519 public key.
HPKE `info` and AAD are identically `UTF8(JCS(context))`, where `context` is
exactly (the generation placeholder is replaced by the actual JSON integer,
not a string):

```text
{
  "type": "heterodyne-credential-reset-config-key-context-v1",
  "persona": "<64 lowercase hex>",
  "reset_id": "<32 lowercase hex>",
  "new_generation": <reset.new_generation as a JSON-safe integer>,
  "new_config_key_id": "<32 lowercase hex>",
  "new_config_key_sha256": "<64 lowercase hex>",
  "recipient_nid": "<canonical Ed25519 did:key>",
  "recipient_fingerprint": "<64 lowercase hex>"
}
```

`bootstrap_recipients_digest` is lowercase-hex SHA-256 of the JCS bytes of the
complete sorted recipient array. The exact array is stored at
`credential-sync/reset-recipients/<new-generation>-<digest>.json`; its path
generation equals the reset generation, its path digest equals
`bootstrap_recipients_digest`, and it is reachable with the reset and
candidate checkpoint at acceptance. The cold-root reset signature commits
that digest. The signed reset and recipient array may travel over an existing
authenticated DR session, local IPC, or offline recovery media even while
credential sync is held; this exceptional profile authorizes only possession
of the named config key for this reset. A recipient verifies the cold-root
reset, its NID proof/delegation, recipient-array digest, HPKE context, key
commitment, new KEL head, and its exact roster membership before decrypting the
new branch. The fresh recovery private key is erased after successful
checkpoint receipt.
Every current or co-committed delegation named by a recipient MUST be
canonical, active, durable, and unrevoked before the reset can be atomically
accepted; candidate event bytes or a fork-only delegation are insufficient.

The Comms encrypted-config key-distribution rule is amended narrowly:
credential sync, the Core keys repository, and portable backup remain the
ordinary exclusive paths, while the cold-root-signed
`heterodyne-credential-reset-config-key-v1` HPKE bootstrap above is the sole
emergency exception. It distributes only the named reset generation's config
audience key to the exact new roster and does not authorize a general
alternate config-key distribution channel.
The config repository's prohibition on audience-key material gains only these
two closed ciphertext exceptions: the ordinary/genesis config bootstrap array
and the emergency reset recipient array. Each contains only recipient-bound
HPKE ciphertext for its exact candidate key; neither may contain plaintext
key bytes outside the encrypted HPKE plaintext, be reused for another
candidate, or serve as a general wrapping namespace.

The new branch carries the last-common authorization record set byte for byte.
Every additional individually valid prior-generation authorization record
recovered from available nodes is retained only under
`credential-sync/lost-generation-audit/<prior-generation>/<record-digest>.json`;
it cannot enter the operational record set. `lost_audit_set_digest` applies
the same sorted complete-signed-record digest algorithm to that audit-only set,
including the `[]` empty-set rule. This preserves all observed evidence
without allowing a post-checkpoint grant to survive reset.

Cross-record equality is exact. The reset persona, last-common checkpoint
persona, and sequence-zero checkpoint persona are identical.
`last_common_checkpoint` names the currently accepted checkpoint;
`prior_generation` equals both that checkpoint's generation and
`current_generation`; `new_generation == prior_generation + 1`; the reset file
path's `<new-generation>` component equals `new_generation`; the sequence-zero
checkpoint generation equals `new_generation`; its sequence is zero; its
`node_roster` JCS-equals `new_roster`; its `generation_transition` equals this
complete signed `reset_digest`; its record-set digest equals the last-common
value; its config key ID
and commitment and pairwise-secret commitment equal the reset's new values;
its `exposure_set_sha256` equals both the transition target and
`result_basis.exposure_set_sha256`;
its `governed_decrypt_key_bindings_sha256` equals the reset, transition
target, `result_basis`, and independently recomputed checkpoint `K(C)`
digest;
its `historical_decrypt_obligations_sha256` equals the reset, transition
target, `result_basis`, and independently recomputed checkpoint frontier
digest;
its `secret_transition_digest` equals the reset's canonical
`secret_transition_digest`;
and its epoch key/KEL head equal the canonical cold-root recovery rotation named by
`epoch_rotation_event_id`. Any mismatch rejects the entire candidate before
receipt evaluation.

The transition target is an exact restatement of the reset candidate:
`reset_id`, `new_generation`, sequence zero, `new_roster`,
`new_config_key_id`, `new_config_key_sha256`,
`new_pairwise_secret_sha256`, the projected `exposure_set_sha256`, the
projected `governed_decrypt_key_bindings_sha256`, the
projected `historical_decrypt_obligations_sha256`, the new epoch public key
and KEL head (`new_epoch_pubkey/new_kel_head`), and
`epoch_rotation_event_id` all equal the corresponding reset values. The
checkpoint carries the corresponding generation, roster, key commitments,
exposure, governed-binding, and obligation digests, and epoch key/KEL head;
its KEL event ID equals the target
rotation event, while its `generation_transition` binds the reset digest. The transition's
`inventory_basis.config_head` equals the last-common checkpoint's
`config_head`; its exposure digest is recomputed from the exact deduplicated
union of `config_head`, `source_ref_head`, every `staging_head`, and every
`recovered_head` as defined above. The resulting set contains every assignment
represented by the last-common checkpoint and may be a strict conservative
superset. Its predecessor obligation digest is recomputed from the complete
maximal frontier across those same authenticated heads, the same-key
candidate audit, and every offline archive basis; its projected digest
preserves every branch and applies only the transition's exact retain/close
records. Its predecessor governed-binding digest is independently recomputed
as complete `K(I)` from those same bases and its projected digest applies the
targeted inventory successor plus the transition's exact
retention-snapshot/binding changes. The target and `result_basis` set digests
are respectively identical.

`reset_digest` is lowercase-hex SHA-256 over the JCS bytes of the complete
signed reset. Closure-basis commit `B` on the new encrypted branch contains
the byte-identical last-common operational record set, config-key transition
metadata, predecessor action/source records, independently noncyclic pending
retirements, and staged current-successor and historical-decrypt-only
assignments that do not depend on a new obligation and whose projected set
contributes to `result_basis.exposure_set_sha256`. It also copies every
non-self-referential governed artifact/provenance and retention-snapshot input
and every predecessor key-binding input that must preexist the targeted
inventory successor; an independently authenticated input remains at its
bound pre-inventory head, and any candidate-new binding `K` follows the
direct-child rule.
The complete prior accepted audit namespace and lost-generation audit-only set
remain in `B`. It contains no current candidate `K`, `R`, `O`, dependent proof,
reset, transition, checkpoint, receipt, or authority payload; prior accepted
record classes remain present byte-identically. Its direct child `T` contains
the new `K`, targeted `R`, transition-bound `O`, every `O`-dependent
source/assignment/retirement record, every transition-action record, the
signed reset, and the signed secret transition at their exact paths and in
their logical dependency and signing order. A direct child candidate commit
contains the new-generation sequence-zero checkpoint.
That checkpoint has
`previous_checkpoint:null`, `generation_transition:reset_digest`, the exact
last-common checkpoint `record_set_digest`, the same signed authorization
record bytes, the new roster, and `config_head` equal to the exact inert
transition commit `T`; the transition's `inventory_basis.config_head` equals
source-basis commit `A`, the last-common checkpoint's exact `config_head`, and its
`result_basis.config_head` equals closure-basis commit `B`. New-roster receipt
commits may follow. The accepted
generation changes atomically only at the first canonical head from which the
reset, sequence-zero checkpoint, and valid receipts from every new-roster node
are all reachable. Until then the transition is pending and credential-plane
authority is held; no intermediate state exposes new-generation authority.

The accepted transition:

- starts the new generation at sequence zero with the byte-identical retained
  record set from that checkpoint;
- invalidates every prior-generation credential-sync authorization, built-in
  issuer-authority record, authorization key claim, claim-ledger authority
  record, workload authorization, pending Authorization Code/PKCE or Device
  Authorization transaction, ID/access/assertion token, Status List Token, and
  derived mint authority under Heterodyne validation;
- requires each affected signed record or token to carry
  `credential_ledger_generation`, and requires a verifier to resolve the
  current reset chain and demand exact equality for operational authority;
- rotates built-in issuer signing authority and publishes status/revocation
  state so ordinary OIDC consumers can observe invalidation; an offline
  third-party verifier remains bounded by the JWT's expiry and its own status
  policy;
- requires affected keys and credentials to be reissued;
- preserves a permanent warning that records may have been lost; and
- never occurs automatically because of timeout or quorum shrink.

The reset cannot assert that an unavailable node held no unseen records. A
consumer rejects a reset without the cold-root signature, a missing fully
receipted checkpoint, a non-incrementing generation, a roster/subset mismatch,
or any affected artifact whose generation is absent or stale.

Generation fields are located and interpreted exactly as follows:

- credential-sync grant/revoke records add top-level
  `credential_ledger_generation` immediately after `persona`; it is part of
  the displayed canonical member order and existing signature transcript;
- every `key-claim-v1` content object adds required members at JSON Pointers
  `/credential_ledger_persona` and `/credential_ledger_generation`. For
  `claim_class:"authorization"`, the persona is the 64-lowercase-hex cold-root
  public key of the affected ledger and the generation is a JSON-safe
  nonnegative integer; for a descriptive claim both members are JSON null.
  JCS, rather than insertion order, determines their serialized position.
  Both members participate in `claim_id`, native proof, event-content, and
  signature inputs. The Core/KEL authority result for the authorization
  claim's typed issuer MUST resolve to that exact persona at `issued_at`, and
  every authorization ancestor must carry the same persona and generation;
  an external JWK or NID with no such authority path cannot mint a
  ledger-affecting authorization claim. Thus `claim-ledger-reader`,
  `oidc-token-issuer`, OIDC client/consent, and
  `heterodyne.agent/workload-registration` authority all bind a generation;
  the workload-registration value schema itself does not acquire a duplicate
  field;
- every `claim-ledger-record-v1` object adds the JSON-safe nonnegative integer
  `/credential_ledger_generation` for all eight record types. JCS determines
  serialized order. The Ed25519 signing object includes
  `credential_ledger_generation`; the generator's current undomained digest
  implementation is corrected to match the existing specification. The exact
  digests are:

  ```text
  payload_digest =
    lowercase_hex(SHA256(
      UTF8("heterodyne-claim-ledger-payload-v1") || 0x00 ||
      JCS(record.payload)
    ))

  record_id =
    lowercase_hex(SHA256(
      UTF8("heterodyne-claim-ledger-record-id-v1") || 0x00 ||
      JCS(complete signed record with record_id omitted)
    ))
  ```

  The generation is outside `/payload`, so it does not change
  `payload_digest`; it is inside the signed record and therefore changes
  `record_id`;
- an `oidc-issuance-record-v1` payload adds
  `/credential_ledger_generation`; the containing
  claim-ledger record carries the same integer and a mismatch rejects;
- an `oidc-signing-jwk-v1` envelope adds
  `/credential_ledger_generation`; the envelope
  content/context digest and every recipient wrap bind it;
- every built-in Authorization Code/PKCE transaction and RFC 8628 Device
  Authorization transaction stores the exact ledger persona and generation
  at creation and approval. Token exchange rechecks both against current state;
  reset atomically invalidates and purges every pending, approved, denied, or
  unredeemed prior-generation code. Reissued registration or consent cannot
  make an old transaction redeemable;
- every built-in ID Token, RFC 9068 access token,
  `heterodyne-assertion+jwt` assertion, and Status List Token adds
  the 64-lowercase-hex JWT payload claim `credential_ledger_persona` and the
  integer claim `credential_ledger_generation`; and
- every mint operation resolves the current generation before signing and
  refuses an authorization claim, ledger record, issuance record, key
  envelope, or token whose persona or generation differs from the current
  ledger.

All claim-ledger records remain replayable audit history. A prior-generation
revocation, remove, status invalidation, or authority reduction remains
monotonic and cannot resurrect authority. A prior-generation grant,
reader/issuer addition, audience-key epoch, issuance reservation, or
authorization claim cannot provide current operational authority. After a
reset, the new generation therefore reissues the needed authorization claims,
issuer-key envelope, audience-key epoch, and credentials while retaining all
old bytes.

The current pre-release 0.5.0 signed records and vectors are regenerated with
generation zero. A missing generation is never inferred as zero and fails
closed even before the first reset; this is an intentional pre-1.0 correction,
not a compatibility rule. Reset invalidation of a self-contained JWT is not
instantly observable to an offline third party; issuer-key rotation, status
publication, token expiry, and that verifier's status policy remain the
external enforcement boundary.

## Social and cross-document corrections

- Core prohibits implicit or inferred cross-persona linkage but permits an
  explicit higher-document assertion that is authorized by both personas.
  Social's `same_holder` assertion is that exception and requires an
  irreversible-linkability confirmation.
- Social's no-retroactive-deattribution rule has an explicit exception for
  Core's compromise cutoff.
- Every bounded delivery requirement says the producer must initiate within
  the interval and retry until success, explicit expiry, user cancellation, a
  superseding state transition, or the profile's terminal retry-budget
  outcome. An external partition is an availability failure, not an
  impossible conformance failure.
- ATProto resolution validates and connects to the same public address for
  each hop, retains the hostname for TLS SNI/certificate validation and HTTP
  `Host`, disables automatic redirects, and repeats resolution and pinning for
  each explicit redirect. An environment unable to bind or inspect the peer
  address cannot claim this resolver feature.
- Exact English UI strings become examples. Structured outcomes carry the
  relevant reason code, missing page or approval identifier, retry state, and
  timestamps for localization.
- Social's current Matrix capability example uses registry revision 3,
  current feature IDs, and the required implementation role.
- Historical ADRs receive precise partial-supersession notes for retired
  room-secret/private-broadcast behavior; their still-active decisions remain
  accepted.
- Comms states that `control-enrollment` is reserved and unreachable while
  the general Control conformance gate is closed.

## Conformance and testing

Every current normative vector carries evidence, regardless of its historical
governing registry revision. The executable form is closed:

```json
{
  "class": "executable",
  "catalog_revision": 4,
  "catalog_sha256": "<64 lowercase hex>",
  "profile": "<allocated wire or kind profile>",
  "operation": "validate",
  "validator_id": "<allocated validator id>",
  "validator_version": "<64 lowercase hex>",
  "corroborating_validator_id": null,
  "corroborating_validator_version": null,
  "generator_provenance_path": "docs/spec/vectors/generator/implementation-provenance.json",
  "generator_provenance_sha256": "<64 lowercase hex>",
  "expected": {"verdict": "reject", "reason_code": "<registered code>"}
}
```

`catalog_sha256` is the history entry-set digest for `catalog_revision`. The
primary validator names that profile, permits the requested operation, and
uses `heterodyne-vector-validator-stdio-v1`. The corroborating members are both
null when that operation contract has `assurance:"semantic"` and both non-null
when it has `assurance:"cryptographic"`. A cryptographic corroborator is a
different allocated validator whose contract has the same profile, operation,
input schema, result schema, and assurance. Its ID/version differ from the
primary. Each selected validator's bundle manifest is the closed JCS object:

```json
{
  "entrypoint_format": "wasm32-wasi-preview1-command-v1",
  "entrypoint": "<safe relative path>",
  "files": [
    {
      "path": "<safe relative path>",
      "role": "entrypoint",
      "size": 0,
      "sha256": "<raw-file SHA-256>"
    }
  ]
}
```

The manifest contains exactly `entrypoint_format`, `entrypoint`, and `files`.
Files are strictly increasing by path UTF-8 bytes, paths are unique and safe,
and each file contains exactly `path`, `role`, `size`, and `sha256`. `size` is
a JSON-safe nonnegative integer equal to the exact raw-byte length. `role` is
`entrypoint` or `non-oracle-support`; `entrypoint` exactly equals the sole
`entrypoint`-role path. Canonical JSON Schema files are harness inputs from
the authenticated artifact closure and are never copied into or preopened
from the validator bundle. The bundle-manifest file bytes
MUST be exactly `UTF8(JCS(bundle_manifest))`, with no BOM, leading/trailing
whitespace, or line feed. `validator_version` is lowercase-hex SHA-256 of
those exact bytes and MUST equal the catalog's
`bundle_manifest_sha256`; every listed file digest must verify before
execution. When present, `corroborating_validator_version` is checked by the
same rule against the corroborating catalog entry and bundle; no primary field
is reused for it. Every listed object is a regular file beneath the resolved
bundle root. Symlinks, hardlinks, junctions, sparse aliases, device/special
files, and any lexical or resolved escape are rejected. Before module
validation or execution, the harness performs one race-safe
descriptor-relative walk, opens each listed file without following links,
verifies its resolved identity and regular-file metadata from the open handle,
reads it once into an immutable byte snapshot, and requires the manifest
digest and declared size to match. The entrypoint is parsed from that snapshot,
and virtual `/bundle` serves only those snapshotted support bytes. No module
call reopens, restats, or rereads a host path. Replacement or mutation before
the stable read causes a type/identity/digest failure; replacement or mutation
afterward cannot change the in-memory execution view.
The harness applies the same stable-handle snapshot rule before use to the
selected vector, catalogs, release/artifact manifests, schemas and metaschema,
KAT source/case map, evidence contract, and every dependency-artifact file
whose bytes affect the run. All digest checks, parsing, schema resolution,
request construction, expected comparison, and reports consume those exact
immutable snapshots; no conformance input is verified from one host-path read
and interpreted from another.

The bundle root is the dedicated directory
`docs/spec/validators/<validator-id>/<validator-version>/`; every listed path
is relative to that root. `validator_version`,
`bundle_manifest_sha256`, and the canonical root's digest component are
byte-identical. The exact `bundle-manifest.json` raw file itself appears in
the selected owner artifact manifest with role `validator-bundle` and the same
digest. Every entrypoint file appears there with role `validator-bundle`, and
every support file with role `normative-support`, with identical raw digest.
A bundle may not list or open
any file with artifact role
`vector`, `normative-document`, or any release/artifact-manifest role. Paths
under `docs/spec/vectors/`, `docs/reviews/`, `docs/adr/`,
`docs/superpowers/`, `docs/spec/releases/`, `docs/spec/registry/`,
`research/`, and every generator source/output directory are categorically
forbidden even if copied or aliased through another path. The bundle build
and review audit reject embedded vector IDs, `expected_output` objects,
generated expected constants, or tables derived from the owner vector corpus;
only independently authored protocol logic, closed schemas, and primitive
cryptographic constants may appear. An executable bundle MUST NOT contain,
list, open, embed, or derive from a `heterodyne-kat-case-map-v1`, a source file
named by such a map, or any KAT input/expected table, even when that file has
artifact role `normative-support`. KAT source/map files are available only to
the external known-answer evidence verifier, never in the validator preopen.

Each selected validator's exact `(profile_id,operation)` contract is resolved
before execution. Its input and result schema files and their complete
transitive reference closure MUST appear only at their canonical
`schema`-role paths in the selected owner/dependency artifact closure with the
same raw-file digests; the harness validates them outside the module and does
not expose them through the bundle preopen. Both root schemas use the
repository's pinned JSON Schema
dialect, close every object and tuple recursively, and MUST NOT rely on an
unconstrained `additionalProperties:true` branch. A deliberately keyed map
uses an explicit key pattern and a closed value schema. The input schema
separates deterministic semantic/context fields from candidate artifact data;
only a branch explicitly marked `x-heterodyne-artifact-data:true` may carry a
wire member whose literal name is also used for a verdict, such as
`reason_code`. Expected-only annotations are prohibited anywhere else in
`/input`.

Before this migration is accepted, every existing
`vector_context.decision_trace`, `expected_*`, `expected_authorized`, and
per-case expected verdict or reason is removed from `/input` and represented
only in withheld vector metadata or the closed expected result. A candidate
artifact's genuine wire `reason_code` remains input only when the selected
schema identifies that exact candidate-artifact branch. For executable
evidence, the harness validates the complete `/input` against the selected
validator input schema before invoking the module. After invocation it
validates the runner result, `vector.expected_output`, and
`evidence.expected` independently against that validator contract's selected
closed result schema before comparing their JCS bytes. A partial expected
result, extra result member, or schema mismatch invalidates the vector; it
cannot be treated as a convenient subset assertion. KAT and schema-only
evidence do not imply a selected validator; their input/result shape is
instead closed by the evidence-bound contract schema below.

The fixed generator-provenance path is a regular
`normative-support`-role file in the selected owner artifact manifest and its
raw digest equals the evidence member. Its bytes use the same closed
`heterodyne-implementation-provenance-v1` shape as validator provenance and
use `artifact_kind:"vector-generator"` to inventory the complete vector
generator source tree, pinned hermetic recipe/toolchain, and all transitive
cryptographic components. An independent release verifier rebuilds and runs
that generator with the authenticated provenance file as a fixed metadata
input and with no access to the prior vector output tree, selected artifact
manifest, validator bundles, reviews, or expected-output corpus. The run MUST
reproduce every generated vector byte-for-byte at exactly the path/digest
recorded by the candidate owner artifact manifest; extra, missing, or
different output rejects before that manifest can be accepted. The provenance
file does not contain those output digests, avoiding a provenance/vector
digest cycle; the independently selected candidate artifact manifest supplies
the comparison set.
For every executable operation, the generator and primary validator have
distinct independently maintained implementation families and source
lineages. Their selected `operation_lineage` entries share no decision or
transcript implementation source, fork, generated translation, vendored copy,
wrapper around common selected-operation logic, or common independently
packaged helper. Separate entrypoints or repositories do not establish
independence when either selected-operation lineage is shared. They may share
the governing standards, closed schemas, public algorithm constants, vector
runner ABI, and generic build/runtime infrastructure only when that shared
code performs none of the selected operation's semantic decisions,
canonicalization, transcript construction, or expected-result derivation.

For `assurance:"cryptographic"`, the primary, corroborator, and generator MUST
have three distinct implementation families, and the same pairwise
decision/transcript-lineage prohibition applies across all three.
For every primitive exercised by the operation, their component inventories
must identify independently maintained source implementations: no two may
share a component repository/revision/source digest, one may not be a fork,
generated translation, wrapper, or vendored copy of another, and source review
must find no shared primitive implementation code. Sharing the governing
standard, public algorithm constants, test-vector publications, or an
independently implemented ABI remains allowed only under the selected-operation
lineage rule above. A missing transitive dependency, self-asserted family
rename, unverifiable source tree, common decision/transcript helper, or common
primitive lineage invalidates the evidence.

The entrypoint is a WebAssembly command module for the frozen
`wasm32-wasi-preview1-command-v1` runner ABI and exports `_start`. Every
transitive code, library, and data dependency is embedded in the module or is
a listed file. The harness passes no arguments or environment variables.
Module validation additionally applies
`heterodyne-wasm-core-deterministic-v1`: one 32-bit unshared linear memory,
integer (`i32`/`i64`) numeric instructions, deterministic control/call/local/
global operations, exactly one MVP `funcref` table with declared initial and
maximum no greater than 65,536 entries, ordinary integer memory
load/store/size/grow, and only `table.get`, `table.set`, `table.size`,
`table.init`, `elem.drop`, `table.copy`, `table.fill`, and deterministic
bulk-memory operations. `table.grow` is forbidden.
The declared maximum is pre-reserved so `memory.grow` succeeds exactly through
that maximum and then returns `-1`. Any `f32`/`f64` type, global, local,
parameter, result, constant, instruction, conversion, or reinterpretation
rejects the module, eliminating observable NaN payload behavior. SIMD and
relaxed SIMD, threads/atomics/shared memory, multi-memory, memory64,
`externref`, GC/reference-type extensions beyond MVP `funcref`, exceptions,
tail calls, the component model, and every undeclared proposal also reject at
validation. The exact core/ABI profile is part of
`entrypoint_format`; an engine accepting a broader module may not silently run
it as conforming evidence. Before execution the harness also reserves the
table's declared maximum; inability to reserve memory or table capacity is a
harness failure, not a module-visible alternate result. Because `table.grow`
is absent, `table.size` remains the declared initial size and every permitted
table instruction has only its specified deterministic success or bounds trap.

File descriptors 0, 1, and 2 are exact standard input, output, and diagnostic
error; descriptor 3 is the sole preopen and has the fixed guest name
`/bundle`. It exposes only exact listed bundle paths read-only. The harness
implements one virtual descriptor table independent of host descriptor types:

| FD class | WASI file type | Base/inheriting rights | flags | seek/tell |
|---|---|---|---|---|
| `0` | `character_device` | `FD_READ \| FD_SEEK \| FD_TELL \| FD_FILESTAT_GET` / none | `0` | `ERRNO_SPIPE` |
| `1`, `2` | `character_device` | `FD_WRITE \| FD_SEEK \| FD_TELL \| FD_FILESTAT_GET` / none | `0` | `ERRNO_SPIPE` |
| `3` | `directory` | `PATH_OPEN \| PATH_FILESTAT_GET \| FD_FILESTAT_GET \| FD_SEEK \| FD_TELL` / `FD_READ \| FD_SEEK \| FD_TELL \| FD_FILESTAT_GET` | `0` | `ERRNO_SPIPE` |
| opened listed file | `regular_file` | `FD_READ \| FD_SEEK \| FD_TELL \| FD_FILESTAT_GET` / none | `0` | deterministic success |

Descriptor 0 is a finite nonseekable stream over the exact standard-input
bytes and returns a zero-length read only at EOF. Descriptors 1 and 2 are
finite nonseekable sinks subject to the declared output caps. Opened files use
an independent cursor initially at zero; `fd_seek` supports only the ordinary
WASI `SET`, `CUR`, and `END` operations within representable offsets, and
`fd_tell` returns that cursor. Wrong-direction reads/writes return
`ERRNO_BADF`; seek/tell on 0 through 3 return exactly `ERRNO_SPIPE`.
The virtual descriptor table has the exact opened-file range 4 through 65,535
inclusive and is pre-reserved before module execution; inability to reserve it
is a harness failure. `path_open` assigns the lowest currently unused
descriptor in that range. When all 65,532 slots are occupied it returns
`ERRNO_MFILE`; `fd_close` frees that exact slot for deterministic lowest-free
reuse.
Closing any open descriptor succeeds once and every later operation on it
returns `ERRNO_BADF`. No behavior depends on whether the host supplied stdin as
a file, pipe, or socket. `fd_prestat_get` and `fd_prestat_dir_name` succeed
only for descriptor 3 and return exactly a directory preopen whose UTF-8 name
is the seven bytes `/bundle`; on every other descriptor they return
`ERRNO_BADF`. `path_filestat_get` succeeds only on descriptor 3 plus one exact
canonical listed path, returns `ERRNO_NOENT` for an unlisted canonical path,
and returns `ERRNO_BADF` for every other descriptor. This error ordering is
part of the ABI profile.
`fd_fdstat_get` and `fd_filestat_get` succeed for each currently open
descriptor 0 through 3 and each currently open listed file, returning exactly
the table and metadata below; an absent or already closed descriptor returns
`ERRNO_BADF`. `fd_seek` and `fd_tell` likewise check existence first, so a
closed descriptor returns `ERRNO_BADF` while an open nonseekable descriptor
returns `ERRNO_SPIPE`. The profile exposes the corresponding stat/seek/tell
rights deliberately so modules observe these specified results rather than a
host-dependent rights error.

`path_open` succeeds only with `fd == 3`, `dirflags == 0`, `oflags == 0`,
`fdflags == 0`, `fs_rights_base` exactly
`FD_READ | FD_SEEK | FD_TELL | FD_FILESTAT_GET`, and
`fs_rights_inheriting == 0`. It never attenuates or elevates a caller-supplied
rights set. After validating guest-memory ranges, an absent/closed or non-3
descriptor returns `ERRNO_BADF`; a nonzero flag returns `ERRNO_INVAL`; a
different rights set returns `ERRNO_NOTCAPABLE`; a non-UTF-8, empty,
noncanonical, absolute, escaping, slash-aliased, or NUL-containing path returns
`ERRNO_INVAL`; a canonical unlisted path returns `ERRNO_NOENT`; and an
otherwise successful open with no free virtual slot returns `ERRNO_MFILE`, in
that precedence. Success creates the exact opened-file table entry above.

Vectored I/O is maximal and deterministic. Before reading or writing, the
harness validates with checked 32-bit arithmetic the complete iovec array,
every pointed byte range, and the result-count pointer; an overflow or
out-of-bounds range returns `ERRNO_FAULT` with no cursor, sink, or memory
change. Overlap between the iovec table, any data range, and the count output
returns `ERRNO_INVAL`; overlapping data ranges likewise return
`ERRNO_INVAL`. Descriptor existence and direction are checked next. `fd_read`
then visits iovecs in array order and fills each completely before the next,
except that source EOF may make the final transfer short; it returns exactly
the minimum of total requested length and source bytes remaining and advances
the stdin or file cursor by exactly that count. `fd_write` visits iovecs in
array order, copies every requested byte to the selected sink, and returns the
exact total. A zero-length iovec and an empty vector are allowed and transfer
zero bytes. A call that would exceed a declared cumulative read or output cap
is a harness resource failure before any transfer, never a short successful
I/O or module-visible errno.

For `fd_seek`, descriptor existence is checked before type; an open
nonseekable descriptor returns `ERRNO_SPIPE`. A regular-file call accepts only
`SET`, `CUR`, or `END`; an unknown whence, negative resulting offset, or
checked signed/unsigned arithmetic overflow returns `ERRNO_INVAL` without
moving the cursor. Seeking beyond EOF is permitted and a later read returns
EOF until the cursor is moved back; the read-only file is never extended.
`fd_prestat_dir_name` first validates its output range, then requires
descriptor 3, then requires `path_len >= 7`; the respective errors are
`ERRNO_FAULT`, `ERRNO_BADF`, and `ERRNO_NAMETOOLONG`. On success it writes
exactly the seven `/bundle` bytes and leaves any remaining buffer bytes
unchanged. The same checked-range/no-partial-side-effect rule applies to every
other allowed call's output structures and is its first error-precedence step
before descriptor, flag, rights, path, or arithmetic validation.
Every successful Preview1 result structure, including `prestat`, `fdstat`, and
`filestat`, is constructed in an exact-size zero-initialized buffer. The
harness writes defined integer fields at their Preview1 ABI offsets in
little-endian order and writes the complete exact-size buffer to guest memory;
every padding or reserved byte therefore remains zero. Scalar count,
descriptor, offset, and timestamp outputs likewise use their exact Preview1
width and little-endian encoding.
`path_filestat_get` then requires descriptor 3, `lookupflags == 0`, a valid
guest-memory range for its input path, and the same canonical path grammar as
`path_open`; it returns respectively `ERRNO_BADF`, `ERRNO_INVAL`,
`ERRNO_FAULT`, `ERRNO_INVAL`, or `ERRNO_NOENT` at the first failing step, and
succeeds only for an exact listed file.

The allowed `wasi_snapshot_preview1` calls are exactly `fd_read`, `fd_write`,
`fd_close`, `fd_seek`, `fd_tell`, `fd_fdstat_get`, `fd_filestat_get`,
`path_open`, `path_filestat_get`, `fd_prestat_get`,
`fd_prestat_dir_name`, and `proc_exit`. `path_open` accepts only the exact
call shape above. `fd_read` is permitted only on descriptor 0 or an opened
listed file, and `fd_write` only on descriptors 1 and 2. Stat calls return the
exact table file type and the verified byte length for a listed regular file
and zero for stream/directory descriptors, set link count to one, and set
device, inode, access, modification, and change metadata to zero;
`fd_fdstat_get` returns exactly the per-class rights/flags above rather than a
generic read-only value. Directory enumeration is not allocated, so host directory
order is unobservable. Every undeclared import or call rejects the module,
including args/environment, clock, random, polling, socket, process-spawn,
filesystem mutation, rename/link, and `fd_readdir` capabilities. Standard
error and process exit remain the only diagnostic/control outputs.

The entrypoint must not load an unlisted path. Time, randomness, locale, host
metadata, and other variable inputs required by a case appear explicitly under
the vector's `input`. A conforming WASI engine MUST produce identical result
bytes; the engine implementation is not part of validator identity. A harness
that cannot enforce this boundary cannot claim executable evidence.

Runner resources are also closed. A bundle is at most 64 MiB total, no listed
file or module exceeds 32 MiB, standard input and standard output are each at
most 16 MiB, diagnostic standard error is at most 1 MiB, cumulative listed-file
reads are at most 128 MiB, and linear memory is at most 4,096 WebAssembly pages
(256 MiB). The module declares a memory maximum no greater than that bound.
`heterodyne-wasm-fuel-v1` permits 1,000,000,000 fuel units: one per executed
core WebAssembly instruction, plus `1 + ceil(bytes/64)` for each bulk-memory
operation or WASI byte transfer. A 120-second wall timeout is a safety
backstop, not a semantic input. Any size, memory, fuel, output, or timeout
exhaustion is a harness failure and never a protocol accept/reject verdict.

The harness constructs this closed request and supplies exactly
`UTF8(JCS(request)) || LF` on standard input:

```json
{
  "protocol": "heterodyne-vector-validator-stdio-v1",
  "owner_document": "<vector.owner_document>",
  "owner_version": "<vector.owner_version>",
  "artifact_manifest_path": "<verified owner artifact-manifest path>",
  "artifact_set_sha256": "<verified owner release artifact set>",
  "dependency_versions": {},
  "dependency_artifact_sets": [],
  "registry_revision": 1,
  "registry_sha256": "<vector.registry_sha256>",
  "allocation_catalog_revision": 4,
  "allocation_catalog_sha256": "<vector.allocation_catalog_sha256>",
  "direction": "consume",
  "profile": "<evidence.profile>",
  "operation": "<vector.validator_operation>",
  "input": {}
}
```

Every placeholder other than `artifact_manifest_path`,
`artifact_set_sha256`, `dependency_artifact_sets`, `profile`, and `operation`
is copied from the same-named vector member. The artifact-set digest comes
from the conformance invocation's externally supplied closed context
`{claim_mode,qualified_version,artifact_manifest_path,artifact_set_sha256}`,
where `claim_mode` is exactly `current` or `historical`. A `current` claim
MUST name the verified owner release record's exact current top-level pair. A
`historical` claim MUST explicitly name one exact member of that record's
`superseded_artifact_sets`. The harness never searches current/superseded
manifests for matching vector bytes and never chooses among artifact sets
after seeing a result. The selected content-addressed artifact manifest MUST
contain this exact vector path and raw-file digest; an unchanged vector in
several artifact sets is still evaluated only in the one preselected context.
The report records that complete context beside the result.
`artifact_manifest_path` is the selected pair's path, and
`dependency_artifact_sets` is the selected artifact manifest's exact verified
`dependencies` array. `profile` is copied from `evidence.profile`,
`operation` from `vector.validator_operation`, and `input` is exactly the
vector's `/input` value after the contract-bound input-schema validation
above. The harness validates the vector's complete
`registry_allocations`, but withholds that array because it can contain an
expected-only rejection reason. The validator also receives no vector ID or
other vector member: in particular it cannot read `expected_output`,
`evidence`, `description`, `spec_refs`, or expected constants. On success it emits exactly
`UTF8(JCS(result)) || LF` on standard output, no other standard-output bytes,
and exit status zero. `result` is the complete independently computed output,
including canonical wire bytes or normalized state when the case defines
them. For every evidence class:

```text
JCS(evidence.expected) == JCS(vector.expected_output)
```

is mandatory. Disagreement invalidates the vector before execution; neither
copy overrides the other. Executable evidence succeeds only when the external
harness finds every selected validator result JCS-identical to both expected
values and, for cryptographic assurance, JCS-identical to the independently
produced corroborator result. Both modules receive the same closed request in
separate fresh harness instances; a crash, disagreement, provenance failure,
or different exit/result bytes invalidates the evidence. A runner that echoes
or imports an expected value is nonconforming even if its bytes happen to
match.

For executable, cryptographic-known-answer, and schema-only evidence,
`evidence.profile` MUST equal `vector.profile` when that optional top-level
member exists. When it does not, only a revision-4 `wire_profiles` entry may be
resolved implicitly, and its single `spec_ref` MUST equal the vector's sole
`spec_refs` item. A vector selecting a nested `kinds[].profiles[]` entry MUST
carry top-level `vector.profile`; it cannot infer that profile through a
top-level kind entry that has no profile-specific `spec_ref`. A mismatch is
rejected before execution. An emitted artifact named by the expected-output
schema must use that selected profile; a different artifact profile requires a
separate vector.

The other evidence classes have these exact closed members:

```text
cryptographic-known-answer:
  class, catalog_revision, catalog_sha256, profile, operation,
  contract_schema_path, contract_schema_sha256,
  source_id, source_uri, source_path, source_sha256,
  case_map_path, case_map_sha256,
  case_id, expected

schema-only:
  class, catalog_revision, catalog_sha256, profile, operation,
  schema_sha256, contract_schema_path, contract_schema_sha256,
  limitation, expected

documented-nonwire:
  class, catalog_revision, catalog_sha256, spec_ref, limitation, expected
```

For `documented-nonwire`, `spec_ref` MUST equal the vector's sole `spec_refs`
item. It has no profile, operation, validator, or validator operation and
cannot establish wire behavior. `limitation` is nonempty.

For `cryptographic-known-answer` and `schema-only`,
`contract_schema_path` is one safe repository-relative JSON Schema file in
the selected profile owner's artifact manifest with role `schema`;
`contract_schema_sha256` equals both that manifest entry's digest and
lowercase-hex SHA-256 of the exact raw file bytes. The schema uses the
repository's pinned dialect, closes every object and tuple recursively,
contains no unconstrained `additionalProperties:true` branch, and accepts
exactly a closed instance with this member shape:

```text
profile, operation, input, result
```

Its `profile` and `operation` properties use `const` values exactly equal to
the evidence values. The harness validates that instance once with
`input = vector.input` and `result = vector.expected_output`, and again with
the same input and `result = evidence.expected`, before requiring the two
result values to JCS-equal. A missing contract, path/digest/manifest-role
mismatch, wrong profile or operation constant, open object/tuple branch, input
rejection, result rejection, partial result, or extra member invalidates the
evidence. This contract authenticates shapes only; it does not turn
schema-only evidence into semantic validation.

For `cryptographic-known-answer`, `source_path` is a safe repository path to
the byte-identical vendored upstream JSON source and `source_sha256` is its
raw-file digest; evidence `source_sha256` MUST equal
`lowercase_hex(SHA256(raw bytes at source_path))`.
`case_map_path` names an exact-JCS
`heterodyne-kat-case-map-v1` object containing exactly `type`,
`source_id`, `source_uri`, `source_sha256`, and `cases`; each sorted unique case contains exactly
`case_id`, `input_pointer`, and `expected_pointer`, where both pointers are
RFC 6901 pointers into the parsed upstream JSON. Before pointer evaluation,
the authenticated raw source MUST parse under
`heterodyne-strict-ijson-v1`: exact UTF-8 without BOM, only valid Unicode
scalar strings, no duplicate object member name at any depth, and only JSON
numbers that map to a finite IEEE-754 binary64 value and round-trip through
the pinned RFC 8785 number serialization to that same value; integer-valued
protocol fields remain within the JSON-safe integer range. Object names are
compared as decoded scalar sequences without Unicode normalization. A
duplicate name, invalid surrogate/scalar, nonfinite or out-of-domain number,
or parser-dependent construct rejects rather than using first-wins,
last-wins, or implementation-native numeric coercion. RFC 6901 is applied
only to that one deterministic parsed tree. Both files appear in the
selected owner artifact manifest with role `normative-support` and matching
digests. Evidence `case_map_sha256` MUST equal
`lowercase_hex(SHA256(raw bytes at case_map_path))`; those bytes MUST be exact
`UTF8(JCS(case_map))`. Evidence `source_id` MUST resolve to exactly one
authenticated revision-4 `kat_sources` entry and be listed in
`registry_allocations`; its canonical URI and raw digest MUST equal evidence
`source_uri/source_sha256`. The case map's source ID, digest, and URI MUST in
turn equal those evidence values byte-for-byte. The selected unique `case_id`
resolves both pointers,
the extracted input JCS-equals vector `/input`, and the extracted expected
value JCS-equals both evidence and vector expected output. Missing source
bytes, a digest/URI/map mismatch, non-JSON source, an ambiguous case, or a
failed pointer invalidates the evidence.
The independently extracted input and expected value are also substituted
into the exact closed contract instance above and MUST validate before either
is compared with the vector.

For `schema-only`, `profile` resolves to a schema-bound wire or kind profile;
`schema_sha256` MUST equal that selected catalog entry's schema digest and the
raw digest of the same `schema_path` entry in the selected owner artifact
manifest with role `schema`. The complete `vector.input` itself, not an
implicit member or inferred wrapper, MUST validate against that selected
profile schema. A nested kind profile without an allocated closed schema
path/digest cannot use schema-only evidence.

Only `executable` and independently sourced `cryptographic-known-answer`
evidence establish semantic or cryptographic conformance. `schema-only` and
`documented-nonwire` never count as wire validation. The reference generator
and semantic validators satisfy the distinct-family and selected-operation
decision/transcript-lineage rule above; separate entrypoints alone are
insufficient. Closed schemas may be shared. A semantic-only validator may
share a primitive library that its selected operation does not exercise, but
no executable participants may share selected-operation logic, and no
`assurance:"cryptographic"` primary, corroborator, or generator may share the
same exercised primitive implementation lineage.

External KATs may anchor a cryptographic primitive only when an authoritative
upstream naturally publishes immutable JSON and one allocated closed
primitive-validation profile plus its evidence-bound contract schema make the
complete input/result shapes exactly match subtrees selected by the raw RFC
6901 pointers above. Revision 4 does not
allocate an open-ended or mandatory primitive-profile set and does not require
an owner-authored adapter. Composite Heterodyne wire profiles establish their
protocol behavior with independent executable evidence; they do not pretend
that an upstream primitive row is a full Heterodyne event. BIP-340's canonical
CSV, RFC prose examples, NIST `.rsp`, or any other non-JSON corpus cannot use
this revision's KAT evidence class. Those suites use executable evidence with
two independently implemented validators and generator separation unless a
later registry revision adds a closed, byte-exact media/parser profile.
Absence of eligible external JSON is not mislabeled as independently sourced
KAT conformance.

Every consume, round-trip, or produce vector whose evidence class is
`executable` executes its selected operation; an emitted wire artifact passes
that profile validator. An executable reject vector executes the invalid
input and asserts the exact failure rather than merely schema-validating its
envelope. KAT, schema-only, and documented-nonwire cases perform only the
closed checks allocated to those evidence classes and never imply a missing
consumer/producer invocation. A negative vector is not committed until its
reason code is allocated.

Minimum new or corrected coverage includes:

- revision-aware registry history preserving revisions 1–3 byte/digests,
  revision 4's exact nine-array entry-set input, live-to-history equality,
  cross-catalog profile-ID collision rejection, KAT-source authority, feature
  DAG cycle rejection, and release provided/required prerequisite closure;
- current and superseded artifact manifests, recursive dependency artifact-set
  selection, immutable-path/digest mismatch, manifest/file
  symlink/junction/hardlink/nonregular/resolved-root escape, and rejection of
  a dependency corpus that is neither current nor append-only superseded,
  plus current-versus-superseded Core diamond mismatch through direct and
  transitive dependency paths and a required feature present only in current
  dependency metadata but absent from the exact selected superseded artifact,
  including identical vector bytes in two sets with mandatory externally
  selected current-versus-historical context and no manifest search;
- offline transitive JSON Schema resolution across the exact owner/dependency
  artifact closure, including missing/duplicate `$id`, non-schema-role or
  mutable-remote targets, fragment/cycle handling, local pinned metaschema,
  cross-document executable `$ref` resolution, and rejection of schema copies
  or preopens inside the validator bundle;
- executable-evidence validator-ID grammar/re-encoding, canonical
  catalog-path/version/runtime-root equality, bundle-manifest artifact
  role/digest, bundle path/symlink/hardlink/alias escapes, fixed WASI import
  profile and virtual FD table, including modules branching on every
  fdstat/seek/tell result for stdin/stdout/stderr/preopen/regular files,
  exact path-open rights/flag/error precedence, maximal vectored read/write
  transfers, zero/overlapping/faulting iovecs, output-cap failure, prestat
  buffer lengths, zero padding/reserved bytes in every exact-size Preview1
  result structure, invalid `path_filestat_get` input-range precedence, seek
  overflow, virtual-FD exhaustion at 65,532 opened files and deterministic
  lowest-slot reuse after close, and forbidden `table.grow` with bounded
  pre-reserved tables, plus mutation/replacement between host verification and
  module open proving all runtime reads use the immutable snapshot,
  deterministic core-Wasm feature/NaN rejection, and two-engine/
  two-host metadata/directory-order differential runs, KAT source or
  case-map preopen denial, embedded/indirect expected-data leakage, withheld
  reason-code handling, cryptographic-assurance primary/corroborator/generator
  provenance closure, rejection of renamed/forked/shared primitive lineages,
  rejection when semantic generator/validator share a replay or decision
  helper and when cryptographic participants share canonicalization or
  transcript logic despite distinct primitive libraries,
  independent hermetic rebuild/run rejection when claimed source or recipe
  does not reproduce the actual Wasm/support/vector bytes,
  and a fixture in which a generator and one validator share the same
  deliberately faulty primitive but the independent corroborator disagrees,
  KAT strict-I-JSON duplicate-name/scalar/number
  rejection, KAT source/URI/map/raw-digest/case mismatch, and
  KAT/schema-only missing, open, or mismatched evidence-contract schemas,
  including wrong profile/operation constants, owner-artifact path/digest/role
  mismatches, and input/result contract rejection;
- valid and invalid inception/rotation bytes, threshold-zero `none`, fork
  stall, receipt thresholds, raw-byte mismatch, and local `did:key`;
- `repo_head` present, missing, mismatched, and malformed, plus scripted
  transport cases distinguishing a successful graph-exclusion rejection from
  retryable connection failure and exercising serve-until-expiry;
- every allowed JWK mapping plus `none`, HS, `oct`, wrong curve, weak RSA,
  type/algorithm mismatch, a missing protected `alg`, and any additional
  protected-header member;
- `deny-until-repo` versus `provisional-accept`;
- root-attestation boundaries at -301, -300, +300, and +301 seconds;
- equal-window attenuation, empty nonce, and revocation-before-trust
  precedence;
- alternative valid DEFLATE encoding;
- complete credential-ledger grant/revoke/order/signature/reset state,
  including the domain-separated claim-ledger payload and record-ID digests,
  generation/persona binding, empty-roster rejection, current-KEL checkpoint
  acceptance, atomic reset-candidate transition, and the combined
  missing-generation/empty-roster case proving
  `credential_generation_missing` precedence;
- generic secret-source commitment encodings for every class, including
  invalid algorithm/purpose combinations and provider-specific encodings,
  class-conditional 32-hex config-key versus 64-hex generic secret IDs, and
  exact checkpoint/target/source/action domain-separated commitment equality
  for config-audience and OAuth-pairwise secrets;
- historical-decrypt obligation root, retain-update, and absorbing-close
  lineages; nonempty retain and objectively empty close; fresh-ID
  post-close retention; monotonic successor provenance with exact
  transition-added retirements; complete maximal-frontier commitment including
  close and every competing branch; disjoint same-secret coverage versus duplicate
  ciphertext-row rejection; typed SHA-1/SHA-256 repository-head and blob OIDs
  with SHA-256-only ciphertext/object digests; retained-ciphertext comparator
  known answers spanning UTF-8 fields, both typed-Git object members, null and
  non-null object IDs, decoded digests, and numeric lengths, plus rejection of
  textual or nested-object ordering substitutions; deterministic governed-binding
  ID/path/authority/signature validation; embedded-tuple versus exactly-one
  pre-obligation binding resolution; independent authenticated
  artifact/key-binding derivation of `G(C)` and exact `G(C) = O(C)`; complete
  simultaneous audience-key/object-DEK retirement for one encrypted
  large-object pointer, with distinct Git-pointer and stored-object locators
  and rejection of omission, tuple swap, or collapse;
  closed `governed-decrypt-source-profile` allocation/table completeness and
  owner/tuple expansion; signed repository-retention inventory genesis,
  targeted successor, maximal conflict frontier, deterministic semantic IDs,
  typed scan cuts, exact-tree scans, monotone advance and ordinary absorbing
  retirement, `EffectiveRefs(C)`, and exact ordinary config-key-acceptance plus
  emergency complete-`V_old` deregistration with complete closure basis,
  same-CAS old-ref deletion, and ancestor-only audit evidence; missing/wrong/
  non-config/premature/partial-variant/different-ref deregistration and
  incomplete-closure rejection; complete `K(C)`
  `{repository_inventory_records,governed_heads,binding_records}` derivation,
  including inventory/binding conflicts, omitted/extra record/ref/cut/head or
  binding rejection, mixed-owner head projection and missing/extra/mismatched
  selected-profile owner, current-key post nonmutation, fully scanned
  no-noncurrent-dependency null inventory advance, rotation-time snapshot
  freezing, and transition-only updates; emergency `H*` convergence with every
  maximal inventory parent, union preservation of branch-only semantic rows
  outside complete `V_old`,
  every distinct variant head as an exact direct parent, scanned signed-result
  reconciled tree, cross-branch physical-locator `L(S)` enumeration independent
  of parent-local currentness, complete `Bound_I` expansion from every
  source-profile tuple and every individually valid signed-binding variant,
  including all conflicts, `D(S)` candidate pairs,
  unanimous sole-current `Current_I` classification, exact total physical
  `L(S)` disposition with conservative noncurrent `U(S)` candidate subset,
  and candidate-complete terminal cleanup; authenticated `ResultPairs(H*)`,
  including same-locator multi-embedded-tuple preservation and a uniquely,
  independently validated fresh fallback result, fresh H*-based locators and
  required pre-inventory bindings, ordinary post-action `Current_B`
  classification and obligations only for noncurrent result pairs,
  old-obligation replacement, `G(B) = O(B)`, `K(I)`/class-action union
  coverage, and the sole retired-row
  reactivation/advance exception, plus rejection of branch-only omission
  outside `V_old`, an
  ordinary, missing/extra-parent, non-common-descendant, unscanned,
  parent-local-current misclassification, unanimously-current artifact
  omission, old-locator-reusing, candidate-winner selection, conflicting
  `L -> t1`/`L -> t2` binding variants without complete terminal accounting,
  missing candidate bytes, or dependency-dropping/incompletely disposed merge;
  missing,
  extra, substituted, wrong-length, wrong-locator, or wrong-provenance rows; preexisting
  artifact-`A`/optional-binding-`K`/inventory-`R`/obligation-`O`/
  transition-`T`/checkpoint-`C` ancestry; self-referential config/checkpoint-head
  rejection; emergency fork preservation and fresh-ID reconciliation;
  historical-decrypt action arrays empty when no result obligation, complete
  fresh-ID same-old-tuple decrypt-only assignments when retention remains,
  simultaneous fresh-current successors, forbidden new-encryption/authority
  use, and final-close retirement; independently recomputed successor
  governed-binding digests and conditionally byte-identical obligation-digest
  propagation through routine config-key transition, abandonment,
  reset `K(I)` inventory/result/target, checkpoint receipt, archive high-water
  with all inventory records/ref cuts/signed-ref proofs, source closure,
  exact-tip append, and acceptance CAS;
- offline-recovery pre-unseal intent bulk-only and combined-slot
  compartmentalization, independent cold-root signer versus rejected
  self-authorizing archived cold root, exact closed preimage templates,
  domain-separated source/assignment/preimage-ID/set/record digests, ordering,
  duplicate and tuple-link rejection, create-only path, signer-confirmed
  nonfuture `created_at`, accepted +300-second first-observation boundary,
  zero/conservatively earlier no-clock value, and rejection of a host-proposed
  future time; durable signed
  intent before authority release; cancellation, authority-AEAD failure,
  hidden-artifact mismatch, crash, and no-final-activation paths preserve
  permanent unreconciled intent evidence; nonexportable post-intent authority
  DEK, internal AEAD/schema/outer-identity/commitment/template validation
  before exact-material or bound-operation release, mismatch zero-output and
  zeroization, and rejection of raw-DEK/unvalidated-plaintext or unenforceable
  validated-release implementations; exact duplicate idempotence,
  nonidentical same-ID intent collision with complete all-variant projection,
  and an exact linked intent plus activation that is not a collision;
  `ObservedPreUnsealIntents`/`ReconciledIntent(I)`/
  `UnreconciledPreUnsealIntents`, including
  intent-only target exclusion with no bootstrap, successor, delivery, or
  role, same-transition intent-plus-activation reconciliation, and a final
  activation first observed after intent reconciliation becoming new
  unreconciled completion evidence whose actual assignments require a new
  cleanup;
- offline-recovery activation exact duplicate idempotence, nonidentical
  activation-ID collision quarantine, all-unreconciled-variant inventory
  union, embedded
  `{record_type,record_digest,record}` byte/digest/type validation,
  source-without-transition-ID versus assignment activation-ID binding,
  exact intent-template completion with only the two signatures and source
  digest link added, byte-identical shared top-level fields and individual
  mismatch rejection, acyclic artifact references and no backwards dependency,
  crash after a completed record requiring preservation as additional
  evidence, dual-marker visibility and incomplete-stage
  noninstallation, archived-epoch conservative first acceptance
  despite KEL-window/compromise-cutoff ineligibility but only with raw BIP-340,
  template, cold-root, archive/KEL/provenance, schema, and bijection validity;
  raw-signature/provenance rejection and rejected operational use of the
  exception; `BaseItems`/`ProvisionalItems`/
  `EffectiveInventoryItems` assignment-frontier deduplication plus
  `IntentItems` and tagged `EffectiveInventoryOrigins`; exact per-exposure and
  per-action `pre_unseal_intent_items`, independently complete actual
  assignment arrays, no pseudo-assignment in predecessor/result hashes, and
  one-to-one retirement only for actual assignments; exact sorted activation
  and intent collision derivation,
  binding, and omission/extra/singleton/wrong-ID rejection; an initial pair of
  unreconciled same-ID variants using the collision-only reset with empty
  unavailable/removed arrays and an unchanged healthy roster; an
  already-reconciled variant plus a late same-ID variant forcing that reset
  while collision evidence binds both but inventory, `ProvisionalItems`, and
  cleanup contain only the late unreconciled variant; collision-only reason
  accepted when either complete collision projection is nonempty, node-loss
  reason precedence when loss and collision coexist, and rejection without
  active collision evidence, with a removed old-roster NID, or through a
  routine mode; optional explicitly authorized addition independent of
  collision ordering; target-included delivery/role closure versus
  target-excluded terminal cleanup with no bootstrap, successor, delivery, or
  role; fresh generation-zero epoch/config/pairwise rotation and mandatory
  collision `compromise_since`, including intent `created_at` precedence over
  linked activation time and rejection of a forged
  predecessor/current-epoch signature created after the earliest bound
  current-epoch exposure but before late collision detection,
  plus a noncolliding routine-addition intent for the predecessor-current epoch
  forcing the same fresh compromise-declaring rotation/cutoff through
  checkpoint and rollover and rejecting interval signatures,
  full-archive exclusion of every clone/device-signing secret, rejection of
  intent/activation for `device-local` or `clone-device`, unchanged same-NID
  logical assignment under exact cloning, and exclusion and ordinary
  enrollment of fresh prospective device/NID, SSH, X25519, and
  platform-wrapper keys, including no restore-only fresh-device rotation,
  mandatory class-complete cleanup, unconditional offline epoch rotation, and
  exact `Reconciled(A)` completion versus partial-transition noncompletion,
  exclusion of a reconciled exact duplicate from later `ProvisionalItems`,
  and late-new-digest authority hold followed by a new cleanup/rollover cycle;
- mergeable exposure assignment collision, pre-delivery fully-receipted
  gating, conservative pending-successor inclusion, and ineffective pending
  retirement, including mandatory cleanup of every failed-candidate successor
  assigned to a target-excluded proposed NID that never joined the roster,
  plus retained-roster bearer/endpoint expiry through an explicit
  routine-key-rotation maintenance set and accepted retirement;
- projected transition receipts and atomic activation, every closed
  class-to-action/disposition mapping, exact conservative
  `EffectiveInventoryOrigins` class-action coverage with assignment-only
  retirement sets and holder partitions, including unreconciled intent
  origins and provisional assignments, retained-peer and
  unilateral Double Ratchet termination, scoped NID revocation, and total
  old-roster loss replay from the checkpoint-bound exposure digest, including
  an ordinary epoch rotation with no node removal and cold-root selection when
  a routine addition/key rotation cleanup set contains recovery-authority
  material, plus routine-key-rotation cleanup of an OAuth-pairwise exposure
  with exact changed target/checkpoint commitment, mandatory inclusion and
  retirement of the previously current pairwise singleton when an abandoned
  pairwise tuple triggers cleanup, safe adoption of an already canonical
  current epoch after an abandoned config candidate, and a further epoch
  rotation when that current tuple names an excluded or competing holder,
  plus universal checkpoint rejection of an exposure-only second/different
  pairwise tuple or mismatched commitment and of a second purported current
  epoch identity;
- config bootstrap no-cycle and exact generation/sequence/head/context
  binding, roster ordering/completeness, duplicate or missing recipients,
  NID delegation/proof, HPKE known answers, path/digest/key commitment,
  ephemeral-key erasure, and receipt-only versus operational authority;
- routine rotation, addition, and removal with empty `G(C)`, mandatory
  old-config-row deregistration and new-row registration, changed
  `repository_inventory_records`/`K(C)`/governed-binding digest,
  byte-identical governed heads, binding records, and obligation digest, and
  rejection of the stale predecessor governed-binding digest;
- the exact parentless-`B`/direct-child-`T`/child-`C` carrier with
  transition-bound `K`/`R`/`O`, dependent proof records, and transition
  finalized in logical dependency/signing order and co-committed in `T`
  independently of lexical Git tree order; rejection of any such new record
  in `B`, transition signing before complete proof bytes, an intermediate
  commit, a record naming `T`'s commit OID, or lexical tree order treated as
  dependency order;
- routine addition pairwise/config rotation, a proposed NID with no pregrant or
  preacceptance protected-key transfer, separately checkpointed postacceptance
  credential grant, already-authorized promotion, and failed-candidate
  nonexposure of both active old secrets, plus withheld-receipt
  candidate-abandonment versus acceptance CAS ordering and a later routine
  cleanup successor that retires every inert staged assignment, including
  same-key null-transition checkpoint/digest path binding and complete
  candidate-exposure delta, mandatory retirement except narrow current-epoch
  adoption, and no nonexistent staging-ref cleanup;
- parentless config-generation copy/compare-and-swap, fresh config-key ID and
  absent candidate-ref validation, create-only candidate publication,
  collision-triggered ID replacement/rebuild, concurrent old-ref mutation
  rejection, equal-head/shared-ancestor old-generation alias rejection, and
  exact complete-acceptance-head reachability for all
  target-roster receipts and removed-node observations versus the
  emergency-loss path, including the narrow predecessor-state
  revocation-before-observation signature boundary, plus
  orphan/side-branch omission rejection,
  failed-staging retention and protected key burn, exact
  retire-then-staging-cleanup deletion/key-erasure CAS race and replay,
  append-only signed candidate-ref durability for partial receipts and removal
  observations, duplicate valid receipts retained but counted once, duplicate
  observation rejection, orphan/side-branch byte-identical retry, exact
  partial-set digest binding, append-versus-acceptance/abandonment/reset CAS
  ordering, same-key invalidating-write rejection and abandonment, abandonment
  of a record-complete config-key tip after its old-ref CAS is invalidated, and
  cleanup closure preservation of every frozen partial record, plus emergency
  reset CAS binding and deterministic non-authoritative raw/safe audit copying
  of a same-key checkpoint/partial/security-write/exposure suffix before old-ref
  deletion with mandatory retirement or narrow current-epoch adoption of its
  exposure delta,
  complete raw Git object-closure commitment and opaque candidate-ciphertext
  copying with no decrypted pairwise/bootstrap/bearer/arbitrary-config bytes
  or bare hashes under the active key, canonical fixed Git commit metadata;
  ordinary zero/one-parent `heterodyne-config-v1` versus a positive exact
  config-class emergency `H*`
  `heterodyne-config-retention-resolution-v1` commit with tree-first,
  complete unique decoded-OID-sorted variant parents and bound reset/`U(S)`
  proof, plus rejection of an unbound resolution merge, extra/missing/
  duplicate/wrong-order parent, ordinary merge, or wrong message;
  schema-public protocol path components, HMAC-tokenized arbitrary logical
  paths, and rejection of secret-bearing commit/path injection,
  safe-record allowlist completeness, including an unsigned lost-generation
  index accepted only through its exact signed reset/transition/checkpoint
  closure and rejection of a free-standing or variant-mismatched index,
  against the active basis with the exact reserved destination excluded from
  prior-reachability and byte-identical audit-path reachability required, old
  baseline key erased before cleanup, inherited-audit
  mutation cannot masquerade as accepted inheritance, authenticated
  whole-subtree elision, and opaque classification when candidate C2 fails
  after pre-staging an as-yet-unaccepted cleanup namespace for S1,
  and two and three consecutive abandon/retire/cleanup cycles with linear
  namespace growth,
  canonical
  abandonment/reset terminalization versus candidate acceptance ordering, and
  cold replay of the complete copied checkpoint/exposure audit chain;
- emergency retained-node inventory completeness, rejection when one retained
  node's signed head is omitted, and byte-preserving lost-generation handling
  for conflicting non-credential paths and deletions;
- the exact NIP-59 peer-tombstone carrier, seal/tombstone/KEL/recipient/session
  mismatches, actual-removed-node versus target-excluded non-roster
  cleanup-only reason selection and mismatch, retained receipt transcript,
  replay/deduplication, old-session rejection after observation, and the
  explicit unacknowledged residual-risk outcome;
- DR atomic acceptance and key deletion;
- DNS validation-address/connection-address mismatch;
- ATProto bidirectional binding, ordering, revocation, redirect, and SSRF;
- Social compromise cutoff and localizable deadline outcomes; and
- current Matrix capability bootstrap.

## Error handling

All security-significant ambiguity fails closed. Network unavailability
produces a retryable availability state unless the relevant policy explicitly
requires `deny-until-repo`. Emergency recovery is never inferred from
unavailability.

Generator defects that make a producer emit nonconformant bytes fail the
authoring check before committed vectors are regenerated. A successful
regeneration is insufficient unless semantic replay also passes.

## Non-goals

This design does not:

- complete ADR-030 or open general Control conformance;
- hide Tier 3 membership;
- make cold-root compromise recoverable;
- specify MLS migration;
- finish repo-relay server admission, retention, quota, namespace, or GC
  conformance; or
- rename stable profile or legacy reason-code identifiers merely for style.
