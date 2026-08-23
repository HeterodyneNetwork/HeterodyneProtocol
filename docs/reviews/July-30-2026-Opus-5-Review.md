# Heterodyne protocol-family review — 2026-07-30

**Reviewer:** Claude Opus 5
**Scope:** `docs/spec/heterodyne-{core,comms,control,social}.md` at `core/0.5.0`,
`comms/0.5.0`, `control/0.5.0`, `social/0.5.0`; `docs/spec/registry/`;
`docs/spec/releases/`; `docs/spec/vectors/` (317 manifest entries, 305 vector
files); `docs/security/threat-model.md`; supporting ADRs 026-036.
**Status:** Non-normative. Findings are observations against the repository as
of commit `e02bdee`, not accepted changes.

## 0. Verification baseline

Both gates pass on a clean tree:

```
npm --prefix docs/spec/vectors/generator run family:check   # exit 0
npm --prefix docs/spec/vectors/generator run check          # exit 0
```

Every finding below is something the current harness does **not** catch. That
is the main structural observation of this review: `family:check` validates the
dependency DAG, anchor syntax, registry schema, and release-manifest pins, and
`check` validates that vectors match what the generator produces. Neither
validates that vectors match what the *documents* require. The two artifact
families have drifted, and the drift is invisible to CI.

The specification is unusually disciplined — closed schemas, byte-exact
canonicalization, explicit fail-closed ordering, an allocation registry with
immutable discriminators, and a genuinely good threat model. The findings
concentrate where that discipline is asserted but not mechanically enforced.

---

## 1. High severity

### H-1. The KEL — the root of the entire identity model — has no byte-exact vector coverage, and the fixture KELs do not satisfy Core 0.5.0

Core §14 (`heterodyne-core.md:1196-1213`) states that the minimum Core vector
set covers "KEL inception/rotation and authority windows" and that "Normative
vectors compare canonical bytes and exact verdicts; semantic equivalence is
insufficient."

All seven `keri/*` vectors are symbolic placeholders containing no cryptographic
material. `docs/spec/vectors/keri/002-inception-event.json`:

```json
"input":  {"event_type":"inception","sequence":0,"witness_threshold":1,
           "witnesses":["did:key:z6Mkwitness"]},
"expected_output": {"verdict":"accept",
           "normalized":{"kel_sequence":0,"witness_threshold":1}}
```

`keri/006-fork-resolution-conflicting-rotations.json` is worse — it takes
`{"rotations":["rotation-a","rotation-b"],"first_seen_winner":"rotation-b"}` and
asserts that `rotation-b` wins. It restates its own input. Duplicity detection
and first-seen fork resolution are the most security-critical behavior in Core,
and they are covered by a vector that tests nothing.

Corpus-wide: of 305 vector files, **25 are byte-exact producer vectors** and
**135 consumer vectors contain no 64-hex value anywhere**, i.e. no keys,
signatures, or event ids. `keri/*`, `moderation/*`, `homeserver-exit/*`,
`config_room/*`, and most `keri-authority/export-*` vectors are in that
symbolic set.

Separately, the fixture KEL that everything else derives from is not a valid
Core 0.5.0 event. `docs/spec/vectors/fixtures.json`, persona `alice`:

```json
{"pubkey":"79be667e…","created_at":1767225600,"kind":31002,
 "tags":[["d",""],["heterodyne","keri_inception"],["p","79be667e…"],
         ["s","0"],["epoch_key","c6047f94…"]],
 "content":""}
```

Missing: the `["spec_version","core/0.5.0"]` tag that Core §3.2 class 2
(`heterodyne-core.md:137-139`) makes mandatory for a Heterodyne-allocated kind
with empty content, and that Core §4.2's own example carries
(`heterodyne-core.md:301`). Also missing: `witness`, `threshold`, and `sig`.

The same defect propagates into a **normative producer vector**.
`keri-authority/024-materialized-log-derivation.json` derives byte-exact git
OIDs from embedded `nip01_raw` bytes whose `kind:31003` rotation content is
`"[]"`. Core §4.3 (`heterodyne-core.md:337-344`) requires that content be
exactly `{"spec_version":"core/0.5.0","receipts":[...]}` and says a
"non-array `receipts` value MUST be rejected" — a bare `[]` has no `receipts`
member at all. So the canonical materialized-KEL blob/tree/commit OIDs pinned
as normative are computed over KEL events that Core 0.5.0 requires an
implementation to reject.

Core §3.2 legacy inference does not rescue this: it is permitted only "for a
Heterodyne-allocated kind whose 0.4.0 schema required that monolith stamp"
(`heterodyne-core.md:156-158`), and the archived 0.4.0 `kind:31002` example
(`docs/spec/archive/heterodyne-0.4.0.md:1260-1279`) carries no stamp either.
Nothing in the corpus declares these fixtures as archived-form events.

**Recommendation.** Treat this as the top pre-1.0 item.
1. Regenerate `fixtures.json` KELs as valid `core/0.5.0` events: real BIP-340
   signatures, `spec_version` tags, a nonempty witness set with weights, and a
   rotation whose content is the exact required object.
2. Replace the seven `keri/*` placeholders with byte-exact producer/consumer
   vectors: inception bytes, `committed` and `none` rotation bytes, real
   witness receipts over `witness_digest`, a genuine same-sequence fork with
   two signed branches and per-witness first-seen evidence, and the stall case.
3. Add a `family:check` rule that rejects any vector whose embedded events fail
   the owning document's schema — the check that would have caught all of this.

### H-2. `kind:31010` node advertisements are unverifiable by their intended audience

Core §7.3 (`heterodyne-core.md:640-655`) defines the NID proof input as:

```text
heterodyne-node-advert-v1|<rid>|<nid>|<endpoint>|<expiry>|<repo_head>
```

but the tag list in the same section — `node_advert`, `rid`, `nid`, `endpoint`,
`expiry`, `nid_proof`, the version tag, and `kel_head` when epoch-signed —
contains **no `repo_head` tag**. The document says the proof input carries the
repo head "as pinned by the conformance vectors," and the vector
(`node-advert/005-valid-dual-signed-v050.json`) supplies `repo_head` in its
`input` block, out of band. It appears nowhere in `canonical_wire`.

The consumer of a node advertisement is a light node that has not yet located
the repository — that is the entire point of `kind:31010`. It cannot know
`repo_head`, so it cannot reconstruct the signed bytes, so it cannot execute the
"MUST validate … inner Ed25519 proof" requirement. The bootstrap is circular in
exactly the way Core §6.2 (`heterodyne-core.md:549-551`) says it must not be.

There is a second problem even if the field were carried: a repo head changes on
every push, so binding it into an immutable proof invalidates the advertisement
on the next commit, while the fixture sets `expiry` a day out.

**Recommendation.** Pick one and write it down:
- drop `repo_head` from the proof input (recommended — `rid`, `nid`, `endpoint`,
  `expiry` already bind everything a locator needs, and repo-head integrity is
  established later by Radicle signed refs); or
- add a mandatory `["repo_head","<oid>"]` tag, define its encoding, state that
  the advertisement must be re-signed on head change, and add a
  stale-head-tolerance rule.

Either way the vector needs a negative case where the proof is checked against
a mismatched bound field.

### H-3. Tier 3 publishes its complete audience roster in the clear

Comms §3 (`heterodyne-comms.md:84-86`) describes Tier 3 as "confidential against
everyone without the audience key, including seeders and full nodes," and
`COMMS-I-TIER3-BLIND-CARRIER` says content is encrypted before reaching any
carrier. That is true of *content*. It is not true of *membership*.

`kind:31011` (`heterodyne-comms.md:105-123`) is published once per recipient
with `["d","<key_id>:<recipient npub>"]` and `["p","<recipient npub>"]` in the
clear, epoch-key signed by the persona. `kind:31012`
(`heterodyne-comms.md:125-128`) is a replaceable roster with `d = key_id` and
one clear `p` tag per recipient. Comms §4 (`heterodyne-comms.md:277-283`)
routes these to the persona's ordinary write relays.

The same `key_id` appears as a clear tag on every Tier 3 post
(`heterodyne-comms.md:186-190`). So any relay can join `key_id` across the
roster and the posts and recover, for free: the persona, the complete member
list of every audience, membership deltas over time, and each audience's posting
volume. Rotating on removal (`heterodyne-comms.md:136-144`) publishes a *fresh*
roster, making removals observable too.

The specification demonstrably knows this: §3.3
(`heterodyne-comms.md:230-232`) forbids distributing the config-repository
audience key by published `kind:31011` precisely because "that would reveal the
repository and audience." That reasoning is never generalized, and the threat
model's metadata section (`docs/security/threat-model.md:230-232`) mentions only
the Tier 2 allow-list, not the Tier 3 roster.

`kind:31012` gets an escape hatch — "A sensitive roster MAY instead be carried
inside a Tier 3 encrypted object" — but `kind:31011` has none, and the wraps
alone are sufficient to enumerate membership.

**Recommendation.**
1. State plainly in §3 that Tier 3 provides content confidentiality and **no
   membership or sender privacy**, and require clients to present it that way,
   the same way `COMMS-I-TIER2-HONESTY` handles Tier 2.
2. Add the threat-model row and a metadata entry.
3. Define an optional private distribution path: gift-wrapped (NIP-59) or
   DR-delivered `kind:31011`, or wraps addressed by a
   `HMAC(audience_key, npub)` pseudonym instead of a clear `p` tag, so a relay
   can serve the wrap without learning the recipient.
4. If the trade-off is deliberate — clear `p` tags make wraps fetchable by a
   vanilla relay filter — say so explicitly as a documented cost.

### H-4. The `jwk-thumbprint` native proof has no algorithm allow-list

Core §3.4 (`heterodyne-core.md:212`) defines the `jwk-thumbprint` verifier as
"JWS with a public JWK whose recomputed thumbprint is identical," and §3.4's
rejection list covers unknown types, non-canonical values, private JWK members,
remote key references, and suite/type mismatch. It never constrains the JWS
`alg`. Neither does Comms §10.1 (`heterodyne-comms.md:1009`), which just says
"JWS with an RFC 7638-matching JWK."

The only `alg` constraint anywhere in the family is `RS256` in the OIDC/JWT
projection (`heterodyne-comms.md:1229-1231`) — a different mechanism with a
different key set. So the proof-of-possession path that gates *authorization*
claims has an open algorithm set. RFC 7638 thumbprints are defined for `oct`
keys as well as `RSA` and `EC`; "private JWK members" does not obviously exclude
an `oct` key's `k`. The classic `alg: none` and HS/RS confusion cases are
therefore not excluded by the normative text.

The reference generator already gets this right —
`docs/spec/vectors/generator/src/claims.ts:988-1043` requires the protected
header to contain **only** `alg`, derives the expected algorithm from `kty`,
restricts it to `EdDSA`/`RS256`/`ES256`, and rejects mismatch. None of that is
in the specification. Generator code is explicitly non-normative
(`heterodyne-core.md:1217`).

**Recommendation.** Lift the generator's rules into Core §3.4 as a closed
profile: permitted `kty` values, the exact `kty`→`alg` mapping, "protected
header contains exactly `alg`," minimum RSA modulus, explicit rejection of
`none` and all MAC algorithms, and rejection of any `alg` not implied by the
referenced key. Add negative vectors for `alg: none`, `oct`/HS256, and
kty/alg mismatch.

### H-5. A witness-free persona has no defined resolution for a hostile `none` rotation

Core §4.2 (`heterodyne-core.md:308-310`) requires `threshold` only "when
witnesses exist" and caps it at the sum of weights; the materialized-state
schema allows `"threshold": {"type":"integer","minimum":0}`
(`heterodyne-core.md:940`) and an explicitly empty witness array
(`heterodyne-core.md:949`). Every fixture persona is witness-free.

Core §4.3 (`heterodyne-core.md:348-350`) says a `none` rotation "requires the
prior epoch-key signature and witness threshold." With zero witnesses and
threshold `0`, that second condition is vacuous: **possession of a single epoch
key is sufficient to rotate the persona to an attacker-chosen key**, and the
attacker can chain `none` rotations indefinitely.

The fork rule then breaks down. Core §4.4(4) (`heterodyne-core.md:407-414`)
says "A branch is accepted only if attestations from witnesses that first saw
that branch reach threshold. If none does, the KEL stalls." At threshold `0`,
*both* branches trivially satisfy a zero threshold, so the rule selects neither
and does not stall. The only remaining tiebreak is repo-carried over relay-only
— which resolves nothing when both forks are relay-only, and resolves the wrong
way when the compromised key is also an authorized repo writer.

The legitimate holder's only recovery is a cold-root `committed` rotation, which
is correct but is not stated as the consequence, and the "stalled continuity"
signal that §4.4 promises never fires.

**Recommendation.**
1. Require `threshold >= 1` and at least one declared witness for any persona
   that intends to use `strategy: none`, or forbid `none` outright for
   witness-free personas (a witness-free persona rotates by cold root).
2. Define same-sequence fork behavior explicitly when `threshold == 0`: stall
   and surface duplicity rather than accept.
3. Add vectors: witness-free `none` rotation rejected; threshold-0 fork stalls;
   cold-root `committed` recovery after a hostile `none` chain.
4. Have clients warn a persona that configures zero witnesses about exactly this
   exposure.

---

## 2. Medium severity

### M-1. Registry-pin drift between documents, vectors, and fixtures

All four documents declare "Registry revision: `2`" and
`docs/spec/registry/manifest.json` is at revision 2 with digest
`b52c0a6f…`. But:

- `docs/spec/vectors/coverage/manifest.json`: **262 of 317** vectors pin
  `registry_revision: 1`; only 55 pin 2.
- `docs/spec/vectors/fixtures.json`: `"registry_revision": 1`.
- All four `docs/spec/releases/*/0.5.0.json`: `registry_revision: 2`.

Revision 2 is purely additive over 1 (kinds `31013`/`31014`, six claim/revocation
profiles, 33 reason codes, 11 `COMMS-I-CLAIM*`/`OIDC` invariants), so nothing is
currently *wrong*. The problem is that no document defines what a vector's
registry pin means. Core §14 (`heterodyne-core.md:1194-1196`) says only that
each vector has "a registry pin." Is `1` a frozen assertion that the behavior
was correct at revision 1, or stale metadata? A conformance report that pins
revision 2 cannot tell whether a revision-1 vector is in scope.

**Recommendation.** Define the semantics in Core §14 in one sentence — either
"a vector's registry pin is the earliest revision at which its behavior is
normative and remains valid under every monotonic successor," or "vectors pin
the current revision and are rewritten on bump" — then make `family:check`
enforce it. Bring `fixtures.json` to revision 2 regardless, since it is shared
state, not per-vector history.

### M-2. Feature IDs are load-bearing for conformance but have no allocation authority

Feature IDs appear throughout the normative text: `core.identity.v1`,
`core.repo-relay-client.v1`, `core.embedded-tor.v1`
(`heterodyne-core.md:1079-1083`); `double-ratchet`
(`heterodyne-comms.md:1468`, `heterodyne-control.md:32`); `key-claims`,
`private-claim-ledger`, `oidc-jwt-projection`, `token-status-list-draft-21`
(`docs/spec/releases/comms/0.5.0.json`). Core §12.1 requires
`required_features` in every capability advertisement and §14 requires
conformance reports to enumerate "supported feature IDs."

Yet:
- The registry (`registry.schema.json`) owns only `kinds`, `reason_codes`, and
  `security_invariants`. **There is no feature registry.**
- Two incompatible naming conventions coexist: dotted-and-versioned
  (`core.identity.v1`) and bare-kebab (`double-ratchet`, `key-claims`).
- `docs/spec/releases/core/0.5.0.json` and `.../social/0.5.0.json` both declare
  `"features": []`, contradicting Core §12.1's three required Core features.
- `docs/spec/releases/control/0.5.0.json` lists `"features": ["double-ratchet"]`
  — but that is a Comms feature Control *requires*, not a feature Control
  *provides*. The manifest schema cannot express the difference.

Core §12.1 also says unknown feature IDs "use the same fail-closed rule," which
is unimplementable without a registry to distinguish unknown-because-new from
unknown-because-typo.

**Recommendation.** Add `docs/spec/registry/features.json` under the same
revision and digest discipline as `kinds.json`: `feature_id`, `owner`,
`first_version`, `status`, one-line description. Fix the naming convention to
one form. Split `provides` from `requires` in the release-manifest schema and
populate Core and Social.

### M-3. Byte-exact key derivation is specified only in non-normative generator prose

Comms §3.2 (`heterodyne-comms.md:151-160`) writes:

```text
post_key  = HKDF-SHA256(audience_key, UTF8(key_id), "heterodyne-post-key-v1", 32)
index_key = HKDF-SHA256(audience_key, UTF8(key_id), "heterodyne-index-key-v1", 32)
```

Positional arguments, unlabeled. HKDF takes `(ikm, salt, info, length)` in some
notations and `(salt, ikm, info, length)` in others — RFC 5869's own
`HKDF-Extract(salt, IKM)` puts salt first. Two implementers will read this
differently, and the section immediately above claims byte-exactness.

The binding exists only in generator vector `notes`:

> `docs/spec/vectors/generator/src/topics-v04.ts:855` — "index_key =
> HKDF-SHA256(audience_key, salt=key_id, info=heterodyne-index-key-v1, 32)"
>
> `docs/spec/vectors/generator/src/topics-v04b.ts:468` — "The NIP-44 v2
> symmetric layer takes post_key directly as the conversation key (no ECDH)."

That second sentence is the more important one and it is *only* in generator
code. Comms §3.2 says it "profiles the symmetric ChaCha20/HMAC-SHA256 layer of
NIP-44 v2" without saying at which layer `post_key` is injected. If a reader
takes `post_key` as the per-message key rather than the conversation key, they
skip NIP-44's per-message HKDF-expand over the nonce — and then nonce reuse
across an audience generation becomes catastrophic rather than negligible. The
correct reading is safe; the text does not compel it.

**Recommendation.** Rewrite §3.2 with labeled parameters
(`ikm=`, `salt=`, `info=`, `L=`), state explicitly that `post_key`/`index_key`
substitute for NIP-44 v2's `conversation_key` and that the per-message nonce and
key-expansion steps are unchanged, and add a negative vector for nonce reuse.

### M-4. Deterministic DEFLATE is not deterministic

Comms §14 (`heterodyne-comms.md:1345-1348`) requires `lst` to be "the unpadded
base64url encoding of the deterministic zlib-wrapped DEFLATE level-9 compression
of the bit array," and the verifier procedure
(`heterodyne-comms.md:1360-1364`) requires checking "canonical compression."

DEFLATE output is not standardized at a given level. zlib, zlib-ng, miniz,
Go's `compress/flate`, and Java's `Deflater` all produce different byte streams
for the same input at level 9, and zlib's own output has changed across
versions. `draft-ietf-oauth-status-list` deliberately requires only that
verifiers *decompress* — it does not canonicalize the compressed form.

Because the same bytes are digest-bound into the continuity manifest
(`heterodyne-comms.md:1276-1283`) and required to be byte-identical between
HTTPS and Radicle (`COMMS-I-STATUS-INTEGRITY`), any implementation not using the
exact zlib build the issuer used will fail verification against a
correctly-generated list.

**Recommendation.** Separate the two requirements. Keep byte-identity between
the HTTPS and Radicle mirrors (that is a real integrity property over
whatever bytes the issuer signed). Drop "canonical compression" from the
verifier's checklist — verify the JWS signature over the token bytes, then
decompress and read the bit. If a canonical form really is wanted, pin an exact
DEFLATE encoder profile (fixed Huffman, no dynamic blocks, specified window and
match strategy) and add a cross-implementation vector; otherwise expect
interoperability failures.

### M-5. `same_holder` contradicts Core's unlinkability MUST NOT

Core §2 (`heterodyne-core.md:49-51`): "Separate personas MUST NOT be linked at
the protocol layer." Unqualified.

Social §3.2 (`heterodyne-social.md:169-179`) defines `kind:31004` with
`['relation','same_holder|endorses|endorsed_by|linked']` — a signed, publishable,
symmetric protocol-layer assertion that two personas share a holder. The
`social-strict` fixture even ships a `related_persona` pair as a normative
example.

The user-opt-in design is defensible; the flat contradiction between two
normative documents is not, and Social is downstream of Core, so it cannot
relax a Core MUST NOT.

**Recommendation.** Amend Core §2 to scope the prohibition: "An implementation
MUST NOT link separate personas at the protocol layer except through an
explicit, user-initiated, dual-signed assertion defined by a higher document."
Add the qualified back-reference from Social §3.2. Also require an
unambiguous, irreversible-linkage confirmation before a client emits
`same_holder`.

### M-6. Credential sync has no path back from a permanently dead node

Comms §8.1 (`heterodyne-comms.md:693-695`): "If configured nodes expose
unresolved candidate canonical heads, **or any configured node is unreachable**,
the canonical record set cannot be established and credential sync is held."

Fail-closed is right for authorization. But the condition quantifies over
*every currently configured* full node with no deconfiguration procedure
anywhere in the document. A persona whose node is permanently destroyed can
never establish canonical state again, and therefore can never enroll a
replacement device — which is precisely the situation in which credential sync
matters most. Core §7.5 (`heterodyne-core.md:674-698`) defines
infrastructure-loss recovery for *identity*, but nothing connects that path back
to the Comms credential ledger's node set.

**Recommendation.** Define an authenticated node-set change as a signed,
ledger-committed record (so removing a node is itself subject to the same
canonical-state rules), and specify how a persona re-establishes canonical
config state after permanent node loss — most likely via the Core keys
repository plus a cold-root-authorized reset that records the discontinuity.
Add vectors for permanent-loss recovery and for an attacker attempting to
shrink the node set to win a canonical-state race.

### M-7. Repository durability — the family's central claim — has no conformant server side

Core §10.1 (`heterodyne-core.md:879-883`) is candid: "Server/storage conformance
remains unavailable until the complete ref namespace, filter-to-git mapping,
retention, garbage-collection, and quota contract is frozen."

That is a much larger hole than its placement suggests. "Radicle-backed durable
repositories" is the first line of `CLAUDE.md` and the family map. Every
finality rule in Core §6.2 (`heterodyne-core.md:530-556`), every
`deny-until-repo` decision, org threshold authorization
(`heterodyne-comms.md:365-372`), the claim ledger (`heterodyne-comms.md:1060+`),
and Radicle editorial gating (`heterodyne-social.md:546-558`) all resolve
against canonical repository state produced by a component with **no conformance
definition at all**.

Compounding it: a repo relay "MUST reject invalid Nostr signatures" and "MUST
namespace non-delegate contributions under Radicle's signed-ref model"
(`heterodyne-core.md:861-867`). Any valid Nostr signature — from anyone — can
therefore force git objects into a full node's backing repository. There is no
quota, rate-limit, or admission rule. Core §10.1 disclaims the Heartwood fetch
limits as non-tunable but says nothing about ingestion volume. Storage
exhaustion of a persona's serving node is an inexpensive denial of the persona's
finality, since `deny-until-repo` clients then have no authority source.

**Recommendation.** Elevate this from a §10.1 aside to a named pre-1.0 blocker
with its own tracking. In the interim, add an explicit ingestion-admission
requirement (delegate-authored events accepted unconditionally; third-party
events subject to a declared, advertised policy) so implementations do not ship
an unbounded write sink. The threat model's §9 already lists the contract as
open work — add the storage-exhaustion attack to §5.1 as a named threat rather
than leaving it only in the out-of-scope list.

---

## 3. Low severity / editorial

### L-1. Exact English UI strings are mandated as conformance requirements

`heterodyne-comms.md:392`: the client "MUST surface exactly `feed truncated
after <created_at> / <d-tag>; missing <event_id>`".
`heterodyne-social.md:427`: "MUST surface exactly `post not approved within
7-day window`".
`heterodyne-social.md:432`: SHOULD warn `"the community may not be accepting
your submissions."`

A protocol specification cannot require a literal English sentence in a UI
without breaking localization, screen-reader conventions, and every non-English
deployment. The repository already has the right mechanism: a closed registry
reason-code vocabulary (`docs/spec/registry/reason-codes.json`, 688 lines),
which Core §14 (`heterodyne-core.md:1217`) correctly calls "registry vocabulary,
not a wire API."

**Recommendation.** Convert each to a registered reason code plus a named
structured payload (`referring_page_created_at`, `referring_page_d`,
`missing_event_id`), and demote the English text to a non-normative example.

### L-2. Kind-range defaults contradict the registry-first rule

Core §3 (`heterodyne-core.md:96-98`): "Implementations MUST NOT infer ownership
from the numeric range; they MUST consult the pinned registry entry."

Social §2 (`heterodyne-social.md:81-85`) then sets feed-index defaults by
numeric range: `10000-10999`, `30000-30099`, and `31000-31099` non-indexed. A
future Heterodyne kind allocated at `31017` silently inherits non-indexed status
from its number rather than from a registry declaration — the same failure mode
Core forbids one document down.

**Recommendation.** Add an `indexed_by_default` boolean to the registry kind
entry and have Social read it, keeping ranges only as a fallback for
unregistered upstream kinds. State the exception explicitly if the range rule is
kept.

### L-3. Bare-message attribution does not carve out compromise cutoffs

`heterodyne-social.md:1093-1094`: "A later delegation revocation MUST NOT
retroactively de-attribute an event valid at its own DAG position."

Social §6.2 (`heterodyne-social.md:485-487`) gets the analogous case right: "A
KERI compromise cutoff MUST invalidate approvals signed after the cutoff." Core
§4.3 (`heterodyne-core.md:382-387`) makes `effective_compromise_since`
retroactive for *every* event, "under full replay and every accelerator."

§11.2's unqualified MUST NOT therefore conflicts with Core for the compromise
case: an event signed by an epoch key later declared compromised remains
attributed under Social while Core requires it to lose authority.

**Recommendation.** Amend to: "…MUST NOT retroactively de-attribute an event
valid at its own DAG position, except where a Core compromise declaration covers
the event's `created_at`, in which case attribution MUST be withdrawn and the
event marked compromise-window content."

### L-4. Wall-clock MUST deadlines are unsatisfiable and untestable

Five hard deadlines are stated as MUSTs over an asynchronous, partition-prone
network: `heterodyne-comms.md:139` and `:438` (60 s for index/descriptor
republication after rotation), `heterodyne-social.md:958` and `:998` (60 s for
config-room invite and revoked-MXID removal), `heterodyne-social.md:1400` (30 s
deletion observation in the strict profile).

None is observable by a conformance verifier, and a partitioned device violates
all of them through no fault of its own. Social §10.2 already acknowledges the
tension — "Transient asymmetric membership MUST NOT stop convergence" — without
relaxing the MUST.

**Recommendation.** Restate as "MUST initiate within N seconds of observing the
triggering event and MUST retry until success," which is both implementable and
testable, and note that unbounded delay is an availability condition rather than
a conformance failure.

### L-5. Two profile IDs break the naming convention

Every registered profile is prefixed `heterodyne-` except two, both on the
subprotocol carriers: `comms-subprotocol-negotiation-v1` (kind `31015`) and
`comms-subprotocol-payload-v1` (kind `31016`). Since Core §12.2
(`heterodyne-core.md:1148-1150`) makes profile IDs stable — "changing membership
or an obligation requires a new ID" — renaming gets harder with every release.

**Recommendation.** Rename now, while both are `status: draft` and Control is
non-claimable.

### L-6. `comms_version` is not `spec_version`

Core §3.2 class 1 (`heterodyne-core.md:136-138`): "Heterodyne-defined JSON
`content` MUST contain the qualified `spec_version` of the base-schema owner."
Every other JSON-content kind complies literally — the rotation content object
(`heterodyne-core.md:332`), the org-feed profile
(`heterodyne-social.md:335-339`), the negotiation and payload frames
(`heterodyne-comms.md:815`, `:897`).

Kinds `31013`/`31014` do not. `docs/spec/schemas/comms/key-claim-v1.schema.json`
requires `comms_version` and `key-claim-revocation-v1.schema.json` the same. A
parser implementing Core §3.2 generically will not find the stamp.

Related: `registry_revision` is a schema `const: 2` inside the *signed* claim
body. Any future registry bump — including one that touches nothing about claims
— produces a claim schema whose const no longer matches, forcing a new claim
schema version and re-issuance of long-lived claims for an unrelated reason.

**Recommendation.** Rename `comms_version` → `spec_version` (cheap now,
expensive after release), or add an explicit exception to Core §3.2 naming the
two kinds. Separately, reconsider whether `registry_revision` needs to be inside
the signed body rather than resolved from the pinned conformance claim.

### L-7. `tuple_hash` is computed and never used

Comms §9 (`heterodyne-comms.md:855-866`) defines five transcript hashes. Four
form a chain: `offer_hash` → `selection_hash` → `initiator_confirmation_hash` →
`responder_confirmation_hash`, and the payload frame binds the last one
(`heterodyne-comms.md:897`). `tuple_hash` is chained into nothing and bound by
nothing — the tuple it covers is already carried in cleartext in the same frame
and already committed via the rumor ids in the chain.

**Recommendation.** Either bind `tuple_hash` into `initiator_confirmation_hash`
so it carries weight, or remove it. Four required hashes are easier to implement
correctly than five, one of which is decorative.

### L-8. Capability bootstrap cannot express a registry digest

Core §3 (`heterodyne-core.md:88-90`) says "A conformance claim MUST pin the
registry revision **or** immutable entry-set digest," but the bootstrap object
(`heterodyne-core.md:1068-1086`) has only `"registry_revision": 2` and the
object's unknown-field rule is fail-closed. There is no way to exercise the
digest half of the disjunction.

**Recommendation.** Add an optional `registry_entry_set_sha256` member to the
bootstrap schema, matching what the release manifests already carry.

### L-9. `control-enrollment` is a reachable-looking dead branch

Comms §8 (`heterodyne-comms.md:568-569`, `:594`) admits `control-enrollment` as
a hook context and gives it a default outcome, while Control §7
(`heterodyne-control.md:281-291`) sets `can_claim_control_conformance: false`.
No conforming implementation can legitimately produce that context in 0.5.0.

Forward-declaring it is reasonable, but the Comms text should say so — otherwise
an implementer will build the branch and an auditor will look for the vectors
that gate it.

**Recommendation.** One sentence in §8: "The `control-enrollment` context is
reserved for the Control profile and is unreachable while the Control
conformance gate at `heterodyne:control/0.5.0#control-conformance` remains
closed."

---

## 4. Security observations that are correct and worth preserving

Worth stating so they are not lost in a later refactor:

- **Verification ordering is genuinely fail-closed.** Core §9's
  `seq_ahead_of_accepted_head-before-off_accepted_kel` rule
  (`heterodyne-core.md:809-816`) is named, ordered, and vectorized. Naming an
  ordering rule so it can be cited is a good pattern; apply it more widely.
- **Provisional/final separation is disciplined.** `accept_provisional` vs
  `provisional_not_final` under the two declared key-material policies
  (`heterodyne-core.md:818-825`) is one of the sharper parts of the family, and
  Comms §10.1's seven-state claim result reuses it correctly.
- **Revocation is absorbing and evaluation-time-independent.** Comms §8.1's
  separation of the canonical signed-record set from operational resolution
  (`heterodyne-comms.md:730-746`) is subtle and right — the canonical set and
  its digest do not change when a grant crosses `valid_until`.
- **The acceptance-hook lattice is monotone.** Social §7.4's
  `accept → hold → reject` one-way lattice with an executable fixture
  (`heterodyne-social.md:663-665`) is a good way to make "policy may tighten,
  never loosen" mechanically checkable. More invariants should get fixtures like
  this.
- **Mechanism-guarantee honesty.** Comms §15's closing paragraph
  (`heterodyne-comms.md:1406-1412`) distinguishing Tier 3 / DR / NIP-17 forward
  secrecy is the kind of statement most protocols omit. H-3 asks for the same
  honesty about membership metadata.
- **SSRF controls on ATProto resolution** (`heterodyne-social.md:696-702`) are
  more complete than most specifications bother with. See the one gap below.

---

## 5. One more security gap worth its own note

**DNS rebinding in ATProto DID/PDS resolution.** Social §8.1
(`heterodyne-social.md:696-702`) requires rejecting RFC 1918, loopback,
link-local, wildcard, and non-public resolved addresses, and requires that
"every redirect MUST be independently re-resolved and revalidated."

Re-resolution is exactly the wrong primitive. Validating an address and then
resolving again before connecting is the classic TOCTOU window: an attacker
controlling the DID's DNS returns a public address for the validation lookup and
a private address for the connect lookup. The requirement as written makes the
attack easier, not harder, because it mandates an extra resolution.

**Recommendation.** Require the client to **pin the validated IP address and
connect to that address**, carrying the original hostname in SNI and `Host`.
Apply the same rule to every redirect hop. Add a short bound on validate-to-
connect elapsed time. This is a small change to one paragraph and closes a real
hole in an otherwise strong section.

---

## 6. Prioritized recommendations

| # | Finding | Action | Cost |
|---:|---|---|---|
| 1 | H-1 | Regenerate fixture KELs as valid `core/0.5.0` events; replace the seven `keri/*` placeholders with byte-exact vectors; add a `family:check` rule validating embedded events against the owning document's schema | High |
| 2 | H-2 | Decide `repo_head` in or out of the `kind:31010` proof input; make the advertisement self-verifiable | Low |
| 3 | H-3 | State the Tier 3 membership-metadata boundary in §3, the threat model, and client UI; design a private `kind:31011` distribution path | Medium |
| 4 | H-4 | Lift the generator's closed JWS profile into Core §3.4; add `alg: none`, `oct`/HS256, and kty/alg-mismatch negative vectors | Low |
| 5 | H-5 | Require a nonzero witness threshold for `none` rotations; define threshold-0 fork behavior as stall | Low |
| 6 | §5 | Replace "re-resolve" with "pin the validated IP and connect to it" in Social §8.1 | Trivial |
| 7 | M-7 | Promote the repo-relay server/storage contract to a tracked pre-1.0 blocker; add an interim ingestion-admission rule and the storage-exhaustion threat row | High |
| 8 | M-2 | Add `registry/features.json`; unify feature-ID naming; split provides/requires in release manifests | Medium |
| 9 | M-3, M-4 | Labeled HKDF parameters and explicit NIP-44 layer binding; drop "canonical compression" from the status verifier | Low |
| 10 | M-1, M-5, M-6 | Define vector registry-pin semantics; scope Core's unlinkability MUST NOT; define node deconfiguration | Medium |
| 11 | L-1 … L-9 | Editorial and consistency pass, best done in one change before release | Low |

Items 2, 4, 5, 6, and 9 are small, self-contained edits that close real holes and
should not wait for the larger work.

## 7. Suggested process change

Every high-severity finding here is a case where a normative statement in a
document had no mechanical link to the artifact that was supposed to enforce it:
the spec says vectors are byte-exact and 44% of them are symbolic; the spec says
JWK proofs are verified and only the generator knows how; the spec pins registry
revision 2 and the fixtures pin 1.

`family:check` already parses all four documents for anchors, dependencies, and
BCP 14 usage. Extending it in three ways would close the class:

1. **Schema-validate every event embedded in a vector** against its owning
   document's declared shape. Catches H-1 outright.
2. **Require a declared `evidence_class`** on each vector — `byte-exact`,
   `verdict-only`, or `illustrative` — and fail if a document's minimum vector
   set claims byte-exact coverage that no `byte-exact` vector supplies. Makes
   the 25-vs-135 ratio visible instead of latent.
3. **Cross-check pins**: `fixtures.json`, coverage manifest, release manifests,
   and document headers must agree on registry revision under whatever rule M-1
   settles on.

That is a smaller investment than the specification work it protects, and it is
the difference between a spec that is careful and one that stays careful.
