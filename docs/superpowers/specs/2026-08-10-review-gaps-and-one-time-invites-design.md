# Review-gap remediation and one-time invites

Date: 2026-08-10

Status: approved design, pending implementation

## Objective

Repair the normative inconsistencies found after the Marmot Control migration
and add a simple, provider-independent one-time invitation path for direct
messages, private Control principals, and KERI-authorized devices. The final
patch must leave the specification family and machine-readable artifacts
canonical and self-contained. ADR 042 will be an archived historical record,
not a normative dependency.

## Confirmed review findings

The review findings are substantively correct:

1. The current Comms acceptance hook describes only Control groups, while the
   retained acceptance vectors and Social admission policy still use the
   deleted double-ratchet vocabulary. Ordinary Marmot direct-message Welcomes
   have no message-request admission rule.
2. `heterodyne-control-strict-v1` does not contain the complete flattened Core
   and Comms invariant closure required by Core.
3. Cross-document feature dependencies are load-bearing but have no
   machine-readable allocation authority. Release manifests also conflate
   provided and required features.
4. Default-on unsolicited Control enrollment has no bounded state or
   KeyPackage-abuse policy.
5. The RFC 8628 projection omits user-code throttling and entropy and
   high-entropy device-code requirements. User-code guidance is in RFC 8628
   section 5.1; device-code guidance is in section 5.2.
6. Control authorization-view freshness has no protocol maximum.
7. Epoch-key use as both BIP-340 authority and a NIP-59 recipient is not
   surfaced in the threat model.

The implementation must also correct the duplicate
`control.recovery.radicle.v1` entry in the release-manifest schema.

## Invitation admission boundaries

Comms will define two separate hooks after Marmot cryptographic validation:

- The ordinary-conversation hook consumes authenticated Marmot inviter and
  recipient accounts, the exact group identifier and KeyPackage reference,
  supported capabilities, prior local acceptance, a valid one-time DM invite
  if present, and an explicit local decision. Its closed outcomes are
  `accept`, `hold-as-message-request`, and `reject`.
- The Control hook consumes authenticated Marmot accounts and leaves, the
  exact group identifier and KeyPackage slot, selected Control version and
  profile, node invitation mode, resource-limit state, private entitlement,
  a valid purpose-bound invite if present, and an explicit local decision.
  Its closed outcomes are `accept-enrollment-only`, `accept-authorized`, and
  `reject`.

An unknown but valid ordinary two-member Welcome defaults to
`hold-as-message-request`. A held conversation emits no receipt, typing,
read, presence, retry, or other sender-observable acceptance signal. A valid
one-time DM invite makes the Comms-native result `accept` for its issuer.
Social mutes, blocks, and web-of-trust policy may only preserve or tighten the
ordinary-conversation result; `reject` remains absorbing.

The Control hook is not a Social admission input. Marmot group membership and
transport validity never grant application authority.

## Control invitation modes and resource bounds

Each full node has exactly one unsolicited Control invitation mode:

- `off`, the default;
- `temporary`, with an authenticated expiry after which the node returns to
  `off`; or
- `permanent`, until explicitly changed.

Open modes may use Marmot's standard `last_resort_key_package` facility for
the public Control slot. This avoids treating every valid Welcome as
irreversible depletion of a single-use public inventory. It does not remove
the need to bound state.

Before durable Welcome acceptance and KeyPackage mutation, a node enforces:

- at most one pending enrollment-only group per authenticated account;
- a finite configured global pending-enrollment cap;
- a hard 30-minute lifetime for an enrollment-only group;
- finite rate and burst limits for Welcome processing and KeyPackage
  replenishment;
- no public-pool replenishment while the global pending cap is full; and
- at least one separately classified invitation slot reserved for an active
  entitled client or an explicitly approved enrollment.

Expired, duplicate, over-quota, disabled, malformed, or unsupported attempts
are rejected during Marmot's tentative Welcome validation, before durable
group creation or KeyPackage consumption. Existing authorized groups are not
terminated merely because the node changes its unsolicited-invitation mode.

## Provider-independent one-time invite envelope

One closed invite format supports three non-convertible purposes:

- `dm`;
- `control-enrollment`; and
- `device-enrollment`.

A normal HTTPS Heterodyne client URL carries the invite envelope in its URL
fragment as `#v1.<base64url-no-pad(JCS(envelope))>`. The closed envelope has
exactly `descriptor`, `signature`, and `secret`. The web origin only loads a
compatible client; it is not authority and does not receive the fragment.
Other hosts may serve the same format, and changing the client origin does not
change the signed descriptor or invite identity.

The signed descriptor binds at least:

- format version and exact purpose;
- inviter Marmot account and, for persona-device enrollment, current Core/KERI
  authority evidence;
- random invite ID;
- fresh ephemeral Nostr rendezvous public key;
- one or more normalized relay hints;
- issue and expiry times;
- SHA-256 commitment to a random 256-bit invite secret;
- whether redemption requires an interactive approval; and
- any exact preauthorization template and expected client public key.

The descriptor is JCS-canonical. `signature` is a BIP-340 signature by the
declared inviter Marmot account over
`SHA-256("heterodyne.one-time-invite.v1" || 0x00 || JCS(descriptor))`. The
descriptor contains only `SHA-256(secret)`; the random secret itself occurs
only in the fragment envelope and protected local issuer state.

A responder generates its Marmot account and KeyPackage locally, then sends a
NIP-59 response to the ephemeral rendezvous key. Registry revision 6 allocates
one Heterodyne-owned unsigned response-rumor kind and a closed response schema.
The NIP-59 seal authenticates the responder account, which must equal the
rumor `pubkey`. The response binds the descriptor digest, fresh serialized
Marmot `mls_key_package` MLSMessage bytes, requested class and capabilities,
and `HMAC-SHA-256(secret, "heterodyne.one-time-invite-response.v1" || 0x00 ||
SHA-256(JCS(response-without-proof)))`. It never carries a persona, device,
epoch, NID, MLS-leaf, repository, or agent-role private key.

Invite state is restart-safe and moves from `active` to `reserved` for the
first completely valid account and canonical response digest, then to `spent`
after successful group establishment. The same reserved responder may retry;
another responder cannot race it. Malformed, expired, revoked,
purpose-mismatched, capability-incompatible, or invalidly authenticated
traffic cannot reserve or spend the invite.

DM invites default to 24 hours and have a configurable maximum of seven days.
Control and device-enrollment invites default to 10 minutes and have an
absolute maximum of one hour.

## Enrollment effects

A `dm` redemption creates a standard two-member Marmot group. The inviter
returns the standard Welcome and locally accepts the conversation, subject to
an absorbing mute or block.

A `control-enrollment` redemption creates a standard pairwise Control group.
By default it bypasses only unsolicited-invitation admission; explicit
approval and durable private entitlement remain required.

A node may be configured to issue a pre-authorized Control invite for a
private `human-light` or `automated` principal. Its descriptor binds the exact
client class, methods, objects, finite limits, agent role, token-lifetime
ceiling, and optional expected client key. Automated enrollment is key-bound
by default. An explicitly enabled unbound bearer template is reported as
higher risk. Redemption can activate only the bound entitlement and still
uses the normal full-node-held signing and agent-attribution path.

Pre-authorized prompt-free redemption is forbidden for every KERI-authorized
persona device.

A `device-enrollment` invite may request any Core device class. The joining
device generates and retains its own keys. Redemption establishes the
authenticated rendezvous but never substitutes for explicit approval,
epoch-key authorization, KERI delegation, repository verification, or the
full/recovery completion ceremony applicable to the requested class.

## OAuth Device Authorization hardening

The Control projection will require:

- a device code with at least 128 bits of uniformly random entropy;
- a user code with at least 34.5 bits of entropy;
- no more than five failed guesses for one active user code;
- per-code and node-wide rate limiting;
- constant-time code comparison after the declared normalization;
- identical code and client fingerprint on initiating and approving displays;
- RFC 8628 polling interval and `slow_down` behavior; and
- atomic invalidation on success, denial, expiry, or attempt exhaustion.

Codes remain node-local, one-use, short-lived, non-replicated, and excluded
from backups.

## Authorization freshness

Token issuance and every privileged Control request require an authenticated,
non-conflicted private authorization view no more than 300 seconds old.
Mutation processing additionally performs an immediate synchronization
attempt before authorization and fails closed if a fresh canonical view
cannot be established. A node cannot extend stale authority by minting a new
token.

## Epoch-key threat boundary

The threat model will state that the same epoch scalar is intentionally used
for BIP-340 authority signatures and Nostr-compatible NIP-59 recipient ECDH.
Compromise of either use therefore compromises both. Implementations must
domain-separate protocol inputs, bound inbox work before decryption, reject
malformed ciphertext without invoking a signing operation, and never sign
while processing untrusted epoch-inbox ciphertext. The epoch key remains
encrypted and absent from memory outside the explicit short unlock ceremony.

## Feature allocation and strict-profile repair

Registry revision 6 will add a normative feature catalog with globally unique
dotted-and-versioned feature IDs, owner document, first version, status,
description, specification reference, and acyclic prerequisite list. The four
legacy bare Comms names become:

- `comms.key-claims.v1`;
- `comms.private-claim-ledger.v1`;
- `comms.oidc-jwt-projection.v1`; and
- `comms.token-status-list-draft-21.v1`.

Release manifests will replace ambiguous `features` with disjoint
`provided_features` and `required_features`. Each required feature must be
owned and provided by an exact declared dependency release. Catalog entries,
release manifests, capability advertisements, document fixtures, registry
history, and the registry digest must agree.

`heterodyne-control-strict-v1` will be corrected in place during the 0.x draft
phase to contain the complete 27-invariant flattened closure required by its
Core and Comms prerequisites. Generator checks will reject incomplete or
conflicting flattened membership.

## Normative artifacts and verification

Implementation will create proposed ADR 042, update the complete specification
family in the same branch, accept and archive the ADR before review, and leave
no normative reference to it outside the changelog/audit trail.

The patch will update:

- Comms, Control, Social, Core registry/conformance text, the threat model,
  glossary, and changelog;
- registry schema, feature catalog, revision-6 snapshot, manifest, and digest;
- release-manifest schema and all four release manifests;
- invite, Control, and any affected authorization schemas;
- the vector generator, validation lint, coverage manifests, and normative
  vectors; and
- every registry pin and artifact digest affected by revision 6.

Acceptance-gating vectors will use Marmot accounts, group identifiers,
KeyPackage references, invitation state, entitlement state, and the two closed
outcome vocabularies. New vectors will cover ordinary message requests,
no-receipt behavior, Social tightening, Control modes and quotas, last-resort
slot behavior, invite purpose/expiry/replay/reservation, preauthorization
boundaries, RFC 8628 guessing defenses, stale authorization views, feature
dependency resolution, and strict-profile flattening.

Final verification is:

```text
npm --prefix docs/spec/vectors/generator run family:check
npm --prefix docs/spec/vectors/generator run check
git diff --check
```

Because normative vectors change, the full vector suite is required.
