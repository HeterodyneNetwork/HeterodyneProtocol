# Heterodyne glossary

This glossary is non-normative. The six-document specification family and its
live registry and schemas govern when a short definition omits a condition.

## Protocol and authority

**Active Nostr key**
: The public key that identifies a baseline persona and whose corresponding
  private key signs that persona's NIP-01 events. A bare active key is a
  first-class identity and does not require Assurance.

**Persona**
: The application identity represented by one active Nostr public key. Valid
  signatures by that key establish its baseline authorship.

**Author**
: The public key that actually produced a valid NIP-01 signature on an event.
  Display metadata, an associated agent, a moderator, a repository, a relay,
  and optional Assurance cannot substitute another author.

**Core**
: The required family member for active-key identity, discovery, repositories,
  versions, registries, schemas, and base conformance.

**Assurance**
: The optional family member for reciprocal continuity enrollment, recovery
  authority, associated keys, succession evidence, and lossless KERI export.
  Its absence or failure does not invalidate a Core-valid persona.

**Comms**
: The Core-dependent family member for delivery, privacy tiers, Marmot,
  claims, private ledgers, OIDC/JWT projections, automation attribution,
  archives, and trusted seeds.

**Control**
: The Comms-dependent family member for own-device enrollment, standard
  NIP-46 signing, persona vaults, audit, and compromise reset.

**Social**
: The Comms-dependent family member for social events, public interactions,
  local moderation, and durable social assets.

**Workspace**
: The Comms-dependent family member for workspace identity, roles, private
  discovery, federation, hosting, and resource-key delivery.

**Strict profile**
: A conformance profile whose required invariant set is the transitive closure
  of declared prerequisite profiles plus only the invariants it adds. The
  six-document strict profile includes optional Assurance; baseline Core does
  not.

**Family registry revision**
: The authoring revision in `docs/spec/registry/manifest.json` for the current
  registry entry set. It is not a wire member and is not a released version.

**Claim profile revision**
: The frozen claim schema member `profile_revision` has value `2`, distinct from the current family registry revision 14. It labels the claim-profile
  wire shape and does not track registry authoring changes.

## Discovery and storage

**Kind `0` profile**
: Ordinary active-key-signed Nostr profile metadata. Along with NIP-05 name
  resolution and NIP-65 relay preferences, it forms the baseline discovery
  surface.

**NID**
: A Radicle node identifier. A NID writer joins a repository union only after
  both the persona owner and that NID prove the same exact delegation binding.

**RID**
: A Radicle repository identifier. Possession, replication, Git authorship, or
  hosting of a RID does not itself grant Heterodyne authority.

**Persona repository**
: A persona-owned Radicle repository carrying exact signed objects in
  independently authorized NID refs.

**Repository union**
: The locally verified union of objects from authorized writer refs. Invalid
  or unauthorized refs contribute nothing.

**Source-neutral selection**
: Selection based on signatures, coordinates, protocol replacement rules, and
  recency rather than whether an exact event arrived from a relay or a
  repository. An observation older than seven days triggers a warning and
  refresh attempt; age alone does not invalidate it.

**Full node**
: A user-controlled service that may host repositories, coordinate policy and
  devices, and act as a NIP-46 signer. Relay service is a separately advertised
  capability, not an intrinsic full-node role.

**Light client**
: A client that uses a full node without receiving persona, NID, repository,
  issuer, seed, or Marmot-leaf private keys.

## Privacy and Marmot

**Tier 1**
: Public, locally verified signed content.

**Tier 2**
: Plaintext selectively replicated through private repositories. This is an
  access boundary, not encryption; every repository reader may observe it.

**Tier 3**
: Audience- or group-encrypted content whose carriers do not receive plaintext.

**Marmot account**
: The standard Marmot account identified by the active persona key. The active
  persona key is the Marmot account key; optional Assurance does not create an
  alias inside MLS.

**Marmot device leaf**
: One independently revocable MLS leaf for an account device. Independent
  leaves do not share their secret by default.

**Trusted seed**
: An availability helper authorized to carry routing metadata and exact
  encrypted Marmot event bytes. Multiple trusted seeds may be active
  concurrently. A seed obtains no persona, repository-owner, group-admin,
  full-node, or MLS authority merely by serving that role.

**Marmot archive**
: Exact-byte storage of signed Marmot conversation events and encrypted media
  ciphertext through Radicle. Marmot remains authoritative for MLS and its
  Nostr transport semantics.

## Authorization and automation

**Persona vault**
: The isolated full-node state for one persona. Key material, grants,
  repositories, audit context, and signer fallback cannot cross its boundary.

**Signer grant**
: A current, revocable, domain-separated authorization binding the persona,
  NIP-46 client, audience, selected signing key and class, methods, kinds,
  finite limits, and time bounds.

**Agent key**
: A registered Nostr signing key for automation. It is preferred for automated
  events; persona-key automation needs an explicit narrow OIDC scope.

**Automation attribution**
: A canonical protected block derived from authenticated current policy,
  digest-bound to the closed intent, durably reserved, and added before
  signing. Caller input cannot suppress it or enlarge its scopes.

**Execute-once fence**
: A durable signer-side token state transition acquired before a key effect.
  Acquisition poisons the token against reacquisition; exact terminal retries
  return isolated cached results and uncertain terminal persistence requires
  reconciliation.

**Complete compromise reset**
: The reset required after active-key compromise: revoke NIP-46 and OIDC
  grants, invalidate subordinate authorities and trusted seeds, remove old
  device leaves, advance reachable groups, publish fresh KeyPackages, and
  explicitly issue fresh distinct continuing authorizations.

**Continuity succession**
: Optional Assurance evidence connecting a former active key to a successor.
  The successor stays a distinct Nostr author and Marmot account; no
  subordinate authority continues implicitly.

## Validation lanes

**Current-draft lane**
: The checker for live specifications, registry entries, schemas, and current
  reference code. It does not execute frozen topic projections.

**Rolling snapshot**
: The non-normative set of 482 frozen historical vectors authored from source
  commit `2ef40a6d6304f8f5e6162f84c12b7b03a42a3c43` and bound by snapshot
  commit `5d4bb5fb58b35c88d8a9db120a09f1087237f35c`. It records a past validation
  surface and does not define current-draft conformance.
