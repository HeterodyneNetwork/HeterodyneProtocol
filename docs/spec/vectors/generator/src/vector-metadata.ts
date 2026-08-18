import { FAMILY_VERSION, QUALIFIED_VERSION } from "./family.js";
import type { DocumentId } from "./types.js";

export type VectorMetadata = {
  owner_document: DocumentId;
  spec_version: string;
  profile?: string;
  spec_refs: string[];
};

const ids = (value: string) => new Set(value.trim().split(/\s+/));

// Ownership is assigned per vector, never inferred from its directory.
// This exhaustive inventory intentionally names every pre-split vector ID.
const CORE_IDS = ids(`
config-backup/config-rid-advertised-rejected
config-backup/config-rid-unadvertised-clean
config-backup/nip49-nsec-wrap
identity-doc/add-before-remove
identity-doc/emergency-reanchor
identity-doc/kel-revoked-nid-rejected
identity/delegation-active
identity/delegation-expired
identity/delegation-revoked
identity/kind31005-race-tiebreaker-core
identity/revocation-post-window
identity/root-attestation-valid
interop/kind31005-identity-pointer
keri-authority/accelerator-backdated-compromise
keri-authority/accelerator-decision-equivalent
keri-authority/delegation-conflict-repo-wins
keri-authority/dependent-events-unresolved
keri-authority/equivocation-flagged
keri-authority/export-aid-digest-anchoring
keri-authority/export-aid-substituted-for-npub-rejected
keri-authority/export-degraded-metadata
keri-authority/export-incomplete
keri-authority/export-origin-absent-not-failure
keri-authority/export-unmappable-feature
keri-authority/export-unsupported-crypto-suite
keri-authority/kel-head-absent-rejected
keri-authority/kel-head-duplicate-rejected
keri-authority/kel-head-forbidden-on-inception
keri-authority/kel-head-forbidden-on-rotation
keri-authority/kel-head-malformed-rejected
keri-authority/kel-head-mandatory-on-delegation
keri-authority/kel-head-mandatory-on-root
keri-authority/kel-head-seq-mismatch-rejected
keri-authority/keri10json-cesr-wire-rejected
keri-authority/materialized-atomic-rebuild
keri-authority/materialized-empty-kel-deletion
keri-authority/materialized-log-derivation
keri-authority/materialized-refs-not-authority
keri-authority/materialized-state-derivation
keri-authority/provisional-not-hardened-repo-unreachable
keri-authority/refresh-failed-not-condition-d
keri-authority/repo-head-regression-rejected
keri-authority/withdrawal-causally-behind-no-withdraw
keri-authority/withdrawal-converged-head
keri/didkey-witness-no-network
keri/first-seen-ordering
keri/fork-resolution-conflicting-rotations
keri/inception-event
keri/informal-vouch-not-counted
keri/rotation-committed-strategy
keri/rotation-none-witness-threshold
light-node/content-not-through-routing-node
light-node/route-around-withholding-host
light-node/verifies-signature-locally
nid-binding/bidirectional-valid
nid-binding/invalid-nid-proof-rejected
nid-binding/missing-nid-proof-rejected
node-advert/expired-rejected
node-advert/nid-proof-invalid-rejected
node-advert/outer-sig-invalid-rejected
node-advert/valid-dual-signed
node-advert/maximum-lifetime
node-advert/excessive-lifetime
node-advert/future-clock-skew
node-advert/past-clock-skew
node-advert/expiry-not-after-created
node-advert/refresh-by-twelve-hours
node-advert/uncertain-clock-rejected
node-advert/previously-accepted-within-expiry
node-advert/provisional-observation-does-not-bypass-skew
org/member-add-dual-authorized
org/member-add-single-authorization-insufficient
org/threshold-delegate-governance
relay-profile/kel-aware-reputation-continuity
relay-profile/nip11-capability-advert
relay-profile/passive-witness-store-signs-nothing
relay-profile/vanilla-nip01-unaffected
repo-relay/invalid-signature-rejected
repo-relay/light-node-submit-write-path
repo-relay/nip01-read-write-roundtrip
routing-node/expired-advert-discarded
routing-node/repo-location-from-ads-only
routing-node/unverifiable-advert-discarded
social-recovery/cold-root-reanchor-authoritative
social-recovery/cache-sourced-marked-stale
transport/egress-tor-off-default-indicator
transport/onion-no-clearnet-dns-leak
transport/onion-reachable-via-tor
transport/strict-mode-egress-tor-default-on
transport/wasm-bridge-no-bridge-indicator
verification/backdated-event-suspicion-window
verification/bad-signature-rejects
verification/delegation-mismatch-rejects
verification/revoked-key-rejects
versioning/capabilities-roundtrip
versioning/older-receiver-newer-sender
versioning/unknown-major-placeholder
core-redundancy/radicle-multihost-replication
core-redundancy/stale-seed-does-not-remove-durability
versioning/qualified-version-valid
versioning/qualified-version-unqualified-rejected
versioning/core-capability-bootstrap
versioning/exact-family-version-negotiation
versioning/unknown-asynchronous-stamp-rejected
persona-profile/designated-publisher-valid
persona-profile/nip05-mismatch-rejected
persona-profile/successor-address-republished
persona-profile/exact-author-set-discovery
persona-profile/relay-only-replacement-rejected
key-retirement/repo-anchored-pre-retirement
key-retirement/local-receipt-pre-retirement
key-retirement/relay-only-provisional
key-retirement/compromise-cutoff-rejected
stamping/heterodyne-json-content-owner
stamping/heterodyne-empty-content-tag-owner
stamping/upstream-unstamped
stamping/upstream-profile-owner
stamping/non-stamping-profile-unchanged
stamping/tier3-profile-owner
profiles/core-breadcrumb-kind0
profiles/core-breadcrumb-kind1
breadcrumbs/unrelated-successor-rejected
breadcrumbs/compromise-rotation-not-produced
breadcrumbs/repointed-nip05-rejected
breadcrumbs/ordinary-consumer-no-profile-inference
registry/downref-nonfrozen-rejected
registry/frozen-entry-immutable
registry/feature-dependency-exact
registry/feature-dependency-unprovided-rejected
registry/control-strict-profile-flattened
role-capabilities/public-reader-reduced-assurance
role-capabilities/strict-missing-tor-rejected
role-capabilities/full-node-feature-set-required
role-capabilities/full-node-onion-advertised
role-capabilities/full-node-tor-default
role-capabilities/browser-shared-relay-required
role-capabilities/role-address-valid
role-capabilities/role-address-invalid
`);

const COMMS_IDS = ids(`
agent-authorship/delegation-valid
agent-authorship/delegation-key-proof-invalid
agent-authorship/role-key-replacement
agent-authorship/multiple-roles-one-nid
agent-authorship/stable-identity-renewal
agent-authorship/cross-persona-unlinkable
agent-authorship/workload-registration-valid
agent-authorship/workload-registration-unbounded-rejected
agent-authorship/token-valid
agent-authorship/token-expired
agent-authorship/token-revoked
agent-authorship/token-audience-invalid
agent-authorship/token-sender-proof-invalid
agent-authorship/token-role-mismatch
agent-authorship/attribution-kind-1
agent-authorship/attribution-kind-6
agent-authorship/attribution-kind-7
agent-authorship/attribution-kind-16
agent-authorship/attribution-kind-1063
agent-authorship/attribution-kind-1985
agent-authorship/attribution-kind-4550
agent-authorship/attribution-kind-30023
agent-authorship/caller-forgery-replaced
agent-authorship/human-review-preserves-agent-label
agent-authorship/tier3-inner-only
agent-authorship/profile-unavailable-rejected
agent-authorship/idempotent-retry-reuses-event
public-reader/launcher-persona-roundtrip
public-reader/launcher-event-roundtrip
public-reader/launcher-address-roundtrip
public-reader/target-absent-from-http-path
public-reader/unknown-version-no-network
public-reader/malformed-entity-no-network
public-reader/oversized-fragment-no-network
public-reader/credential-relay-hint-rejected
public-reader/localhost-relay-hint-rejected
public-reader/private-resolved-relay-hint-rejected
public-reader/onion-hint-tor-required
public-reader/nip65-refresh-replaces-stale-hint
public-reader/resolution-canonical
public-reader/resolution-provisional-canonical
public-reader/resolution-unindexed-signed-event
public-reader/resolution-conflicted
public-reader/resolution-unavailable
public-reader/resolution-private
public-reader/tier3-refused
public-reader/external-media-disclosure
public-reader/transition-without-reload
public-reader/logout-cleanup
public-reader/failed-revocation-expiry
claims/canonical-nostr-subject
claims/canonical-radicle-nid-subject
claims/canonical-jwk-thumbprint-subject
claims/claim-id-mismatch
claims/persona-issuance-active
claims/delegated-issuance-active
claims/third-party-issuer-untrusted
claims/chain-attenuation-valid
claims/chain-widening-rejected
claims/chain-depth-exceeded
claims/subject-proof-valid
claims/copied-proof-rejected
claims/provisional-authorization-denied
claims/repository-confirmed-active
claims/authorization-self-revocation
claims/descriptive-subject-rejection
claims/public-claim-publication
claims/pairwise-private-marmot-delivery
claims/repository-private-encryption
claims/local-only-no-publication
claim-ledger/reader-nid-authorized
claim-ledger/nidless-reader-denied
claim-ledger/delivered-grant-provisional
claim-ledger/immediate-revocation
claim-ledger/multiwriter-revocation-wins
claim-ledger/authority-reduction-wins
claim-ledger/nonmonotonic-conflict-blocks
claim-ledger/checkpoint-rollback-rejected
claim-ledger/keyed-path-metadata-private
claim-ledger/reader-removal-key-rotation
claim-ledger/multiwriter-status-allocation
claim-ledger/stale-minter-denied
claim-ledger/source-claim-revokes-token
oidc/discovery-exact-issuer
oidc/issuer-mismatch-rejected
oidc/authorization-code-pkce
oidc/device-authorization
oidc/prohibited-grants
oidc/pairwise-subject
oidc/stable-key-consent-gated
oidc/id-token-valid
oidc/rfc9068-access-token-valid
oidc/token-type-confusion-rejected
oidc/dpop-confirmation-bound
oidc/registered-jwt-assertion
oidc/mtls-confirmation-bound
token-status/valid-status-list
token-status/invalidated-token
token-status/stale-status-list-rejected
token-status/writer-index-collision-rejected
token-status/https-radicle-byte-identity
token-status/radicle-digest-mismatch
token-status/https-outage-radicle-fallback
token-status/issuer-successor
token-status/signing-key-compromise
config-backup/config-blob-encrypt-decrypt
config-backup/key-id-derivation
config-backup/key-rotation-ref-delta
index/complete-fetch-attempt
index/missing-predecessor-structured-outcome
index/prev-page-hash
org/canonical-branch-reachability
outbox/full-public-outbox
outbox/scoped-outbox
outbox/transitive-discovery-walk
privacy-tiers/audience-key-rotation-on-removal
privacy-tiers/complete-fetch-attempt
privacy-tiers/tier3-membership-metadata-disclosed
privacy-tiers/non-circular-bootstrap
privacy-tiers/tier1-public-plaintext-both-backends
privacy-tiers/tier2-private-repo-not-encrypted
privacy-tiers/tier3-index-key-derivation-and-encryption
privacy-tiers/tier3-kind31011-audience-key-wrap
privacy-tiers/tier3-kind31012-audience-roster
privacy-tiers/tier3-prev-page-hash-mismatch
privacy-tiers/tier3-prev-page-hash-valid
privacy-tiers/all-active-devices
privacy-tiers/selected-device-narrowing
privacy-tiers/cold-root-recipient-rejected
privacy-tiers/epoch-recipient-rejected
privacy-tiers/revoked-device-rejected
privacy-tiers/light-device-decryption
privacy-tiers/device-removal-rotates-generation
relay-interop/auth-rejection-permanent
relay-interop/keri-rotation-auth-new-key
relay-interop/nip42-auth-current-epoch-key
acceptance-gating/authentication-before-policy
acceptance-gating/message-request-no-receipt
acceptance-gating/established-ordinary-accept
acceptance-gating/new-ordinary-hold
acceptance-gating/authentication-reject
acceptance-gating/dm-invite-accept
acceptance-gating/ordinary-explicit-reject
acceptance-gating/control-default-off-reject
acceptance-gating/control-permanent-enrollment-only
acceptance-gating/control-entitled-authorized
acceptance-gating/control-entitlement-conflict-reject
acceptance-gating/control-capacity-reject
acceptance-gating/control-explicit-reject-absorbing
one-time-invite/descriptor-and-fragment
one-time-invite/response-proof
one-time-invite/purpose-mismatch
one-time-invite/expired
one-time-invite/first-valid-reservation
one-time-invite/reserved-responder-retry
one-time-invite/reservation-race-rejected
one-time-invite/invalid-keypackage-no-reservation
profiles/tier3-kind-1
profiles/tier3-kind-6
profiles/tier3-kind-16
profiles/tier3-kind-1063
profiles/tier3-kind-30023
profiles/tier3-kind-30402
credential-continuity/checkpoint-genesis
credential-continuity/stale-generation
credential-continuity/pending-retirement-conservative
credential-continuity/retention-inventory-genesis
credential-continuity/governed-obligation-equation
credential-continuity/routine-removal-complete
credential-continuity/cold-root-exposure-migrates
credential-continuity/candidate-exact-tip-append
credential-continuity/config-git-raw-projection
credential-continuity/seventeen-schemas-draft
`);

const SOCIAL_IDS = ids(`
agent-moderation/receipt-valid
agent-moderation/receipt-malformed
agent-moderation/receipt-private-leakage
agent-moderation/policy-list-valid
agent-moderation/policy-binding-mismatch
agent-moderation/subscribed-canonical-mutes
agent-moderation/unsubscribed-no-effect
agent-moderation/relay-only-no-effect
agent-moderation/unmerged-pr-no-effect
agent-moderation/default-visible-removable
agent-moderation/replacement-key-independent
agent-moderation/correction-valid
agent-moderation/correction-list-retained
agent-moderation/correction-list-removed
atproto/pinned-public-hop
atproto/connection-pinning-unavailable
identity/identity-room-full-state
discussion/reaction-reply-bare-not-indexed
interop/vanilla-nostr-only-follow
lists/kind-mute-set-addressing
lists/mute-list-private-items-encrypted-to-self
lists/mute-list-public-roundtrip
lists/policy-list-adoption-parsed
lists/private-items-reencrypt-on-rotation
lists/stale-list-rollback-rejected
moderation/approvals-required-absent-default-one
moderation/contributor-implicit-rejection-window
moderation/kind34550-approvals-required
moderation/moderator-rotation-through-kel
moderation/multi-mod-requirement
moderation/nip72-approval
moderation/radicle-editorial-gating
moderation/redaction-of-approved-post
moderation/relay-only-created-at-fallback
moderation/repo-anchor-asof-after-removal-rejected
moderation/repo-anchor-asof-before-removal-counts
moderation/strict-mode-bare-not-hidden
moderation/strict-mode-invalid-event-signature
moderation/strict-mode-kind5-deletion-30s
moderation/strict-mode-state-downgrade-warning
outbox/cross-backend-reply-dedup
outbox/cross-persona-attestation-invalid
outbox/cross-persona-attestation-valid
social-recovery/retention-30-days
social-recovery/three-tier-caching
versioning/unknown-room-kind-tolerance
acceptance-gating/social-mute-tightens
acceptance-gating/social-policy-cannot-loosen
acceptance-gating/social-wot-tightens-only
acceptance-gating/social-wot-cannot-loosen
profiles/social-org-feed-kind31007
`);

const CONTROL_IDS = ids(`
control/invitation-enrollment-only
control/invitation-disabled
control/invitation-revoked
control/invitation-nonenrollment-rejected
control/invitation-account-cap
control/invitation-global-cap
control/invitation-rate-limited
control/invitation-replenishment-paused
control/invitation-reserved-slot
control/pending-enrollment-live
control/pending-enrollment-expired
control/entitlement-reduction
control/entitlement-expansion-rejected
control/entitlement-revocation-absorbing
control/token-default-five-minutes
control/token-explicit-sixty-minutes
control/token-extension-missing-capability
control/token-valid
control/token-wrong-sender
control/token-wrong-group
control/token-wrong-node
control/token-scope-rejected
control/token-stale-authorization-view
control/token-over-sixty-minutes-rejected
control/token-entitlement-id-mismatch
control/token-client-key-mismatch
control/token-client-id-mismatch
control/token-client-class-mismatch
control/token-current-scope-mismatch
control/token-current-method-mismatch
control/token-current-object-mismatch
control/token-current-limit-mismatch
control/token-registry-checkpoint-mismatch
control/token-agent-role-mismatch
control/token-current-lifetime-mismatch
control/token-human-role-omitted
control/device-code-hardened
control/device-code-exhausted
control/device-code-node-rate-limited
control/device-code-display-mismatch
control/authorization-fresh-read
control/authorization-stale-read
control/authorization-mutation-sync-failed
control/invite-preauthorization-key-bound
control/invite-preauthorization-unbound-rejected
control/invite-preauthorization-keri-rejected
control/invite-preauthorization-unbound-higher-risk
control/operation-first-reservation
control/operation-identical-join
control/operation-conflicting-bytes
control/failover-read
control/failover-idempotent-mutation
control/failover-indeterminate-mutation
control/retention-ceiling-and-backup-exclusion
control/epoch-locked
control/epoch-prepare-and-relock
control/epoch-exact-activation
control/epoch-activation-mismatch
control/recovery-grant-accepted
control/recovery-grant-confined
control/sftp-grant-accepted
control/sftp-address-separated
control/sftp-root-confined
control/sftp-grant-expired
`);

const WORKSPACE_IDS = ids(`
workspace-object/canonical-valid
workspace-object/unknown-member-rejected
workspace-object/signature-invalid
workspace-policy/intersection-valid
workspace-policy/escalation-rejected
workspace-policy/denial-wins
workspace-policy/conflict-rejected
workspace-grant/single-actor-active
workspace-grant/multi-approval-insufficient
workspace-grant/invite-replay-rejected
workspace-grant/admin-no-governance
workspace-relationship/bilateral-valid
workspace-relationship/grace-boundary
workspace-relationship/stale-rejected
workspace-relationship/mismatched-signatures
workspace-privacy/public-clean
workspace-privacy/concealed-correlation-rejected
workspace-host/inherited-failover
workspace-host/replace-retains-backstop
workspace-host/no-backstop-rejected
workspace-device/independent-leaf-removal
workspace-device/persona-removes-all-leaves
workspace-key/full-history
workspace-key/from-admission-denied
workspace-key/selected-snapshot
workspace-key/unauthorized-host
workspace-key/revoked-device
workspace-key/keypackage-readmission
workspace-freshness/ordinary-boundary
workspace-freshness/ordinary-stale
workspace-freshness/authority-boundary
workspace-freshness/authority-stale
workspace-joint/threshold-valid
workspace-joint/host-not-authority
workspace-events/mls-epoch-rotation
workspace-events/size-rotation
workspace-events/exact-bytes
workspace-events/mutated-bytes-rejected
workspace-events/nostr-radicle-equivalent
`);

const PROFILE_BY_VECTOR = new Map<string, string>([
  ["agent-moderation/receipt-valid", "heterodyne-social-agent-policy-receipt-v1"],
  ["agent-moderation/policy-list-valid", "heterodyne-social-agent-policy-list-v1"],
  ["agent-authorship/delegation-valid", "heterodyne-comms-agent-signing-delegation-v1"],
  ["agent-authorship/attribution-kind-1", "heterodyne-comms-agent-attribution-kind-1-v1"],
  ["agent-authorship/attribution-kind-6", "heterodyne-comms-agent-attribution-kind-6-v1"],
  ["agent-authorship/attribution-kind-7", "heterodyne-comms-agent-attribution-kind-7-v1"],
  ["agent-authorship/attribution-kind-16", "heterodyne-comms-agent-attribution-kind-16-v1"],
  ["agent-authorship/attribution-kind-1063", "heterodyne-comms-agent-attribution-kind-1063-v1"],
  ["agent-authorship/attribution-kind-1985", "heterodyne-comms-agent-attribution-kind-1985-v1"],
  ["agent-authorship/attribution-kind-4550", "heterodyne-comms-agent-attribution-kind-4550-v1"],
  ["agent-authorship/attribution-kind-30023", "heterodyne-comms-agent-attribution-kind-30023-v1"],
  ["claims/canonical-nostr-subject", "heterodyne-comms-key-claim-nostr-bip340-v1"],
  ["claims/canonical-radicle-nid-subject", "heterodyne-comms-key-claim-radicle-ed25519-v1"],
  ["claims/subject-proof-valid", "heterodyne-comms-key-claim-jwk-jws-v1"],
  ["claims/authorization-self-revocation", "heterodyne-comms-claim-revocation-nostr-bip340-v1"],
  ["claims/descriptive-subject-rejection", "heterodyne-comms-claim-revocation-radicle-ed25519-v1"],
  ["claims/canonical-jwk-thumbprint-subject", "heterodyne-comms-claim-revocation-jwk-jws-v1"],
  ["stamping/upstream-profile-owner", "heterodyne-social-mute-list-v1"],
  ["stamping/non-stamping-profile-unchanged", "heterodyne-core-rotation-breadcrumb-profile-v1"],
  ["stamping/tier3-profile-owner", "heterodyne-comms-tier3-wrapped-content-kind-1-v1"],
  ["profiles/core-breadcrumb-kind0", "heterodyne-core-rotation-breadcrumb-profile-v1"],
  ["profiles/core-breadcrumb-kind1", "heterodyne-core-rotation-breadcrumb-note-v1"],
  ["profiles/tier3-kind-1", "heterodyne-comms-tier3-wrapped-content-kind-1-v1"],
  ["profiles/tier3-kind-6", "heterodyne-comms-tier3-wrapped-content-kind-6-v1"],
  ["profiles/tier3-kind-16", "heterodyne-comms-tier3-wrapped-content-kind-16-v1"],
  ["profiles/tier3-kind-1063", "heterodyne-comms-tier3-wrapped-content-kind-1063-v1"],
  ["profiles/tier3-kind-30023", "heterodyne-comms-tier3-wrapped-content-kind-30023-v1"],
  ["profiles/tier3-kind-30402", "heterodyne-comms-tier3-wrapped-content-kind-30402-v1"],
  ["profiles/social-org-feed-kind31007", "heterodyne-social-org-feed-v1"],
  ["lists/private-items-reencrypt-on-rotation", "heterodyne-social-mute-list-v1"],
  ["lists/stale-list-rollback-rejected", "heterodyne-social-mute-list-v1"],
]);

export function vectorMetadata(vectorId: string): VectorMetadata {
  const owners = vectorId.startsWith("marmot-radicle/")
    ? (["comms"] as const)
    : ([
    ["core", CORE_IDS],
    ["comms", COMMS_IDS],
    ["control", CONTROL_IDS],
    ["social", SOCIAL_IDS],
    ["workspace", WORKSPACE_IDS],
  ] as const).filter(([, entries]) => entries.has(vectorId)).map(([owner]) => owner);
  if (owners.length !== 1) {
    throw new Error(`vector owner is not assigned exactly once: ${vectorId}`);
  }
  const owner = owners[0];
  const reference = referenceFor(vectorId, owner);
  const profile = vectorId.startsWith("control/")
    ? "heterodyne-control-marmot-frame-v1"
    : PROFILE_BY_VECTOR.get(vectorId);
  return {
    owner_document: owner,
    spec_version: QUALIFIED_VERSION,
    ...(profile === undefined ? {} : { profile }),
    spec_refs: [`heterodyne:${FAMILY_VERSION}#${reference}`],
  };
}

function referenceFor(vectorId: string, owner: DocumentId): string {
  if (vectorId.startsWith("marmot-radicle/")) {
    const id = vectorId.slice("marmot-radicle/".length);
    if (/kind445-exact|media-exact/.test(id)) {
      return "comms-marmot-exact-bytes";
    }
    if (/media-locators/.test(id)) {
      return "comms-marmot-media";
    }
    if (/standard-marmot|private-group/.test(id)) {
      return "comms-marmot-groups";
    }
    if (/directory|invites-individually/.test(id)) {
      return "comms-marmot-directory";
    }
    if (/routing-binding|routing-genesis|concurrent-routing|canonical-h|removal-before/.test(id)) {
      return "comms-marmot-routing-generation";
    }
    if (/writer-ref|unauthorized-ref|logical-size/.test(id)) {
      return "comms-marmot-event-repository";
    }
    if (/relay-routes/.test(id)) {
      return "comms-marmot-relay";
    }
    if (/durable-ack|ack-before|failover|redundant/.test(id)) {
      return "comms-marmot-rotation";
    }
    if (/retained-routing|expiration-is/.test(id)) {
      return "comms-marmot-retention";
    }
    if (/persona-inbox|private-inbox|keypackage|public-inbox/.test(id)) {
      return "comms-marmot-persona-inbox";
    }
    if (/agent-group/.test(id)) {
      return "comms-agent-authorship";
    }
    return "comms-marmot-participation";
  }
  if (vectorId === "interop/vanilla-nostr-only-follow") {
    return "social-following";
  }
  if (vectorId.startsWith("claims/")) {
    const id = vectorId.slice("claims/".length);
    if (/^chain-/.test(id)) return "comms-claim-chain";
    if (/revocation|rejection/.test(id)) return "comms-claim-revocation";
    if (/provisional|repository-confirmed/.test(id)) return "comms-claim-ledger";
    if (/proof|issuance|issuer/.test(id)) return "comms-claim-verification";
    return "comms-key-claims";
  }
  if (vectorId.startsWith("claim-ledger/")) {
    const id = vectorId.slice("claim-ledger/".length);
    if (id === "source-claim-revokes-token") return "comms-claim-revocation";
    if (/multiwriter-status-allocation|stale-minter-denied/.test(id)) {
      return "comms-multiwriter-minting";
    }
    return "comms-claim-ledger";
  }
  if (vectorId.startsWith("oidc/")) {
    const id = vectorId.slice("oidc/".length);
    if (/^discovery|^issuer-mismatch/.test(id)) return "comms-oidc-endpoints";
    if (/authorization|grant|pairwise|consent/.test(id)) {
      return "comms-oidc-authorization";
    }
    return "comms-jwt-projection";
  }
  if (vectorId.startsWith("token-status/")) {
    const id = vectorId.slice("token-status/".length);
    return /https-outage|issuer-successor/.test(id)
      ? "comms-issuer-continuity" : "comms-token-status";
  }
  if (vectorId.startsWith("profiles/core-breadcrumb")) {
    return "core-kel-rotation";
  }
  if (vectorId.startsWith("stamping/")) {
    return "core-version-stamps";
  }
  const profile = PROFILE_BY_VECTOR.get(vectorId);
  if (profile?.startsWith("heterodyne-comms-tier3-")) {
    return "comms-tier-three-profile";
  }
  if (profile?.startsWith("heterodyne-comms-double-ratchet-")) {
    return "comms-dm-wire";
  }
  if (profile === "comms-subprotocol-negotiation-v1" || profile === "comms-subprotocol-payload-v1") {
    return "comms-subprotocol-negotiation";
  }
  if (profile === "heterodyne-social-org-feed-v1") {
    return "social-org-feed-profile";
  }
  if (profile === "heterodyne-social-mute-list-v1") {
    return "social-mute-profile";
  }
  return anchorFor(vectorId, owner);
}

function anchorFor(vectorId: string, owner: DocumentId): string {
  if (vectorId.startsWith("keri-authority/export-")) return "core-keri-export";
  if (vectorId.startsWith("keri-authority/materialized-")) return "core-materialized-kel";
  if (vectorId.includes("kel-head")) return "core-kel-head";
  const prefix = vectorId.split("/", 1)[0];
  const anchors: Partial<Record<DocumentId, Record<string, string>>> = {
    core: {
      breadcrumbs: "core-kel-rotation",
      identity: vectorId.startsWith("identity/root-attestation-valid") ? "core-root-attestation" : "core-nid-delegation",
      "identity-doc": "core-identity-discovery",
      keri: "core-kel-primitives",
      "keri-authority": "core-kel-verification",
      "nid-binding": "core-nid-delegation",
      "node-advert": "core-node-advertisement",
      "persona-profile": "core-persona-profile",
      "key-retirement": "core-retired-key-observation",
      "repo-relay": "core-repo-relay",
      "routing-node": "core-node-roles",
      "light-node": "core-client-responsibilities",
      "relay-profile": "core-nostr-relay-interop",
      transport: "core-tor-reachability",
      versioning: "core-versioning",
      verification: "core-verification",
      "config-backup": "core-keys-repository",
      "social-recovery": "core-recovery",
      interop: "core-identity-pointer",
      org: "core-threshold-authority",
      "core-redundancy": "core-multi-host-seeding",
      stamping: "core-version-stamps",
      registry: "core-registry",
      "role-capabilities": vectorId.includes("role-address")
        ? "core-role-delegation"
        : "core-node-roles",
    },
    comms: {
      "agent-authorship": vectorId.includes("delegation")
        || vectorId.includes("role-key")
        || vectorId.includes("multiple-roles")
        ? "comms-agent-delegation"
        : vectorId.includes("identity")
          || vectorId.includes("workload-registration")
          ? "comms-agent-workload"
          : vectorId.includes("token-")
            ? "comms-agent-token"
            : vectorId.includes("profile-unavailable")
              ? "comms-agent-fail-closed"
              : "comms-agent-attribution",
      "public-reader": vectorId.includes("launcher")
        || vectorId.includes("http-path")
        || vectorId.includes("relay-hint")
        || vectorId.includes("onion-hint")
        ? "comms-public-launcher"
        : vectorId.includes("transition")
          || vectorId.includes("logout")
          || vectorId.includes("revocation-expiry")
          ? "comms-public-transition"
          : vectorId.includes("external-media")
            ? "comms-public-reader-security"
            : "comms-public-resolution",
      "config-backup": "comms-config-repository",
      index: "comms-feed-index",
      org: "comms-org-authorization",
      outbox: "comms-retrieval",
      "privacy-tiers": "comms-privacy-tiers",
      "relay-interop": "comms-publishing",
      "acceptance-gating": "comms-acceptance-hook",
      "one-time-invite": "comms-one-time-invites",
      "credential-continuity": "comms-credential-continuity",
    },
    social: {
      "agent-moderation": vectorId.includes("receipt")
        || vectorId.includes("correction")
        ? "social-agent-policy-receipts"
        : "social-agent-policy-list",
      atproto: "social-atproto-resolution",
      discussion: "social-discussion-rooms",
      identity: "social-identity-room",
      lists: "social-lists",
      moderation: "social-moderation",
      outbox: "social-interactions",
      "social-recovery": "social-recovery-binding",
      versioning: "social-discussion-rooms",
      "acceptance-gating": "social-admission-policy",
    },
    control: {
      control: vectorId.includes("invitation-")
        ? "control-invitation-policy"
        : vectorId.includes("device-code-")
          ? "control-device-authorization"
          : vectorId.includes("authorization-")
            ? "control-token"
            : vectorId.includes("invite-preauthorization-")
              ? "control-one-time-invites"
        : vectorId.includes("token-")
          ? "control-token"
          : vectorId.includes("entitlement-")
            ? "control-entitlement"
            : vectorId.includes("operation-")
              ? "control-request-processing"
              : vectorId.includes("failover-")
                ? "control-failover"
                : vectorId.includes("retention-")
                  ? "control-retention"
                  : vectorId.includes("epoch-")
                    ? "control-epoch-bootstrap"
                    : vectorId.includes("recovery-")
                      ? "control-radicle-recovery"
                      : vectorId.includes("sftp-")
                        ? "control-sftp-recovery"
                        : "control-conformance",
    },
    workspace: {
      "workspace-object": "workspace-object-types",
      "workspace-policy": "workspace-role-policy",
      "workspace-grant": "workspace-grants",
      "workspace-relationship": "workspace-relationships",
      "workspace-privacy": "workspace-privacy",
      "workspace-host": "workspace-advertisements",
      "workspace-device": "workspace-role-control",
      "workspace-key": "workspace-key-delivery",
      "workspace-freshness": "workspace-freshness",
      "workspace-joint": "workspace-relationships",
      "workspace-events": "workspace-role-repositories",
    },
  };
  return anchors[owner]?.[prefix] ?? `${owner}-conformance`;
}
