import { DOCUMENT_DEPENDENCIES, DOCUMENT_VERSIONS } from "./family.js";
import type { DocumentId } from "./types.js";

export type VectorMetadata = {
  owner_document: DocumentId;
  owner_version: string;
  dependency_versions: Partial<Record<DocumentId, string>>;
  registry_revision: number;
  profile?: string;
  spec_refs: string[];
};

const ids = (value: string) => new Set(value.trim().split(/\s+/));

// ADR-033 requirement 38 assigns ownership per vector, never by directory.
// This exhaustive inventory intentionally names every pre-split vector ID.
const CORE_IDS = ids(`
config-backup/config-rid-advertised-rejected
config-backup/config-rid-unadvertised-clean
config-backup/nip49-nsec-wrap
identity-doc/add-before-remove
identity-doc/emergency-reanchor
identity-doc/emergency-reanchor-v050
identity-doc/kel-revoked-nid-rejected
identity/delegation-active
identity/delegation-expired
identity/delegation-revoked
identity/kind31005-race-tiebreaker-core
identity/revocation-post-window
identity/root-attestation-valid
identity/root-attestation-valid-v050
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
keri-authority/kel-head-forbidden-on-dr-wire
keri-authority/kel-head-forbidden-on-inception
keri-authority/kel-head-forbidden-on-rotation
keri-authority/kel-head-malformed-rejected
keri-authority/kel-head-mandatory-on-delegation
keri-authority/kel-head-mandatory-on-epoch-invite
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
nid-binding/bidirectional-valid-v050
nid-binding/invalid-nid-proof-rejected
nid-binding/missing-nid-proof-rejected
node-advert/expired-rejected
node-advert/nid-proof-invalid-rejected
node-advert/outer-sig-invalid-rejected
node-advert/valid-dual-signed
node-advert/valid-dual-signed-v050
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
social-recovery/cache-rejects-unauthorized-content
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
versioning/per-document-negotiation
versioning/unknown-asynchronous-stamp-rejected
stamping/heterodyne-json-content-owner
stamping/heterodyne-empty-content-tag-owner
stamping/upstream-unstamped
stamping/upstream-profile-owner
stamping/non-stamping-profile-unchanged
stamping/dr-outer-unstamped
stamping/control-profile-retains-core-owner
stamping/control-carrier-comms-owner
stamping/legacy-monolith-explicit
stamping/legacy-monolith-inferred
stamping/legacy-upstream-not-inferable
stamping/no-restamp-existing-bytes
stamping/tier3-profile-owner
stamping/legacy-malformed-not-inferable
stamping/legacy-post-split-not-inferable
stamping/legacy-profile-only-not-inferable
profiles/core-breadcrumb-kind0
profiles/core-breadcrumb-kind1
breadcrumbs/unrelated-successor-rejected
breadcrumbs/compromise-rotation-not-produced
breadcrumbs/repointed-nip05-rejected
breadcrumbs/ordinary-consumer-no-profile-inference
registry/downref-nonfrozen-rejected
registry/frozen-entry-immutable
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
claims/pairwise-private-dr-delivery
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
dm/double-ratchet-transcript
dm/invite-delegated-device-valid
dm/invite-revoked-device-rejected
dm/invite-unbound-device-rejected
dm/kind1060-outer-message-shape
dm/repo-relay-refuses-kind1060
index/complete-fetch-attempt
index/prev-page-hash
org/canonical-branch-reachability
outbox/full-public-outbox
outbox/scoped-outbox
outbox/transitive-discovery-walk
privacy-tiers/audience-key-rotation-on-removal
privacy-tiers/complete-fetch-attempt
privacy-tiers/non-circular-bootstrap
privacy-tiers/tier1-public-plaintext-both-backends
privacy-tiers/tier2-private-repo-not-encrypted
privacy-tiers/tier3-index-key-derivation-and-encryption
privacy-tiers/tier3-kind31011-audience-key-wrap
privacy-tiers/tier3-kind31012-audience-roster
privacy-tiers/tier3-prev-page-hash-mismatch
privacy-tiers/tier3-prev-page-hash-valid
privacy-tiers/tier1-public-plaintext-both-backends-v050
privacy-tiers/tier3-index-key-derivation-and-encryption-v050
privacy-tiers/tier3-kind31011-audience-key-wrap-v050
privacy-tiers/tier3-kind31012-audience-roster-v050
relay-interop/auth-rejection-permanent
relay-interop/keri-rotation-auth-new-key
relay-interop/nip42-auth-current-epoch-key
comms-envelope/nostr-native-event-valid
comms-envelope/owner-stamp-valid
comms-envelope/nostr-native-signature-mutation
acceptance-gating/authentication-before-policy
acceptance-gating/message-request-no-receipt
acceptance-gating/established-ordinary-accept
acceptance-gating/new-ordinary-hold
acceptance-gating/authentication-reject
acceptance-gating/credential-valid-accept
acceptance-gating/authoritative-state-unavailable-hold
acceptance-gating/credential-invalid-reject
acceptance-gating/credential-revoked-reject
acceptance-gating/credential-expired-reject
acceptance-gating/credential-subject-mismatch-reject
acceptance-gating/credential-nidless-reject
acceptance-gating/control-enrollment-default-hold
profiles/tier3-kind-1
profiles/tier3-kind-6
profiles/tier3-kind-16
profiles/tier3-kind-1063
profiles/tier3-kind-30023
profiles/tier3-kind-30402
profiles/dr-invite-response-kind1059
profiles/comms-negotiation-kind31015
profiles/comms-payload-kind31016
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
bridge/idempotent-republication
bridge/matrix-permanent-failure-index-updated
bridge/nostr-permanent-failure-index-not-updated
broadcast/member-decrypts
broadcast/nip59-rejected
broadcast/non-member-cannot-decrypt
broadcast/private-broadcast-wrapped
broadcast/private-broadcast-wrapped-v050
broadcast/reaction-reply-bare-not-indexed
config_room/device-inventory-not-synced
config_room/key-backup-wrapping-algorithms
config_room/minimal-config-room
config_room/private-mutes
encryption/delegation-revocation-rotation
encryption/encryption-version-event
encryption/mls-migration-eligibility-check
encryption/mls-migration-intent-and-ack
encryption/mls-migration-missing-ack-aborts
encryption/mls-migration-non-mls-receiver-fallback
encryption/mls-migration-offline-reconnect-reencrypt
encryption/mls-migration-receiver-verifiable-flip
encryption/mls-migration-tail-period-acceptance
envelope/bare-dm-signature-badge
envelope/cross-kind-wrapping
envelope/fallback-rendering
envelope/minimal-kind1-wrapped
homeserver-exit/dual-publish-during-exit
homeserver-exit/identity-room-migration
homeserver-exit/migration-pointer-precedence
identity/identity-room-full-state
index/context-binding-mismatch
index/room-key-wrap-encryption
interop/bare-hide-pref
interop/vanilla-nostr-only-follow
interop/wrapped-vanilla-roundtrip
lists/kind-mute-set-addressing
lists/mute-list-private-items-encrypted-to-self
lists/mute-list-public-roundtrip
lists/mute-list-public-roundtrip-v050
lists/mute-list-private-items-encrypted-to-self-v050
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
moderation/strict-mode-invalid-broadcast-signature
moderation/strict-mode-kind5-deletion-30s
moderation/strict-mode-state-downgrade-warning
multi-homing/active-room-election
multi-homing/kind31005-race-tiebreaker
multi-homing/partition-window-void-requeue
multi-homing/publish-lease-acquire-renew
multi-homing/single-mxid-revocation
outbox/cross-backend-reply-dedup
outbox/cross-persona-attestation-invalid
outbox/cross-persona-attestation-valid
redundancy/dedupe-across-replicas
redundancy/mirror-group-primary-replicas
redundancy/private-body-relay-borne
redundancy/promotion-republishes-pointer
redundancy/rekey-remove-not-join
room-kind/current-kinds-roundtrip
room-kind/legacy-read-back-map
room-kind/retired-kind-rejected
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
control/first-arrival-reserved
control/concurrent-identical-joins
control/cross-relay-final-response-replay
control/restart-reserved-operation-joins
control/expired-request-rejected
control/reply-relay-rejected
control/changed-method-rejected
control/changed-payload-rejected
control/complete-without-response-rejected
control/agent-publish-authorized
control/raw-signing-refused
control/key-access-refused
control/human-profile-refused
control/attribution-bypass-refused
control/expired-token-refused
control/sender-proof-refused
control/kind-resource-refused
control/content-size-refused
control/rate-refused
control/burst-refused
control/token-request-bounded
control/agent-publish-schema-intent-only
control/audit-omits-raw-token
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
  ["stamping/dr-outer-unstamped", "heterodyne-comms-double-ratchet-message-v1"],
  ["stamping/control-profile-retains-core-owner", "heterodyne-control-session-device-v1"],
  ["stamping/control-carrier-comms-owner", "comms-subprotocol-payload-v1"],
  ["stamping/tier3-profile-owner", "heterodyne-comms-tier3-wrapped-content-kind-1-v1"],
  ["profiles/core-breadcrumb-kind0", "heterodyne-core-rotation-breadcrumb-profile-v1"],
  ["profiles/core-breadcrumb-kind1", "heterodyne-core-rotation-breadcrumb-note-v1"],
  ["profiles/tier3-kind-1", "heterodyne-comms-tier3-wrapped-content-kind-1-v1"],
  ["profiles/tier3-kind-6", "heterodyne-comms-tier3-wrapped-content-kind-6-v1"],
  ["profiles/tier3-kind-16", "heterodyne-comms-tier3-wrapped-content-kind-16-v1"],
  ["profiles/tier3-kind-1063", "heterodyne-comms-tier3-wrapped-content-kind-1063-v1"],
  ["profiles/tier3-kind-30023", "heterodyne-comms-tier3-wrapped-content-kind-30023-v1"],
  ["profiles/tier3-kind-30402", "heterodyne-comms-tier3-wrapped-content-kind-30402-v1"],
  ["profiles/dr-invite-response-kind1059", "heterodyne-comms-double-ratchet-invite-response-v1"],
  ["profiles/social-org-feed-kind31007", "heterodyne-social-org-feed-v1"],
  ["profiles/comms-negotiation-kind31015", "comms-subprotocol-negotiation-v1"],
  ["profiles/comms-payload-kind31016", "comms-subprotocol-payload-v1"],
  ["comms-envelope/owner-stamp-valid", "comms-subprotocol-payload-v1"],
  ["broadcast/private-broadcast-wrapped-v050", "heterodyne-comms-tier3-wrapped-content-kind-1-v1"],
  ["lists/mute-list-public-roundtrip-v050", "heterodyne-social-mute-list-v1"],
  ["lists/mute-list-private-items-encrypted-to-self-v050", "heterodyne-social-mute-list-v1"],
  ["lists/private-items-reencrypt-on-rotation", "heterodyne-social-mute-list-v1"],
  ["lists/stale-list-rollback-rejected", "heterodyne-social-mute-list-v1"],
  ["broadcast/member-decrypts", "heterodyne-comms-tier3-wrapped-content-kind-1-v1"],
  ["broadcast/non-member-cannot-decrypt", "heterodyne-comms-tier3-wrapped-content-kind-1-v1"],
  ["dm/invite-delegated-device-valid", "heterodyne-comms-double-ratchet-invite-v1"],
  ["dm/invite-unbound-device-rejected", "heterodyne-comms-double-ratchet-invite-v1"],
  ["dm/invite-revoked-device-rejected", "heterodyne-comms-double-ratchet-invite-v1"],
  ["dm/kind1060-outer-message-shape", "heterodyne-comms-double-ratchet-message-v1"],
  ["dm/repo-relay-refuses-kind1060", "heterodyne-comms-double-ratchet-message-v1"],
  ["dm/double-ratchet-transcript", "heterodyne-comms-double-ratchet-message-v1"],
]);

export function vectorMetadata(vectorId: string): VectorMetadata {
  const owners = ([
    ["core", CORE_IDS],
    ["comms", COMMS_IDS],
    ["control", CONTROL_IDS],
    ["social", SOCIAL_IDS],
  ] as const).filter(([, entries]) => entries.has(vectorId));
  if (owners.length !== 1) {
    throw new Error(`vector owner is not assigned exactly once: ${vectorId}`);
  }
  const owner = owners[0][0];
  const dependencies = Object.fromEntries(
    DOCUMENT_DEPENDENCIES[owner].map((dependency) => [
      dependency,
      `${dependency}/${DOCUMENT_VERSIONS[dependency]}`,
    ]),
  ) as Partial<Record<DocumentId, string>>;
  const reference = referenceFor(vectorId, owner);
  const profile = PROFILE_BY_VECTOR.get(vectorId);
  return {
    owner_document: owner,
    owner_version: `${owner}/${DOCUMENT_VERSIONS[owner]}`,
    dependency_versions: dependencies,
    registry_revision: vectorId.startsWith("role-capabilities/")
      || vectorId.startsWith("public-reader/")
      || vectorId.startsWith("agent-authorship/")
      || vectorId.startsWith("agent-moderation/")
      || vectorId.startsWith("control/") ? 3
      : vectorId.startsWith("claims/") || vectorId.startsWith("claim-ledger/") ||
        vectorId.startsWith("oidc/") || vectorId.startsWith("token-status/") ? 2
      : 1,
    ...(profile === undefined ? {} : { profile }),
    spec_refs: [`heterodyne:${reference.document}/${DOCUMENT_VERSIONS[reference.document]}#${reference.anchor}`],
  };
}

function referenceFor(vectorId: string, owner: DocumentId): { document: DocumentId; anchor: string } {
  if (vectorId === "interop/vanilla-nostr-only-follow") {
    return { document: "social", anchor: "social-following" };
  }
  if (vectorId.startsWith("claims/")) {
    const id = vectorId.slice("claims/".length);
    if (/^chain-/.test(id)) return { document: "comms", anchor: "comms-claim-chain" };
    if (/revocation|rejection/.test(id)) return { document: "comms", anchor: "comms-claim-revocation" };
    if (/provisional|repository-confirmed/.test(id)) return { document: "comms", anchor: "comms-claim-ledger" };
    if (/proof|issuance|issuer/.test(id)) return { document: "comms", anchor: "comms-claim-verification" };
    return { document: "comms", anchor: "comms-key-claims" };
  }
  if (vectorId.startsWith("claim-ledger/")) {
    const id = vectorId.slice("claim-ledger/".length);
    if (id === "source-claim-revokes-token") return { document: "comms", anchor: "comms-claim-revocation" };
    if (/multiwriter-status-allocation|stale-minter-denied/.test(id)) {
      return { document: "comms", anchor: "comms-multiwriter-minting" };
    }
    return { document: "comms", anchor: "comms-claim-ledger" };
  }
  if (vectorId.startsWith("oidc/")) {
    const id = vectorId.slice("oidc/".length);
    if (/^discovery|^issuer-mismatch/.test(id)) return { document: "comms", anchor: "comms-oidc-endpoints" };
    if (/authorization|grant|pairwise|consent/.test(id)) {
      return { document: "comms", anchor: "comms-oidc-authorization" };
    }
    return { document: "comms", anchor: "comms-jwt-projection" };
  }
  if (vectorId.startsWith("token-status/")) {
    const id = vectorId.slice("token-status/".length);
    return { document: "comms", anchor: /https-outage|issuer-successor/.test(id)
      ? "comms-issuer-continuity" : "comms-token-status" };
  }
  if (vectorId.startsWith("profiles/core-breadcrumb")) {
    return { document: "core", anchor: "core-kel-rotation" };
  }
  if (vectorId.startsWith("stamping/")) {
    return { document: "core", anchor: "core-version-stamps" };
  }
  const profile = PROFILE_BY_VECTOR.get(vectorId);
  if (profile?.startsWith("heterodyne-comms-tier3-")) {
    return { document: "comms", anchor: "comms-tier-three-profile" };
  }
  if (profile?.startsWith("heterodyne-comms-double-ratchet-")) {
    return { document: "comms", anchor: "comms-dm-wire" };
  }
  if (profile === "comms-subprotocol-negotiation-v1" || profile === "comms-subprotocol-payload-v1") {
    return { document: "comms", anchor: "comms-subprotocol-negotiation" };
  }
  if (profile === "heterodyne-social-org-feed-v1") {
    return { document: "social", anchor: "social-org-feed-profile" };
  }
  if (profile === "heterodyne-social-mute-list-v1") {
    return { document: "social", anchor: "social-mute-profile" };
  }
  return { document: owner, anchor: anchorFor(vectorId, owner) };
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
      dm: "comms-direct-messages",
      index: "comms-feed-index",
      org: "comms-org-authorization",
      outbox: "comms-retrieval",
      "privacy-tiers": "comms-privacy-tiers",
      "relay-interop": "comms-publishing",
      "comms-envelope": "comms-envelope",
      "acceptance-gating": "comms-acceptance-hook",
    },
    social: {
      "agent-moderation": vectorId.includes("receipt")
        || vectorId.includes("correction")
        ? "social-agent-policy-receipts"
        : "social-agent-policy-list",
      bridge: "social-headless-bridge",
      broadcast: "social-matrix-envelopes",
      config_room: "social-config-room",
      encryption: "social-matrix-encryption",
      envelope: "social-matrix-envelopes",
      "homeserver-exit": "social-homeserver-exit",
      identity: "social-identity-room",
      index: "social-encrypted-state",
      interop: "social-vanilla-matrix",
      lists: "social-lists",
      moderation: "social-moderation",
      "multi-homing": "social-active-room-election",
      outbox: "social-interactions",
      redundancy: "social-matrix-mirroring",
      "room-kind": "social-discussion-rooms",
      "social-recovery": "social-recovery-binding",
      versioning: "social-discussion-rooms",
      "acceptance-gating": "social-admission-policy",
    },
    control: {
      control: vectorId.includes("arrival")
        || vectorId.includes("relay")
        || vectorId.includes("restart")
        || vectorId.includes("expired-request")
        || vectorId.includes("changed-")
        || vectorId.includes("complete-without")
        ? "control-relay-affinity"
        : vectorId.includes("token-request")
          ? "control-agent-token"
          : vectorId.includes("audit")
            ? "control-agent-audit"
            : vectorId.includes("schema-intent")
              ? "control-agent-publish"
              : "control-agent-requirements",
    },
  };
  return anchors[owner]?.[prefix] ?? `${owner}-conformance`;
}
