# Protocol-family vector coverage

Generated from [manifest.json](manifest.json); do not edit by hand.

- core: 123
- comms: 77
- control: 0
- social: 82

| Vector | Owner | Version | Dependencies | Registry | Profile | Spec references |
|---|---|---|---|---:|---|---|
| `acceptance-gating/authentication-before-policy` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | — | `heterodyne:comms/0.5.0#comms-acceptance-hook` |
| `acceptance-gating/authentication-reject` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | — | `heterodyne:comms/0.5.0#comms-acceptance-hook` |
| `acceptance-gating/authoritative-state-unavailable-hold` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | — | `heterodyne:comms/0.5.0#comms-acceptance-hook` |
| `acceptance-gating/control-enrollment-default-hold` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | — | `heterodyne:comms/0.5.0#comms-acceptance-hook` |
| `acceptance-gating/credential-expired-reject` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | — | `heterodyne:comms/0.5.0#comms-acceptance-hook` |
| `acceptance-gating/credential-invalid-reject` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | — | `heterodyne:comms/0.5.0#comms-acceptance-hook` |
| `acceptance-gating/credential-nidless-reject` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | — | `heterodyne:comms/0.5.0#comms-acceptance-hook` |
| `acceptance-gating/credential-revoked-reject` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | — | `heterodyne:comms/0.5.0#comms-acceptance-hook` |
| `acceptance-gating/credential-subject-mismatch-reject` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | — | `heterodyne:comms/0.5.0#comms-acceptance-hook` |
| `acceptance-gating/credential-valid-accept` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | — | `heterodyne:comms/0.5.0#comms-acceptance-hook` |
| `acceptance-gating/established-ordinary-accept` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | — | `heterodyne:comms/0.5.0#comms-acceptance-hook` |
| `acceptance-gating/message-request-no-receipt` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | — | `heterodyne:comms/0.5.0#comms-acceptance-hook` |
| `acceptance-gating/new-ordinary-hold` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | — | `heterodyne:comms/0.5.0#comms-acceptance-hook` |
| `acceptance-gating/social-mute-tightens` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-admission-policy` |
| `acceptance-gating/social-policy-cannot-loosen` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-admission-policy` |
| `acceptance-gating/social-wot-cannot-loosen` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-admission-policy` |
| `acceptance-gating/social-wot-tightens-only` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-admission-policy` |
| `bridge/idempotent-republication` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-headless-bridge` |
| `bridge/matrix-permanent-failure-index-updated` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-headless-bridge` |
| `bridge/nostr-permanent-failure-index-not-updated` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-headless-bridge` |
| `broadcast/member-decrypts` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | `heterodyne-comms-tier3-wrapped-content-kind-1-v1` | `heterodyne:comms/0.5.0#comms-tier-three-profile` |
| `broadcast/nip59-rejected` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-matrix-envelopes` |
| `broadcast/non-member-cannot-decrypt` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | `heterodyne-comms-tier3-wrapped-content-kind-1-v1` | `heterodyne:comms/0.5.0#comms-tier-three-profile` |
| `broadcast/private-broadcast-wrapped` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-matrix-envelopes` |
| `broadcast/private-broadcast-wrapped-v050` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | `heterodyne-comms-tier3-wrapped-content-kind-1-v1` | `heterodyne:comms/0.5.0#comms-tier-three-profile` |
| `broadcast/reaction-reply-bare-not-indexed` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-matrix-envelopes` |
| `claims/authorization-self-revocation` | comms | `comms/0.5.0` | core=core/0.5.0 | 2 | `heterodyne-comms-claim-revocation-nostr-bip340-v1` | `heterodyne:comms/0.5.0#comms-conformance` |
| `claims/canonical-jwk-thumbprint-subject` | comms | `comms/0.5.0` | core=core/0.5.0 | 2 | `heterodyne-comms-claim-revocation-jwk-jws-v1` | `heterodyne:comms/0.5.0#comms-conformance` |
| `claims/canonical-nostr-subject` | comms | `comms/0.5.0` | core=core/0.5.0 | 2 | `heterodyne-comms-key-claim-nostr-bip340-v1` | `heterodyne:comms/0.5.0#comms-conformance` |
| `claims/canonical-radicle-nid-subject` | comms | `comms/0.5.0` | core=core/0.5.0 | 2 | `heterodyne-comms-key-claim-radicle-ed25519-v1` | `heterodyne:comms/0.5.0#comms-conformance` |
| `claims/chain-attenuation-valid` | comms | `comms/0.5.0` | core=core/0.5.0 | 2 | — | `heterodyne:comms/0.5.0#comms-conformance` |
| `claims/chain-depth-exceeded` | comms | `comms/0.5.0` | core=core/0.5.0 | 2 | — | `heterodyne:comms/0.5.0#comms-conformance` |
| `claims/chain-widening-rejected` | comms | `comms/0.5.0` | core=core/0.5.0 | 2 | — | `heterodyne:comms/0.5.0#comms-conformance` |
| `claims/claim-id-mismatch` | comms | `comms/0.5.0` | core=core/0.5.0 | 2 | — | `heterodyne:comms/0.5.0#comms-conformance` |
| `claims/copied-proof-rejected` | comms | `comms/0.5.0` | core=core/0.5.0 | 2 | — | `heterodyne:comms/0.5.0#comms-conformance` |
| `claims/delegated-issuance-active` | comms | `comms/0.5.0` | core=core/0.5.0 | 2 | — | `heterodyne:comms/0.5.0#comms-conformance` |
| `claims/descriptive-subject-rejection` | comms | `comms/0.5.0` | core=core/0.5.0 | 2 | `heterodyne-comms-claim-revocation-radicle-ed25519-v1` | `heterodyne:comms/0.5.0#comms-conformance` |
| `claims/local-only-no-publication` | comms | `comms/0.5.0` | core=core/0.5.0 | 2 | — | `heterodyne:comms/0.5.0#comms-conformance` |
| `claims/pairwise-private-dr-delivery` | comms | `comms/0.5.0` | core=core/0.5.0 | 2 | — | `heterodyne:comms/0.5.0#comms-conformance` |
| `claims/persona-issuance-active` | comms | `comms/0.5.0` | core=core/0.5.0 | 2 | — | `heterodyne:comms/0.5.0#comms-conformance` |
| `claims/provisional-authorization-denied` | comms | `comms/0.5.0` | core=core/0.5.0 | 2 | — | `heterodyne:comms/0.5.0#comms-conformance` |
| `claims/public-claim-publication` | comms | `comms/0.5.0` | core=core/0.5.0 | 2 | — | `heterodyne:comms/0.5.0#comms-conformance` |
| `claims/repository-confirmed-active` | comms | `comms/0.5.0` | core=core/0.5.0 | 2 | — | `heterodyne:comms/0.5.0#comms-conformance` |
| `claims/repository-private-encryption` | comms | `comms/0.5.0` | core=core/0.5.0 | 2 | — | `heterodyne:comms/0.5.0#comms-conformance` |
| `claims/subject-proof-valid` | comms | `comms/0.5.0` | core=core/0.5.0 | 2 | `heterodyne-comms-key-claim-jwk-jws-v1` | `heterodyne:comms/0.5.0#comms-conformance` |
| `claims/third-party-issuer-untrusted` | comms | `comms/0.5.0` | core=core/0.5.0 | 2 | — | `heterodyne:comms/0.5.0#comms-conformance` |
| `comms-envelope/nostr-native-event-valid` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | — | `heterodyne:comms/0.5.0#comms-envelope` |
| `comms-envelope/nostr-native-signature-mutation` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | — | `heterodyne:comms/0.5.0#comms-envelope` |
| `comms-envelope/owner-stamp-valid` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | `comms-subprotocol-payload-v1` | `heterodyne:comms/0.5.0#comms-subprotocol-negotiation` |
| `config-backup/config-blob-encrypt-decrypt` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | — | `heterodyne:comms/0.5.0#comms-config-repository` |
| `config-backup/config-rid-advertised-rejected` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-keys-repository` |
| `config-backup/config-rid-unadvertised-clean` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-keys-repository` |
| `config-backup/key-id-derivation` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | — | `heterodyne:comms/0.5.0#comms-config-repository` |
| `config-backup/key-rotation-ref-delta` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | — | `heterodyne:comms/0.5.0#comms-config-repository` |
| `config-backup/nip49-nsec-wrap` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-keys-repository` |
| `config_room/device-inventory-not-synced` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-config-room` |
| `config_room/key-backup-wrapping-algorithms` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-config-room` |
| `config_room/minimal-config-room` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-config-room` |
| `config_room/private-mutes` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-config-room` |
| `core-redundancy/radicle-multihost-replication` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-multi-host-seeding` |
| `core-redundancy/stale-seed-does-not-remove-durability` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-multi-host-seeding` |
| `dm/double-ratchet-transcript` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | `heterodyne-comms-double-ratchet-message-v1` | `heterodyne:comms/0.5.0#comms-dm-wire` |
| `dm/invite-delegated-device-valid` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | `heterodyne-comms-double-ratchet-invite-v1` | `heterodyne:comms/0.5.0#comms-dm-wire` |
| `dm/invite-revoked-device-rejected` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | `heterodyne-comms-double-ratchet-invite-v1` | `heterodyne:comms/0.5.0#comms-dm-wire` |
| `dm/invite-unbound-device-rejected` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | `heterodyne-comms-double-ratchet-invite-v1` | `heterodyne:comms/0.5.0#comms-dm-wire` |
| `dm/kind1060-outer-message-shape` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | `heterodyne-comms-double-ratchet-message-v1` | `heterodyne:comms/0.5.0#comms-dm-wire` |
| `dm/repo-relay-refuses-kind1060` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | `heterodyne-comms-double-ratchet-message-v1` | `heterodyne:comms/0.5.0#comms-dm-wire` |
| `encryption/delegation-revocation-rotation` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-matrix-encryption` |
| `encryption/encryption-version-event` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-matrix-encryption` |
| `encryption/mls-migration-eligibility-check` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-matrix-encryption` |
| `encryption/mls-migration-intent-and-ack` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-matrix-encryption` |
| `encryption/mls-migration-missing-ack-aborts` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-matrix-encryption` |
| `encryption/mls-migration-non-mls-receiver-fallback` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-matrix-encryption` |
| `encryption/mls-migration-offline-reconnect-reencrypt` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-matrix-encryption` |
| `encryption/mls-migration-receiver-verifiable-flip` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-matrix-encryption` |
| `encryption/mls-migration-tail-period-acceptance` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-matrix-encryption` |
| `envelope/bare-dm-signature-badge` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-matrix-envelopes` |
| `envelope/cross-kind-wrapping` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-matrix-envelopes` |
| `envelope/fallback-rendering` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-matrix-envelopes` |
| `envelope/minimal-kind1-wrapped` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-matrix-envelopes` |
| `homeserver-exit/dual-publish-during-exit` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-homeserver-exit` |
| `homeserver-exit/identity-room-migration` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-homeserver-exit` |
| `homeserver-exit/migration-pointer-precedence` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-homeserver-exit` |
| `identity-doc/add-before-remove` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-identity-discovery` |
| `identity-doc/emergency-reanchor` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-identity-discovery` |
| `identity-doc/emergency-reanchor-v050` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-identity-discovery` |
| `identity-doc/kel-revoked-nid-rejected` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-identity-discovery` |
| `identity/delegation-active` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-nid-delegation` |
| `identity/delegation-expired` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-nid-delegation` |
| `identity/delegation-revoked` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-nid-delegation` |
| `identity/identity-room-full-state` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-identity-room` |
| `identity/kind31005-race-tiebreaker-core` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-nid-delegation` |
| `identity/revocation-post-window` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-nid-delegation` |
| `identity/root-attestation-valid` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-root-attestation` |
| `identity/root-attestation-valid-v050` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-root-attestation` |
| `index/complete-fetch-attempt` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | — | `heterodyne:comms/0.5.0#comms-feed-index` |
| `index/context-binding-mismatch` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-encrypted-state` |
| `index/prev-page-hash` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | — | `heterodyne:comms/0.5.0#comms-feed-index` |
| `index/room-key-wrap-encryption` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-encrypted-state` |
| `interop/bare-hide-pref` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-vanilla-matrix` |
| `interop/kind31005-identity-pointer` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-identity-pointer` |
| `interop/vanilla-nostr-only-follow` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-vanilla-matrix` |
| `interop/wrapped-vanilla-roundtrip` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-vanilla-matrix` |
| `keri-authority/accelerator-backdated-compromise` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-kel-verification` |
| `keri-authority/accelerator-decision-equivalent` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-kel-verification` |
| `keri-authority/delegation-conflict-repo-wins` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-kel-verification` |
| `keri-authority/dependent-events-unresolved` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-kel-verification` |
| `keri-authority/equivocation-flagged` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-kel-verification` |
| `keri-authority/export-aid-digest-anchoring` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-keri-export` |
| `keri-authority/export-aid-substituted-for-npub-rejected` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-keri-export` |
| `keri-authority/export-degraded-metadata` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-keri-export` |
| `keri-authority/export-incomplete` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-keri-export` |
| `keri-authority/export-origin-absent-not-failure` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-keri-export` |
| `keri-authority/export-unmappable-feature` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-keri-export` |
| `keri-authority/export-unsupported-crypto-suite` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-keri-export` |
| `keri-authority/kel-head-absent-rejected` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-kel-head` |
| `keri-authority/kel-head-duplicate-rejected` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-kel-head` |
| `keri-authority/kel-head-forbidden-on-breadcrumb` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-kel-head` |
| `keri-authority/kel-head-forbidden-on-dr-wire` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-kel-head` |
| `keri-authority/kel-head-forbidden-on-inception` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-kel-head` |
| `keri-authority/kel-head-forbidden-on-rotation` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-kel-head` |
| `keri-authority/kel-head-malformed-rejected` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-kel-head` |
| `keri-authority/kel-head-mandatory-on-delegation` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-kel-head` |
| `keri-authority/kel-head-mandatory-on-epoch-invite` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-kel-head` |
| `keri-authority/kel-head-mandatory-on-root` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-kel-head` |
| `keri-authority/kel-head-seq-mismatch-rejected` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-kel-head` |
| `keri-authority/keri10json-cesr-wire-rejected` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-kel-verification` |
| `keri-authority/materialized-atomic-rebuild` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-materialized-kel` |
| `keri-authority/materialized-empty-kel-deletion` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-materialized-kel` |
| `keri-authority/materialized-log-derivation` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-materialized-kel` |
| `keri-authority/materialized-refs-not-authority` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-materialized-kel` |
| `keri-authority/materialized-state-derivation` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-materialized-kel` |
| `keri-authority/provisional-not-hardened-repo-unreachable` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-kel-verification` |
| `keri-authority/refresh-failed-not-condition-d` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-kel-verification` |
| `keri-authority/repo-head-regression-rejected` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-kel-verification` |
| `keri-authority/withdrawal-causally-behind-no-withdraw` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-kel-verification` |
| `keri-authority/withdrawal-converged-head` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-kel-verification` |
| `keri/didkey-witness-no-network` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-kel-primitives` |
| `keri/first-seen-ordering` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-kel-primitives` |
| `keri/fork-resolution-conflicting-rotations` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-kel-primitives` |
| `keri/inception-event` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-kel-primitives` |
| `keri/informal-vouch-not-counted` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-kel-primitives` |
| `keri/rotation-committed-strategy` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-kel-primitives` |
| `keri/rotation-none-witness-threshold` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-kel-primitives` |
| `light-node/content-not-through-routing-node` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-client-responsibilities` |
| `light-node/route-around-withholding-host` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-client-responsibilities` |
| `light-node/verifies-signature-locally` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-client-responsibilities` |
| `lists/kind-mute-set-addressing` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-lists` |
| `lists/mute-list-private-items-encrypted-to-self` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-lists` |
| `lists/mute-list-private-items-encrypted-to-self-v050` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | `heterodyne-social-mute-list-v1` | `heterodyne:social/0.5.0#social-mute-profile` |
| `lists/mute-list-public-roundtrip` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-lists` |
| `lists/mute-list-public-roundtrip-v050` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | `heterodyne-social-mute-list-v1` | `heterodyne:social/0.5.0#social-mute-profile` |
| `lists/policy-list-adoption-parsed` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-lists` |
| `lists/private-items-reencrypt-on-rotation` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | `heterodyne-social-mute-list-v1` | `heterodyne:social/0.5.0#social-mute-profile` |
| `lists/stale-list-rollback-rejected` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | `heterodyne-social-mute-list-v1` | `heterodyne:social/0.5.0#social-mute-profile` |
| `moderation/approvals-required-absent-default-one` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-moderation` |
| `moderation/contributor-implicit-rejection-window` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-moderation` |
| `moderation/kind34550-approvals-required` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-moderation` |
| `moderation/moderator-rotation-through-kel` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-moderation` |
| `moderation/multi-mod-requirement` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-moderation` |
| `moderation/nip72-approval` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-moderation` |
| `moderation/radicle-editorial-gating` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-moderation` |
| `moderation/redaction-of-approved-post` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-moderation` |
| `moderation/relay-only-created-at-fallback` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-moderation` |
| `moderation/repo-anchor-asof-after-removal-rejected` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-moderation` |
| `moderation/repo-anchor-asof-before-removal-counts` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-moderation` |
| `moderation/strict-mode-bare-not-hidden` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-moderation` |
| `moderation/strict-mode-invalid-broadcast-signature` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-moderation` |
| `moderation/strict-mode-kind5-deletion-30s` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-moderation` |
| `moderation/strict-mode-state-downgrade-warning` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-moderation` |
| `multi-homing/active-room-election` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-active-room-election` |
| `multi-homing/kind31005-race-tiebreaker` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-active-room-election` |
| `multi-homing/partition-window-void-requeue` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-active-room-election` |
| `multi-homing/publish-lease-acquire-renew` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-active-room-election` |
| `multi-homing/single-mxid-revocation` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-active-room-election` |
| `nid-binding/bidirectional-valid` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-nid-delegation` |
| `nid-binding/bidirectional-valid-v050` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-nid-delegation` |
| `nid-binding/invalid-nid-proof-rejected` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-nid-delegation` |
| `nid-binding/missing-nid-proof-rejected` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-nid-delegation` |
| `node-advert/expired-rejected` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-node-advertisement` |
| `node-advert/nid-proof-invalid-rejected` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-node-advertisement` |
| `node-advert/outer-sig-invalid-rejected` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-node-advertisement` |
| `node-advert/valid-dual-signed` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-node-advertisement` |
| `node-advert/valid-dual-signed-v050` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-node-advertisement` |
| `org/canonical-branch-reachability` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | — | `heterodyne:comms/0.5.0#comms-org-authorization` |
| `org/member-add-dual-authorized` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-threshold-authority` |
| `org/member-add-single-authorization-insufficient` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-threshold-authority` |
| `org/threshold-delegate-governance` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-threshold-authority` |
| `outbox/cross-backend-reply-dedup` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-interactions` |
| `outbox/cross-persona-attestation-invalid` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-interactions` |
| `outbox/cross-persona-attestation-valid` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-interactions` |
| `outbox/full-public-outbox` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | — | `heterodyne:comms/0.5.0#comms-retrieval` |
| `outbox/scoped-outbox` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | — | `heterodyne:comms/0.5.0#comms-retrieval` |
| `outbox/transitive-discovery-walk` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | — | `heterodyne:comms/0.5.0#comms-retrieval` |
| `privacy-tiers/audience-key-rotation-on-removal` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | — | `heterodyne:comms/0.5.0#comms-privacy-tiers` |
| `privacy-tiers/complete-fetch-attempt` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | — | `heterodyne:comms/0.5.0#comms-privacy-tiers` |
| `privacy-tiers/non-circular-bootstrap` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | — | `heterodyne:comms/0.5.0#comms-privacy-tiers` |
| `privacy-tiers/tier1-public-plaintext-both-backends` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | — | `heterodyne:comms/0.5.0#comms-privacy-tiers` |
| `privacy-tiers/tier1-public-plaintext-both-backends-v050` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | — | `heterodyne:comms/0.5.0#comms-privacy-tiers` |
| `privacy-tiers/tier2-private-repo-not-encrypted` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | — | `heterodyne:comms/0.5.0#comms-privacy-tiers` |
| `privacy-tiers/tier3-index-key-derivation-and-encryption` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | — | `heterodyne:comms/0.5.0#comms-privacy-tiers` |
| `privacy-tiers/tier3-index-key-derivation-and-encryption-v050` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | — | `heterodyne:comms/0.5.0#comms-privacy-tiers` |
| `privacy-tiers/tier3-kind31011-audience-key-wrap` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | — | `heterodyne:comms/0.5.0#comms-privacy-tiers` |
| `privacy-tiers/tier3-kind31011-audience-key-wrap-v050` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | — | `heterodyne:comms/0.5.0#comms-privacy-tiers` |
| `privacy-tiers/tier3-kind31012-audience-roster` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | — | `heterodyne:comms/0.5.0#comms-privacy-tiers` |
| `privacy-tiers/tier3-kind31012-audience-roster-v050` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | — | `heterodyne:comms/0.5.0#comms-privacy-tiers` |
| `privacy-tiers/tier3-prev-page-hash-mismatch` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | — | `heterodyne:comms/0.5.0#comms-privacy-tiers` |
| `privacy-tiers/tier3-prev-page-hash-valid` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | — | `heterodyne:comms/0.5.0#comms-privacy-tiers` |
| `profiles/comms-negotiation-kind31015` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | `comms-subprotocol-negotiation-v1` | `heterodyne:comms/0.5.0#comms-subprotocol-negotiation` |
| `profiles/comms-payload-kind31016` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | `comms-subprotocol-payload-v1` | `heterodyne:comms/0.5.0#comms-subprotocol-negotiation` |
| `profiles/core-breadcrumb-kind0` | core | `core/0.5.0` | — | 1 | `heterodyne-core-rotation-breadcrumb-profile-v1` | `heterodyne:core/0.5.0#core-version-stamps` |
| `profiles/core-breadcrumb-kind1` | core | `core/0.5.0` | — | 1 | `heterodyne-core-rotation-breadcrumb-note-v1` | `heterodyne:core/0.5.0#core-version-stamps` |
| `profiles/dr-invite-response-kind1059` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | `heterodyne-comms-double-ratchet-invite-response-v1` | `heterodyne:comms/0.5.0#comms-dm-wire` |
| `profiles/social-org-feed-kind31007` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | `heterodyne-social-org-feed-v1` | `heterodyne:social/0.5.0#social-org-feed-profile` |
| `profiles/tier3-kind-1` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | `heterodyne-comms-tier3-wrapped-content-kind-1-v1` | `heterodyne:comms/0.5.0#comms-tier-three-profile` |
| `profiles/tier3-kind-1063` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | `heterodyne-comms-tier3-wrapped-content-kind-1063-v1` | `heterodyne:comms/0.5.0#comms-tier-three-profile` |
| `profiles/tier3-kind-16` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | `heterodyne-comms-tier3-wrapped-content-kind-16-v1` | `heterodyne:comms/0.5.0#comms-tier-three-profile` |
| `profiles/tier3-kind-30023` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | `heterodyne-comms-tier3-wrapped-content-kind-30023-v1` | `heterodyne:comms/0.5.0#comms-tier-three-profile` |
| `profiles/tier3-kind-30402` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | `heterodyne-comms-tier3-wrapped-content-kind-30402-v1` | `heterodyne:comms/0.5.0#comms-tier-three-profile` |
| `profiles/tier3-kind-6` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | `heterodyne-comms-tier3-wrapped-content-kind-6-v1` | `heterodyne:comms/0.5.0#comms-tier-three-profile` |
| `redundancy/dedupe-across-replicas` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-matrix-mirroring` |
| `redundancy/mirror-group-primary-replicas` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-matrix-mirroring` |
| `redundancy/private-body-relay-borne` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-matrix-mirroring` |
| `redundancy/promotion-republishes-pointer` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-matrix-mirroring` |
| `redundancy/rekey-remove-not-join` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-matrix-mirroring` |
| `registry/downref-nonfrozen-rejected` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-registry` |
| `registry/frozen-entry-immutable` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-registry` |
| `relay-interop/auth-rejection-permanent` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | — | `heterodyne:comms/0.5.0#comms-publishing` |
| `relay-interop/keri-rotation-auth-new-key` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | — | `heterodyne:comms/0.5.0#comms-publishing` |
| `relay-interop/nip42-auth-current-epoch-key` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | — | `heterodyne:comms/0.5.0#comms-publishing` |
| `relay-profile/kel-aware-reputation-continuity` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-nostr-relay-interop` |
| `relay-profile/nip11-capability-advert` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-nostr-relay-interop` |
| `relay-profile/passive-witness-store-signs-nothing` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-nostr-relay-interop` |
| `relay-profile/vanilla-nip01-unaffected` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-nostr-relay-interop` |
| `repo-relay/invalid-signature-rejected` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-repo-relay` |
| `repo-relay/light-node-submit-write-path` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-repo-relay` |
| `repo-relay/nip01-read-write-roundtrip` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-repo-relay` |
| `room-kind/current-kinds-roundtrip` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-discussion-rooms` |
| `room-kind/legacy-read-back-map` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-discussion-rooms` |
| `room-kind/retired-kind-rejected` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-discussion-rooms` |
| `routing-node/expired-advert-discarded` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-node-roles` |
| `routing-node/repo-location-from-ads-only` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-node-roles` |
| `routing-node/unverifiable-advert-discarded` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-node-roles` |
| `social-recovery/cache-rejects-unauthorized-content` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-recovery` |
| `social-recovery/cache-sourced-marked-stale` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-recovery` |
| `social-recovery/cold-root-reanchor-authoritative` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-recovery` |
| `social-recovery/retention-30-days` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-recovery-binding` |
| `social-recovery/three-tier-caching` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-recovery-binding` |
| `stamping/control-carrier-comms-owner` | core | `core/0.5.0` | — | 1 | `comms-subprotocol-payload-v1` | `heterodyne:core/0.5.0#core-version-stamps` |
| `stamping/control-profile-retains-core-owner` | core | `core/0.5.0` | — | 1 | `heterodyne-control-session-device-v1` | `heterodyne:core/0.5.0#core-version-stamps` |
| `stamping/dr-outer-unstamped` | core | `core/0.5.0` | — | 1 | `heterodyne-comms-double-ratchet-message-v1` | `heterodyne:core/0.5.0#core-version-stamps` |
| `stamping/heterodyne-empty-content-tag-owner` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-version-stamps` |
| `stamping/heterodyne-json-content-owner` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-version-stamps` |
| `stamping/legacy-malformed-not-inferable` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-version-stamps` |
| `stamping/legacy-monolith-explicit` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-version-stamps` |
| `stamping/legacy-monolith-inferred` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-version-stamps` |
| `stamping/legacy-post-split-not-inferable` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-version-stamps` |
| `stamping/legacy-profile-only-not-inferable` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-version-stamps` |
| `stamping/legacy-upstream-not-inferable` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-version-stamps` |
| `stamping/no-restamp-existing-bytes` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-version-stamps` |
| `stamping/non-stamping-profile-unchanged` | core | `core/0.5.0` | — | 1 | `heterodyne-core-rotation-breadcrumb-profile-v1` | `heterodyne:core/0.5.0#core-version-stamps` |
| `stamping/tier3-profile-owner` | core | `core/0.5.0` | — | 1 | `heterodyne-comms-tier3-wrapped-content-kind-1-v1` | `heterodyne:core/0.5.0#core-version-stamps` |
| `stamping/upstream-profile-owner` | core | `core/0.5.0` | — | 1 | `heterodyne-social-mute-list-v1` | `heterodyne:core/0.5.0#core-version-stamps` |
| `stamping/upstream-unstamped` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-version-stamps` |
| `transport/egress-tor-off-default-indicator` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-tor-reachability` |
| `transport/onion-no-clearnet-dns-leak` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-tor-reachability` |
| `transport/onion-reachable-via-tor` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-tor-reachability` |
| `transport/strict-mode-egress-tor-default-on` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-tor-reachability` |
| `transport/wasm-bridge-no-bridge-indicator` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-tor-reachability` |
| `verification/backdated-event-suspicion-window` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-verification` |
| `verification/bad-signature-rejects` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-verification` |
| `verification/delegation-mismatch-rejects` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-verification` |
| `verification/revoked-key-rejects` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-verification` |
| `versioning/capabilities-roundtrip` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-versioning` |
| `versioning/core-capability-bootstrap` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-versioning` |
| `versioning/older-receiver-newer-sender` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-versioning` |
| `versioning/per-document-negotiation` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-versioning` |
| `versioning/qualified-version-unqualified-rejected` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-versioning` |
| `versioning/qualified-version-valid` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-versioning` |
| `versioning/unknown-asynchronous-stamp-rejected` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-versioning` |
| `versioning/unknown-major-placeholder` | core | `core/0.5.0` | — | 1 | — | `heterodyne:core/0.5.0#core-versioning` |
| `versioning/unknown-room-kind-tolerance` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 1 | — | `heterodyne:social/0.5.0#social-discussion-rooms` |
