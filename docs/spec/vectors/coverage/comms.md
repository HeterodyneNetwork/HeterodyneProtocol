# Comms vector coverage

Generated from [manifest.json](manifest.json); do not edit by hand.

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
| `comms-envelope/nostr-native-event-valid` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | — | `heterodyne:comms/0.5.0#comms-envelope` |
| `comms-envelope/nostr-native-signature-mutation` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | — | `heterodyne:comms/0.5.0#comms-envelope` |
| `comms-envelope/owner-stamp-valid` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | `comms-subprotocol-payload-v1` | `heterodyne:comms/0.5.0#comms-subprotocol-negotiation` |
| `config-backup/config-blob-encrypt-decrypt` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | — | `heterodyne:comms/0.5.0#comms-config-repository` |
| `config-backup/key-id-derivation` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | — | `heterodyne:comms/0.5.0#comms-config-repository` |
| `config-backup/key-rotation-ref-delta` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | — | `heterodyne:comms/0.5.0#comms-config-repository` |
| `dm/double-ratchet-transcript` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | `heterodyne-comms-double-ratchet-message-v1` | `heterodyne:comms/0.5.0#comms-dm-wire` |
| `dm/invite-delegated-device-valid` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | `heterodyne-comms-double-ratchet-invite-v1` | `heterodyne:comms/0.5.0#comms-dm-wire` |
| `dm/invite-revoked-device-rejected` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | `heterodyne-comms-double-ratchet-invite-v1` | `heterodyne:comms/0.5.0#comms-dm-wire` |
| `dm/invite-unbound-device-rejected` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | `heterodyne-comms-double-ratchet-invite-v1` | `heterodyne:comms/0.5.0#comms-dm-wire` |
| `dm/kind1060-outer-message-shape` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | `heterodyne-comms-double-ratchet-message-v1` | `heterodyne:comms/0.5.0#comms-dm-wire` |
| `dm/repo-relay-refuses-kind1060` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | `heterodyne-comms-double-ratchet-message-v1` | `heterodyne:comms/0.5.0#comms-dm-wire` |
| `index/complete-fetch-attempt` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | — | `heterodyne:comms/0.5.0#comms-feed-index` |
| `index/prev-page-hash` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | — | `heterodyne:comms/0.5.0#comms-feed-index` |
| `org/canonical-branch-reachability` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | — | `heterodyne:comms/0.5.0#comms-org-authorization` |
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
| `profiles/dr-invite-response-kind1059` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | `heterodyne-comms-double-ratchet-invite-response-v1` | `heterodyne:comms/0.5.0#comms-dm-wire` |
| `profiles/tier3-kind-1` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | `heterodyne-comms-tier3-wrapped-content-kind-1-v1` | `heterodyne:comms/0.5.0#comms-tier-three-profile` |
| `profiles/tier3-kind-1063` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | `heterodyne-comms-tier3-wrapped-content-kind-1063-v1` | `heterodyne:comms/0.5.0#comms-tier-three-profile` |
| `profiles/tier3-kind-16` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | `heterodyne-comms-tier3-wrapped-content-kind-16-v1` | `heterodyne:comms/0.5.0#comms-tier-three-profile` |
| `profiles/tier3-kind-30023` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | `heterodyne-comms-tier3-wrapped-content-kind-30023-v1` | `heterodyne:comms/0.5.0#comms-tier-three-profile` |
| `profiles/tier3-kind-30402` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | `heterodyne-comms-tier3-wrapped-content-kind-30402-v1` | `heterodyne:comms/0.5.0#comms-tier-three-profile` |
| `profiles/tier3-kind-6` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | `heterodyne-comms-tier3-wrapped-content-kind-6-v1` | `heterodyne:comms/0.5.0#comms-tier-three-profile` |
| `relay-interop/auth-rejection-permanent` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | — | `heterodyne:comms/0.5.0#comms-publishing` |
| `relay-interop/keri-rotation-auth-new-key` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | — | `heterodyne:comms/0.5.0#comms-publishing` |
| `relay-interop/nip42-auth-current-epoch-key` | comms | `comms/0.5.0` | core=core/0.5.0 | 1 | — | `heterodyne:comms/0.5.0#comms-publishing` |
