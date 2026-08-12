# Protocol-family vector coverage

Generated from [manifest.json](manifest.json); do not edit by hand.

- core: 146
- comms: 206
- control: 51
- social: 53

| Vector | Owner | Version | Dependencies | Registry | Profile | Spec references |
|---|---|---|---|---:|---|---|
| `acceptance-gating/authentication-before-policy` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-acceptance-hook` |
| `acceptance-gating/authentication-reject` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-acceptance-hook` |
| `acceptance-gating/control-capacity-reject` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-acceptance-hook` |
| `acceptance-gating/control-default-off-reject` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-acceptance-hook` |
| `acceptance-gating/control-entitled-authorized` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-acceptance-hook` |
| `acceptance-gating/control-entitlement-conflict-reject` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-acceptance-hook` |
| `acceptance-gating/control-explicit-reject-absorbing` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-acceptance-hook` |
| `acceptance-gating/control-permanent-enrollment-only` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-acceptance-hook` |
| `acceptance-gating/dm-invite-accept` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-acceptance-hook` |
| `acceptance-gating/established-ordinary-accept` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-acceptance-hook` |
| `acceptance-gating/message-request-no-receipt` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-acceptance-hook` |
| `acceptance-gating/new-ordinary-hold` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-acceptance-hook` |
| `acceptance-gating/ordinary-explicit-reject` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-acceptance-hook` |
| `acceptance-gating/social-mute-tightens` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | — | `heterodyne:social/0.5.0#social-admission-policy` |
| `acceptance-gating/social-policy-cannot-loosen` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | — | `heterodyne:social/0.5.0#social-admission-policy` |
| `acceptance-gating/social-wot-cannot-loosen` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | — | `heterodyne:social/0.5.0#social-admission-policy` |
| `acceptance-gating/social-wot-tightens-only` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | — | `heterodyne:social/0.5.0#social-admission-policy` |
| `agent-authorship/attribution-kind-1` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | `heterodyne-comms-agent-attribution-kind-1-v1` | `heterodyne:comms/0.5.0#comms-agent-attribution` |
| `agent-authorship/attribution-kind-1063` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | `heterodyne-comms-agent-attribution-kind-1063-v1` | `heterodyne:comms/0.5.0#comms-agent-attribution` |
| `agent-authorship/attribution-kind-16` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | `heterodyne-comms-agent-attribution-kind-16-v1` | `heterodyne:comms/0.5.0#comms-agent-attribution` |
| `agent-authorship/attribution-kind-1985` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | `heterodyne-comms-agent-attribution-kind-1985-v1` | `heterodyne:comms/0.5.0#comms-agent-attribution` |
| `agent-authorship/attribution-kind-30023` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | `heterodyne-comms-agent-attribution-kind-30023-v1` | `heterodyne:comms/0.5.0#comms-agent-attribution` |
| `agent-authorship/attribution-kind-4550` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | `heterodyne-comms-agent-attribution-kind-4550-v1` | `heterodyne:comms/0.5.0#comms-agent-attribution` |
| `agent-authorship/attribution-kind-6` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | `heterodyne-comms-agent-attribution-kind-6-v1` | `heterodyne:comms/0.5.0#comms-agent-attribution` |
| `agent-authorship/attribution-kind-7` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | `heterodyne-comms-agent-attribution-kind-7-v1` | `heterodyne:comms/0.5.0#comms-agent-attribution` |
| `agent-authorship/caller-forgery-replaced` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-agent-attribution` |
| `agent-authorship/cross-persona-unlinkable` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-agent-attribution` |
| `agent-authorship/delegation-key-proof-invalid` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-agent-delegation` |
| `agent-authorship/delegation-valid` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | `heterodyne-comms-agent-signing-delegation-v1` | `heterodyne:comms/0.5.0#comms-agent-delegation` |
| `agent-authorship/human-review-preserves-agent-label` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-agent-attribution` |
| `agent-authorship/idempotent-retry-reuses-event` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-agent-attribution` |
| `agent-authorship/multiple-roles-one-nid` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-agent-delegation` |
| `agent-authorship/profile-unavailable-rejected` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-agent-fail-closed` |
| `agent-authorship/role-key-replacement` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-agent-delegation` |
| `agent-authorship/stable-identity-renewal` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-agent-workload` |
| `agent-authorship/tier3-inner-only` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-agent-attribution` |
| `agent-authorship/token-audience-invalid` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-agent-token` |
| `agent-authorship/token-expired` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-agent-token` |
| `agent-authorship/token-revoked` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-agent-token` |
| `agent-authorship/token-role-mismatch` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-agent-token` |
| `agent-authorship/token-sender-proof-invalid` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-agent-token` |
| `agent-authorship/token-valid` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-agent-token` |
| `agent-authorship/workload-registration-unbounded-rejected` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-agent-workload` |
| `agent-authorship/workload-registration-valid` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-agent-workload` |
| `agent-moderation/correction-list-removed` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | — | `heterodyne:social/0.5.0#social-agent-policy-receipts` |
| `agent-moderation/correction-list-retained` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | — | `heterodyne:social/0.5.0#social-agent-policy-receipts` |
| `agent-moderation/correction-valid` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | — | `heterodyne:social/0.5.0#social-agent-policy-receipts` |
| `agent-moderation/default-visible-removable` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | — | `heterodyne:social/0.5.0#social-agent-policy-list` |
| `agent-moderation/policy-binding-mismatch` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | — | `heterodyne:social/0.5.0#social-agent-policy-list` |
| `agent-moderation/policy-list-valid` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | `heterodyne-social-agent-policy-list-v1` | `heterodyne:social/0.5.0#social-agent-policy-list` |
| `agent-moderation/receipt-malformed` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | — | `heterodyne:social/0.5.0#social-agent-policy-receipts` |
| `agent-moderation/receipt-private-leakage` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | — | `heterodyne:social/0.5.0#social-agent-policy-receipts` |
| `agent-moderation/receipt-valid` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | `heterodyne-social-agent-policy-receipt-v1` | `heterodyne:social/0.5.0#social-agent-policy-receipts` |
| `agent-moderation/relay-only-no-effect` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | — | `heterodyne:social/0.5.0#social-agent-policy-list` |
| `agent-moderation/replacement-key-independent` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | — | `heterodyne:social/0.5.0#social-agent-policy-list` |
| `agent-moderation/subscribed-canonical-mutes` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | — | `heterodyne:social/0.5.0#social-agent-policy-list` |
| `agent-moderation/unmerged-pr-no-effect` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | — | `heterodyne:social/0.5.0#social-agent-policy-list` |
| `agent-moderation/unsubscribed-no-effect` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | — | `heterodyne:social/0.5.0#social-agent-policy-list` |
| `atproto/connection-pinning-unavailable` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | — | `heterodyne:social/0.5.0#social-atproto-resolution` |
| `atproto/pinned-public-hop` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | — | `heterodyne:social/0.5.0#social-atproto-resolution` |
| `breadcrumbs/compromise-rotation-not-produced` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-kel-rotation` |
| `breadcrumbs/ordinary-consumer-no-profile-inference` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-kel-rotation` |
| `breadcrumbs/repointed-nip05-rejected` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-kel-rotation` |
| `breadcrumbs/unrelated-successor-rejected` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-kel-rotation` |
| `claim-ledger/authority-reduction-wins` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-claim-ledger` |
| `claim-ledger/checkpoint-rollback-rejected` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-claim-ledger` |
| `claim-ledger/delivered-grant-provisional` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-claim-ledger` |
| `claim-ledger/immediate-revocation` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-claim-ledger` |
| `claim-ledger/keyed-path-metadata-private` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-claim-ledger` |
| `claim-ledger/multiwriter-revocation-wins` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-claim-ledger` |
| `claim-ledger/multiwriter-status-allocation` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-multiwriter-minting` |
| `claim-ledger/nidless-reader-denied` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-claim-ledger` |
| `claim-ledger/nonmonotonic-conflict-blocks` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-claim-ledger` |
| `claim-ledger/reader-nid-authorized` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-claim-ledger` |
| `claim-ledger/reader-removal-key-rotation` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-claim-ledger` |
| `claim-ledger/source-claim-revokes-token` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-claim-revocation` |
| `claim-ledger/stale-minter-denied` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-multiwriter-minting` |
| `claims/authorization-self-revocation` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | `heterodyne-comms-claim-revocation-nostr-bip340-v1` | `heterodyne:comms/0.5.0#comms-claim-revocation` |
| `claims/canonical-jwk-thumbprint-subject` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | `heterodyne-comms-claim-revocation-jwk-jws-v1` | `heterodyne:comms/0.5.0#comms-key-claims` |
| `claims/canonical-nostr-subject` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | `heterodyne-comms-key-claim-nostr-bip340-v1` | `heterodyne:comms/0.5.0#comms-key-claims` |
| `claims/canonical-radicle-nid-subject` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | `heterodyne-comms-key-claim-radicle-ed25519-v1` | `heterodyne:comms/0.5.0#comms-key-claims` |
| `claims/chain-attenuation-valid` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-claim-chain` |
| `claims/chain-depth-exceeded` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-claim-chain` |
| `claims/chain-widening-rejected` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-claim-chain` |
| `claims/claim-id-mismatch` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-key-claims` |
| `claims/copied-proof-rejected` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-claim-verification` |
| `claims/delegated-issuance-active` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-claim-verification` |
| `claims/descriptive-subject-rejection` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | `heterodyne-comms-claim-revocation-radicle-ed25519-v1` | `heterodyne:comms/0.5.0#comms-claim-revocation` |
| `claims/local-only-no-publication` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-key-claims` |
| `claims/pairwise-private-marmot-delivery` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-key-claims` |
| `claims/persona-issuance-active` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-claim-verification` |
| `claims/provisional-authorization-denied` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-claim-ledger` |
| `claims/public-claim-publication` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-key-claims` |
| `claims/repository-confirmed-active` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-claim-ledger` |
| `claims/repository-private-encryption` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-key-claims` |
| `claims/subject-proof-valid` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | `heterodyne-comms-key-claim-jwk-jws-v1` | `heterodyne:comms/0.5.0#comms-claim-verification` |
| `claims/third-party-issuer-untrusted` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-claim-verification` |
| `config-backup/config-blob-encrypt-decrypt` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-config-repository` |
| `config-backup/config-rid-advertised-rejected` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-keys-repository` |
| `config-backup/config-rid-unadvertised-clean` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-keys-repository` |
| `config-backup/key-id-derivation` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-config-repository` |
| `config-backup/key-rotation-ref-delta` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-config-repository` |
| `config-backup/nip49-nsec-wrap` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-keys-repository` |
| `control/authorization-fresh-read` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-token` |
| `control/authorization-mutation-sync-failed` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-token` |
| `control/authorization-stale-read` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-token` |
| `control/device-code-display-mismatch` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-device-authorization` |
| `control/device-code-exhausted` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-device-authorization` |
| `control/device-code-hardened` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-device-authorization` |
| `control/device-code-node-rate-limited` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-device-authorization` |
| `control/entitlement-expansion-rejected` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-entitlement` |
| `control/entitlement-reduction` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-entitlement` |
| `control/entitlement-revocation-absorbing` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-entitlement` |
| `control/epoch-activation-mismatch` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-epoch-bootstrap` |
| `control/epoch-exact-activation` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-epoch-bootstrap` |
| `control/epoch-locked` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-epoch-bootstrap` |
| `control/epoch-prepare-and-relock` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-epoch-bootstrap` |
| `control/failover-idempotent-mutation` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-failover` |
| `control/failover-indeterminate-mutation` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-failover` |
| `control/failover-read` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-failover` |
| `control/invitation-account-cap` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-invitation-policy` |
| `control/invitation-disabled` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-invitation-policy` |
| `control/invitation-enrollment-only` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-invitation-policy` |
| `control/invitation-global-cap` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-invitation-policy` |
| `control/invitation-nonenrollment-rejected` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-invitation-policy` |
| `control/invitation-rate-limited` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-invitation-policy` |
| `control/invitation-replenishment-paused` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-invitation-policy` |
| `control/invitation-reserved-slot` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-invitation-policy` |
| `control/invitation-revoked` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-invitation-policy` |
| `control/invite-preauthorization-keri-rejected` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-token` |
| `control/invite-preauthorization-key-bound` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-token` |
| `control/invite-preauthorization-unbound-higher-risk` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-token` |
| `control/invite-preauthorization-unbound-rejected` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-token` |
| `control/operation-conflicting-bytes` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-request-processing` |
| `control/operation-first-reservation` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-request-processing` |
| `control/operation-identical-join` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-request-processing` |
| `control/pending-enrollment-expired` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-conformance` |
| `control/pending-enrollment-live` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-conformance` |
| `control/recovery-grant-accepted` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-radicle-recovery` |
| `control/recovery-grant-confined` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-radicle-recovery` |
| `control/retention-ceiling-and-backup-exclusion` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-retention` |
| `control/sftp-address-separated` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-sftp-recovery` |
| `control/sftp-grant-accepted` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-sftp-recovery` |
| `control/sftp-grant-expired` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-sftp-recovery` |
| `control/sftp-root-confined` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-sftp-recovery` |
| `control/token-default-five-minutes` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-token` |
| `control/token-explicit-sixty-minutes` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-token` |
| `control/token-extension-missing-capability` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-token` |
| `control/token-scope-rejected` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-token` |
| `control/token-stale-authorization-view` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-token` |
| `control/token-valid` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-token` |
| `control/token-wrong-group` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-token` |
| `control/token-wrong-node` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-token` |
| `control/token-wrong-sender` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-token` |
| `core-redundancy/radicle-multihost-replication` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-multi-host-seeding` |
| `core-redundancy/stale-seed-does-not-remove-durability` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-multi-host-seeding` |
| `credential-continuity/candidate-exact-tip-append` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-credential-continuity` |
| `credential-continuity/checkpoint-genesis` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-credential-continuity` |
| `credential-continuity/cold-root-exposure-migrates` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-credential-continuity` |
| `credential-continuity/config-git-raw-projection` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-credential-continuity` |
| `credential-continuity/governed-obligation-equation` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-credential-continuity` |
| `credential-continuity/pending-retirement-conservative` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-credential-continuity` |
| `credential-continuity/retention-inventory-genesis` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-credential-continuity` |
| `credential-continuity/routine-removal-complete` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-credential-continuity` |
| `credential-continuity/seventeen-schemas-draft` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-credential-continuity` |
| `credential-continuity/stale-generation` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-credential-continuity` |
| `discussion/reaction-reply-bare-not-indexed` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | — | `heterodyne:social/0.5.0#social-discussion-rooms` |
| `identity-doc/add-before-remove` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-identity-discovery` |
| `identity-doc/emergency-reanchor` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-identity-discovery` |
| `identity-doc/emergency-reanchor-v050` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-identity-discovery` |
| `identity-doc/kel-revoked-nid-rejected` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-identity-discovery` |
| `identity/delegation-active` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-nid-delegation` |
| `identity/delegation-expired` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-nid-delegation` |
| `identity/delegation-revoked` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-nid-delegation` |
| `identity/identity-room-full-state` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | — | `heterodyne:social/0.5.0#social-identity-room` |
| `identity/revocation-post-window` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-nid-delegation` |
| `identity/root-attestation-valid` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-root-attestation` |
| `identity/root-attestation-valid-v050` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-root-attestation` |
| `index/complete-fetch-attempt` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-feed-index` |
| `index/missing-predecessor-structured-outcome` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-feed-index` |
| `index/prev-page-hash` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-feed-index` |
| `interop/kind31005-identity-pointer` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-identity-pointer` |
| `interop/vanilla-nostr-only-follow` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | — | `heterodyne:social/0.5.0#social-following` |
| `keri-authority/accelerator-backdated-compromise` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-kel-verification` |
| `keri-authority/accelerator-decision-equivalent` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-kel-verification` |
| `keri-authority/delegation-conflict-repo-wins` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-kel-verification` |
| `keri-authority/dependent-events-unresolved` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-kel-verification` |
| `keri-authority/equivocation-flagged` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-kel-verification` |
| `keri-authority/export-aid-digest-anchoring` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-keri-export` |
| `keri-authority/export-aid-substituted-for-npub-rejected` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-keri-export` |
| `keri-authority/export-degraded-metadata` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-keri-export` |
| `keri-authority/export-incomplete` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-keri-export` |
| `keri-authority/export-origin-absent-not-failure` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-keri-export` |
| `keri-authority/export-unmappable-feature` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-keri-export` |
| `keri-authority/export-unsupported-crypto-suite` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-keri-export` |
| `keri-authority/kel-head-absent-rejected` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-kel-head` |
| `keri-authority/kel-head-duplicate-rejected` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-kel-head` |
| `keri-authority/kel-head-forbidden-on-inception` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-kel-head` |
| `keri-authority/kel-head-forbidden-on-rotation` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-kel-head` |
| `keri-authority/kel-head-malformed-rejected` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-kel-head` |
| `keri-authority/kel-head-mandatory-on-delegation` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-kel-head` |
| `keri-authority/kel-head-mandatory-on-root` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-kel-head` |
| `keri-authority/kel-head-seq-mismatch-rejected` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-kel-head` |
| `keri-authority/keri10json-cesr-wire-rejected` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-kel-verification` |
| `keri-authority/materialized-atomic-rebuild` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-materialized-kel` |
| `keri-authority/materialized-empty-kel-deletion` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-materialized-kel` |
| `keri-authority/materialized-log-derivation` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-materialized-kel` |
| `keri-authority/materialized-refs-not-authority` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-materialized-kel` |
| `keri-authority/materialized-state-derivation` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-materialized-kel` |
| `keri-authority/provisional-not-hardened-repo-unreachable` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-kel-verification` |
| `keri-authority/refresh-failed-not-condition-d` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-kel-verification` |
| `keri-authority/repo-head-regression-rejected` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-kel-verification` |
| `keri-authority/withdrawal-causally-behind-no-withdraw` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-kel-verification` |
| `keri-authority/withdrawal-converged-head` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-kel-verification` |
| `keri/didkey-witness-no-network` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-kel-primitives` |
| `keri/first-seen-ordering` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-kel-primitives` |
| `keri/fork-resolution-conflicting-rotations` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-kel-primitives` |
| `keri/inception-event` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-kel-primitives` |
| `keri/informal-vouch-not-counted` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-kel-primitives` |
| `keri/rotation-committed-strategy` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-kel-primitives` |
| `keri/rotation-none-witness-threshold` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-kel-primitives` |
| `key-retirement/compromise-cutoff-rejected` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-retired-key-observation` |
| `key-retirement/local-receipt-pre-retirement` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-retired-key-observation` |
| `key-retirement/relay-only-provisional` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-retired-key-observation` |
| `key-retirement/repo-anchored-pre-retirement` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-retired-key-observation` |
| `light-node/content-not-through-routing-node` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-client-responsibilities` |
| `light-node/route-around-withholding-host` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-client-responsibilities` |
| `light-node/verifies-signature-locally` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-client-responsibilities` |
| `lists/kind-mute-set-addressing` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | — | `heterodyne:social/0.5.0#social-lists` |
| `lists/mute-list-private-items-encrypted-to-self` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | — | `heterodyne:social/0.5.0#social-lists` |
| `lists/mute-list-private-items-encrypted-to-self-v050` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | `heterodyne-social-mute-list-v1` | `heterodyne:social/0.5.0#social-mute-profile` |
| `lists/mute-list-public-roundtrip` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | — | `heterodyne:social/0.5.0#social-lists` |
| `lists/mute-list-public-roundtrip-v050` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | `heterodyne-social-mute-list-v1` | `heterodyne:social/0.5.0#social-mute-profile` |
| `lists/policy-list-adoption-parsed` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | — | `heterodyne:social/0.5.0#social-lists` |
| `lists/private-items-reencrypt-on-rotation` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | `heterodyne-social-mute-list-v1` | `heterodyne:social/0.5.0#social-mute-profile` |
| `lists/stale-list-rollback-rejected` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | `heterodyne-social-mute-list-v1` | `heterodyne:social/0.5.0#social-mute-profile` |
| `marmot-radicle/agent-group-attribution` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-agent-authorship` |
| `marmot-radicle/agent-group-scope-denied` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-agent-authorship` |
| `marmot-radicle/canonical-h-equivocation` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-marmot-routing-generation` |
| `marmot-radicle/concurrent-routing-marmot-wins` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-marmot-routing-generation` |
| `marmot-radicle/direct-member-history-boundary` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-marmot-participation` |
| `marmot-radicle/directory-sensitive-fields-encrypted` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-marmot-directory` |
| `marmot-radicle/expiration-is-not-erasure` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-marmot-retention` |
| `marmot-radicle/failover-delivery` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-marmot-rotation` |
| `marmot-radicle/invites-individually-sealed` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-marmot-directory` |
| `marmot-radicle/keypackage-replay-rejected` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-marmot-persona-inbox` |
| `marmot-radicle/kind445-exact-bytes` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-marmot-exact-bytes` |
| `marmot-radicle/logical-size-cap-control-open` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-marmot-event-repository` |
| `marmot-radicle/media-exact-bytes` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-marmot-exact-bytes` |
| `marmot-radicle/node-mediated-secret-confinement` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-marmot-participation` |
| `marmot-radicle/persona-inbox-atomic-bootstrap` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-marmot-persona-inbox` |
| `marmot-radicle/private-group-radicle-required` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-marmot-groups` |
| `marmot-radicle/private-inbox-nid-required` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-marmot-persona-inbox` |
| `marmot-radicle/public-inbox-lazy-media` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-marmot-persona-inbox` |
| `marmot-radicle/radicle-durable-ack` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-marmot-rotation` |
| `marmot-radicle/redundant-delivery-dedup` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-marmot-rotation` |
| `marmot-radicle/relay-ack-before-durable-rejected` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-marmot-rotation` |
| `marmot-radicle/relay-routes-by-h-only` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-marmot-relay` |
| `marmot-radicle/removal-before-routing-rotation` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-marmot-routing-generation` |
| `marmot-radicle/repeated-media-locators` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-marmot-media` |
| `marmot-radicle/retained-routing-overlap` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-marmot-retention` |
| `marmot-radicle/routing-binding-valid` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-marmot-routing-generation` |
| `marmot-radicle/routing-genesis-mismatch` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-marmot-routing-generation` |
| `marmot-radicle/standard-marmot-interop` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-marmot-groups` |
| `marmot-radicle/unauthorized-ref-rejected` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-marmot-event-repository` |
| `marmot-radicle/writer-ref-union-dedup` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-marmot-event-repository` |
| `moderation/approvals-required-absent-default-one` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | — | `heterodyne:social/0.5.0#social-moderation` |
| `moderation/contributor-implicit-rejection-window` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | — | `heterodyne:social/0.5.0#social-moderation` |
| `moderation/kind34550-approvals-required` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | — | `heterodyne:social/0.5.0#social-moderation` |
| `moderation/moderator-rotation-through-kel` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | — | `heterodyne:social/0.5.0#social-moderation` |
| `moderation/multi-mod-requirement` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | — | `heterodyne:social/0.5.0#social-moderation` |
| `moderation/nip72-approval` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | — | `heterodyne:social/0.5.0#social-moderation` |
| `moderation/radicle-editorial-gating` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | — | `heterodyne:social/0.5.0#social-moderation` |
| `moderation/redaction-of-approved-post` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | — | `heterodyne:social/0.5.0#social-moderation` |
| `moderation/relay-only-created-at-fallback` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | — | `heterodyne:social/0.5.0#social-moderation` |
| `moderation/repo-anchor-asof-after-removal-rejected` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | — | `heterodyne:social/0.5.0#social-moderation` |
| `moderation/repo-anchor-asof-before-removal-counts` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | — | `heterodyne:social/0.5.0#social-moderation` |
| `moderation/strict-mode-bare-not-hidden` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | — | `heterodyne:social/0.5.0#social-moderation` |
| `moderation/strict-mode-invalid-event-signature` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | — | `heterodyne:social/0.5.0#social-moderation` |
| `moderation/strict-mode-kind5-deletion-30s` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | — | `heterodyne:social/0.5.0#social-moderation` |
| `moderation/strict-mode-state-downgrade-warning` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | — | `heterodyne:social/0.5.0#social-moderation` |
| `nid-binding/bidirectional-valid` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-nid-delegation` |
| `nid-binding/bidirectional-valid-v050` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-nid-delegation` |
| `nid-binding/invalid-nid-proof-rejected` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-nid-delegation` |
| `nid-binding/missing-nid-proof-rejected` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-nid-delegation` |
| `node-advert/excessive-lifetime` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-node-advertisement` |
| `node-advert/expired-rejected` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-node-advertisement` |
| `node-advert/expiry-not-after-created` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-node-advertisement` |
| `node-advert/future-clock-skew` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-node-advertisement` |
| `node-advert/maximum-lifetime` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-node-advertisement` |
| `node-advert/nid-proof-invalid-rejected` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-node-advertisement` |
| `node-advert/outer-sig-invalid-rejected` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-node-advertisement` |
| `node-advert/past-clock-skew` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-node-advertisement` |
| `node-advert/refresh-by-twelve-hours` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-node-advertisement` |
| `node-advert/uncertain-clock-rejected` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-node-advertisement` |
| `node-advert/valid-dual-signed` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-node-advertisement` |
| `node-advert/valid-dual-signed-v050` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-node-advertisement` |
| `oidc/authorization-code-pkce` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-oidc-authorization` |
| `oidc/device-authorization` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-oidc-authorization` |
| `oidc/discovery-exact-issuer` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-oidc-endpoints` |
| `oidc/dpop-confirmation-bound` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-jwt-projection` |
| `oidc/id-token-valid` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-jwt-projection` |
| `oidc/issuer-mismatch-rejected` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-oidc-endpoints` |
| `oidc/mtls-confirmation-bound` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-jwt-projection` |
| `oidc/pairwise-subject` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-oidc-authorization` |
| `oidc/prohibited-grants` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-oidc-authorization` |
| `oidc/registered-jwt-assertion` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-jwt-projection` |
| `oidc/rfc9068-access-token-valid` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-jwt-projection` |
| `oidc/stable-key-consent-gated` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-oidc-authorization` |
| `oidc/token-type-confusion-rejected` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-jwt-projection` |
| `one-time-invite/descriptor-and-fragment` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-one-time-invites` |
| `one-time-invite/expired` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-one-time-invites` |
| `one-time-invite/first-valid-reservation` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-one-time-invites` |
| `one-time-invite/invalid-keypackage-no-reservation` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-one-time-invites` |
| `one-time-invite/purpose-mismatch` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-one-time-invites` |
| `one-time-invite/reservation-race-rejected` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-one-time-invites` |
| `one-time-invite/reserved-responder-retry` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-one-time-invites` |
| `one-time-invite/response-proof` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-one-time-invites` |
| `org/canonical-branch-reachability` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-org-authorization` |
| `org/member-add-dual-authorized` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-threshold-authority` |
| `org/member-add-single-authorization-insufficient` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-threshold-authority` |
| `org/threshold-delegate-governance` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-threshold-authority` |
| `outbox/cross-backend-reply-dedup` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | — | `heterodyne:social/0.5.0#social-interactions` |
| `outbox/cross-persona-attestation-invalid` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | — | `heterodyne:social/0.5.0#social-interactions` |
| `outbox/cross-persona-attestation-valid` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | — | `heterodyne:social/0.5.0#social-interactions` |
| `outbox/full-public-outbox` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-retrieval` |
| `outbox/scoped-outbox` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-retrieval` |
| `outbox/transitive-discovery-walk` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-retrieval` |
| `persona-profile/designated-publisher-valid` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-persona-profile` |
| `persona-profile/exact-author-set-discovery` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-persona-profile` |
| `persona-profile/nip05-mismatch-rejected` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-persona-profile` |
| `persona-profile/relay-only-replacement-rejected` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-persona-profile` |
| `persona-profile/successor-address-republished` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-persona-profile` |
| `privacy-tiers/all-active-devices` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-privacy-tiers` |
| `privacy-tiers/audience-key-rotation-on-removal` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-privacy-tiers` |
| `privacy-tiers/cold-root-recipient-rejected` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-privacy-tiers` |
| `privacy-tiers/complete-fetch-attempt` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-privacy-tiers` |
| `privacy-tiers/device-removal-rotates-generation` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-privacy-tiers` |
| `privacy-tiers/epoch-recipient-rejected` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-privacy-tiers` |
| `privacy-tiers/light-device-decryption` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-privacy-tiers` |
| `privacy-tiers/revoked-device-rejected` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-privacy-tiers` |
| `privacy-tiers/selected-device-narrowing` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-privacy-tiers` |
| `privacy-tiers/tier1-public-plaintext-both-backends` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-privacy-tiers` |
| `privacy-tiers/tier1-public-plaintext-both-backends-v050` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-privacy-tiers` |
| `privacy-tiers/tier2-private-repo-not-encrypted` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-privacy-tiers` |
| `privacy-tiers/tier3-index-key-derivation-and-encryption` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-privacy-tiers` |
| `privacy-tiers/tier3-index-key-derivation-and-encryption-v050` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-privacy-tiers` |
| `privacy-tiers/tier3-kind31011-audience-key-wrap` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-privacy-tiers` |
| `privacy-tiers/tier3-kind31011-audience-key-wrap-v050` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-privacy-tiers` |
| `privacy-tiers/tier3-kind31012-audience-roster` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-privacy-tiers` |
| `privacy-tiers/tier3-kind31012-audience-roster-v050` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-privacy-tiers` |
| `privacy-tiers/tier3-membership-metadata-disclosed` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-privacy-tiers` |
| `privacy-tiers/tier3-prev-page-hash-mismatch` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-privacy-tiers` |
| `privacy-tiers/tier3-prev-page-hash-valid` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-privacy-tiers` |
| `profiles/core-breadcrumb-kind0` | core | `core/0.5.0` | — | 7 | `heterodyne-core-rotation-breadcrumb-profile-v1` | `heterodyne:core/0.5.0#core-kel-rotation` |
| `profiles/core-breadcrumb-kind1` | core | `core/0.5.0` | — | 7 | `heterodyne-core-rotation-breadcrumb-note-v1` | `heterodyne:core/0.5.0#core-kel-rotation` |
| `profiles/social-org-feed-kind31007` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | `heterodyne-social-org-feed-v1` | `heterodyne:social/0.5.0#social-org-feed-profile` |
| `profiles/tier3-kind-1` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | `heterodyne-comms-tier3-wrapped-content-kind-1-v1` | `heterodyne:comms/0.5.0#comms-tier-three-profile` |
| `profiles/tier3-kind-1063` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | `heterodyne-comms-tier3-wrapped-content-kind-1063-v1` | `heterodyne:comms/0.5.0#comms-tier-three-profile` |
| `profiles/tier3-kind-16` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | `heterodyne-comms-tier3-wrapped-content-kind-16-v1` | `heterodyne:comms/0.5.0#comms-tier-three-profile` |
| `profiles/tier3-kind-30023` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | `heterodyne-comms-tier3-wrapped-content-kind-30023-v1` | `heterodyne:comms/0.5.0#comms-tier-three-profile` |
| `profiles/tier3-kind-30402` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | `heterodyne-comms-tier3-wrapped-content-kind-30402-v1` | `heterodyne:comms/0.5.0#comms-tier-three-profile` |
| `profiles/tier3-kind-6` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | `heterodyne-comms-tier3-wrapped-content-kind-6-v1` | `heterodyne:comms/0.5.0#comms-tier-three-profile` |
| `public-reader/credential-relay-hint-rejected` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-public-launcher` |
| `public-reader/external-media-disclosure` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-public-reader-security` |
| `public-reader/failed-revocation-expiry` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-public-transition` |
| `public-reader/launcher-address-roundtrip` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-public-launcher` |
| `public-reader/launcher-event-roundtrip` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-public-launcher` |
| `public-reader/launcher-persona-roundtrip` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-public-launcher` |
| `public-reader/localhost-relay-hint-rejected` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-public-launcher` |
| `public-reader/logout-cleanup` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-public-transition` |
| `public-reader/malformed-entity-no-network` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-public-resolution` |
| `public-reader/nip65-refresh-replaces-stale-hint` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-public-resolution` |
| `public-reader/onion-hint-tor-required` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-public-launcher` |
| `public-reader/oversized-fragment-no-network` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-public-resolution` |
| `public-reader/private-resolved-relay-hint-rejected` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-public-launcher` |
| `public-reader/resolution-canonical` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-public-resolution` |
| `public-reader/resolution-conflicted` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-public-resolution` |
| `public-reader/resolution-private` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-public-resolution` |
| `public-reader/resolution-provisional-canonical` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-public-resolution` |
| `public-reader/resolution-unavailable` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-public-resolution` |
| `public-reader/resolution-unindexed-signed-event` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-public-resolution` |
| `public-reader/target-absent-from-http-path` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-public-launcher` |
| `public-reader/tier3-refused` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-public-resolution` |
| `public-reader/transition-without-reload` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-public-transition` |
| `public-reader/unknown-version-no-network` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-public-resolution` |
| `registry/control-strict-profile-flattened` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-registry` |
| `registry/downref-nonfrozen-rejected` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-registry` |
| `registry/feature-dependency-exact` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-registry` |
| `registry/feature-dependency-unprovided-rejected` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-registry` |
| `registry/frozen-entry-immutable` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-registry` |
| `relay-interop/auth-rejection-permanent` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-publishing` |
| `relay-interop/keri-rotation-auth-new-key` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-publishing` |
| `relay-interop/nip42-auth-current-epoch-key` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-publishing` |
| `relay-profile/kel-aware-reputation-continuity` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-nostr-relay-interop` |
| `relay-profile/nip11-capability-advert` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-nostr-relay-interop` |
| `relay-profile/passive-witness-store-signs-nothing` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-nostr-relay-interop` |
| `relay-profile/vanilla-nip01-unaffected` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-nostr-relay-interop` |
| `repo-relay/invalid-signature-rejected` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-repo-relay` |
| `repo-relay/light-node-submit-write-path` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-repo-relay` |
| `repo-relay/nip01-read-write-roundtrip` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-repo-relay` |
| `role-capabilities/browser-shared-relay-required` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-node-roles` |
| `role-capabilities/full-node-feature-set-required` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-node-roles` |
| `role-capabilities/full-node-onion-advertised` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-node-roles` |
| `role-capabilities/full-node-tor-default` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-node-roles` |
| `role-capabilities/public-reader-reduced-assurance` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-node-roles` |
| `role-capabilities/role-address-invalid` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-role-delegation` |
| `role-capabilities/role-address-valid` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-role-delegation` |
| `role-capabilities/strict-missing-tor-rejected` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-node-roles` |
| `routing-node/expired-advert-discarded` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-node-roles` |
| `routing-node/repo-location-from-ads-only` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-node-roles` |
| `routing-node/unverifiable-advert-discarded` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-node-roles` |
| `social-recovery/cache-sourced-marked-stale` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-recovery` |
| `social-recovery/cold-root-reanchor-authoritative` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-recovery` |
| `social-recovery/retention-30-days` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | — | `heterodyne:social/0.5.0#social-recovery-binding` |
| `social-recovery/three-tier-caching` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | — | `heterodyne:social/0.5.0#social-recovery-binding` |
| `stamping/heterodyne-empty-content-tag-owner` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-version-stamps` |
| `stamping/heterodyne-json-content-owner` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-version-stamps` |
| `stamping/legacy-malformed-not-inferable` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-version-stamps` |
| `stamping/legacy-monolith-explicit` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-version-stamps` |
| `stamping/legacy-monolith-inferred` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-version-stamps` |
| `stamping/legacy-post-split-not-inferable` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-version-stamps` |
| `stamping/legacy-profile-only-not-inferable` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-version-stamps` |
| `stamping/legacy-upstream-not-inferable` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-version-stamps` |
| `stamping/no-restamp-existing-bytes` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-version-stamps` |
| `stamping/non-stamping-profile-unchanged` | core | `core/0.5.0` | — | 7 | `heterodyne-core-rotation-breadcrumb-profile-v1` | `heterodyne:core/0.5.0#core-version-stamps` |
| `stamping/tier3-profile-owner` | core | `core/0.5.0` | — | 7 | `heterodyne-comms-tier3-wrapped-content-kind-1-v1` | `heterodyne:core/0.5.0#core-version-stamps` |
| `stamping/upstream-profile-owner` | core | `core/0.5.0` | — | 7 | `heterodyne-social-mute-list-v1` | `heterodyne:core/0.5.0#core-version-stamps` |
| `stamping/upstream-unstamped` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-version-stamps` |
| `token-status/https-outage-radicle-fallback` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-issuer-continuity` |
| `token-status/https-radicle-byte-identity` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-token-status` |
| `token-status/invalidated-token` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-token-status` |
| `token-status/issuer-successor` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-issuer-continuity` |
| `token-status/radicle-digest-mismatch` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-token-status` |
| `token-status/signing-key-compromise` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-token-status` |
| `token-status/stale-status-list-rejected` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-token-status` |
| `token-status/valid-status-list` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-token-status` |
| `token-status/writer-index-collision-rejected` | comms | `comms/0.5.0` | core=core/0.5.0 | 7 | — | `heterodyne:comms/0.5.0#comms-token-status` |
| `transport/egress-tor-off-default-indicator` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-tor-reachability` |
| `transport/onion-no-clearnet-dns-leak` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-tor-reachability` |
| `transport/onion-reachable-via-tor` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-tor-reachability` |
| `transport/strict-mode-egress-tor-default-on` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-tor-reachability` |
| `transport/wasm-bridge-no-bridge-indicator` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-tor-reachability` |
| `verification/backdated-event-suspicion-window` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-verification` |
| `verification/bad-signature-rejects` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-verification` |
| `verification/delegation-mismatch-rejects` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-verification` |
| `verification/revoked-key-rejects` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-verification` |
| `versioning/capabilities-roundtrip` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-versioning` |
| `versioning/core-capability-bootstrap` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-versioning` |
| `versioning/older-receiver-newer-sender` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-versioning` |
| `versioning/per-document-negotiation` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-versioning` |
| `versioning/qualified-version-unqualified-rejected` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-versioning` |
| `versioning/qualified-version-valid` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-versioning` |
| `versioning/unknown-asynchronous-stamp-rejected` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-versioning` |
| `versioning/unknown-major-placeholder` | core | `core/0.5.0` | — | 7 | — | `heterodyne:core/0.5.0#core-versioning` |
| `versioning/unknown-room-kind-tolerance` | social | `social/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 7 | — | `heterodyne:social/0.5.0#social-discussion-rooms` |
