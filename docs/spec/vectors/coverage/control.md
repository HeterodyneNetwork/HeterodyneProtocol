# Control vector coverage

Status: `conformant`.

These vectors cover baseline Marmot Control plus separately advertised optional recovery profiles. Baseline conformance does not require a recovery feature.

Generated from [manifest.json](manifest.json); do not edit by hand.

| Vector | Owner | Profile | Invariants | Reason codes | Spec references |
|---|---|---|---|---|---|
| `control/activation-binding-mismatch` | control | — | `CONTROL-I-NIP46-OIDC-ACTIVATION` | `control-activation-binding-mismatch` | `heterodyne:control#control-oidc-activation` |
| `control/agent-attribution-bypass-prohibited` | control | — | `CONTROL-I-AUTOMATION-ATTRIBUTION-BEFORE-SIGNING` | `agent-attribution-bypass-prohibited` | `heterodyne:control#control-agent-requirements` |
| `control/agent-human-profile-prohibited` | control | — | `CONTROL-I-AUTOMATION-ATTRIBUTION-BEFORE-SIGNING` | `agent-human-profile-prohibited` | `heterodyne:control#control-agent-requirements` |
| `control/agent-intent-invalid` | control | — | `CONTROL-I-AUTOMATION-ATTRIBUTION-BEFORE-SIGNING` | `control-agent-intent-invalid` | `heterodyne:control#control-agent-requirements` |
| `control/agent-key-access-prohibited` | control | — | `CONTROL-I-AUTOMATION-ATTRIBUTION-BEFORE-SIGNING` | `agent-key-access-prohibited` | `heterodyne:control#control-agent-requirements` |
| `control/agent-method-prohibited` | control | — | `CONTROL-I-AUTOMATION-ATTRIBUTION-BEFORE-SIGNING` | `agent-method-prohibited` | `heterodyne:control#control-agent-requirements` |
| `control/agent-rate-limited` | control | — | `CONTROL-I-OPERATION-AT-MOST-ONCE` | `agent-rate-limited` | `heterodyne:control#control-agent-requirements` |
| `control/agent-resource-denied` | control | — | `CONTROL-I-EXACT-SIGNER-GRANT` | `agent-resource-denied` | `heterodyne:control#control-agent-requirements` |
| `control/agent-size-exceeded` | control | — | `CONTROL-I-EXACT-SIGNER-GRANT` | `agent-size-exceeded` | `heterodyne:control#control-agent-requirements` |
| `control/attribution-binding-mismatch` | control | — | `CONTROL-I-AUTOMATION-ATTRIBUTION-BEFORE-SIGNING` | `control-attribution-binding-mismatch` | `heterodyne:control#control-agent-requirements` |
| `control/attribution-required` | control | — | `CONTROL-I-AUTOMATION-ATTRIBUTION-BEFORE-SIGNING` | `control-attribution-required` | `heterodyne:control#control-agent-requirements` |
| `control/authorization-view-stale-at-effect` | control | — | `CONTROL-I-NIP46-OIDC-ACTIVATION` | `control-authorization-view-stale` | `heterodyne:control#control-token` |
| `control/automation-attributed-before-signing` | control | — | `CONTROL-I-AUTOMATION-ATTRIBUTION-BEFORE-SIGNING`<br>`CONTROL-I-OPERATION-AT-MOST-ONCE` | — | `heterodyne:control#control-agent-requirements` |
| `control/caller-freshness-booleans-rejected` | control | — | `CONTROL-I-NIP46-OIDC-ACTIVATION` | `control-authorization-view-stale` | `heterodyne:control#control-token` |
| `control/client-metadata-widening` | control | — | `CONTROL-I-CLIENT-KEY-CONFINEMENT` | `control-client-metadata-widening` | `heterodyne:control#control-nip46-signing` |
| `control/compromise-reset-closure-required` | control | — | `CONTROL-I-COMPROMISE-RESET`<br>`CONTROL-I-MARMOT-LEAF-COMPROMISE` | `control-compromise-reset-incomplete` | `heterodyne:control#control-compromise-reset` |
| `control/compromise-reset-evidence-invalid` | control | — | `CONTROL-I-COMPROMISE-RESET` | `control-compromise-reset-evidence-invalid` | `heterodyne:control#control-compromise-reset` |
| `control/compromise-reset-inventory-mismatch` | control | — | `CONTROL-I-COMPROMISE-RESET` | `control-compromise-reset-inventory-mismatch` | `heterodyne:control#control-compromise-reset` |
| `control/compromise-reset-unauthenticated` | control | — | `CONTROL-I-COMPROMISE-RESET` | `control-compromise-reset-unauthenticated` | `heterodyne:control#control-compromise-reset` |
| `control/connection-secret-invalid` | control | — | `CONTROL-I-NIP46-OIDC-ACTIVATION` | `control-connection-secret-invalid` | `heterodyne:control#control-oidc-activation` |
| `control/connection-secret-reused` | control | — | `CONTROL-I-NIP46-OIDC-ACTIVATION` | `control-connection-secret-reused` | `heterodyne:control#control-oidc-activation` |
| `control/device-code-display-mismatch` | control | — | `CONTROL-I-NIP46-OIDC-ACTIVATION` | `control-device-code-display-mismatch` | `heterodyne:control#control-device-authorization` |
| `control/device-code-invalid` | control | — | `CONTROL-I-NIP46-OIDC-ACTIVATION` | `control-device-code-invalid` | `heterodyne:control#control-device-authorization` |
| `control/device-code-rate-limited` | control | — | `CONTROL-I-NIP46-OIDC-ACTIVATION` | `control-device-code-rate-limited` | `heterodyne:control#control-device-authorization` |
| `control/enrollment-rate-limited` | control | — | `CONTROL-I-MARMOT-GRANT-CONFINEMENT` | `control-enrollment-rate-limited` | `heterodyne:control#control-invitation-policy` |
| `control/enrollment-required` | control | — | `CONTROL-I-MARMOT-GRANT-CONFINEMENT` | `control-enrollment-required` | `heterodyne:control#control-enrollment` |
| `control/enrollment-unavailable` | control | — | `CONTROL-I-MARMOT-GRANT-CONFINEMENT` | `control-enrollment-unavailable` | `heterodyne:control#control-invitation-policy` |
| `control/entitlement-conflict` | control | — | `CONTROL-I-MARMOT-GRANT-CONFINEMENT` | `control-entitlement-conflict` | `heterodyne:control#control-entitlement` |
| `control/exact-signer-grant-reserved` | control | — | `CONTROL-I-AUDIT-AT-REST`<br>`CONTROL-I-BASELINE-ACTIVE-KEY`<br>`CONTROL-I-CLIENT-KEY-CONFINEMENT`<br>`CONTROL-I-EXACT-SIGNER-GRANT`<br>`CONTROL-I-NO-SIGNER-FALLBACK`<br>`CONTROL-I-OPERATION-AT-MOST-ONCE`<br>`CONTROL-I-PERSONA-VAULT-ISOLATION` | — | `heterodyne:control#control-signer-grants` |
| `control/frame-invalid` | control | — | `CONTROL-I-MARMOT-GRANT-CONFINEMENT` | `control-frame-invalid` | `heterodyne:control#control-frame` |
| `control/invite-preauthorization-invalid` | control | — | `CONTROL-I-MARMOT-GRANT-CONFINEMENT` | `invite-preauthorization-invalid` | `heterodyne:control#control-one-time-invites` |
| `control/keypackage-invalid` | control | — | `CONTROL-I-MARMOT-GRANT-CONFINEMENT` | `control-keypackage-invalid` | `heterodyne:control#control-invitation-policy` |
| `control/keypackage-replenishment-paused` | control | — | `CONTROL-I-MARMOT-GRANT-CONFINEMENT` | `control-keypackage-replenishment-paused` | `heterodyne:control#control-invitation-policy` |
| `control/nip46-request-invalid` | control | — | `CONTROL-I-OPERATION-AT-MOST-ONCE` | `control-nip46-request-invalid` | `heterodyne:control#control-request-processing` |
| `control/opaque-authorization-view-accepted` | control | — | `CONTROL-I-NIP46-OIDC-ACTIVATION` | — | `heterodyne:control#control-token` |
| `control/operation-conflict` | control | — | `CONTROL-I-OPERATION-AT-MOST-ONCE` | `control-operation-conflict` | `heterodyne:control#control-request-processing` |
| `control/operation-execution-fence-required` | control | — | `CONTROL-I-OPERATION-AT-MOST-ONCE` | `control-operation-execution-fence-required` | `heterodyne:control#control-request-processing` |
| `control/operation-indeterminate` | control | — | `CONTROL-I-OPERATION-AT-MOST-ONCE` | `control-operation-indeterminate` | `heterodyne:control#control-failover` |
| `control/operation-reservation-required` | control | — | `CONTROL-I-OPERATION-AT-MOST-ONCE` | `control-operation-reservation-required` | `heterodyne:control#control-request-processing` |
| `control/persona-authority-required` | control | — | `CONTROL-I-BASELINE-ACTIVE-KEY` | `control-persona-authority-required` | `heterodyne:control#control-signer-selection` |
| `control/profile-heterodyne-control-marmot-frame-v1` | control | `heterodyne-control-marmot-frame-v1` | `CONTROL-I-MARMOT-GRANT-CONFINEMENT` | — | `heterodyne:control#control-security` |
| `control/refresh-prohibited` | control | — | `CONTROL-I-CLIENT-KEY-CONFINEMENT` | `control-refresh-prohibited` | `heterodyne:control#control-token` |
| `control/request-expired` | control | — | `CONTROL-I-OPERATION-AT-MOST-ONCE` | `control-request-expired` | `heterodyne:control#control-request-processing` |
| `control/request-id-conflict` | control | — | `CONTROL-I-OPERATION-AT-MOST-ONCE` | `control-request-id-conflict` | `heterodyne:control#control-request-processing` |
| `control/signed-event-invalid` | control | — | `CONTROL-I-AUTOMATION-ATTRIBUTION-BEFORE-SIGNING` | `control-signed-event-invalid` | `heterodyne:control#control-agent-requirements` |
| `control/signer-binding-mismatch` | control | — | `CONTROL-I-EXACT-SIGNER-GRANT` | `control-signer-binding-mismatch` | `heterodyne:control#control-signer-grants` |
| `control/signer-effect-indeterminate` | control | — | `CONTROL-I-OPERATION-AT-MOST-ONCE` | — | `heterodyne:control#control-agent-requirements` |
| `control/signer-unavailable` | control | — | `CONTROL-I-NO-SIGNER-FALLBACK` | `control-signer-unavailable` | `heterodyne:control#control-signer-selection` |
| `control/signing-grant-inactive` | control | — | `CONTROL-I-EXACT-SIGNER-GRANT` | `control-signing-grant-inactive` | `heterodyne:control#control-signer-grants` |
| `control/signing-grant-invalid` | control | — | `CONTROL-I-EXACT-SIGNER-GRANT` | `control-signing-grant-invalid` | `heterodyne:control#control-signer-grants` |
| `control/signing-grant-stale` | control | — | `CONTROL-I-EXACT-SIGNER-GRANT` | `control-signing-grant-stale` | `heterodyne:control#control-signer-grants` |
| `control/signing-grant-unauthenticated` | control | — | `CONTROL-I-EXACT-SIGNER-GRANT` | `control-signing-grant-unauthenticated` | `heterodyne:control#control-signer-grants` |
| `control/signing-rate-limited` | control | — | `CONTROL-I-OPERATION-AT-MOST-ONCE` | `control-signing-rate-limited` | `heterodyne:control#control-request-processing` |
| `control/subordinate-reauthorization-required` | control | — | `CONTROL-I-COMPROMISE-RESET` | `control-subordinate-reauthorization-required` | `heterodyne:control#control-compromise-reset` |
| `control/token-invalid` | control | — | `CONTROL-I-CLIENT-KEY-CONFINEMENT` | `control-token-invalid` | `heterodyne:control#control-token` |
| `control/usage-binding-mismatch` | control | — | `CONTROL-I-OPERATION-AT-MOST-ONCE` | `control-usage-binding-mismatch` | `heterodyne:control#control-request-processing` |
| `control/vault-isolation-failed` | control | — | `CONTROL-I-PERSONA-VAULT-ISOLATION` | `control-vault-isolation-failed` | `heterodyne:control#control-persona-vaults` |
