# Control vector coverage

Status: `conformant`.

These vectors cover baseline Marmot Control plus separately advertised optional recovery profiles. Baseline conformance does not require a recovery feature.

Generated from [manifest.json](manifest.json); do not edit by hand.

| Vector | Owner | Profile | Spec references |
|---|---|---|---|
| `control/authorization-fresh-read` | control | `heterodyne-control-marmot-frame-v1` | `heterodyne:control#control-token` |
| `control/authorization-mutation-sync-failed` | control | `heterodyne-control-marmot-frame-v1` | `heterodyne:control#control-token` |
| `control/authorization-stale-read` | control | `heterodyne-control-marmot-frame-v1` | `heterodyne:control#control-token` |
| `control/device-code-display-mismatch` | control | `heterodyne-control-marmot-frame-v1` | `heterodyne:control#control-device-authorization` |
| `control/device-code-exhausted` | control | `heterodyne-control-marmot-frame-v1` | `heterodyne:control#control-device-authorization` |
| `control/device-code-hardened` | control | `heterodyne-control-marmot-frame-v1` | `heterodyne:control#control-device-authorization` |
| `control/device-code-node-rate-limited` | control | `heterodyne-control-marmot-frame-v1` | `heterodyne:control#control-device-authorization` |
| `control/entitlement-expansion-rejected` | control | `heterodyne-control-marmot-frame-v1` | `heterodyne:control#control-entitlement` |
| `control/entitlement-reduction` | control | `heterodyne-control-marmot-frame-v1` | `heterodyne:control#control-entitlement` |
| `control/entitlement-revocation-absorbing` | control | `heterodyne-control-marmot-frame-v1` | `heterodyne:control#control-entitlement` |
| `control/epoch-activation-mismatch` | control | `heterodyne-control-marmot-frame-v1` | `heterodyne:control#control-epoch-bootstrap` |
| `control/epoch-exact-activation` | control | `heterodyne-control-marmot-frame-v1` | `heterodyne:control#control-epoch-bootstrap` |
| `control/epoch-locked` | control | `heterodyne-control-marmot-frame-v1` | `heterodyne:control#control-epoch-bootstrap` |
| `control/epoch-prepare-and-relock` | control | `heterodyne-control-marmot-frame-v1` | `heterodyne:control#control-epoch-bootstrap` |
| `control/failover-idempotent-mutation` | control | `heterodyne-control-marmot-frame-v1` | `heterodyne:control#control-failover` |
| `control/failover-indeterminate-mutation` | control | `heterodyne-control-marmot-frame-v1` | `heterodyne:control#control-failover` |
| `control/failover-read` | control | `heterodyne-control-marmot-frame-v1` | `heterodyne:control#control-failover` |
| `control/invitation-account-cap` | control | `heterodyne-control-marmot-frame-v1` | `heterodyne:control#control-invitation-policy` |
| `control/invitation-disabled` | control | `heterodyne-control-marmot-frame-v1` | `heterodyne:control#control-invitation-policy` |
| `control/invitation-enrollment-only` | control | `heterodyne-control-marmot-frame-v1` | `heterodyne:control#control-invitation-policy` |
| `control/invitation-global-cap` | control | `heterodyne-control-marmot-frame-v1` | `heterodyne:control#control-invitation-policy` |
| `control/invitation-nonenrollment-rejected` | control | `heterodyne-control-marmot-frame-v1` | `heterodyne:control#control-invitation-policy` |
| `control/invitation-rate-limited` | control | `heterodyne-control-marmot-frame-v1` | `heterodyne:control#control-invitation-policy` |
| `control/invitation-replenishment-paused` | control | `heterodyne-control-marmot-frame-v1` | `heterodyne:control#control-invitation-policy` |
| `control/invitation-reserved-slot` | control | `heterodyne-control-marmot-frame-v1` | `heterodyne:control#control-invitation-policy` |
| `control/invitation-revoked` | control | `heterodyne-control-marmot-frame-v1` | `heterodyne:control#control-invitation-policy` |
| `control/invite-preauthorization-keri-rejected` | control | `heterodyne-control-marmot-frame-v1` | `heterodyne:control#control-token` |
| `control/invite-preauthorization-key-bound` | control | `heterodyne-control-marmot-frame-v1` | `heterodyne:control#control-token` |
| `control/invite-preauthorization-unbound-higher-risk` | control | `heterodyne-control-marmot-frame-v1` | `heterodyne:control#control-token` |
| `control/invite-preauthorization-unbound-rejected` | control | `heterodyne-control-marmot-frame-v1` | `heterodyne:control#control-token` |
| `control/operation-conflicting-bytes` | control | `heterodyne-control-marmot-frame-v1` | `heterodyne:control#control-request-processing` |
| `control/operation-first-reservation` | control | `heterodyne-control-marmot-frame-v1` | `heterodyne:control#control-request-processing` |
| `control/operation-identical-join` | control | `heterodyne-control-marmot-frame-v1` | `heterodyne:control#control-request-processing` |
| `control/pending-enrollment-expired` | control | `heterodyne-control-marmot-frame-v1` | `heterodyne:control#control-conformance` |
| `control/pending-enrollment-live` | control | `heterodyne-control-marmot-frame-v1` | `heterodyne:control#control-conformance` |
| `control/recovery-grant-accepted` | control | `heterodyne-control-marmot-frame-v1` | `heterodyne:control#control-radicle-recovery` |
| `control/recovery-grant-confined` | control | `heterodyne-control-marmot-frame-v1` | `heterodyne:control#control-radicle-recovery` |
| `control/retention-ceiling-and-backup-exclusion` | control | `heterodyne-control-marmot-frame-v1` | `heterodyne:control#control-retention` |
| `control/sftp-address-separated` | control | `heterodyne-control-marmot-frame-v1` | `heterodyne:control#control-sftp-recovery` |
| `control/sftp-grant-accepted` | control | `heterodyne-control-marmot-frame-v1` | `heterodyne:control#control-sftp-recovery` |
| `control/sftp-grant-expired` | control | `heterodyne-control-marmot-frame-v1` | `heterodyne:control#control-sftp-recovery` |
| `control/sftp-root-confined` | control | `heterodyne-control-marmot-frame-v1` | `heterodyne:control#control-sftp-recovery` |
| `control/token-default-five-minutes` | control | `heterodyne-control-marmot-frame-v1` | `heterodyne:control#control-token` |
| `control/token-explicit-sixty-minutes` | control | `heterodyne-control-marmot-frame-v1` | `heterodyne:control#control-token` |
| `control/token-extension-missing-capability` | control | `heterodyne-control-marmot-frame-v1` | `heterodyne:control#control-token` |
| `control/token-scope-rejected` | control | `heterodyne-control-marmot-frame-v1` | `heterodyne:control#control-token` |
| `control/token-stale-authorization-view` | control | `heterodyne-control-marmot-frame-v1` | `heterodyne:control#control-token` |
| `control/token-valid` | control | `heterodyne-control-marmot-frame-v1` | `heterodyne:control#control-token` |
| `control/token-wrong-group` | control | `heterodyne-control-marmot-frame-v1` | `heterodyne:control#control-token` |
| `control/token-wrong-node` | control | `heterodyne-control-marmot-frame-v1` | `heterodyne:control#control-token` |
| `control/token-wrong-sender` | control | `heterodyne-control-marmot-frame-v1` | `heterodyne:control#control-token` |
