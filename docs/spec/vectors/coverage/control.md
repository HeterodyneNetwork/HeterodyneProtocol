# Control vector coverage

Status: `conformant`.

These vectors cover baseline Marmot Control plus separately advertised optional recovery profiles. Baseline conformance does not require a recovery feature.

Generated from [manifest.json](manifest.json); do not edit by hand.

| Vector | Owner | Version | Dependencies | Registry | Profile | Spec references |
|---|---|---|---|---:|---|---|
| `control/authorization-fresh-read` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 6 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-token` |
| `control/authorization-mutation-sync-failed` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 6 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-token` |
| `control/authorization-stale-read` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 6 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-token` |
| `control/device-code-display-mismatch` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 6 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-device-authorization` |
| `control/device-code-exhausted` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 6 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-device-authorization` |
| `control/device-code-hardened` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 6 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-device-authorization` |
| `control/device-code-node-rate-limited` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 6 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-device-authorization` |
| `control/entitlement-expansion-rejected` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 6 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-entitlement` |
| `control/entitlement-reduction` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 6 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-entitlement` |
| `control/entitlement-revocation-absorbing` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 6 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-entitlement` |
| `control/epoch-activation-mismatch` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 6 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-epoch-bootstrap` |
| `control/epoch-exact-activation` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 6 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-epoch-bootstrap` |
| `control/epoch-locked` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 6 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-epoch-bootstrap` |
| `control/epoch-prepare-and-relock` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 6 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-epoch-bootstrap` |
| `control/failover-idempotent-mutation` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 6 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-failover` |
| `control/failover-indeterminate-mutation` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 6 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-failover` |
| `control/failover-read` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 6 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-failover` |
| `control/invitation-account-cap` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 6 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-invitation-policy` |
| `control/invitation-disabled` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 6 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-invitation-policy` |
| `control/invitation-enrollment-only` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 6 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-invitation-policy` |
| `control/invitation-global-cap` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 6 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-invitation-policy` |
| `control/invitation-nonenrollment-rejected` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 6 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-invitation-policy` |
| `control/invitation-rate-limited` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 6 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-invitation-policy` |
| `control/invitation-replenishment-paused` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 6 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-invitation-policy` |
| `control/invitation-reserved-slot` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 6 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-invitation-policy` |
| `control/invitation-revoked` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 6 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-invitation-policy` |
| `control/invite-preauthorization-keri-rejected` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 6 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-token` |
| `control/invite-preauthorization-key-bound` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 6 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-token` |
| `control/invite-preauthorization-unbound-higher-risk` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 6 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-token` |
| `control/invite-preauthorization-unbound-rejected` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 6 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-token` |
| `control/operation-conflicting-bytes` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 6 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-request-processing` |
| `control/operation-first-reservation` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 6 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-request-processing` |
| `control/operation-identical-join` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 6 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-request-processing` |
| `control/pending-enrollment-expired` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 6 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-conformance` |
| `control/pending-enrollment-live` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 6 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-conformance` |
| `control/recovery-grant-accepted` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 6 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-radicle-recovery` |
| `control/recovery-grant-confined` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 6 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-radicle-recovery` |
| `control/retention-ceiling-and-backup-exclusion` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 6 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-retention` |
| `control/sftp-address-separated` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 6 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-sftp-recovery` |
| `control/sftp-grant-accepted` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 6 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-sftp-recovery` |
| `control/sftp-grant-expired` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 6 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-sftp-recovery` |
| `control/sftp-root-confined` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 6 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-sftp-recovery` |
| `control/token-default-five-minutes` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 6 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-token` |
| `control/token-explicit-sixty-minutes` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 6 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-token` |
| `control/token-extension-missing-capability` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 6 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-token` |
| `control/token-scope-rejected` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 6 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-token` |
| `control/token-stale-authorization-view` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 6 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-token` |
| `control/token-valid` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 6 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-token` |
| `control/token-wrong-group` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 6 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-token` |
| `control/token-wrong-node` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 6 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-token` |
| `control/token-wrong-sender` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 6 | `heterodyne-control-marmot-frame-v1` | `heterodyne:control/0.5.0#control-token` |
