# Control vector coverage

Status: `incomplete-draft`.

The ingress-relay-affinity and automated-agent subset vectors are listed below. They are normative partial evidence but do not open Control conformance; the profile remains non-claimable until the remaining enrollment and session blockers are resolved.

Generated from [manifest.json](manifest.json); do not edit by hand.

| Vector | Owner | Version | Dependencies | Registry | Profile | Spec references |
|---|---|---|---|---:|---|---|
| `control/agent-feed-authorization-rejected` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-claim-consumption` |
| `control/agent-generation-reset` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-agent-token` |
| `control/agent-missing-scope-rejected` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-agent-requirements` |
| `control/agent-proof-jti-mismatch-rejected` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-agent-requirements` |
| `control/agent-publish-authorized` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-agent-requirements` |
| `control/agent-publish-schema-intent-only` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-agent-publish` |
| `control/agent-source-claim-inactive-rejected` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-agent-requirements` |
| `control/agent-source-claim-substitution-rejected` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-agent-requirements` |
| `control/agent-stale-role-key-rejected` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-agent-requirements` |
| `control/agent-token-per-use-binding` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-agent-token` |
| `control/agent-wrong-audience-rejected` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-agent-requirements` |
| `control/attribution-bypass-refused` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-agent-requirements` |
| `control/audit-omits-raw-token` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-agent-audit` |
| `control/authorization-conflicted` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-claim-consumption` |
| `control/authorization-expired` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-claim-consumption` |
| `control/authorization-invalid` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-claim-consumption` |
| `control/authorization-provisional` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-claim-consumption` |
| `control/authorization-revoked` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-claim-consumption` |
| `control/authorization-untrusted` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-claim-consumption` |
| `control/burst-refused` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-agent-requirements` |
| `control/changed-method-rejected` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-relay-affinity` |
| `control/changed-payload-rejected` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-relay-affinity` |
| `control/complete-without-response-rejected` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-relay-affinity` |
| `control/concurrent-identical-joins` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-agent-requirements` |
| `control/configuration-filter-excludes-policy` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-configuration` |
| `control/content-size-refused` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-agent-requirements` |
| `control/cross-relay-final-response-replay` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-relay-affinity` |
| `control/enrollment-binding-proof-rejected` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-enrollment` |
| `control/enrollment-challenge-ceremony-required` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-enrollment` |
| `control/enrollment-identity-join-valid` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-enrollment` |
| `control/enrollment-identity-substitution-rejected` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-enrollment` |
| `control/enrollment-pending-expired` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-enrollment` |
| `control/enrollment-qr-ceremony-required` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-enrollment` |
| `control/enrollment-relay-provisional` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-enrollment` |
| `control/enrollment-repository-final-active` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-enrollment` |
| `control/enrollment-token-different-key-conflict` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-enrollment-token` |
| `control/enrollment-token-full-grant-rejected` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-enrollment-token` |
| `control/enrollment-token-redeemed` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-enrollment-token` |
| `control/enrollment-token-same-key-replay` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-enrollment-token` |
| `control/enrollment-token-workload-class-rejected` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-enrollment-token` |
| `control/expired-request-rejected` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-relay-affinity` |
| `control/expired-token-refused` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-agent-requirements` |
| `control/first-arrival-reserved` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-relay-affinity` |
| `control/grant-full-ceremony-authorized` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-grants` |
| `control/grant-full-ceremony-required` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-grants` |
| `control/grant-object-scope-refused` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-grants` |
| `control/grant-policy-state-write-refused` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-grants` |
| `control/grant-regular-object-authorized` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-grants` |
| `control/human-profile-refused` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-agent-requirements` |
| `control/key-access-refused` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-agent-requirements` |
| `control/kind-resource-refused` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-agent-requirements` |
| `control/lifecycle-inactivity-lapse` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-session-lifecycle` |
| `control/lifecycle-self-revocation` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-session-lifecycle` |
| `control/mcp-cancellation` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-mcp` |
| `control/mcp-inbound-execution-default-deny` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-mcp` |
| `control/mcp-initialize-required` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-mcp` |
| `control/mcp-timeout` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-mcp` |
| `control/mcp-unadvertised-tool-refused` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-mcp` |
| `control/rate-refused` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-agent-requirements` |
| `control/raw-signing-refused` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-agent-requirements` |
| `control/recovery-no-session-restore` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-audit-retention` |
| `control/reply-relay-rejected` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-relay-affinity` |
| `control/restart-reserved-operation-joins` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-relay-affinity` |
| `control/retention-no-backfill` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-audit-retention` |
| `control/rpc-changed-expiry-conflict` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-relay-affinity` |
| `control/rpc-cross-session-conflict` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-relay-affinity` |
| `control/rpc-schema-transport-context-excluded` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-enrollment` |
| `control/sender-proof-refused` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-agent-requirements` |
| `control/token-request-bounded` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-agent-token` |
| `control/transition-peer-tombstone` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-session-lifecycle` |
| `control/transport-browser-reduced-assurance` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-enrollment` |
| `control/transport-strict-tor` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-enrollment` |
