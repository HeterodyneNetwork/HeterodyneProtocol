# Control vector coverage

Status: `incomplete-draft`.

The integrated ADR-035 relay-affinity and ADR-036 automated-agent subset vectors are listed below. They are normative partial evidence but do not open Control conformance; the profile remains non-claimable until the remaining ADR-030 blockers are resolved.

Generated from [manifest.json](manifest.json); do not edit by hand.

| Vector | Owner | Version | Dependencies | Registry | Profile | Spec references |
|---|---|---|---|---:|---|---|
| `control/agent-publish-authorized` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-agent-requirements` |
| `control/agent-publish-schema-intent-only` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-agent-publish` |
| `control/attribution-bypass-refused` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-agent-requirements` |
| `control/audit-omits-raw-token` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-agent-audit` |
| `control/burst-refused` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-agent-requirements` |
| `control/changed-method-rejected` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-relay-affinity` |
| `control/changed-payload-rejected` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-relay-affinity` |
| `control/complete-without-response-rejected` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-relay-affinity` |
| `control/concurrent-identical-joins` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-agent-requirements` |
| `control/content-size-refused` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-agent-requirements` |
| `control/cross-relay-final-response-replay` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-relay-affinity` |
| `control/expired-request-rejected` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-relay-affinity` |
| `control/expired-token-refused` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-agent-requirements` |
| `control/first-arrival-reserved` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-relay-affinity` |
| `control/human-profile-refused` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-agent-requirements` |
| `control/key-access-refused` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-agent-requirements` |
| `control/kind-resource-refused` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-agent-requirements` |
| `control/rate-refused` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-agent-requirements` |
| `control/raw-signing-refused` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-agent-requirements` |
| `control/reply-relay-rejected` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-relay-affinity` |
| `control/restart-reserved-operation-joins` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-relay-affinity` |
| `control/sender-proof-refused` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-agent-requirements` |
| `control/token-request-bounded` | control | `control/0.5.0` | core=core/0.5.0, comms=comms/0.5.0 | 3 | — | `heterodyne:control/0.5.0#control-agent-token` |
