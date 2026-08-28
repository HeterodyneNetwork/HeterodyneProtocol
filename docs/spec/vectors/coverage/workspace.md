# Workspace vector coverage

Generated from [manifest.json](manifest.json); do not edit by hand.

| Vector | Owner | Profile | Invariants | Reason codes | Spec references |
|---|---|---|---|---|---|
| `workspace/affiliation-stale` | workspace | — | `WORKSPACE-I-FRESHNESS-BOUNDED` | `affiliation_stale` | `heterodyne:workspace#workspace-relationships` |
| `workspace/assurance-dual-removal` | workspace | — | `WORKSPACE-I-OPTIONAL-ASSURANCE` | — | `heterodyne:workspace#workspace-optional-assurance` |
| `workspace/assurance-history-mutation-revalidated` | workspace | — | `WORKSPACE-I-OPTIONAL-ASSURANCE` | `workspace-assurance-state-required` | `heterodyne:workspace#workspace-optional-assurance` |
| `workspace/assurance-pending-activation` | workspace | — | `WORKSPACE-I-OPTIONAL-ASSURANCE` | `workspace-assurance-state-required` | `heterodyne:workspace#workspace-optional-assurance` |
| `workspace/assurance-unilateral-removal` | workspace | — | `WORKSPACE-I-OPTIONAL-ASSURANCE` | `workspace-assurance-state-required` | `heterodyne:workspace#workspace-optional-assurance` |
| `workspace/assurance-verified-activation` | workspace | — | `WORKSPACE-I-OPTIONAL-ASSURANCE` | — | `heterodyne:workspace#workspace-optional-assurance` |
| `workspace/authority-checkpoint-stale` | workspace | — | `WORKSPACE-I-AUTHENTICATED-CURRENT-STATE`<br>`WORKSPACE-I-FRESHNESS-BOUNDED` | `checkpoint_stale` | `heterodyne:workspace#workspace-freshness` |
| `workspace/authority-conflict` | workspace | — | `WORKSPACE-I-AUTHENTICATED-CURRENT-STATE` | `authority_conflict` | `heterodyne:workspace#workspace-role-repositories` |
| `workspace/authority-freshness-boundary` | workspace | — | `WORKSPACE-I-FRESHNESS-BOUNDED` | — | `heterodyne:workspace#workspace-freshness` |
| `workspace/bare-key-baseline` | workspace | — | `WORKSPACE-I-OPTIONAL-ASSURANCE` | — | `heterodyne:workspace#workspace-optional-assurance` |
| `workspace/carrier-not-ambient-authority` | workspace | — | `WORKSPACE-I-CARRIER-NOT-AUTHORITY`<br>`WORKSPACE-I-NO-AMBIENT-AUTHORITY` | `policy_denied` | `heterodyne:workspace#workspace-authorization` |
| `workspace/current-capability-intersection` | workspace | — | `WORKSPACE-I-AUTHENTICATED-CURRENT-STATE`<br>`WORKSPACE-I-INHERITANCE-NARROWS`<br>`WORKSPACE-I-NO-AMBIENT-AUTHORITY` | — | `heterodyne:workspace#workspace-authorization` |
| `workspace/device-revoked` | workspace | — | `WORKSPACE-I-DEVICE-LEAF-SEPARATION` | `device_revoked` | `heterodyne:workspace#workspace-role-control` |
| `workspace/history-denied` | workspace | — | `WORKSPACE-I-REVOCATION-FUTURE-ONLY` | `history_denied` | `heterodyne:workspace#workspace-key-delivery` |
| `workspace/host-unauthorized` | workspace | — | `WORKSPACE-I-HOST-AUTHORITY-SEPARATION` | `host_unauthorized` | `heterodyne:workspace#workspace-key-delivery` |
| `workspace/independent-device-leaf-removal` | workspace | — | `WORKSPACE-I-DEVICE-LEAF-SEPARATION`<br>`WORKSPACE-I-REVOCATION-FUTURE-ONLY` | — | `heterodyne:workspace#workspace-device-leaves` |
| `workspace/independent-resource-content-keys` | workspace | — | `WORKSPACE-I-INDEPENDENT-RESOURCE-KEYS` | — | `heterodyne:workspace#workspace-resource-key-delivery` |
| `workspace/inheritance-escalation-rejected` | workspace | — | `WORKSPACE-I-INHERITANCE-NARROWS` | `capability_escalation` | `heterodyne:workspace#workspace-inheritance` |
| `workspace/invitation-replay` | workspace | — | `WORKSPACE-I-NO-AMBIENT-AUTHORITY` | `workspace_replay` | `heterodyne:workspace#workspace-grants` |
| `workspace/private-topology-clean` | workspace | — | `WORKSPACE-I-PRIVATE-TOPOLOGY` | — | `heterodyne:workspace#workspace-private-discovery` |
| `workspace/private-topology-disclosed` | workspace | — | `WORKSPACE-I-PRIVATE-TOPOLOGY` | `private_topology_disclosed` | `heterodyne:workspace#workspace-private-discovery` |
| `workspace/radicle-backed-hosts` | workspace | — | `WORKSPACE-I-HOST-AUTHORITY-SEPARATION`<br>`WORKSPACE-I-RADICLE-BACKSTOP` | — | `heterodyne:workspace#workspace-hosting` |
| `workspace/repository-invalid` | workspace | — | `WORKSPACE-I-AUTHENTICATED-CURRENT-STATE` | `workspace_repository_invalid` | `heterodyne:workspace#workspace-role-repositories` |
| `workspace/resource-unknown` | workspace | — | `WORKSPACE-I-INDEPENDENT-RESOURCE-KEYS` | `resource_unknown` | `heterodyne:workspace#workspace-key-delivery` |
| `workspace/revocation-blocks-future-effect` | workspace | — | `WORKSPACE-I-REVOCATION-FUTURE-ONLY` | `policy_denied` | `heterodyne:workspace#workspace-revocation` |
| `workspace/schema-invalid` | workspace | — | `WORKSPACE-I-AUTHENTICATED-CURRENT-STATE` | `workspace_schema_invalid` | `heterodyne:workspace#workspace-object-types` |
| `workspace/signature-invalid` | workspace | — | `WORKSPACE-I-AUTHENTICATED-CURRENT-STATE` | `workspace_signature_invalid` | `heterodyne:workspace#workspace-object-types` |
