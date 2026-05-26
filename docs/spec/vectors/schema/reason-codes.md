# Reason codes

`reason_code` values are conformance-test vocabulary. Implementations do not need to emit these strings on the wire.

| Code | Spec refs | Meaning |
|---|---|---|
| `bad_signature` | §4.5, §14.2 | Nostr event id or BIP-340 signature verification failed. |
| `delegation_mismatch` | §3.3, §4.5 | The Matrix sender is not covered by the active delegation. |
| `revoked_key_post_revoked_at` | §3.5, §4.5 | An event signed by a revoked epoch key was created after revoked_at. |
| `expired_delegation` | §3.3, §4.5 | The verifier clock is after the delegation valid_until bound. |
| `retired_room_kind` | §5, §14.3 | A new room asserts a retired pre-ADR-017 room kind. |
| `informal_vouch_not_counted` | §3.5, §3.12, §14.3 | A KERI threshold is satisfied only if advisory vouches are counted. |
| `nip59_broadcast_rejected` | §5.3, §6.10, §14.3 | A private broadcast post used the withdrawn NIP-59 wrapping path. |
| `auth_rejected_permanent` | §6.4, §10.5 | Relay rejected the write after NIP-42 AUTH, so the failure is permanent. |
| `context_binding_mismatch` | §6.7, §6.10, §14.5 | Encrypted payload decrypted under a key derived for the wrong Matrix room context. |
| `onion_dns_leak` | §7.7, §14.3 | A .onion host was sent to a clearnet resolver instead of Tor. |
| `strict_mode_tor_disabled` | §7.7, §11.7 | Strict mode started with egress-over-Tor disabled without explicit user choice. |
| `mls_missing_ack` | §9.2, §14.3 | MLS migration proceeded without all required ACKs. |
| `homeserver_exit_stale_pointer` | §3.10, §14.3 | A stale identity-room pointer was preferred over the migration pointer. |
| `unauthorized_cache_content` | §3.12, §14.3 | Friend-cache content was not owner-signed non-KERI content. |
| `relay_profile_mutation` | §10.6, §14.3 | A Heterodyne-aware relay profile changed vanilla NIP-01 read/write behavior. |
| `unknown_major_version` | §12, §14.3 | A receiver encountered an incompatible future major version. |
