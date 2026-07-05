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
| `nid_binding_missing_signature` | §3.3.1, §14.3 | A kind:31001 NID delegation lacked the epoch-key Schnorr sig or the NID Ed25519 nid_proof. |
| `nid_proof_invalid` | §3.3.1, §7.0, §14.3 | An Ed25519 nid_proof did not verify against the advertised NID over the pinned binding payload. |
| `node_advert_expired` | §7.0, §10.1.1, §14.3 | A kind:31010 node advertisement was past its expiry. |
| `kel_revoked_nid` | §3.9.10, §14.3 | A NID revoked by the KEL was used as a delegate despite the identity document still listing it. |
| `not_canonical_branch_reachable` | §6.7.0, §8.8, §14.3 | An org kind:31007 or post was not reachable from the delegate-threshold-approved canonical feed branch. |
| `org_member_add_unauthorized` | §3.3.1, §3.9.10, §14.3 | An org member NID add carried only one of the required member-KEL and org-admin-threshold authorizations. |
| `page_chain_broken` | §6.7.2, §6.7.4, §14.3 | A feed-index page's prev_page_hash did not match the prior page's canonical serialization. |
| `stale_list_rollback` | §8.5, §3.0, §14.3 | A relay served an older NIP-51 list revision than one reachable in the repo's canonical history. |
| `dm_invite_unbound_device` | §5.7.2, §3.3.1, §14.3 | A kind:30078 DM invite was signed by a publishing key with no valid kind:31001 delegation to the persona. |
| `dm_invite_revoked_device` | §5.7.2, §3.9.7, §14.3 | A kind:30078 DM invite was signed by a device whose kind:31001 delegation is revoked. |
| `dm_event_not_storable` | §5.7.3, §10.1.2, §14.3 | A repo relay refused to store a kind:1060 double-ratchet message (or kind:1059 response); ratchet ciphertext MUST NOT be archived. |
| `config_rid_advertised` | §3.8.6, §14.3 | The config repository RID appeared on a published surface (kind:31005, kind:31010, kind:0, NIP-65, or a NIP-51 list). |
| `moderator_not_in_asof_declaration` | §8.1, §8.2.1, §14.3 | A kind:4550 approval's moderator is not listed in the kind:34550 declaration resolved as-of the approval's anchor. |
