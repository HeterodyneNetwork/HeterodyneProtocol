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
| `kel_head_missing` | §3.0, §4.5.1, §14.3 | An epoch-key-signed Heterodyne event required to carry kel_head does not carry exactly one well-formed instance (absent, duplicate, or malformed). |
| `kel_head_mismatch` | §3.0, §4.5.1, §14.3 | The kel_head tag's decimal seq does not equal the s value of the KEL event it names once that event is resolved on the accepted KEL. |
| `kel_head_forbidden` | §3.0, §4.5.1, §14.3 | A kel_head tag appears on an event class the §3.0 matrix forbids it on (kind:31002/31003 KEL events, §5.7 DR wire events kind:1060/1059 and inner rumors, or ADR-031 breadcrumbs). |
| `equivocation_flagged` | §4.5.1, §13, §14.3 | A structurally valid kel_head names an event that is not on the persona's accepted KEL; the verifier flags equivocation and surfaces it through the §13 security-warning interface. |
| `signing_key_compromised_at_created_at` | §3.5.2, §4.5.1, §14.3 | The signing epoch key is retroactively non-authoritative at the event's created_at: an accepted compromise-declaring rotation covers created_at under effective_compromise_since - 300 seconds. |
| `provisional_not_final` | §4.5.2, §14.3 | Acceptance rests on relay-only key-material state (kind:31002/31003/31001); under deny-until-repo policy the event does not take effect until repo-carried, and provisional-accept results MUST NOT be reported as final. |
| `withdrawn_on_reconcile` | §4.5.2, §14.3 | A prior provisional or §4.5.1-accelerator acceptance is withdrawn after convergence-gated repo reconciliation, a KEL update, or later full verification contradicts it. |
| `repo_head_regression` | §3.9.10.1, §14.3 | A repo presented a key-material head regressing below a previously finalized canonical head without an authenticated re-anchor. |
| `export_unmappable_feature` | §11.8, §14.3 | did:webs export failed: security-relevant KEL state uses a construct with no semantics-preserving canonical-KERI mapping (UNMAPPABLE_FEATURE). |
| `export_unsupported_crypto_suite` | §11.8, §14.3 | did:webs export failed: a mapping exists but the target crypto suite is unavailable locally (UNSUPPORTED_CRYPTO_SUITE). |
| `export_incomplete` | §11.8, §14.3 | did:webs export failed: required source KEL events or attachments are unavailable (INCOMPLETE_EXPORT). |
| `keri_wire_format_rejected` | §11.8, §3.0.1, §14.3 | A KEL event or stream was presented in KERI10JSON/CESR on the Heterodyne wire or as storage; NIP-01 with nip01_raw is the only wire and storage format. |
| `export_aid_substituted_for_npub` | §11.8, §14.3 | A derived export AID or its did:webs DID was substituted for the persona npub where the spec requires the npub; the export identity is never an alternate authoritative identity. |
