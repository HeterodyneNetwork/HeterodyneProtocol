export type ReasonCode = {
  code: string;
  spec_refs: string[];
  description: string;
};

export const REASON_CODES: ReasonCode[] = [
  {
    code: "bad_signature",
    spec_refs: ["§4.5", "§14.2"],
    description: "Nostr event id or BIP-340 signature verification failed.",
  },
  {
    code: "delegation_mismatch",
    spec_refs: ["§3.3", "§4.5"],
    description: "The Matrix sender is not covered by the active delegation.",
  },
  {
    code: "revoked_key_post_revoked_at",
    spec_refs: ["§3.5", "§4.5"],
    description: "An event signed by a revoked epoch key was created after revoked_at.",
  },
  {
    code: "expired_delegation",
    spec_refs: ["§3.3", "§4.5"],
    description: "The verifier clock is after the delegation valid_until bound.",
  },
  {
    code: "retired_room_kind",
    spec_refs: ["§5", "§14.3"],
    description: "A new room asserts a retired pre-ADR-017 room kind.",
  },
  {
    code: "informal_vouch_not_counted",
    spec_refs: ["§3.5", "§3.12", "§14.3"],
    description: "A KERI threshold is satisfied only if advisory vouches are counted.",
  },
  {
    code: "nip59_broadcast_rejected",
    spec_refs: ["§5.3", "§6.10", "§14.3"],
    description: "A private broadcast post used the withdrawn NIP-59 wrapping path.",
  },
  {
    code: "auth_rejected_permanent",
    spec_refs: ["§6.4", "§10.5"],
    description: "Relay rejected the write after NIP-42 AUTH, so the failure is permanent.",
  },
  {
    code: "context_binding_mismatch",
    spec_refs: ["§6.7", "§6.10", "§14.5"],
    description: "Encrypted payload decrypted under a key derived for the wrong Matrix room context.",
  },
  {
    code: "onion_dns_leak",
    spec_refs: ["§7.7", "§14.3"],
    description: "A .onion host was sent to a clearnet resolver instead of Tor.",
  },
  {
    code: "strict_mode_tor_disabled",
    spec_refs: ["§7.7", "§11.7"],
    description: "Strict mode started with egress-over-Tor disabled without explicit user choice.",
  },
  {
    code: "mls_missing_ack",
    spec_refs: ["§9.2", "§14.3"],
    description: "MLS migration proceeded without all required ACKs.",
  },
  {
    code: "homeserver_exit_stale_pointer",
    spec_refs: ["§3.10", "§14.3"],
    description: "A stale identity-room pointer was preferred over the migration pointer.",
  },
  {
    code: "unauthorized_cache_content",
    spec_refs: ["§3.12", "§14.3"],
    description: "Friend-cache content was not owner-signed non-KERI content.",
  },
  {
    code: "relay_profile_mutation",
    spec_refs: ["§10.6", "§14.3"],
    description: "A Heterodyne-aware relay profile changed vanilla NIP-01 read/write behavior.",
  },
  {
    code: "unknown_major_version",
    spec_refs: ["§12", "§14.3"],
    description: "A receiver encountered an incompatible future major version.",
  },
  {
    code: "nid_binding_missing_signature",
    spec_refs: ["§3.3.1", "§14.3"],
    description: "A kind:31001 NID delegation lacked the epoch-key Schnorr sig or the NID Ed25519 nid_proof.",
  },
  {
    code: "nid_proof_invalid",
    spec_refs: ["§3.3.1", "§7.0", "§14.3"],
    description: "An Ed25519 nid_proof did not verify against the advertised NID over the pinned binding payload.",
  },
  {
    code: "node_advert_expired",
    spec_refs: ["§7.0", "§10.1.1", "§14.3"],
    description: "A kind:31010 node advertisement was past its expiry.",
  },
  {
    code: "kel_revoked_nid",
    spec_refs: ["§3.9.10", "§14.3"],
    description: "A NID revoked by the KEL was used as a delegate despite the identity document still listing it.",
  },
  {
    code: "not_canonical_branch_reachable",
    spec_refs: ["§6.7.0", "§8.8", "§14.3"],
    description: "An org kind:31007 or post was not reachable from the delegate-threshold-approved canonical feed branch.",
  },
  {
    code: "org_member_add_unauthorized",
    spec_refs: ["§3.3.1", "§3.9.10", "§14.3"],
    description: "An org member NID add carried only one of the required member-KEL and org-admin-threshold authorizations.",
  },
  {
    code: "page_chain_broken",
    spec_refs: ["§6.7.2", "§6.7.4", "§14.3"],
    description: "A feed-index page's prev_page_hash did not match the prior page's canonical serialization.",
  },
  {
    code: "stale_list_rollback",
    spec_refs: ["§8.5", "§3.0", "§14.3"],
    description: "A relay served an older NIP-51 list revision than one reachable in the repo's canonical history.",
  },
  {
    code: "dm_invite_unbound_device",
    spec_refs: ["§5.7.2", "§3.3.1", "§14.3"],
    description: "A kind:30078 DM invite was signed by a publishing key with no valid kind:31001 delegation to the persona.",
  },
  {
    code: "dm_invite_revoked_device",
    spec_refs: ["§5.7.2", "§3.9.7", "§14.3"],
    description: "A kind:30078 DM invite was signed by a device whose kind:31001 delegation is revoked.",
  },
  {
    code: "dm_event_not_storable",
    spec_refs: ["§5.7.3", "§10.1.2", "§14.3"],
    description: "A repo relay refused to store a kind:1060 double-ratchet message (or kind:1059 response); ratchet ciphertext MUST NOT be archived.",
  },
  {
    code: "config_rid_advertised",
    spec_refs: ["§3.8.6", "§14.3"],
    description: "The config repository RID appeared on a published surface (kind:31005, kind:31010, kind:0, NIP-65, or a NIP-51 list).",
  },
  {
    code: "moderator_not_in_asof_declaration",
    spec_refs: ["§8.1", "§8.2.1", "§14.3"],
    description: "A kind:4550 approval's moderator is not listed in the kind:34550 declaration resolved as-of the approval's anchor.",
  },
  {
    code: "kel_head_missing",
    spec_refs: ["§3.0", "§4.5.1", "§14.3"],
    description: "An epoch-key-signed Heterodyne event required to carry kel_head does not carry exactly one well-formed instance (absent, duplicate, or malformed).",
  },
  {
    code: "kel_head_mismatch",
    spec_refs: ["§3.0", "§4.5.1", "§14.3"],
    description: "The kel_head tag's decimal seq does not equal the s value of the KEL event it names once that event is resolved on the accepted KEL.",
  },
  {
    code: "kel_head_forbidden",
    spec_refs: ["§3.0", "§4.5.1", "§14.3"],
    description: "A kel_head tag appears on an event class the §3.0 matrix forbids it on (kind:31002/31003 KEL events, §5.7 DR wire events kind:1060/1059 and inner rumors, or ADR-031 breadcrumbs).",
  },
  {
    code: "equivocation_flagged",
    spec_refs: ["§4.5.1", "§13", "§14.3"],
    description: "A structurally valid kel_head names an event that is not on the persona's accepted KEL; the verifier flags equivocation and surfaces it through the §13 security-warning interface.",
  },
  {
    code: "signing_key_compromised_at_created_at",
    spec_refs: ["§3.5.2", "§4.5.1", "§14.3"],
    description: "The signing epoch key is retroactively non-authoritative at the event's created_at: an accepted compromise-declaring rotation covers created_at under effective_compromise_since - 300 seconds.",
  },
  {
    code: "provisional_not_final",
    spec_refs: ["§4.5.2", "§14.3"],
    description: "Acceptance rests on relay-only key-material state (kind:31002/31003/31001); under deny-until-repo policy the event does not take effect until repo-carried, and provisional-accept results MUST NOT be reported as final.",
  },
  {
    code: "withdrawn_on_reconcile",
    spec_refs: ["§4.5.2", "§14.3"],
    description: "A prior provisional or §4.5.1-accelerator acceptance is withdrawn after convergence-gated repo reconciliation, a KEL update, or later full verification contradicts it.",
  },
  {
    code: "repo_head_regression",
    spec_refs: ["§3.9.10.1", "§14.3"],
    description: "A repo presented a key-material head regressing below a previously finalized canonical head without an authenticated re-anchor.",
  },
  {
    code: "export_unmappable_feature",
    spec_refs: ["§11.8", "§14.3"],
    description: "did:webs export failed: security-relevant KEL state uses a construct with no semantics-preserving canonical-KERI mapping (UNMAPPABLE_FEATURE).",
  },
  {
    code: "export_unsupported_crypto_suite",
    spec_refs: ["§11.8", "§14.3"],
    description: "did:webs export failed: a mapping exists but the target crypto suite is unavailable locally (UNSUPPORTED_CRYPTO_SUITE).",
  },
  {
    code: "export_incomplete",
    spec_refs: ["§11.8", "§14.3"],
    description: "did:webs export failed: required source KEL events or attachments are unavailable (INCOMPLETE_EXPORT).",
  },
  {
    code: "keri_wire_format_rejected",
    spec_refs: ["§11.8", "§3.0.1", "§14.3"],
    description: "A KEL event or stream was presented in KERI10JSON/CESR on the Heterodyne wire or as storage; NIP-01 with nip01_raw is the only wire and storage format.",
  },
  {
    code: "export_aid_substituted_for_npub",
    spec_refs: ["§11.8", "§14.3"],
    description: "A derived export AID or its did:webs DID was substituted for the persona npub where the spec requires the npub; the export identity is never an alternate authoritative identity.",
  },
];

export function reasonCodeValues(): string[] {
  return REASON_CODES.map((reason) => reason.code);
}
