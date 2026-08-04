import { hexToBytes } from "./hex.js";
import { inceptionTemplate, kelHeadTag, withKelHead } from "./kel.js";
import { getPublicKey, signEvent } from "./nostr.js";
import { ed25519Sign, nidBindingPayload } from "./radicle.js";
import { AUX_RAND, consumeVector } from "./vector-helpers.js";
import type { Fixtures } from "./fixtures.js";
import type { AuthoredVector } from "./types.js";

const WIRE = ["§3.0", "§4.5.1", "§14.3"];

// keri-authority/ wire-level vectors (ADR-032): kel_head structural handling
// (absent / duplicate / malformed / mismatch), the forbidden classes, the
// mandatory classes, the equivocation-flagged outcome, and the KERI10JSON /
// CESR wire-format rejection. Every embedded event is a real signed Nostr
// event so a consumer exercises the actual §4.5.1 checks.
export async function buildKeriAuthorityWireVectors(fixtures: Fixtures): Promise<AuthoredVector[]> {
  const alice = fixtures.personas.alice;
  const epoch = alice.epoch_keys.epoch_1;
  const cold = alice.cold_root;
  const head = fixtures.kel.alice.head;
  const nid2 = fixtures.ed25519_nids.alice_device_2;
  const pub2 = fixtures.device_publishing_keys.alice_device_2;
  const T = fixtures.test_epoch;

  const acceptedKel = [{ kind: 31002, id: head.id, s: 0, epoch_key: epoch.pubkey }];

  // W1: a kind:1 post signed by the epoch key with NO kel_head tag.
  const absentEvent = await signEvent({
    secretKey: epoch.private_key,
    created_at: T + 300,
    kind: 1,
    tags: [["client", "heterodyne"]],
    content: "epoch-key-signed post missing the mandatory kel_head",
    auxRand: AUX_RAND,
  });

  // W2: two kel_head tags (duplicate is not "exactly one").
  const duplicateEvent = await signEvent({
    secretKey: epoch.private_key,
    created_at: T + 301,
    kind: 1,
    tags: [["client", "heterodyne"], kelHeadTag(head), kelHeadTag(head)],
    content: "post carrying two kel_head tags",
    auxRand: AUX_RAND,
  });

  // W3: one kel_head whose id is not 64-hex (malformed).
  const malformedEvent = await signEvent({
    secretKey: epoch.private_key,
    created_at: T + 302,
    kind: 1,
    tags: [["client", "heterodyne"], ["kel_head", "g".repeat(64), "0"]],
    content: "post carrying a malformed kel_head id",
    auxRand: AUX_RAND,
  });

  // W4: well-formed kel_head naming the inception but claiming seq 1 (it is s=0).
  const mismatchEvent = await signEvent({
    secretKey: epoch.private_key,
    created_at: T + 303,
    kind: 1,
    tags: [["client", "heterodyne"], ["kel_head", head.id, "1"]],
    content: "post whose kel_head seq disagrees with the named event's s",
    auxRand: AUX_RAND,
  });

  // W5: forbidden kel_head on a kind:31002 inception (KEL events chain via prior_digest).
  const forbiddenInception = await signEvent({
    secretKey: cold.private_key,
    created_at: T,
    kind: 31002,
    tags: [...inceptionTemplate(cold.pubkey, epoch.pubkey, T).tags, kelHeadTag(head)],
    content: "",
    auxRand: AUX_RAND,
  });

  // W6: forbidden kel_head on a kind:31003 rotation (including this committed one).
  const forbiddenRotation = await signEvent({
    secretKey: cold.private_key,
    created_at: T + 3600,
    kind: 31003,
    tags: [
      ["d", "1"],
      ["heterodyne", "keri_rotation"],
      ["p", cold.pubkey],
      ["s", "1"],
      ["prior_digest", head.id],
      ["strategy", "committed"],
      ["epoch_key", getPublicKey("22".padStart(64, "0"))],
      kelHeadTag(head),
    ],
    content: "[]",
    auxRand: AUX_RAND,
  });

  // W7: forbidden kel_head on a kind:1060 DR outer message (ratchet-key-signed wire event).
  const forbiddenDrWire = await signEvent({
    secretKey: "d2".padStart(64, "0"),
    created_at: T + 320,
    kind: 1060,
    tags: [["header", "ratchet-header-placeholder"], kelHeadTag(head)],
    content: "ratchet-ciphertext-placeholder",
    auxRand: AUX_RAND,
  });

  // W9: mandatory kel_head present and well-formed on a kind:31000 root attestation.
  const rootWithHead = await signEvent({
    secretKey: epoch.private_key,
    created_at: T + 340,
    kind: 31000,
    tags: withKelHead([["d", ""], ["heterodyne", "root"], ["cold_root", cold.pubkey]], head),
    content: "",
    auxRand: AUX_RAND,
  });

  // W10: mandatory kel_head on a kind:31001 NID delegation (fully valid, distinct device).
  const bindPayload2 = nidBindingPayload(cold.pubkey, nid2.did_key);
  const bindProof2 = ed25519Sign(bindPayload2, nid2.private_key);
  const delegationWithHead = await signEvent({
    secretKey: epoch.private_key,
    created_at: T + 341,
    kind: 31001,
    tags: withKelHead(
      [
        ["d", `nid:${nid2.did_key}`],
        ["heterodyne", "delegation"],
        ["radicle_nid", nid2.did_key],
        ["publishing_key", pub2.pubkey],
        ["cold_root", cold.pubkey],
        ["nid_proof", bindProof2],
        ["valid_until", ""],
      ],
      head,
    ),
    content: "",
    auxRand: AUX_RAND,
  });

  // W11: mandatory kel_head on the ADR-030 epoch-key-signed enrollment invite.
  const epochInvite = await signEvent({
    secretKey: epoch.private_key,
    created_at: T + 342,
    kind: 30078,
    tags: withKelHead(
      [
        ["d", "double-ratchet/invites/epoch"],
        ["heterodyne", "dm_invite"],
        ["ephemeral_key", getPublicKey("e5".padStart(64, "0"))],
      ],
      head,
    ),
    content: "",
    auxRand: AUX_RAND,
  });

  // W12: structurally valid kel_head naming an event off the accepted KEL.
  const offKelId = "ab".repeat(32);
  const equivocationEvent = await signEvent({
    secretKey: epoch.private_key,
    created_at: T + 350,
    kind: 1,
    tags: [["client", "heterodyne"], ["kel_head", offKelId, "0"]],
    content: "post whose kel_head names an event not on the accepted KEL",
    auxRand: AUX_RAND,
  });

  return [
    consumeVector("keri-authority/001-kel-head-absent-rejected.json", {
      vector_id: "keri-authority/kel-head-absent-rejected",
      spec_refs: WIRE,
      description: "An epoch-key-signed kind:1 post with no kel_head tag fails verification: the tag is mandatory per the §3.0 matrix.",
      input: { event: absentEvent, signer: "epoch_1" },
      expected_output: { verdict: "reject", reason_code: "kel_head_missing" },
      decision_trace: ["verify_bip340_signature", "require_kel_head", "kel_head_absent"],
    }),
    consumeVector("keri-authority/002-kel-head-duplicate-rejected.json", {
      vector_id: "keri-authority/kel-head-duplicate-rejected",
      spec_refs: WIRE,
      description: "An epoch-key-signed post carrying two kel_head tags fails: the event MUST carry exactly one well-formed instance.",
      input: { event: duplicateEvent, kel_head_count: 2 },
      expected_output: { verdict: "reject", reason_code: "kel_head_missing" },
      decision_trace: ["verify_bip340_signature", "count_kel_head_tags", "reject_not_exactly_one"],
      notes: "kel_head_missing covers absent, duplicate, and malformed (a single well-formed instance is required, §4.5.1).",
    }),
    consumeVector("keri-authority/003-kel-head-malformed-rejected.json", {
      vector_id: "keri-authority/kel-head-malformed-rejected",
      spec_refs: WIRE,
      description: "An epoch-key-signed post whose single kel_head tag carries a non-hex id (not 64 lowercase-hex) fails verification.",
      input: { event: malformedEvent, malformed_field: "id" },
      expected_output: { verdict: "reject", reason_code: "kel_head_missing" },
      decision_trace: ["verify_bip340_signature", "parse_kel_head", "reject_malformed_id"],
    }),
    consumeVector("keri-authority/004-kel-head-seq-mismatch-rejected.json", {
      vector_id: "keri-authority/kel-head-seq-mismatch-rejected",
      spec_refs: WIRE,
      description: "A well-formed kel_head names the inception event (s=0) but declares seq 1; once the named event is resolved on the accepted KEL its s (0) does not equal the tag's decimal seq (1).",
      input: { event: mismatchEvent, accepted_kel: acceptedKel, resolved_event_s: 0, kel_head_seq: 1 },
      expected_output: { verdict: "reject", reason_code: "kel_head_mismatch" },
      decision_trace: ["verify_bip340_signature", "resolve_kel_head_on_accepted_kel", "compare_seq_to_s", "seq_mismatch"],
    }),
    consumeVector("keri-authority/005-kel-head-forbidden-on-inception.json", {
      vector_id: "keri-authority/kel-head-forbidden-on-inception",
      spec_refs: WIRE,
      description: "A kind:31002 inception carrying a kel_head tag is rejected: KEL events chain via prior_digest and MUST NOT carry kel_head.",
      input: { event: forbiddenInception },
      expected_output: { verdict: "reject", reason_code: "kel_head_forbidden" },
      decision_trace: ["classify_kel_event", "reject_kel_head_on_kel_event"],
    }),
    consumeVector("keri-authority/006-kel-head-forbidden-on-rotation.json", {
      vector_id: "keri-authority/kel-head-forbidden-on-rotation",
      spec_refs: WIRE,
      description: "A kind:31003 rotation carrying a kel_head tag is rejected, including committed rotations; freshness comes from replay ordering, never kel_head (§3.5.2).",
      input: { event: forbiddenRotation },
      expected_output: { verdict: "reject", reason_code: "kel_head_forbidden" },
      decision_trace: ["classify_kel_event", "reject_kel_head_on_kel_event"],
    }),
    consumeVector("keri-authority/007-kel-head-forbidden-on-dr-wire.json", {
      vector_id: "keri-authority/kel-head-forbidden-on-dr-wire",
      spec_refs: ["§3.0", "§4.5.1", "§5.7", "§14.3"],
      description: "A kind:1060 double-ratchet outer message (signed by a ratchet key) carrying a kel_head tag is rejected: §5.7 DR wire events MUST NOT carry it.",
      input: { event: forbiddenDrWire, signer_kind: "current_ratchet_key" },
      expected_output: { verdict: "reject", reason_code: "kel_head_forbidden" },
      decision_trace: ["classify_dr_wire_event", "reject_kel_head_on_dr_wire"],
    }),
    consumeVector("keri-authority/009-kel-head-mandatory-on-root.json", {
      vector_id: "keri-authority/kel-head-mandatory-on-root",
      spec_refs: WIRE,
      description: "A kind:31000 root attestation carrying exactly one well-formed kel_head that resolves to the accepted KEL head (s=0) passes the structural and resolution checks and is accepted.",
      input: { event: rootWithHead, accepted_kel: acceptedKel },
      expected_output: {
        verdict: "accept",
        normalized: { kel_head_present: true, kel_head_seq: 0, kel_head_on_accepted_kel: true },
      },
      decision_trace: ["verify_bip340_signature", "require_kel_head_present", "kel_head_well_formed", "resolve_on_accepted_kel", "accept"],
    }),
    consumeVector("keri-authority/010-kel-head-mandatory-on-delegation.json", {
      vector_id: "keri-authority/kel-head-mandatory-on-delegation",
      spec_refs: ["§3.0", "§3.3.1", "§4.5.1", "§14.3"],
      description: "A kind:31001 NID delegation carrying a well-formed kel_head (bidirectional binding otherwise valid, cf. nid-binding/) is accepted.",
      input: { event: delegationWithHead, accepted_kel: acceptedKel, nid_binding_payload: bindPayload2 },
      expected_output: {
        verdict: "accept",
        normalized: { kel_head_present: true, kel_head_seq: 0, kel_head_on_accepted_kel: true },
      },
      decision_trace: ["verify_bip340_signature", "verify_nid_proof", "require_kel_head_present", "resolve_on_accepted_kel", "accept"],
      notes: "The bidirectional NID binding is exercised in nid-binding/; this vector isolates the mandatory kel_head on a delegation.",
    }),
    consumeVector("keri-authority/011-kel-head-mandatory-on-epoch-invite.json", {
      vector_id: "keri-authority/kel-head-mandatory-on-epoch-invite",
      spec_refs: ["§3.0", "§4.5.1", "§5.7.1", "§14.3"],
      description: "The ADR-030 epoch-key-signed enrollment invite (kind:30078, d=double-ratchet/invites/epoch) carrying a well-formed kel_head is accepted; this is the epoch-key carve-out from §5.7.2's device-key invite rule.",
      input: { event: epochInvite, accepted_kel: acceptedKel, signer: "epoch_key" },
      expected_output: {
        verdict: "accept",
        normalized: { d: "double-ratchet/invites/epoch", signer: "epoch_key", kel_head_present: true },
      },
      decision_trace: ["classify_epoch_key_invite", "verify_bip340_signature", "require_kel_head_present", "accept"],
    }),
    consumeVector("keri-authority/012-equivocation-flagged.json", {
      vector_id: "keri-authority/equivocation-flagged",
      spec_refs: ["§4.5.1", "§13", "§14.3"],
      description: "A structurally valid kel_head names an event that is not on the persona's accepted KEL; the verifier produces the equivocation-flagged outcome and surfaces it through the §13 security-warning interface.",
      input: { event: equivocationEvent, accepted_kel: acceptedKel, kel_head_names: offKelId },
      expected_output: {
        verdict: "equivocation_flagged",
        normalized: { kel_head_on_accepted_kel: false, surfaced_via_security_warning: true },
        warnings: ["equivocation_flagged"],
      },
      decision_trace: ["verify_bip340_signature", "resolve_kel_head_on_accepted_kel", "kel_head_not_on_accepted_kel", "flag_equivocation_surface_warning"],
      notes: "equivocation_flagged is a distinct verification outcome (not a plain reject): the event is not silently accepted, and the duplicity is surfaced per §13.",
    }),
    consumeVector("keri-authority/013-keri10json-cesr-wire-rejected.json", {
      vector_id: "keri-authority/keri10json-cesr-wire-rejected",
      spec_refs: ["§11.8", "§3.0.1", "§14.3"],
      description: "A KEL event presented in KERI10JSON/CESR on the wire (or as storage) is rejected: NIP-01 with nip01_raw is the only Heterodyne wire and storage format; canonical-KERI forms exist only as derived export artifacts.",
      input: {
        received_format: "KERI10JSON",
        payload_excerpt: "{\"v\":\"KERI10JSON0000fb_\",\"t\":\"icp\",\"d\":\"...\",\"i\":\"...\",\"s\":\"0\"}",
        also_rejected: "CESR",
        context: "kel_event_on_heterodyne_wire",
      },
      expected_output: { verdict: "reject", reason_code: "keri_wire_format_rejected" },
      decision_trace: ["inspect_wire_format", "detect_non_nip01_keri_cesr", "reject"],
    }),
  ];
}
