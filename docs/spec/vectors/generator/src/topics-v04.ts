import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha2";
import { nip44 } from "nostr-tools";
import { bytesToHex, hexToBytes, utf8Bytes } from "./hex.js";
import { canonicalNip01, getEventId, signEvent } from "./nostr.js";
import { ed25519Sign, nidBindingPayload, nodeAdvertPayload } from "./radicle.js";
import {
  AUX_RAND,
  baseVector,
  consumeVector,
  produceAuthored,
} from "./vector-helpers.js";
import type { Fixtures } from "./fixtures.js";
import type { AuthoredVector } from "./types.js";
import type { NostrSignedEvent } from "./nostr.js";

type ProduceMeta = {
  vector_id: string;
  spec_refs: string[];
  description: string;
  input: Record<string, unknown>;
  notes?: string;
};

function produced(
  relativePath: string,
  meta: ProduceMeta,
  event: NostrSignedEvent,
  extraDecoded: Record<string, unknown> = {},
): AuthoredVector {
  return produceAuthored(relativePath, {
    ...meta,
    expected_output: {
      canonical_wire: canonicalNip01(event),
      decoded: { event, ...extraDecoded },
      id: event.id,
      sig: event.sig,
    },
  });
}

// The v0.4.0 CORE categories (ADR-026..029) plus the fixture-aware reframes of
// existing categories that moved from MXID/room targets to NID/RID targets.
export async function buildV04Vectors(fixtures: Fixtures): Promise<AuthoredVector[]> {
  const alice = fixtures.personas.alice;
  const bob = fixtures.personas.bob;
  const carol = fixtures.personas.carol;
  const epoch = alice.epoch_keys.epoch_1;
  const cold = alice.cold_root;
  const nid1 = fixtures.ed25519_nids.alice_device_1;
  const nid2 = fixtures.ed25519_nids.alice_device_2;
  const bobNid = fixtures.ed25519_nids.bob_device_1;
  const pub1 = fixtures.device_publishing_keys.alice_device_1;
  const pub2 = fixtures.device_publishing_keys.alice_device_2;
  const rid = fixtures.radicle_rids.alice;
  const reanchorRid = fixtures.radicle_rids.alice_reanchor;
  const orgRid = fixtures.radicle_rids.org_acme;
  const audA = fixtures.audience_keys.alice_tier3_gen_a;
  const audB = fixtures.audience_keys.alice_tier3_gen_b;
  const T = fixtures.test_epoch;

  const vectors: AuthoredVector[] = [];

  // ---- Reframed existing CORE categories (NID / RID targets) ----------------

  vectors.push(
    consumeVector("identity/002-delegation-active.json", {
      vector_id: "identity/delegation-active",
      spec_refs: ["§3.3.1", "§3.3.3", "§14.3"],
      description: "NID delegation is active while valid_until is greater than simulated_clock.",
      input: { nid: nid1.did_key, publishing_key: pub1.pubkey, valid_until: T + 7200 },
      expected_output: { verdict: "accept", normalized: { delegation_state: "active" } },
      simulated_clock: T + 3600,
    }),
    consumeVector("identity/003-delegation-expired.json", {
      vector_id: "identity/delegation-expired",
      spec_refs: ["§3.3.1", "§3.3.3", "§4.5", "§14.3"],
      description: "NID delegation is rejected after valid_until.",
      input: { nid: nid1.did_key, publishing_key: pub1.pubkey, valid_until: T },
      expected_output: { verdict: "reject", reason_code: "expired_delegation" },
      simulated_clock: T + 3600,
    }),
    consumeVector("identity/004-delegation-revoked.json", {
      vector_id: "identity/delegation-revoked",
      spec_refs: ["§3.3.1", "§3.9.7", "§4.5", "§14.3"],
      description: "NID delegation is rejected after a revocation event for the delegated NID.",
      input: { nid: nid1.did_key, revoked_at: T + 900, event_created_at: T + 1000 },
      expected_output: { verdict: "reject", reason_code: "revoked_key_post_revoked_at" },
      simulated_clock: T + 1100,
    }),
    consumeVector("verification/002-delegation-mismatch-rejects.json", {
      vector_id: "verification/delegation-mismatch-rejects",
      spec_refs: ["§3.3.1", "§4.5", "§14.3"],
      description: "An event signed by a publishing key not covered by the active NID delegation rejects.",
      input: {
        delegated_nid: nid1.did_key,
        delegated_publishing_key: pub1.pubkey,
        event_pubkey: pub2.pubkey,
      },
      expected_output: { verdict: "reject", reason_code: "delegation_mismatch" },
    }),
    consumeVector("interop/004-kind31005-identity-pointer.json", {
      vector_id: "interop/kind31005-identity-pointer",
      spec_refs: ["§11.3", "§7.0", "§14.3"],
      description: "kind:31005 identity pointer maps an npub to its canonical Radicle RID plus optional host hints.",
      input: { kind: 31005, npub: cold.pubkey, rid, host_hints: ["wss://node-a.example/relay"] },
      expected_output: { verdict: "accept", normalized: { rid, host_hints: ["wss://node-a.example/relay"] } },
    }),
  );

  // ---- identity/ CORE Matrix-free kind:31005 race tiebreaker (§3.9.8) -------

  vectors.push(
    consumeVector("identity/007-kind31005-race-tiebreaker-core.json", {
      vector_id: "identity/kind31005-race-tiebreaker-core",
      spec_refs: ["§3.9.8", "§11.3", "§14.3"],
      description: "CORE Matrix-free kind:31005 tiebreaker: discard invalid cold-root sig, prefer KEL-consistent, then highest created_at, then lex-min id, with no Matrix input.",
      input: {
        npub: cold.pubkey,
        candidates: [
          { id: "a1".repeat(32), rid, created_at: T + 10, cold_root_sig_valid: true, kel_consistent: true },
          { id: "b2".repeat(32), rid: reanchorRid, created_at: T + 20, cold_root_sig_valid: true, kel_consistent: true },
          { id: "c3".repeat(32), rid: "rad:zBogusStalePointer", created_at: T + 30, cold_root_sig_valid: false, kel_consistent: false },
        ],
        matrix_input: null,
      },
      expected_output: {
        verdict: "accept",
        normalized: {
          selected_pointer_id: "b2".repeat(32),
          selected_rid: reanchorRid,
          matrix_input_used: false,
          tiebreaker_step: "higher_created_at",
        },
      },
      decision_trace: [
        "discard_invalid_cold_root_sig",
        "prefer_kel_consistent",
        "higher_created_at",
        "lex_min_id",
      ],
    }),
  );

  // ---- outbox/ cross-backend reply/reaction dedup (§6.5) --------------------

  vectors.push(
    consumeVector("outbox/006-cross-backend-reply-dedup.json", {
      vector_id: "outbox/cross-backend-reply-dedup",
      spec_refs: ["§6.5", "§6.3", "§14.3"],
      description: "Outbox-model reply and reaction observed on both the Nostr relay and the repo relay are deduplicated by event id during scatter-gather thread assembly.",
      input: {
        reply_event_id: "ab".repeat(32),
        reply_observed_on: ["nostr_relay", "repo_relay"],
        reaction_event_id: "cd".repeat(32),
        reaction_observed_on: ["nostr_relay", "repo_relay"],
      },
      expected_output: {
        verdict: "accept",
        normalized: {
          unique_event_ids: ["ab".repeat(32), "cd".repeat(32)],
          duplicate_count: 2,
          thread_assembly: "scatter_gather",
        },
      },
      decision_trace: ["gather_across_backends", "dedup_by_event_id"],
    }),
  );

  // ---- moderation/ Radicle editorial-gating mode (§8.8, §6.7.0) ------------

  vectors.push(
    consumeVector("moderation/006-radicle-editorial-gating.json", {
      vector_id: "moderation/radicle-editorial-gating",
      spec_refs: ["§8.8", "§6.7.0", "§14.3"],
      description: "A post is editorially approved in Radicle mode iff it is reachable from the delegate-threshold-approved canonical feed branch, evaluated independently of any kind:4550 approval.",
      input: {
        mode: "radicle_editorial",
        post_event_id: "ef".repeat(32),
        reachable_from_canonical_branch: true,
        delegate_threshold: 2,
        kind_4550_present: false,
      },
      expected_output: {
        verdict: "accept",
        normalized: {
          approved: true,
          mechanism: "radicle_editorial_gating",
          via_kind_4550: false,
          reachable_from_canonical_branch: true,
        },
      },
      decision_trace: [
        "resolve_canonical_defaultBranch",
        "check_reachability_of_post_and_index",
        "approved_without_kind_4550",
      ],
    }),
  );

  // ---- repo-relay/ CLIENT conformance (§10.1.2) ----------------------------

  const repoRelayEvent = await signEvent({
    secretKey: epoch.private_key,
    created_at: T + 40,
    kind: 1,
    tags: [["client", "heterodyne"]],
    content: "posted over a repo relay's NIP-01 wire",
    auxRand: AUX_RAND,
  });
  vectors.push(
    {
      relativePath: "repo-relay/001-nip01-read-write-roundtrip.json",
      vector: baseVector({
        vector_id: "repo-relay/nip01-read-write-roundtrip",
        spec_refs: ["§10.1.2", "§10.2", "§14.1", "§14.3"],
        direction: "round-trip",
        description: "A Nostr event read and written over a repo relay's NIP-01 wire is byte-identical to the same event over a plain Nostr relay (indistinguishable at the wire).",
        input: {
          fixture_persona: "alice",
          repo_relay_frame: ["EVENT", "sub-1", repoRelayEvent],
          plain_relay_frame: ["EVENT", "sub-1", repoRelayEvent],
        },
        expected_output: {
          comparison_surface: "nip01_canonical_event_serialization",
          canonical_wire: canonicalNip01(repoRelayEvent),
          decoded: repoRelayEvent,
          id: repoRelayEvent.id,
          sig: repoRelayEvent.sig,
        },
        notes: "Repo-relay CLIENT conformance only. The repo relay presents the ordinary NIP-01 websocket wire; the SERVER/STORAGE contract (ref namespace, COB registry, filter-to-git-read, GC/quota) is a named pre-1.0 work item (§10.1.2) and is NOT vectored.",
      }),
    },
    consumeVector("repo-relay/002-invalid-signature-rejected.json", {
      vector_id: "repo-relay/invalid-signature-rejected",
      spec_refs: ["§10.1.2", "§14.3"],
      description: "A repo relay MUST reject an event whose Nostr signature does not verify before persisting it into its backing repo.",
      input: {
        event: {
          id: "00".repeat(32),
          pubkey: epoch.pubkey,
          created_at: T + 40,
          kind: 1,
          tags: [],
          content: "not really signed",
          sig: "11".repeat(64),
        },
      },
      expected_output: { verdict: "reject", reason_code: "bad_signature" },
      decision_trace: ["validate_nip01_id", "verify_bip340_signature"],
    }),
    consumeVector("repo-relay/003-light-node-submit-write-path.json", {
      vector_id: "repo-relay/light-node-submit-write-path",
      spec_refs: ["§3.3.1", "§10.1.2", "§14.3"],
      description: "A light node authors a Nostr event with its secp256k1 publishing key and submits it to a repo relay; the full node commits it under its delegate NID. Event authenticity is the Nostr signature, not the git-ref signature.",
      input: {
        author_publishing_key: pub1.pubkey,
        submitted_via: "repo_relay",
        full_node_commit_nid: nid1.did_key,
      },
      expected_output: {
        verdict: "accept",
        normalized: {
          persisted: true,
          authenticity: "nostr_signature",
          git_ref_signature: "storage_attestation",
        },
      },
    }),
  );

  // ---- routing-node/ (§7.0, §10.1.1) ---------------------------------------

  vectors.push(
    consumeVector("routing-node/001-repo-location-from-ads-only.json", {
      vector_id: "routing-node/repo-location-from-ads-only",
      spec_refs: ["§7.0", "§10.1.1", "§14.3"],
      description: "A routing node answers a repo-location query from kind:31005 and kind:31010 advertisements only, returns host hints, and serves no content.",
      input: {
        npub: cold.pubkey,
        kind31005: { rid, host_hints: ["wss://node-a.example/relay"] },
        kind31010: [
          { rid, nid: nid1.did_key, endpoint: "wss://node-a.example/relay", expiry: T + 86400, nid_proof_valid: true },
        ],
      },
      expected_output: {
        verdict: "accept",
        normalized: { rid, hosts: ["wss://node-a.example/relay"], content_served: false },
      },
      simulated_clock: T + 100,
      decision_trace: ["resolve_kind31005_rid", "collect_kind31010_for_rid", "verify_and_filter", "return_hints_only"],
    }),
    consumeVector("routing-node/002-expired-advert-discarded.json", {
      vector_id: "routing-node/expired-advert-discarded",
      spec_refs: ["§7.0", "§10.1.1", "§14.3"],
      description: "A routing node discards an expired kind:31010 advertisement and returns only the live host hints.",
      input: {
        rid,
        kind31010: [
          { nid: nid1.did_key, endpoint: "wss://live.example/relay", expiry: T + 86400, nid_proof_valid: true },
          { nid: nid2.did_key, endpoint: "wss://stale.example/relay", expiry: T - 1, nid_proof_valid: true },
        ],
      },
      expected_output: {
        verdict: "accept",
        normalized: { hosts: ["wss://live.example/relay"], discarded_expired: ["wss://stale.example/relay"] },
      },
      simulated_clock: T + 100,
    }),
    consumeVector("routing-node/003-unverifiable-advert-discarded.json", {
      vector_id: "routing-node/unverifiable-advert-discarded",
      spec_refs: ["§7.0", "§10.1.1", "§14.3"],
      description: "A routing node discards a kind:31010 advertisement whose nid_proof does not verify and returns only the verifiable host hints.",
      input: {
        rid,
        kind31010: [
          { nid: nid1.did_key, endpoint: "wss://good.example/relay", expiry: T + 86400, nid_proof_valid: true },
          { nid: nid2.did_key, endpoint: "wss://bad.example/relay", expiry: T + 86400, nid_proof_valid: false },
        ],
      },
      expected_output: {
        verdict: "accept",
        normalized: { hosts: ["wss://good.example/relay"], discarded_unverifiable: ["wss://bad.example/relay"] },
      },
      simulated_clock: T + 100,
    }),
  );

  // ---- node-advert/ kind:31010 dual signature (§7.0) -----------------------

  const endpoint = "wss://node-a.example/relay";
  const repoHead = bytesToHex(sha256(utf8Bytes("heterodyne-fixture-repo-head|alice")).slice(0, 20));
  const advExpiry = T + 86400;
  const advPayload = nodeAdvertPayload(rid, nid1.did_key, endpoint, advExpiry, repoHead);
  const nidProof = ed25519Sign(advPayload, nid1.private_key);
  const advTags = (proof: string, expiry: number): string[][] => [
    ["d", rid],
    ["heterodyne", "node_advert"],
    ["rid", rid],
    ["nid", nid1.did_key],
    ["endpoint", endpoint],
    ["expiry", String(expiry)],
    ["nid_proof", proof],
  ];
  const advEvent = await signEvent({
    secretKey: epoch.private_key,
    created_at: T + 50,
    kind: 31010,
    tags: advTags(nidProof, advExpiry),
    content: "",
    auxRand: AUX_RAND,
  });
  vectors.push(
    produced(
      "node-advert/001-valid-dual-signed.json",
      {
        vector_id: "node-advert/valid-dual-signed",
        spec_refs: ["§7.0", "§10.1.1", "§14.1", "§14.3"],
        description: "kind:31010 node advertisement: valid outer BIP-340 Nostr signature AND inner Ed25519 nid_proof over the pinned advertisement payload.",
        input: {
          fixture_persona: "alice",
          signer: "epoch_1",
          advertised_nid: nid1.did_key,
          rid,
          endpoint,
          expiry: advExpiry,
          repo_head: repoHead,
          aux_rand: AUX_RAND,
        },
        notes: "The nid_proof payload serialization is defined by this vector (§7.0 fixes the bound fields - RID, NID, endpoint, expiry, canonical repo head - and defers the exact bytes here): heterodyne-node-advert-v1|<rid>|<nid>|<endpoint>|<expiry>|<repo_head>, UTF-8, single ASCII '|' separator. A single endpoint is used for determinism.",
      },
      advEvent,
      { nid_proof_payload: advPayload, nid_proof: nidProof, repo_head: repoHead },
    ),
    consumeVector("node-advert/002-outer-sig-invalid-rejected.json", {
      vector_id: "node-advert/outer-sig-invalid-rejected",
      spec_refs: ["§7.0", "§14.3"],
      description: "A kind:31010 advertisement whose outer BIP-340 Nostr signature does not verify is rejected.",
      input: { event: { ...advEvent, sig: "22".repeat(64) } },
      expected_output: { verdict: "reject", reason_code: "bad_signature" },
      decision_trace: ["validate_nip01_id", "verify_outer_bip340_signature"],
    }),
  );

  const wrongNidProof = ed25519Sign(advPayload, nid2.private_key);
  const badProofEvent = await signEvent({
    secretKey: epoch.private_key,
    created_at: T + 50,
    kind: 31010,
    tags: advTags(wrongNidProof, advExpiry),
    content: "",
    auxRand: AUX_RAND,
  });
  const expExpiry = T - 1;
  const expPayload = nodeAdvertPayload(rid, nid1.did_key, endpoint, expExpiry, repoHead);
  const expProof = ed25519Sign(expPayload, nid1.private_key);
  const expiredEvent = await signEvent({
    secretKey: epoch.private_key,
    created_at: T + 50,
    kind: 31010,
    tags: advTags(expProof, expExpiry),
    content: "",
    auxRand: AUX_RAND,
  });
  vectors.push(
    consumeVector("node-advert/003-nid-proof-invalid-rejected.json", {
      vector_id: "node-advert/nid-proof-invalid-rejected",
      spec_refs: ["§7.0", "§3.3.1", "§14.3"],
      description: "A kind:31010 advertisement whose inner Ed25519 nid_proof does not verify under the advertised NID is rejected, even though the outer Nostr signature is valid.",
      input: { event: badProofEvent, advertised_nid: nid1.did_key, nid_proof_payload: advPayload },
      expected_output: { verdict: "reject", reason_code: "nid_proof_invalid" },
      decision_trace: ["verify_outer_bip340_signature", "verify_inner_ed25519_nid_proof"],
    }),
    consumeVector("node-advert/004-expired-rejected.json", {
      vector_id: "node-advert/expired-rejected",
      spec_refs: ["§7.0", "§10.1.1", "§14.3"],
      description: "A kind:31010 advertisement whose expiry is in the past is rejected even though both signatures verify.",
      input: { event: expiredEvent, advertised_nid: nid1.did_key, nid_proof_payload: expPayload },
      expected_output: { verdict: "reject", reason_code: "node_advert_expired" },
      simulated_clock: T + 100,
      decision_trace: ["verify_outer_bip340_signature", "verify_inner_ed25519_nid_proof", "check_expiry"],
    }),
  );

  // ---- light-node/ (§7.3, §10.1.1) -----------------------------------------

  const fetched = await signEvent({
    secretKey: epoch.private_key,
    created_at: T + 60,
    kind: 1,
    tags: [["client", "heterodyne"]],
    content: "fetched from an untrusted full node",
    auxRand: AUX_RAND,
  });
  vectors.push(
    consumeVector("light-node/001-verifies-signature-locally.json", {
      vector_id: "light-node/verifies-signature-locally",
      spec_refs: ["§7.3", "§10.1.1", "§14.3"],
      description: "A light node verifies a fetched event's Nostr signature locally and accepts it on a valid signature regardless of which (untrusted) host served it.",
      input: { fetched_event: fetched, served_by: "wss://untrusted.example/relay", host_trusted: false },
      expected_output: {
        verdict: "accept",
        normalized: { signature_verified_locally: true, trusted_host: false },
      },
      decision_trace: ["fetch_event", "verify_bip340_locally", "accept_on_valid_signature"],
    }),
    consumeVector("light-node/002-content-not-through-routing-node.json", {
      vector_id: "light-node/content-not-through-routing-node",
      spec_refs: ["§7.3", "§10.1.1", "§14.3"],
      description: "A light node queries a routing node only for host hints and fetches content directly from a full node; it pulls no content through the routing node.",
      input: {
        routing_node: "https://routing.example",
        hosts_returned: ["wss://node-a.example/relay"],
        fetched_direct_from: "wss://node-a.example/relay",
        content_bytes_via_routing_node: 0,
      },
      expected_output: {
        verdict: "accept",
        normalized: { fetched_direct: true, routing_node_content_bytes: 0 },
      },
      decision_trace: ["query_routing_node_for_hosts", "connect_directly_to_full_node", "verify_signature_locally"],
    }),
    consumeVector("light-node/003-route-around-withholding-host.json", {
      vector_id: "light-node/route-around-withholding-host",
      spec_refs: ["§7.0", "§7.3", "§10.1.1", "§14.3"],
      description: "A light node routes around a full node that withholds an event by retrying an alternate host from the routing node's list, then verifies the obtained event locally.",
      input: {
        target_event_id: "ab".repeat(32),
        hosts: ["wss://withholds.example/relay", "wss://serves.example/relay"],
        withholding_hosts: ["wss://withholds.example/relay"],
        nostr_relay_fallback: ["wss://relay.example"],
      },
      expected_output: {
        verdict: "accept",
        normalized: {
          obtained: true,
          obtained_from: "wss://serves.example/relay",
          routed_around: ["wss://withholds.example/relay"],
        },
      },
      decision_trace: [
        "query_routing_node",
        "fetch_primary_host_withheld",
        "retry_alternate_host",
        "obtained",
        "verify_signature_locally",
      ],
    }),
  );

  // ---- nid-binding/ kind:31001 NID delegation (§3.3.1) ---------------------

  const bindPayload = nidBindingPayload(cold.pubkey, nid1.did_key);
  const bindProof = ed25519Sign(bindPayload, nid1.private_key);
  const nidDelegationTags = (proof: string | null): string[][] => {
    const tags: string[][] = [
      ["d", `nid:${nid1.did_key}`],
      ["heterodyne", "delegation"],
      ["radicle_nid", nid1.did_key],
      ["publishing_key", pub1.pubkey],
      ["cold_root", cold.pubkey],
    ];
    if (proof !== null) {
      tags.push(["nid_proof", proof]);
    }
    tags.push(["valid_until", ""]);
    return tags;
  };
  const nidDelegation = await signEvent({
    secretKey: epoch.private_key,
    created_at: T + 5,
    kind: 31001,
    tags: nidDelegationTags(bindProof),
    content: "",
    auxRand: AUX_RAND,
  });
  const noProofDelegation = await signEvent({
    secretKey: epoch.private_key,
    created_at: T + 5,
    kind: 31001,
    tags: nidDelegationTags(null),
    content: "",
    auxRand: AUX_RAND,
  });
  const wrongBindProof = ed25519Sign(bindPayload, nid2.private_key);
  const badProofDelegation = await signEvent({
    secretKey: epoch.private_key,
    created_at: T + 5,
    kind: 31001,
    tags: nidDelegationTags(wrongBindProof),
    content: "",
    auxRand: AUX_RAND,
  });
  vectors.push(
    produced(
      "nid-binding/001-bidirectional-valid.json",
      {
        vector_id: "nid-binding/bidirectional-valid",
        spec_refs: ["§3.3.1", "§3.3.3", "§14.1", "§14.3"],
        description: "kind:31001 NID delegation: bidirectionally bound by the epoch-key Schnorr signature (outer Nostr sig over the tags) AND the NID's Ed25519 nid_proof over the pinned binding payload.",
        input: {
          fixture_persona: "alice",
          signer: "epoch_1",
          radicle_nid: nid1.did_key,
          publishing_key: pub1.pubkey,
          cold_root: cold.pubkey,
          aux_rand: AUX_RAND,
        },
        notes: "Binding payload bytes are pinned by §3.3.1: heterodyne-nid-binding-v1|<npub>|<nid>|radicle-nid-delegation, UTF-8. <npub> is the 64-char lowercase-hex x-only cold-root key; <nid> is the did:key verbatim.",
      },
      nidDelegation,
      { nid_binding_payload: bindPayload, nid_proof: bindProof },
    ),
    consumeVector("nid-binding/002-missing-nid-proof-rejected.json", {
      vector_id: "nid-binding/missing-nid-proof-rejected",
      spec_refs: ["§3.3.1", "§14.3"],
      description: "A kind:31001 NID delegation that lacks the NID Ed25519 nid_proof is rejected: the binding MUST carry both signatures.",
      input: { event: noProofDelegation },
      expected_output: { verdict: "reject", reason_code: "nid_binding_missing_signature" },
      decision_trace: ["verify_outer_bip340_signature", "require_nid_proof_tag"],
    }),
    consumeVector("nid-binding/003-invalid-nid-proof-rejected.json", {
      vector_id: "nid-binding/invalid-nid-proof-rejected",
      spec_refs: ["§3.3.1", "§14.3"],
      description: "A kind:31001 NID delegation whose nid_proof does not verify under the advertised radicle_nid over the pinned binding payload is rejected.",
      input: { event: badProofDelegation, radicle_nid: nid1.did_key, nid_binding_payload: bindPayload },
      expected_output: { verdict: "reject", reason_code: "nid_proof_invalid" },
      decision_trace: ["verify_outer_bip340_signature", "verify_ed25519_nid_proof"],
    }),
  );

  // ---- identity-doc/ KEL over Radicle identity document (§3.9.10) ----------

  const reanchorPointer = await signEvent({
    secretKey: cold.private_key,
    created_at: T + 70,
    kind: 31005,
    tags: [
      ["d", ""],
      ["heterodyne", "identity_pointer"],
      ["rid", reanchorRid],
      ["host_hint", "wss://node-b.example/relay"],
      ["spec_version", "0.4.0"],
    ],
    content: "",
    auxRand: AUX_RAND,
  });
  vectors.push(
    consumeVector("identity-doc/001-kel-revoked-nid-rejected.json", {
      vector_id: "identity-doc/kel-revoked-nid-rejected",
      spec_refs: ["§3.9.10", "§14.3"],
      description: "A NID revoked by the KEL MUST NOT be honored as a delegate even if the Radicle identity document still lists it; git refs signed by it are rejected.",
      input: {
        identity_doc_delegates: [nid1.did_key, nid2.did_key],
        kel_revoked_nids: [nid2.did_key],
        ref_signed_by_nid: nid2.did_key,
      },
      expected_output: { verdict: "reject", reason_code: "kel_revoked_nid" },
      decision_trace: ["replay_kel", "project_authorized_nids", "reject_ref_signed_by_kel_revoked_nid"],
    }),
    consumeVector("identity-doc/002-add-before-remove.json", {
      vector_id: "identity-doc/add-before-remove",
      spec_refs: ["§3.9.10", "§14.3"],
      description: "A delegate-set update adds the replacement NID and reaches delegate majority before the replaced NID is rescinded, so the live delegate set never drops below the majority identity-document revisions require.",
      input: {
        current_delegates: [nid1.did_key, bobNid.did_key],
        replacement_nid: nid2.did_key,
        sequence: [`add:${nid2.did_key}`, "reach_delegate_majority", `remove:${bobNid.did_key}`],
      },
      expected_output: {
        verdict: "accept",
        normalized: { ordering: "add_before_remove", live_delegates_never_below_majority: true },
      },
      decision_trace: ["add_replacement_nid", "reach_delegate_majority", "then_rescind_old_nid"],
    }),
    produced(
      "identity-doc/003-emergency-reanchor.json",
      {
        vector_id: "identity-doc/emergency-reanchor",
        spec_refs: ["§3.9.10", "§11.3", "§14.1", "§14.3"],
        description: "Emergency re-anchor: a cold-root-signed kind:31005 republishes the npub->RID binding to a fresh RID after the live delegate set falls below the Radicle identity-document quorum.",
        input: {
          fixture_persona: "alice",
          signer: "cold_root",
          fresh_rid: reanchorRid,
          aux_rand: AUX_RAND,
        },
        notes: "The RID binding is cold-root-signed (pubkey is the npub), so vanilla Nostr clients can follow authors:[npub] to the fresh RID (§11.3, §3.9.10).",
      },
      reanchorPointer,
    ),
  );

  // ---- org/ delegate-threshold governance and feed canonicity (§6.7.0, §8.8)

  vectors.push(
    consumeVector("org/001-threshold-delegate-governance.json", {
      vector_id: "org/threshold-delegate-governance",
      spec_refs: ["§3.9.10", "§6.7.0", "§14.3"],
      description: "An org persona has threshold>1 delegates; an identity-document revision is adopted once a majority of the live delegate set signs it.",
      input: {
        org_rid: orgRid,
        delegates: [nid1.did_key, nid2.did_key, bobNid.did_key],
        threshold: 2,
        id_doc_revision_signed_by: [nid1.did_key, nid2.did_key],
      },
      expected_output: {
        verdict: "accept",
        normalized: {
          delegate_count: 3,
          threshold: 2,
          id_doc_revision_adopted: true,
          adopted_by: "delegate_majority",
        },
      },
      notes: "Identity-document revisions adopt by majority of live delegates; the threshold field governs canonical-branch acceptance, not its own revisions (§3.9.10, verified against Heartwood 1.9.1).",
    }),
    consumeVector("org/002-member-add-dual-authorized.json", {
      vector_id: "org/member-add-dual-authorized",
      spec_refs: ["§3.3.1", "§3.9.10", "§14.3"],
      description: "Adding a member NID to an org is authorized only when BOTH the member's own KEL kind:31001 and the org admin delegate threshold authorize it.",
      input: { member_nid: nid2.did_key, member_kel_kind31001: true, org_admin_threshold_met: true },
      expected_output: {
        verdict: "accept",
        normalized: { authorized: true, member_kel: true, org_admin_threshold: true },
      },
    }),
    consumeVector("org/003-member-add-single-authorization-insufficient.json", {
      vector_id: "org/member-add-single-authorization-insufficient",
      spec_refs: ["§3.3.1", "§3.9.10", "§14.3"],
      description: "An org member NID add carrying only the org admin threshold (no member KEL kind:31001) is rejected: either authorization alone is insufficient.",
      input: { member_nid: nid2.did_key, member_kel_kind31001: false, org_admin_threshold_met: true },
      expected_output: { verdict: "reject", reason_code: "org_member_add_unauthorized" },
    }),
    consumeVector("org/004-canonical-branch-reachability.json", {
      vector_id: "org/canonical-branch-reachability",
      spec_refs: ["§6.7.0", "§8.8", "§14.3"],
      description: "A lone-epoch-key org kind:31007 published to ordinary relays but NOT reachable from the delegate-threshold-approved canonical feed branch is not the org's canonical feed (rogue-epoch-key relay-bypass rejected).",
      input: {
        org_rid: orgRid,
        kind31007_signed_by_epoch_key: true,
        published_to_relays: true,
        reachable_from_canonical_branch: false,
        delegate_threshold: 2,
      },
      expected_output: { verdict: "reject", reason_code: "not_canonical_branch_reachable" },
      notes: "A published Nostr event carries exactly one signature; org governance is proven by reachability from the threshold-approved canonical defaultBranch, not by the event signature alone. The per-ref xyz.radicle.crefs refinement is OPTIONAL and not part of this baseline vector.",
      decision_trace: ["resolve_canonical_defaultBranch", "check_reachability", "reject_unreachable_lone_epoch_key_feed"],
    }),
  );

  // ---- privacy-tiers/ CORE three-tier coverage (§5.2, §9.0, §6.10, §6.7.4) -

  const tier1Index = await signEvent({
    secretKey: epoch.private_key,
    created_at: T + 80,
    kind: 31007,
    tags: [
      ["d", "tech:2026-q2"],
      ["heterodyne", "feed_index"],
      ["cold_root", cold.pubkey],
      ["rid", rid],
      ["feed_label", "Tech"],
      ["e", "cd".repeat(32), "wss://relay.example"],
    ],
    content: "",
    auxRand: AUX_RAND,
  });

  const recipientNpub = bob.cold_root.pubkey;
  const wrapConvKey = nip44.v2.utils.getConversationKey(hexToBytes(epoch.private_key), recipientNpub);
  const wrapNonce = hexToBytes("50".repeat(32));
  const wrapContent = nip44.v2.encrypt(audA.key, wrapConvKey, wrapNonce);
  const audienceWrap = await signEvent({
    secretKey: epoch.private_key,
    created_at: T + 81,
    kind: 31011,
    tags: [
      ["d", `${audA.key_id}:${recipientNpub}`],
      ["heterodyne", "audience_key_wrap"],
      ["key_id", audA.key_id],
      ["p", recipientNpub],
      ["cold_root", cold.pubkey],
    ],
    content: wrapContent,
    auxRand: AUX_RAND,
  });

  const indexKey = hkdf(sha256, hexToBytes(audA.key), utf8Bytes(audA.key_id), utf8Bytes("heterodyne-index-key-v1"), 32);
  const idxNonce = hexToBytes("51".repeat(32));
  const indexPayload = JSON.stringify({
    spec_version: "0.4.0",
    rid,
    page_id: "opaque-page-01",
    feed_label: "Close friends",
    entries: [{ event_id: "cd".repeat(32), relay_hint: "wss://relay.example" }],
    previous_index: null,
  });
  const idxCipher = nip44.v2.encrypt(indexPayload, indexKey, idxNonce);
  const tier3Index = await signEvent({
    secretKey: epoch.private_key,
    created_at: T + 82,
    kind: 31007,
    tags: [
      ["d", "opaque-page-01"],
      ["heterodyne", "feed_index"],
      ["cold_root", cold.pubkey],
      ["heterodyne_wrap", "room_key.v2"],
      ["key_id", audA.key_id],
    ],
    content: idxCipher,
    auxRand: AUX_RAND,
  });
  const priorPageHash = getEventId(tier3Index);

  const roster = await signEvent({
    secretKey: epoch.private_key,
    created_at: T + 83,
    kind: 31012,
    tags: [
      ["d", audA.key_id],
      ["heterodyne", "audience_roster"],
      ["key_id", audA.key_id],
      ["cold_root", cold.pubkey],
      ["p", bob.cold_root.pubkey],
      ["p", carol.cold_root.pubkey],
    ],
    content: "",
    auxRand: AUX_RAND,
  });

  vectors.push(
    produced(
      "privacy-tiers/001-tier1-public-plaintext-both-backends.json",
      {
        vector_id: "privacy-tiers/tier1-public-plaintext-both-backends",
        spec_refs: ["§5.2.1", "§6.7.1", "§6.7.3", "§9.0", "§14.3"],
        description: "Tier 1 (public repo) kind:31007 feed index is plaintext (content empty, e tags in the clear) and published to both core backends.",
        input: { fixture_persona: "alice", signer: "epoch_1", rid, aux_rand: AUX_RAND },
        notes: "Trust boundary: confidential against no one. The same event is published to the persona's Nostr write relays and its repo relay.",
      },
      tier1Index,
    ),
    consumeVector("privacy-tiers/002-tier2-private-repo-not-encrypted.json", {
      vector_id: "privacy-tiers/tier2-private-repo-not-encrypted",
      spec_refs: ["§5.2.2", "§6.10.2", "§9.0", "§14.3"],
      description: "Tier 2 private repo grants plaintext read via visibility.allow, is not published to public relays, and MUST NOT be described as encrypted or confidential against members.",
      input: {
        tier: 2,
        repo_visibility: "private",
        allow_list: [nid1.did_key],
        published_to_public_relays: false,
        described_as_encrypted: false,
      },
      expected_output: {
        verdict: "accept",
        normalized: {
          tier: 2,
          confidential_against_members: false,
          plaintext_on_allowed_seeders: true,
          published_to_public_relays: false,
        },
        warnings: ["tier2_plaintext_on_allowed_seeders"],
      },
      notes: "Tier 2 boundary is Radicle selective replication, not encryption (§9.0).",
    }),
    produced(
      "privacy-tiers/003-tier3-kind31011-audience-key-wrap.json",
      {
        vector_id: "privacy-tiers/tier3-kind31011-audience-key-wrap",
        spec_refs: ["§6.7.4", "§6.10", "§9.0", "§14.3"],
        description: "Tier 3 kind:31011 per-recipient audience-key wrap: the 32-byte audience key is NIP-44 v2 ECDH-wrapped from the persona's epoch key to the recipient npub.",
        input: {
          fixture_persona: "alice",
          signer: "epoch_1",
          fixture_recipient: "bob",
          recipient_npub: recipientNpub,
          key_id: audA.key_id,
          nip44_nonce: bytesToHex(wrapNonce),
          audience_key: audA.key,
        },
        notes: "The NIP-44 plaintext is the 32-byte audience key as its 64-char lowercase-hex string. The conversation key is the NIP-44 v2 ECDH of the epoch private key and the recipient npub.",
      },
      audienceWrap,
      {
        recipient_npub: recipientNpub,
        conversation_key: bytesToHex(wrapConvKey),
        nip44_nonce: bytesToHex(wrapNonce),
        audience_key_plaintext: audA.key,
        nip44_payload: wrapContent,
      },
    ),
    produced(
      "privacy-tiers/004-tier3-index-key-derivation-and-encryption.json",
      {
        vector_id: "privacy-tiers/tier3-index-key-derivation-and-encryption",
        spec_refs: ["§6.7.4", "§9.0", "§14.3", "§14.5"],
        description: "Tier 3 kind:31007 index: index_key = HKDF-SHA256(audience_key, salt=key_id, info=heterodyne-index-key-v1, 32); content is NIP-44 v2 symmetric encryption of the index payload under index_key; relay-visible tags carry only heterodyne_wrap, key_id, cold_root and an opaque d.",
        input: {
          fixture_persona: "alice",
          signer: "epoch_1",
          fixture_audience_key: "alice_tier3_gen_a",
          key_id: audA.key_id,
          hkdf: { salt: audA.key_id, info: "heterodyne-index-key-v1", output_len: 32 },
          nip44_nonce: bytesToHex(idxNonce),
          plaintext: indexPayload,
        },
        notes: "NIP-44 v2 symmetric layer only (index_key used directly as the conversation key; no ECDH). The opaque d value is a fixture placeholder; producers SHOULD derive it from >=128 bits of randomness per §6.7.4.",
      },
      tier3Index,
      {
        index_key: bytesToHex(indexKey),
        plaintext: JSON.parse(indexPayload) as unknown,
        nip44_payload: idxCipher,
      },
    ),
    consumeVector("privacy-tiers/005-tier3-prev-page-hash-valid.json", {
      vector_id: "privacy-tiers/tier3-prev-page-hash-valid",
      spec_refs: ["§6.7.2", "§6.7.4", "§14.3"],
      description: "A Tier 3 index page chains to its predecessor: the decrypted previous_index.prev_page_hash equals the SHA-256 of the prior page's canonical NIP-01 serialization.",
      input: {
        prior_page_id: tier3Index.id,
        prior_page_canonical_hash: priorPageHash,
        current_page_previous_index: { event_id: tier3Index.id, prev_page_hash: priorPageHash },
      },
      expected_output: { verdict: "accept", normalized: { page_chain_valid: true } },
      decision_trace: ["verify_prior_page_signature", "sha256_prior_page_canonical", "compare_to_prev_page_hash"],
    }),
    consumeVector("privacy-tiers/006-tier3-prev-page-hash-mismatch.json", {
      vector_id: "privacy-tiers/tier3-prev-page-hash-mismatch",
      spec_refs: ["§6.7.2", "§6.7.4", "§14.3"],
      description: "A Tier 3 index page whose decrypted prev_page_hash does not match the prior page's canonical serialization indicates relay-side page substitution; the chain is broken.",
      input: {
        prior_page_id: tier3Index.id,
        prior_page_canonical_hash: priorPageHash,
        current_page_previous_index: { event_id: tier3Index.id, prev_page_hash: "99".repeat(32) },
      },
      expected_output: { verdict: "reject", reason_code: "page_chain_broken" },
      decision_trace: ["sha256_prior_page_canonical", "compare_to_prev_page_hash", "mismatch"],
    }),
    consumeVector("privacy-tiers/007-complete-fetch-attempt.json", {
      vector_id: "privacy-tiers/complete-fetch-attempt",
      spec_refs: ["§6.7.2", "§6.9.1", "§14.3"],
      description: "A complete fetch attempt queries the full configured relay set and repo-relay set before declaring a Tier 3 page missing.",
      input: {
        relay_set: ["wss://relay-a", "wss://relay-b"],
        repo_relay_set: ["wss://node-a.example/relay"],
        queried: ["wss://relay-a", "wss://relay-b", "wss://node-a.example/relay"],
      },
      expected_output: { verdict: "accept", normalized: { complete_fetch_attempt: true, queried_all_backends: true } },
    }),
    produced(
      "privacy-tiers/008-tier3-kind31012-audience-roster.json",
      {
        vector_id: "privacy-tiers/tier3-kind31012-audience-roster",
        spec_refs: ["§6.7.4", "§7.2", "§14.3"],
        description: "Tier 3 kind:31012 audience roster: an epoch-key-signed replaceable event keyed by key_id enumerating the recipient npubs with one p tag each.",
        input: {
          fixture_persona: "alice",
          signer: "epoch_1",
          key_id: audA.key_id,
          recipients: [bob.cold_root.pubkey, carol.cold_root.pubkey],
          aux_rand: AUX_RAND,
        },
        notes: "The roster and the per-recipient kind:31011 wraps share the same key_id.",
      },
      roster,
    ),
    consumeVector("privacy-tiers/009-non-circular-bootstrap.json", {
      vector_id: "privacy-tiers/non-circular-bootstrap",
      spec_refs: ["§6.7.4", "§7.3", "§14.3"],
      description: "A new member locates the encrypted object and their wrapped audience key from clear data alone (opaque key_id, the recipient-addressed kind:31011, and kind:31005/kind:31010 routing), with no Matrix dependency.",
      input: {
        key_id: audA.key_id,
        kind31011_present: true,
        routing: { kind31005_rid: rid, kind31010_hosts: ["wss://node-a.example/relay"] },
        matrix_available: false,
      },
      expected_output: {
        verdict: "accept",
        normalized: {
          bootstrap: "non_circular",
          located_from_clear: ["key_id", "kind:31011", "kind:31005", "kind:31010"],
          matrix_required: false,
        },
      },
      decision_trace: [
        "locate_key_id",
        "find_kind31011_for_recipient",
        "resolve_rid_and_hosts",
        "unwrap_audience_key",
        "fetch_encrypted_object",
      ],
    }),
    consumeVector("privacy-tiers/010-audience-key-rotation-on-removal.json", {
      vector_id: "privacy-tiers/audience-key-rotation-on-removal",
      spec_refs: ["§6.7.4", "§6.10", "§14.3"],
      description: "Removing a member rotates the audience key to a fresh key_id, republishes the kind:31012 roster, and redistributes via kind:31011; the removed member cannot read post-removal content but retains content wrapped under the prior key_id.",
      input: {
        removed_member: carol.cold_root.pubkey,
        prior_key_id: audA.key_id,
        new_key_id: audB.key_id,
        remaining_roster: [bob.cold_root.pubkey],
        rotated_within_seconds: 60,
      },
      expected_output: {
        verdict: "accept",
        normalized: {
          rotated: true,
          new_key_id: audB.key_id,
          removed_member_reads_future: false,
          removed_member_reads_past: true,
          kind31012_republished: true,
          kind31011_redistributed: true,
        },
      },
    }),
  );

  return vectors;
}
