import { describe, expect, it } from "vitest";
import { buildFixtures } from "./fixtures.js";
import { verifyEventSignature } from "./nostr.js";
import { buildSplitVectors, validateInviteResponseProfileFixture } from "./topics-split.js";
import { buildKeriAuthorityWireVectors } from "./topics-keri-authority.js";
import { buildAllVectors } from "./topics.js";
import { vectorMetadata } from "./vector-metadata.js";

const fixtures = buildFixtures();
const vectors = await buildSplitVectors(fixtures);
const byId = (id: string) => vectors.find(({ vector }) => vector.vector_id === id)!.vector;

describe("split remediation wire and hook contracts", () => {
  it("uses exact Comms hook contexts, outcomes, and authenticated credential preconditions", () => {
    const expected = new Map([
      ["acceptance-gating/established-ordinary-accept", ["ordinary-dm", "accept"]],
      ["acceptance-gating/new-ordinary-hold", ["ordinary-dm", "hold-as-message-request"]],
      ["acceptance-gating/credential-valid-accept", ["credential-sync", "accept"]],
      ["acceptance-gating/authoritative-state-unavailable-hold", ["credential-sync", "hold-as-message-request"]],
      ["acceptance-gating/credential-invalid-reject", ["credential-sync", "reject"]],
      ["acceptance-gating/credential-revoked-reject", ["credential-sync", "reject"]],
      ["acceptance-gating/credential-expired-reject", ["credential-sync", "reject"]],
      ["acceptance-gating/credential-subject-mismatch-reject", ["credential-sync", "reject"]],
      ["acceptance-gating/credential-nidless-reject", ["credential-sync", "reject"]],
      ["acceptance-gating/control-enrollment-default-hold", ["control-enrollment", "hold-as-message-request"]],
    ]);
    for (const [id, [context, outcome]] of expected) {
      const vector = byId(id);
      expect(vector.input.context).toBe(context);
      expect((vector.expected_output.normalized as Record<string, unknown>).outcome).toBe(outcome);
      expect(vector.input).toEqual(expect.objectContaining({
        peer_persona_cold_root: expect.any(String),
        peer_device_publishing_key: expect.any(String),
        peer_delegation_id: expect.any(String),
        session_id: expect.any(String),
        transcript_binding: expect.any(String),
        protocol_id: expect.any(String),
        requested_features: expect.any(Array),
        active_delegation: expect.any(Boolean),
        finality: expect.any(String),
        revoked: expect.any(Boolean),
      }));
      if (id.includes("credential-")) expect(vector.input.authenticated).toBe(true);
    }
  });

  it("uses session-authenticated device publishing keys and 16-byte negotiation ids", () => {
    for (const id of [
      "comms-envelope/owner-stamp-valid",
      "profiles/comms-negotiation-kind31015",
      "profiles/comms-payload-kind31016",
    ]) {
      const rumor = byId(id).input.rumor as Record<string, unknown>;
      expect(rumor.pubkey).toBe(fixtures.device_publishing_keys.alice_device_1.pubkey);
      expect(rumor.tags).toEqual([["p", fixtures.device_publishing_keys.bob_device_1.pubkey]]);
      expect((JSON.parse(rumor.content as string).negotiation_id as string)).toMatch(/^[0-9a-f]{32}$/);
    }
  });

  it.each([
    ["profiles/core-breadcrumb-kind0", "heterodyne:core/0.5.0#core-kel-rotation"],
    ["profiles/tier3-kind-6", "heterodyne:comms/0.5.0#comms-tier-three-profile"],
    ["profiles/dr-invite-response-kind1059", "heterodyne:comms/0.5.0#comms-dm-wire"],
    ["profiles/comms-payload-kind31016", "heterodyne:comms/0.5.0#comms-subprotocol-negotiation"],
    ["profiles/social-org-feed-kind31007", "heterodyne:social/0.5.0#social-org-feed-profile"],
    ["lists/mute-list-public-roundtrip-v050", "heterodyne:social/0.5.0#social-mute-profile"],
    ["stamping/control-profile-retains-core-owner", "heterodyne:core/0.5.0#core-version-stamps"],
  ])("anchors %s at its concrete profile section", (id, ref) => {
    expect(vectorMetadata(id).spec_refs).toContain(ref);
  });

  it("authors a complete deterministic transient kind:1059 pinned-wire response", () => {
    const vector = byId("profiles/dr-invite-response-kind1059");
    const event = vector.input.event as Parameters<typeof verifyEventSignature>[0];
    expect(event.kind).toBe(1059);
    expect(event.id).toHaveLength(64);
    expect(event.sig).toHaveLength(128);
    expect(event.content.length).toBeGreaterThan(100);
    expect(verifyEventSignature(event)).toBe(true);
    expect(vector.expected_output.normalized).toEqual(expect.objectContaining({
      repo_storable: false,
      backfill: false,
      relay_carriage: "transient",
    }));
    expect(() => validateInviteResponseProfileFixture(vector)).not.toThrow();
    expect(() => validateInviteResponseProfileFixture({
      ...vector,
      input: { ...vector.input, event: { ...event, sig: undefined } },
    })).toThrow(/complete signed/);
    expect(() => validateInviteResponseProfileFixture({
      ...vector,
      expected_output: { normalized: { ...(vector.expected_output.normalized as object), repo_storable: true } },
    })).toThrow(/transient/);
  });

  it("recognizes ADR-031 v1 profiles only from a trusted same-persona producer workflow", () => {
    for (const id of ["profiles/core-breadcrumb-kind0", "profiles/core-breadcrumb-kind1"]) {
      const vector = byId(id);
      expect(vector.direction).toBe("produce");
      expect(vector.input).not.toHaveProperty("role");
      expect(vector.input).not.toHaveProperty("profile_id");
      expect(vector.input).toEqual(expect.objectContaining({
        trusted_rotation_context: expect.objectContaining({
          prior_kel_accepted: true,
          routine_rotation_accepted: true,
          same_persona: true,
          retiring_epoch_key: expect.any(String),
          successor_epoch_key: expect.any(String),
          nip65_write_relays: ["wss://relay.example"],
          kel_accepted_at: expect.any(Number),
          retiring_secret_destroyed_at: expect.any(Number),
        }),
        candidate_event: expect.objectContaining({
          pubkey: expect.any(String),
          kind: expect.any(Number),
          id: expect.any(String),
          sig: expect.any(String),
        }),
        publication_relays: ["wss://relay.example"],
      }));
      expect(vector.expected_output.normalized).toEqual(expect.objectContaining({
        classification_source: "trusted-local-producer-workflow",
        same_persona: true,
        emitted_after_kel_acceptance: true,
        emitted_before_secret_destruction: true,
      }));
      expect(vector.spec_refs).toEqual([
        "heterodyne:core/0.5.0#core-kel-rotation",
      ]);
    }

    const profile = byId("profiles/core-breadcrumb-kind0");
    const profileEvent = profile.input.candidate_event as { content: string; tags: string[][] };
    const content = JSON.parse(profileEvent.content) as Record<string, unknown>;
    expect(content.about).toMatch(/npub1/);
    expect(content.website).toMatch(/npub1/);
    expect(content.nip05).toBeUndefined();
    expect(profileEvent.tags.some((tag) => tag[0] === "kel_head")).toBe(false);
  });

  it.each([
    ["breadcrumbs/unrelated-successor-rejected", "successor_persona_mismatch"],
    ["breadcrumbs/compromise-rotation-not-produced", "compromise_rotation"],
    ["breadcrumbs/repointed-nip05-rejected", "retiring_key_nip05_invalid"],
  ])("rejects invalid producer context in %s", (id, reasonCode) => {
    const vector = byId(id);
    expect(vector.direction).toBe("produce");
    expect(vector.input).not.toHaveProperty("role");
    expect(vector.expected_output).toEqual({
      verdict: "reject",
      reason_code: reasonCode,
    });
  });

  it("consumes unstamped kind:0/1 as ordinary Nostr without inferring a v1 profile", () => {
    const vector = byId("breadcrumbs/ordinary-consumer-no-profile-inference");
    expect(vector.direction).toBe("consume");
    expect(vector.input).toEqual({
      event: expect.objectContaining({
        kind: 0,
        tags: expect.not.arrayContaining([expect.arrayContaining(["kel_head"])]),
      }),
    });
    expect(vector.input).not.toHaveProperty("role");
    expect(vector.input).not.toHaveProperty("profile_id");
    expect(vector.input).not.toHaveProperty("expected_identity");
    expect(vector.expected_output.normalized).toEqual({
      signature_valid: true,
      authority: "nip01-signature-only",
      inferred_heterodyne_profile: null,
      kel_succession: false,
    });
  });

  it("removes the hidden breadcrumb-role oracle from KEL-head wire vectors", async () => {
    const wireVectors = await buildKeriAuthorityWireVectors(fixtures);
    const formerHiddenOracle = wireVectors.find(
      ({ vector }) => vector.vector_id === "keri-authority/kel-head-forbidden-on-breadcrumb",
    );
    expect(formerHiddenOracle).toBeUndefined();
  });

  it("makes vanilla Nostr authors first-class Social follow targets", async () => {
    const allVectors = await buildAllVectors(fixtures);
    const vector = allVectors.find(
      ({ vector: candidate }) => candidate.vector_id === "interop/vanilla-nostr-only-follow",
    )!.vector;
    expect(vectorMetadata(vector.vector_id).spec_refs).toContain(
      "heterodyne:social/0.5.0#social-following",
    );
    expect(vector.input).toEqual(expect.objectContaining({
      nip01_signature_valid: true,
      nip65_write_relays: expect.any(Array),
      follow_change_requested_by_user: true,
      breadcrumb_claimed_successor: null,
    }));
    expect(vector.expected_output.normalized).toEqual({
      follow_target: "vanilla-nostr-author",
      authority: "nip01-signature-only",
      presentation: "external-reduced-assurance",
      subscription_source: "nip65",
      dm_fallback: "nip17-reduced-assurance",
      automatic_refollow: false,
    });
  });

  it("validates the exact session-device shape without opening its revision-3 gate", () => {
    const vector = byId("session-device/reserved-shape-valid-but-gated");
    expect(vector.registry_revision).toBe(3);
    const event = vector.input.event as {
      kind: number;
      content: string;
      tags: string[][];
      id: string;
      sig: string;
    };
    expect(event.kind).toBe(31001);
    expect(event.content).toBe("");
    expect(event.id).toHaveLength(64);
    expect(event.sig).toHaveLength(128);
    expect(event.tags).toEqual([
      ["d", expect.stringMatching(/^pubkey:[0-9a-f]{64}$/)],
      ["heterodyne", "delegation"],
      ["publishing_key", expect.stringMatching(/^[0-9a-f]{64}$/)],
      ["cold_root", expect.stringMatching(/^[0-9a-f]{64}$/)],
      ["valid_until", expect.stringMatching(/^[1-9][0-9]*$/)],
      ["binding_nonce", expect.stringMatching(/^[0-9a-f]{64}$/)],
      ["kel_head", expect.stringMatching(/^[0-9a-f]{64}$/), "0"],
      ["key_proof", expect.stringMatching(/^[0-9a-f]{128}$/)],
      ["spec_version", "core/0.5.0"],
    ]);
    expect(event.tags.some((tag) => tag[0] === "radicle_nid" || tag[0] === "nid_proof")).toBe(false);
    expect(vector.expected_output.normalized).toEqual({
      base_owner: "core",
      profile_state: "reserved-inactive",
      schema_valid: true,
      key_proof_valid: true,
      relay_state: "provisional",
      repository_final: false,
      control_authority: false,
      conformance_claimable: false,
    });
  });

  it.each([
    [
      "session-device/nid-fields-forbidden",
      "nid_fields_forbidden",
      "role-delegation-address-invalid",
    ],
    [
      "session-device/key-proof-invalid",
      "key_proof_invalid",
      "bad_signature",
    ],
  ])("rejects malformed reserved session shape in %s", (id, validationError, reasonCode) => {
    const vector = byId(id);
    expect(vector.expected_output).toEqual({
      verdict: "reject",
      reason_code: reasonCode,
      validation_error: validationError,
      conformance_claimable: false,
    });
  });

  it("distinguishes repository finality from the still-closed profile gate", () => {
    const vector = byId("session-device/repository-final-gate-closed");
    expect(vector.input).toEqual(expect.objectContaining({
      relay_valid: true,
      repository_reachable: true,
      profile_gate_open: false,
      comms_authorization_state: "active",
    }));
    expect(vector.expected_output.normalized).toEqual({
      repository_final: true,
      delegation_state: "final-but-gated",
      control_authority: false,
      conformance_claimable: false,
    });
  });

  it("refuses to produce the candidate without the Core owner stamp", () => {
    const vector = byId("session-device/owner-stamp-missing");
    const event = vector.input.event as { tags: string[][] };
    expect(vector.direction).toBe("produce");
    expect(event.tags.some((tag) => tag[0] === "spec_version")).toBe(false);
    expect(vector.expected_output).toEqual({
      verdict: "reject",
      reason_code: "owner_stamp_missing",
      conformance_claimable: false,
    });
  });

  it.each([
    ["session-device/live-challenge-binding-valid", "live-challenge"],
    ["session-device/one-time-token-binding-valid", "one-time-token"],
  ])("binds the candidate nonce to authenticated enrollment state in %s", (id, source) => {
    const vector = byId(id);
    expect(vector.input.enrollment_binding).toEqual(expect.objectContaining({
      source,
      authenticated_session: true,
      unexpired: true,
    }));
    expect(vector.expected_output.normalized).toEqual(expect.objectContaining({
      binding_valid: true,
      binding_source: source,
      control_authority: false,
      conformance_claimable: false,
    }));
  });

  it("makes revocation authoritative even for a repository-final candidate", () => {
    const vector = byId("session-device/revoked-no-authority");
    expect(vector.input).toEqual(expect.objectContaining({
      repository_final: true,
      delegation_revoked: true,
    }));
    expect(vector.expected_output.normalized).toEqual({
      delegation_state: "revoked",
      control_authority: false,
      conformance_claimable: false,
    });
  });

  it.each([
    ["acceptance-gating/control-enrollment-active-invite-gated-hold", "control-enrollment", false, "hold-as-message-request"],
    ["acceptance-gating/control-enrollment-stale-invite-reject", "control-enrollment", false, "reject"],
    ["acceptance-gating/control-enrollment-tombstoned-invite-reject", "control-enrollment", false, "reject"],
    ["acceptance-gating/ordinary-undelegated-reject", "ordinary-dm", false, "reject"],
  ])("enforces the epoch-invite undelegated carve-out in %s", (id, context, delegated, outcome) => {
    const vector = byId(id);
    expect(vector.registry_revision).toBe(3);
    expect(vector.input).toEqual(expect.objectContaining({
      context,
      active_delegation: delegated,
      epoch_invite_event_id: expect.any(String),
      current_epoch_invite_event_id: expect.any(String),
    }));
    expect((vector.expected_output.normalized as Record<string, unknown>).outcome).toBe(outcome);
    if (id.includes("gated-hold")) {
      expect(vector.expected_output.normalized).toEqual(expect.objectContaining({
        control_interpretation_allowed: false,
        sender_visible_signals: 0,
      }));
    }
  });

  it("does not rewrite the historical revision of the earlier default-hold vector", () => {
    expect(
      byId("acceptance-gating/control-enrollment-default-hold").registry_revision,
    ).toBe(1);
  });
});
