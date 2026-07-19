import { describe, expect, it } from "vitest";
import { buildFixtures } from "./fixtures.js";
import { verifyEventSignature } from "./nostr.js";
import { buildSplitVectors, validateInviteResponseProfileFixture } from "./topics-split.js";
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
    ["profiles/core-breadcrumb-kind0", "heterodyne:core/0.5.0#core-version-stamps"],
    ["profiles/tier3-kind-6", "heterodyne:comms/0.5.0#comms-tier-three-profile"],
    ["profiles/dr-invite-response-kind1059", "heterodyne:comms/0.5.0#comms-dm-wire"],
    ["profiles/comms-payload-kind31016", "heterodyne:comms/0.5.0#comms-subprotocol-negotiation"],
    ["profiles/social-org-feed-kind31007", "heterodyne:social/0.5.0#social-org-feed-profile"],
    ["lists/mute-list-public-roundtrip-v050", "heterodyne:social/0.5.0#social-mute-profile"],
    ["stamping/control-profile-retains-core-owner", "heterodyne:control/0.5.0#control-session-device-profile"],
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
});
