import { describe, expect, it } from "vitest";
import { QUALIFIED_VERSION } from "./family.js";
import { getPublicKey, signEvent } from "./nostr.js";
import * as corePolicy from "./core-policy.js";
import {
  evaluateCoreOperationalBoundary,
  validateCorePersonaSignedEvent,
  validateCoreWireEnvelope,
} from "./core-policy.js";

const SECRET = "31".repeat(32);
const AUX_RAND = "00".repeat(32);

describe("current Core semantic boundaries", () => {
  it("rejects an authenticated event whose author is not the active persona key", async () => {
    const event = await signEvent({
      secretKey: SECRET,
      created_at: 1_800_000_000,
      kind: 1,
      tags: [["spec_version", QUALIFIED_VERSION]],
      content: "active persona binding",
      auxRand: AUX_RAND,
    });
    expect(validateCorePersonaSignedEvent({
      event,
      nip01_raw: JSON.stringify([
        0,
        event.pubkey,
        event.created_at,
        event.kind,
        event.tags,
        event.content,
      ]),
      stamp_policy: "required",
      active_persona_key: getPublicKey("32".repeat(32)),
    })).toEqual({ verdict: "reject", reason_code: "delegation_mismatch" });
  });

  it("validates raw NIP-01 bytes and exact current version stamps", async () => {
    const event = await signEvent({
      secretKey: SECRET,
      created_at: 1_800_000_000,
      kind: 1,
      tags: [["spec_version", QUALIFIED_VERSION]],
      content: "core policy",
      auxRand: AUX_RAND,
    });
    expect(validateCoreWireEnvelope({ event, nip01_raw: "[]", stamp_policy: "required" }))
      .toEqual({ verdict: "reject", reason_code: "nip01_raw_mismatch" });
    const future = await signEvent({
      secretKey: SECRET,
      created_at: event.created_at,
      kind: event.kind,
      tags: [["spec_version", "heterodyne/1.0.0"]],
      content: event.content,
      auxRand: AUX_RAND,
    });
    expect(validateCoreWireEnvelope({
      event: future,
      nip01_raw: JSON.stringify([0, future.pubkey, future.created_at, future.kind, future.tags, future.content]),
      stamp_policy: "required",
    })).toEqual({ verdict: "reject", reason_code: "unknown_major_version" });
  });

  it("enforces transport, cache, relay, and publication boundaries", () => {
    expect(evaluateCoreOperationalBoundary({ operation: "resolve-host", host: "hidden.onion", resolver: "clearnet" }))
      .toEqual({ verdict: "reject", reason_code: "onion_dns_leak" });
    expect(evaluateCoreOperationalBoundary({ operation: "start-strict-mode", tor_egress: false, explicit_user_choice: false }))
      .toEqual({ verdict: "reject", reason_code: "strict_mode_tor_disabled" });
    expect(evaluateCoreOperationalBoundary({ operation: "read-friend-cache", owner_signed: false, content_class: "nostr" }))
      .toEqual({ verdict: "reject", reason_code: "unauthorized_cache_content" });
    expect(evaluateCoreOperationalBoundary({ operation: "relay-profile", vanilla_nip01_unchanged: false }))
      .toEqual({ verdict: "reject", reason_code: "relay_profile_mutation" });
    expect(evaluateCoreOperationalBoundary({ operation: "publish-surface", config_rid: "rad:zConfigRid", values: ["rad:zConfigRid"] }))
      .toEqual({ verdict: "reject", reason_code: "config_rid_advertised" });
  });

  it("BLUE TEAM VALIDATION: synthetic/local retired authority is not callable from current Core", () => {
    // BLUE TEAM VALIDATION: inspect only the local compiled module export surface.
    expect(Object.keys(corePolicy)).not.toContain("validateOrganizationMemberAddition");
    expect(Object.keys(corePolicy)).not.toContain("validateRoleDelegation");
  });
});
