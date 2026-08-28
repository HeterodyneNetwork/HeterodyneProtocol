import { describe, expect, it } from "vitest";
import { QUALIFIED_VERSION } from "./family.js";
import { getPublicKey, signEvent } from "./nostr.js";
import {
  evaluateCoreOperationalBoundary,
  validateCoreWireEnvelope,
  validateOrganizationMemberAddition,
  validateRoleDelegation,
} from "./core-policy.js";

const SECRET = "31".repeat(32);
const AUX_RAND = "00".repeat(32);

describe("current Core semantic boundaries", () => {
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

  it("requires both organization authorities and exact role proofs", () => {
    expect(validateOrganizationMemberAddition({ member_kel_authorized: true, org_admin_threshold_authorized: false }))
      .toEqual({ verdict: "reject", reason_code: "org_member_add_unauthorized" });
    expect(validateRoleDelegation({ namespace: "wrong", registered_namespace: "workspace.role", role_id: "maintainer", key_proof_valid: true }))
      .toEqual({ verdict: "reject", reason_code: "role-delegation-address-invalid" });
    expect(validateRoleDelegation({ namespace: "workspace.role", registered_namespace: "workspace.role", role_id: "maintainer", key_proof_valid: false }))
      .toEqual({ verdict: "reject", reason_code: "role-delegation-key-proof-invalid" });
    expect(validateRoleDelegation({ namespace: "workspace.role", registered_namespace: "workspace.role", role_id: "maintainer", key_proof_valid: true }))
      .toMatchObject({ verdict: "accept", role_id: "maintainer" });
    expect(getPublicKey(SECRET)).toMatch(/^[0-9a-f]{64}$/);
  });
});
