import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { loadRegistry } from "./registry.js";
import { inferLegacyOwner, stampOwner, type StampInput } from "./stamping.js";

const here = dirname(fileURLToPath(import.meta.url));
const registry = loadRegistry(resolve(here, "../../../../../"));

const input = (overrides: Partial<StampInput>): StampInput => ({
  kind: 31001,
  content_is_heterodyne_json: true,
  is_dr_outer: false,
  ...overrides,
});

describe("registry-driven owner stamping", () => {
  it.each([
    ["kind:31001 base", input({}), "core"],
    [
      "kind:31001 inactive Control profile retains Core",
      input({ profile_id: "heterodyne-control-session-device-v1" }),
      "core",
    ],
    [
      "registered Social NIP-51 profile",
      input({ kind: 10000, profile_id: "heterodyne-social-mute-list-v1" }),
      "social",
    ],
    ["plain upstream NIP-51", input({ kind: 10000 }), null],
    [
      "registered Tier-3 wrapped upstream profile",
      input({
        kind: 1,
        profile_id: "heterodyne-comms-tier3-wrapped-content-kind-1-v1",
        content_is_heterodyne_json: false,
      }),
      "comms",
    ],
    [
      "non-stamping Core breadcrumb",
      input({
        kind: 0,
        profile_id: "heterodyne-core-rotation-breadcrumb-profile-v1",
      }),
      null,
    ],
    [
      "double-ratchet outer kind:1060",
      input({
        kind: 1060,
        profile_id: "heterodyne-comms-double-ratchet-message-v1",
        is_dr_outer: true,
      }),
      null,
    ],
    [
      "Control carrier rumor retains Comms owner",
      input({ kind: 31016, profile_id: "comms-subprotocol-payload-v1" }),
      "comms",
    ],
    ["unknown kind", input({ kind: 65535 }), null],
    ["unknown profile on allocated kind", input({ profile_id: "unknown-profile" }), null],
    ["empty or non-JSON allocated kind uses owner tag", input({ content_is_heterodyne_json: false }), "core"],
  ])("classifies %s", (_name, stampInput, expected) => {
    expect(stampOwner(stampInput as StampInput, registry)).toBe(expected);
  });

  it("scopes legacy inference to archived monolith forms", () => {
    expect(
      inferLegacyOwner({ kind: 31001, stamp: "0.4.0", adopted_upstream: false,
        archived_form_valid: true, post_split_discriminator: false, profile_only: false }),
    ).toBe("monolith/0.4.0");
    expect(
      inferLegacyOwner({ kind: 31007, adopted_upstream: false,
        archived_form_valid: true, post_split_discriminator: false, profile_only: false }),
    ).toBe("monolith/0.4.0");
    expect(() =>
      inferLegacyOwner({ kind: 1, adopted_upstream: true,
        archived_form_valid: true, post_split_discriminator: false, profile_only: false }),
    ).toThrow("not inferable");
    expect(() =>
      inferLegacyOwner({ kind: 31006, adopted_upstream: false,
        archived_form_valid: true, post_split_discriminator: false, profile_only: false }),
    ).toThrow("not inferable");
    expect(() =>
      inferLegacyOwner({ kind: 31001, stamp: "core/0.5.0", adopted_upstream: false,
        archived_form_valid: true, post_split_discriminator: false, profile_only: false }),
    ).toThrow("not inferable");
  });

  it.each([
    ["malformed archived form", { archived_form_valid: false }],
    ["post-split discriminator", { post_split_discriminator: true }],
    ["profile-only form", { profile_only: true }],
    ["adopted upstream form", { adopted_upstream: true }],
  ])("does not infer an unstamped %s", (_name, overrides) => {
    expect(() => inferLegacyOwner({
      kind: 31001,
      adopted_upstream: false,
      archived_form_valid: true,
      post_split_discriminator: false,
      profile_only: false,
      ...overrides,
    })).toThrow("not inferable");
  });
});
