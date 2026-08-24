import { Ajv2020 } from "ajv/dist/2020.js";
import { describe, expect, it } from "vitest";
import personaProfileSchema from "../../../schemas/core/persona-profile-v1.schema.json" with { type: "json" };

const ajv = new Ajv2020({ allErrors: true, strict: true });
const validatePersonaProfile = ajv.compile(personaProfileSchema);
const CANONICAL_RID = "rad:z2TJoDAhK5pTmLzqmK9W4FMdtjyy1";
const CANONICAL_NADDR =
  "naddr1qvzqqqr4gupzqyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3qyw8wumn8ghj7ctyv3ex2umn94ex2mrp0yhx27rpd4cxcef0qqrkzun5d93kceguqvdyu";

describe("kind-0 Heterodyne extension schema", () => {
  it("accepts a canonical profile RID inside an otherwise ordinary upstream kind-0 object", () => {
    expect(validatePersonaProfile({
      name: "Ada",
      arbitrary_upstream_field: { preserved: true },
      heterodyne: { profile: CANONICAL_RID },
    })).toBe(true);
  });

  it("accepts an ordinary upstream kind-0 object with no Heterodyne extension", () => {
    expect(validatePersonaProfile({ name: "Ada", another_client_field: 7 })).toBe(true);
  });

  it("accepts every optional extension hint in its canonical representation", () => {
    expect(validatePersonaProfile({
      heterodyne: {
        profile: CANONICAL_RID,
        identity_chain: CANONICAL_NADDR,
        cold_root: "ab".repeat(32),
        succession_authority: "cd".repeat(32),
      },
    })).toBe(true);
  });

  it.each([
    ["missing profile", { heterodyne: {} }],
    ["unknown extension member", { heterodyne: { profile: CANONICAL_RID, authority: "extra" } }],
    ["invalid RID", { heterodyne: { profile: "rad:z0malformed" } }],
    ["invalid naddr", { heterodyne: { profile: CANONICAL_RID, identity_chain: "naddr1invalid" } }],
    ["uppercase cold root", { heterodyne: { profile: CANONICAL_RID, cold_root: "AB".repeat(32) } }],
    ["uppercase succession authority", {
      heterodyne: { profile: CANONICAL_RID, succession_authority: "CD".repeat(32) },
    }],
  ])("rejects the %s", (_name, value) => {
    expect(validatePersonaProfile(value)).toBe(false);
  });
});
