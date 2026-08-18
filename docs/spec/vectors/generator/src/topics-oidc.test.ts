import { describe, expect, it } from "vitest";
import { validateControlTokenUse, type TokenUseInput } from "./control-profile.js";
import { buildFixtures } from "./fixtures.js";
import { buildControlVectors } from "./topics-control.js";
import { buildOidcVectors } from "./topics-oidc.js";

function decodeJwtPart(compact: string, index: number): Record<string, unknown> {
  const encoded = compact.split(".")[index];
  if (encoded === undefined) throw new Error("malformed compact JWT fixture");
  return JSON.parse(Buffer.from(encoded, "base64url").toString("utf8")) as Record<string, unknown>;
}

describe("OIDC and node-scoped Control vector ownership", () => {
  it("keeps third-party OIDC JWT semantics in Comms", async () => {
    const vectors = await buildOidcVectors(buildFixtures());
    expect(vectors.every(({ vector }) =>
      vector.owner_document === "comms"
      && vector.spec_refs.every((reference) => reference.includes("#comms-")),
    )).toBe(true);

    const access = vectors.find(({ vector }) =>
      vector.vector_id === "oidc/rfc9068-access-token-valid",
    )?.vector;
    if (access === undefined) throw new Error("missing RFC 9068 OIDC vector");
    const compact = access.input.compact;
    if (typeof compact !== "string") throw new Error("missing compact JWT fixture");
    const header = decodeJwtPart(compact, 0);
    const claims = decodeJwtPart(compact, 1);

    expect(header.typ).toBe("at+jwt");
    expect(claims.aud).toEqual(["https://api.example"]);
    for (const controlClaim of [
      "group_id", "authorization_id", "methods", "objects", "limits", "agent_role",
    ]) {
      expect(claims).not.toHaveProperty(controlClaim);
    }
  }, 30_000);

  it("assigns every node-scoped token vector to the Control token contract", () => {
    const tokenVectors = buildControlVectors().filter(({ vector }) =>
      vector.vector_id.startsWith("control/token-"),
    );
    expect(tokenVectors.length).toBeGreaterThan(0);
    for (const { vector } of tokenVectors) {
      expect(vector.owner_document).toBe("control");
      expect(vector.spec_refs).toEqual(["heterodyne:0.5.0#control-token"]);
    }
  });

  it("enforces the Control token sixty-minute ceiling during validation", () => {
    const vector = buildControlVectors().find(({ vector }) =>
      vector.vector_id === "control/token-valid",
    )?.vector;
    if (vector === undefined) throw new Error("missing valid Control token vector");
    const input = structuredClone(vector.input) as unknown as TokenUseInput;
    input.token.exp = input.token.iat + 3_601;

    expect(validateControlTokenUse(input)).toEqual({
      verdict: "reject",
      reason_code: "control-token-invalid",
    });
  });
});
