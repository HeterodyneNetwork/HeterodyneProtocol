import { nip19 } from "nostr-tools";
import { describe, expect, it } from "vitest";
import { buildFixtures } from "./fixtures.js";
import {
  discoveryPaths,
  issuerMetadata,
  issuerUrl,
  validateIssuerMetadata,
  validatePersonaBinding,
  type PersonaIdentityState,
} from "./oidc.js";

const fixtures = buildFixtures();
const personaKey = fixtures.personas.alice.epoch_keys.epoch_1.pubkey;
const personaNpub = nip19.npubEncode(personaKey);
const identity: PersonaIdentityState = {
  persona_key: personaKey,
  persona_npub: personaNpub,
};

describe("active-persona OIDC issuer identity", () => {
  it("uses the active persona npub as the exact issuer path", () => {
    const issuer = issuerUrl("https://node.example", personaNpub, identity);
    expect(issuer).toBe(`https://node.example/oidc/${personaNpub}`);
    expect(discoveryPaths("https://node.example", personaNpub, identity)).toEqual({
      issuer,
      oidc_discovery: `${issuer}/.well-known/openid-configuration`,
      rfc8414_alias:
        `https://node.example/.well-known/oauth-authorization-server/oidc/${personaNpub}`,
    });
  });

  it("rejects a legacy root or any npub not bound to the active persona key", () => {
    const legacyRoot = nip19.npubEncode(fixtures.personas.alice.cold_root.pubkey);
    expect(validatePersonaBinding(personaNpub, identity)).toMatchObject({ allowed: true });
    expect(validatePersonaBinding(legacyRoot, identity)).toMatchObject({ allowed: false });
    expect(() => issuerUrl("https://node.example", legacyRoot, identity))
      .toThrow(/active persona/i);
  });

  it("round-trips only metadata derived from the active persona issuer", () => {
    const metadata = issuerMetadata("https://node.example", personaNpub, identity);
    expect(validateIssuerMetadata(metadata, metadata.issuer, metadata.jwks_uri))
      .toMatchObject({ allowed: true });
    expect(validateIssuerMetadata(
      { ...metadata, issuer: `${metadata.issuer}-alias` },
      metadata.issuer,
      metadata.jwks_uri,
    )).toMatchObject({ allowed: false });
  });
});
