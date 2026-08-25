import { createHash } from "node:crypto";
import { nip19 } from "nostr-tools";
import { describe, expect, it } from "vitest";
import { buildFixtures } from "./fixtures.js";
import { utf8Bytes } from "./hex.js";
import { jcsCanonicalize } from "./jcs.js";
import { OIDC_RSA_ONE } from "./oidc-rsa-fixtures.js";
import {
  buildContinuityTree,
  createContinuityAuthorityProof,
  createPersonaSuccessionProof,
  type ContinuityManifest,
  type ContinuityManifestBody,
} from "./token-status.js";

const fixtures = buildFixtures();
const personaKey = fixtures.personas.alice.epoch_keys.epoch_1.pubkey;
const personaNpub = nip19.npubEncode(personaKey);
const jwksBytes = utf8Bytes(JSON.stringify({ keys: [OIDC_RSA_ONE.public_jwk] }));
const sha256 = (value: Uint8Array) => createHash("sha256").update(value).digest("hex");

function manifestBody(): ContinuityManifestBody {
  return {
    profile: "heterodyne-oidc-continuity-v1",
    repository_rid: fixtures.radicle_rids.alice,
    branch: "main",
    persona_npub: personaNpub,
    persona_key: personaKey,
    issuer: `https://node.example/oidc/${personaNpub}`,
    sequence: 0,
    predecessor_digest: null,
    max_checkpoint_age_seconds: 300,
    current_jwks_sha256: sha256(jwksBytes),
    current_signing_key_id: OIDC_RSA_ONE.key_id,
    current_signing_jwk_sha256: sha256(utf8Bytes(jcsCanonicalize(OIDC_RSA_ONE.public_jwk))),
    retiring_signing_key_ids: [],
    retiring_jwks_sha256: [],
    status_lists: [],
    successor: null,
    authority: {
      writer_nid: fixtures.ed25519_nids.alice_device_1.did_key,
      issued_at: fixtures.test_epoch,
      checkpoint: {
        repository_rid: fixtures.radicle_rids.alice,
        branch: "main",
        commit_oid: "11".repeat(32),
        observed_at: fixtures.test_epoch,
      },
    },
  };
}

describe("active-persona OIDC continuity material", () => {
  it("materializes a closed tree under the active persona npub", () => {
    const body = manifestBody();
    const manifest: ContinuityManifest = {
      ...body,
      authority_proof: createContinuityAuthorityProof(
        body,
        fixtures.ed25519_nids.alice_device_1.private_key,
      ),
    };
    const tree = buildContinuityTree(
      manifest,
      { issuer: manifest.issuer },
      jwksBytes,
      new Map(),
    );
    expect([...tree.keys()].sort()).toEqual([
      `.well-known/${personaNpub}/issuer.json`,
      `.well-known/${personaNpub}/jwks.json`,
      `.well-known/${personaNpub}/manifest.json`,
      `.well-known/${personaNpub}/openid-configuration`,
    ]);
  });

  it("creates successor authorization only in the active-persona class", () => {
    const proof = createPersonaSuccessionProof(
      manifestBody(),
      "active-persona",
      fixtures.personas.alice.epoch_keys.epoch_1.private_key,
    );
    expect(proof).toMatchObject({ authority: "active-persona", signer_pubkey: personaKey });
  });
});
