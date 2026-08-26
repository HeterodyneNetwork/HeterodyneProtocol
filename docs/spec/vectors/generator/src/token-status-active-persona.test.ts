import { createHash } from "node:crypto";
import { nip19 } from "nostr-tools";
import { describe, expect, it } from "vitest";
import { buildFixtures } from "./fixtures.js";
import { utf8Bytes } from "./hex.js";
import { jcsCanonicalize } from "./jcs.js";
import { OIDC_RSA_ONE } from "./oidc-rsa-fixtures.js";
import { buildClaimLedgerScenario } from "./claim-ledger-test-support.js";
import {
  buildContinuityTree,
  continuityManifestDigest,
  continuitySuccessorDigest,
  createContinuityAuthorityProof,
  createPersonaSuccessionProof,
  resolveIssuerContinuity,
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

  it("rejects an unrelated active-key proof even when the supplied authority window names that key", async () => {
    const scenario = await buildClaimLedgerScenario(fixtures);
    const authorityCheckpoint = scenario.issuerKeyEpochOneState.checkpoint;
    const base = {
      ...manifestBody(),
      current_signing_key_id: scenario.issuerKeyEnvelopeOne.signing_key_id,
      authority: {
        writer_nid: scenario.writerOne.did_key,
        issued_at: authorityCheckpoint.observed_at,
        checkpoint: authorityCheckpoint,
      },
    };
    const successorIssuer = base.issuer.replace("node.example", "successor.example");
    const commitmentBody = {
      ...base,
      issuer: successorIssuer,
      sequence: 1,
      predecessor_digest: "00".repeat(32),
    };
    const commitment: ContinuityManifest = {
      ...commitmentBody,
      authority_proof: createContinuityAuthorityProof(
        commitmentBody,
        scenario.writerOne.private_key,
      ),
    };
    const previousBody = {
      ...base,
      successor: {
        issuer: successorIssuer,
        manifest_sha256: continuitySuccessorDigest(commitment),
      },
    };
    const previous: ContinuityManifest = {
      ...previousBody,
      authority_proof: createContinuityAuthorityProof(
        previousBody,
        scenario.writerOne.private_key,
      ),
    };
    const candidateBody = {
      ...base,
      issuer: successorIssuer,
      sequence: 1,
      predecessor_digest: continuityManifestDigest(previous),
    };
    const candidate: ContinuityManifest = {
      ...candidateBody,
      authority_proof: createContinuityAuthorityProof(
        candidateBody,
        scenario.writerOne.private_key,
      ),
    };
    const context = {
      identity: { persona_npub: personaNpub, persona_key: personaKey },
      repository_rid: scenario.rid,
      canonical_branch: "main" as const,
      writer_nid: scenario.writerOne.did_key,
      now: authorityCheckpoint.observed_at,
      ledger_state: scenario.issuerKeyEpochOneState,
      succession_authority: createPersonaSuccessionProof(
        candidate,
        "active-persona",
        fixtures.personas.alice.epoch_keys.epoch_1.private_key,
      ),
      active_persona_authority: {
        persona_key: personaKey,
        valid_from: authorityCheckpoint.observed_at,
        valid_until: authorityCheckpoint.observed_at + 300,
      },
    };

    expect(resolveIssuerContinuity(previous, candidate, context)).toMatchObject({
      allowed: true,
      standard_oidc_action: "register-successor",
    });

    const unrelatedKey = fixtures.personas.carol.epoch_keys.epoch_1.pubkey;
    const unrelatedContext = {
      ...context,
      succession_authority: createPersonaSuccessionProof(
        candidate,
        "active-persona",
        fixtures.personas.carol.epoch_keys.epoch_1.private_key,
      ),
      active_persona_authority: {
        ...context.active_persona_authority,
        persona_key: unrelatedKey,
      },
    };
    expect(resolveIssuerContinuity(previous, candidate, unrelatedContext)).toMatchObject({
      allowed: false,
      reason_code: "oidc-issuer-authority-invalid",
    });
  });
});
