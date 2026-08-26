import { nip44 } from "nostr-tools";
import { describe, expect, it } from "vitest";
import { buildFixtures } from "./snapshot-fixtures-adapter.js";
import { hexToBytes } from "./hex.js";
import {
  validateClaimEnvelope,
  validateClaimRevocationEnvelope,
  verifyClaimChain,
  type ClaimAuthorityEvidence,
  type ClaimSemanticBody,
  type RevocationAuthorityEvidence,
} from "./snapshot-claims-adapter.js";
import { verifyEventSignature, type NostrSignedEvent } from "./nostr.js";
import { buildSnapshotClaimVectors } from "./snapshot-topic-runtime.js";

const fixtures = buildFixtures();
const credentialLedger = {
  credential_ledger_persona: fixtures.personas.alice.cold_root.pubkey,
  credential_ledger_generation: 0,
};

describe("normative claim vector authoring", () => {
  it("authors exactly the 20 named Comms vectors with closed visibility carriers", async () => {
    const vectors = await buildSnapshotClaimVectors(fixtures);
    expect(vectors.map(({ relativePath }) => relativePath)).toEqual([
      "claims/001-canonical-nostr-subject.json",
      "claims/002-canonical-radicle-nid-subject.json",
      "claims/003-canonical-jwk-thumbprint-subject.json",
      "claims/004-claim-id-mismatch.json",
      "claims/005-persona-issuance-active.json",
      "claims/006-delegated-issuance-active.json",
      "claims/007-third-party-issuer-untrusted.json",
      "claims/008-chain-attenuation-valid.json",
      "claims/009-chain-widening-rejected.json",
      "claims/010-chain-depth-exceeded.json",
      "claims/011-subject-proof-valid.json",
      "claims/012-copied-proof-rejected.json",
      "claims/013-provisional-authorization-denied.json",
      "claims/014-repository-confirmed-active.json",
      "claims/015-authorization-self-revocation.json",
      "claims/016-descriptive-subject-rejection.json",
      "claims/017-public-claim-publication.json",
      "claims/018-pairwise-private-marmot-delivery.json",
      "claims/019-repository-private-encryption.json",
      "claims/020-local-only-no-publication.json",
    ]);
    expect(vectors.every(({ vector }) =>
      vector.owner_document === "comms" &&
      vector.spec_version === "heterodyne/0.5.0" &&
      vector.spec_refs.every((ref) => ref.startsWith("heterodyne:0.5.0#")),
    )).toBe(true);

    const byId = new Map(vectors.map(({ vector }) => [vector.vector_id, vector]));
    const claimMutations = byId.get("claims/canonical-nostr-subject")!
      .input.rejection_mutations as Array<{ name: string; event: NostrSignedEvent; reason_code: string }>;
    expect(claimMutations.map(({ name }) => name)).toEqual([
      "extra-tag-after", "extra-tag-before", "duplicate-d", "malformed-d", "misordered-d",
      "missing-spec-version", "legacy-comms-version", "wrong-spec-version",
    ]);
    for (const mutation of claimMutations) {
      expect(verifyEventSignature(mutation.event)).toBe(true);
      expect(mutation.reason_code).toBe("claim-schema-invalid");
      expect(() => validateClaimEnvelope(mutation.event, {
        issuer_authorized: true,
        profile_revision: 2,
        credential_ledger: credentialLedger,
      })).toThrow(/claim-schema-invalid/);
    }
    const revocationMutations = byId.get("claims/authorization-self-revocation")!
      .input.rejection_mutations as Array<{ name: string; event: NostrSignedEvent; reason_code: string }>;
    expect(revocationMutations).toHaveLength(10);
    expect(revocationMutations.map(({ name }) => name)).toEqual([
      "revocation-extra-tag-after", "revocation-extra-tag-before", "revocation-duplicate-d",
      "revocation-malformed-d", "revocation-misordered-d", "missing-spec-version",
      "legacy-comms-version", "missing-profile-revision", "wrong-spec-version",
      "wrong-profile-revision",
    ]);
    const jwkMutations = byId.get("claims/canonical-jwk-thumbprint-subject")!
      .input.jwk_rejection_mutations as Array<{
        name: string;
        event: NostrSignedEvent;
        reason_code: string;
      }>;
    expect(jwkMutations.map(({ name }) => name)).toEqual([
      "missing-protected-alg",
      "extra-protected-member",
      "none-protected-alg",
      "hmac-protected-alg",
      "extra-jwk-member",
      "wrong-jwk-alg",
      "wrong-jwk-kid",
    ]);
    for (const mutation of jwkMutations) {
      expect(verifyEventSignature(mutation.event)).toBe(true);
      expect(() => validateClaimRevocationEnvelope(mutation.event)).toThrow();
      expect(["claim-schema-invalid", "claim-key-reference-invalid", "claim-subject-proof-invalid"])
        .toContain(mutation.reason_code);
    }
    for (const mutation of revocationMutations) {
      expect(verifyEventSignature(mutation.event)).toBe(true);
      expect(mutation.reason_code).toBe("claim-schema-invalid");
      expect(() => validateClaimRevocationEnvelope(mutation.event)).toThrow(/claim-schema-invalid/);
    }
    const pairwise = byId.get("claims/pairwise-private-marmot-delivery")!;
    const marmotGroup = pairwise.input.marmot_group as {
      member_accounts: string[];
      application_event: NostrSignedEvent;
      outer_kind: number;
      outer_claim_metadata_fields: string[];
    };
    expect(marmotGroup.member_accounts).toHaveLength(2);
    expect(marmotGroup.outer_kind).toBe(445);
    expect(marmotGroup.outer_claim_metadata_fields).toEqual([]);
    const carriedClaimEvent = JSON.parse(marmotGroup.application_event.content) as NostrSignedEvent;
    expect(carriedClaimEvent.kind).toBe(31013);
    expect(verifyEventSignature(carriedClaimEvent)).toBe(true);
    const repository = byId.get("claims/repository-private-encryption")!;
    const repositoryClaimId = (repository.expected_output.normalized as { inner_claim_id: string }).inner_claim_id;
    const repositoryMetadata = JSON.stringify({
      commit: repository.input.commit,
      tree: repository.input.tree,
      rid: repository.input.rid,
      branch: repository.input.branch,
    });
    expect(repositoryMetadata).not.toContain(repositoryClaimId);
    expect(repositoryMetadata).not.toContain("heterodyne.device");
    expect(repositoryMetadata).not.toContain("claim-ledger-reader");
    expect(JSON.stringify(repository.input.blobs)).not.toContain(repositoryClaimId);
    const encryptedBlob = Object.values(repository.input.blobs as Record<string, string>)[0];
    const repositoryEvent = JSON.parse(nip44.v2.decrypt(
      encryptedBlob,
      hexToBytes(repository.input.fixture_audience_key as string),
    )) as NostrSignedEvent;
    expect(repositoryEvent.kind).toBe(31013);
    expect(verifyEventSignature(repositoryEvent)).toBe(true);
    expect((byId.get("claims/local-only-no-publication")!.expected_output.normalized as { transport_artifacts: unknown[] }).transport_artifacts).toEqual([]);
    const localInput = byId.get("claims/local-only-no-publication")!.input;
    expect(localInput).not.toHaveProperty("valid_signed_event");
    expect(localInput).not.toHaveProperty("canonical_wire");
    expect((byId.get("claims/persona-issuance-active")!.input.vector_context as { decision_trace: string[] }).decision_trace).toHaveLength(8);
    const personaVector = byId.get("claims/persona-issuance-active")!;
    expect((personaVector.input.claim_authority_evidence as ClaimAuthorityEvidence[])[0].event_id)
      .toBe((personaVector.input.event as NostrSignedEvent).id);

    const cycleVector = byId.get("claims/chain-depth-exceeded")!;
    const cycleCase = (cycleVector.input.cases as Array<{
      name: string;
      leaf_claim_id: string;
      claims_by_id: Record<string, ClaimSemanticBody>;
    }>).find(({ name }) => name === "cycle")!;
    const cycleMap = new Map(Object.entries(cycleCase.claims_by_id));
    expect(() => verifyClaimChain(cycleMap.get(cycleCase.leaf_claim_id)!, cycleMap))
      .toThrow(/claim-chain-cycle/);

    const jwkRevocation = byId.get("claims/canonical-jwk-thumbprint-subject")!
      .input.positive_native_revocation_event as NostrSignedEvent;
    expect(validateClaimRevocationEnvelope(jwkRevocation).signer.type).toBe("jwk-thumbprint");
    const authorizationRoles = byId.get("claims/authorization-self-revocation")!
      .input.role_cases as Array<{
        role: string;
        event: NostrSignedEvent;
        authority_evidence: RevocationAuthorityEvidence | null;
        persona_cold_root: string | null;
        expected_authorized: boolean;
      }>;
    expect(authorizationRoles).toHaveLength(6);
    expect(authorizationRoles.filter(({ expected_authorized }) => expected_authorized)).toHaveLength(5);
    expect(authorizationRoles.every(({ event }) => validateClaimRevocationEnvelope(event).event_id === event.id)).toBe(true);
    const personaEpochRole = authorizationRoles.find(({ role }) => role === "persona-epoch")!;
    expect(personaEpochRole.event.pubkey).toBe(fixtures.personas.alice.epoch_keys.epoch_1.pubkey);
    expect(personaEpochRole.authority_evidence).toMatchObject({
      signer: { type: "nostr-secp256k1", value: fixtures.personas.alice.epoch_keys.epoch_1.pubkey },
      authority: "persona-epoch",
    });
    expect(personaEpochRole.persona_cold_root).toBe(fixtures.personas.alice.cold_root.pubkey);
    expect(new Map([
      ["claims/canonical-nostr-subject", "heterodyne-comms-key-claim-nostr-bip340-v1"],
      ["claims/canonical-radicle-nid-subject", "heterodyne-comms-key-claim-radicle-ed25519-v1"],
      ["claims/subject-proof-valid", "heterodyne-comms-key-claim-jwk-jws-v1"],
      ["claims/canonical-jwk-thumbprint-subject", "heterodyne-comms-claim-revocation-jwk-jws-v1"],
      ["claims/authorization-self-revocation", "heterodyne-comms-claim-revocation-nostr-bip340-v1"],
      ["claims/descriptive-subject-rejection", "heterodyne-comms-claim-revocation-radicle-ed25519-v1"],
    ])).toEqual(new Map(
      [...byId.values()].filter(({ profile }) => profile !== undefined).map(({ vector_id, profile }) => [vector_id, profile!]),
    ));
  });
});
