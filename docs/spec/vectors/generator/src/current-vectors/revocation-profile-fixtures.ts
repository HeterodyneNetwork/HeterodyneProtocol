import { ed25519 } from "@noble/curves/ed25519";
import {
  buildLedgerRepositoryEvidence,
  type LedgerRecord,
  type LedgerValidationContext,
  type ReaderAccessRequest,
  type RevocationArtifact,
} from "../claim-ledger.js";
import type { ClaimLedgerScenario } from "../claim-ledger-test-support.js";
import {
  CLAIM_REVOCATION_PROFILE,
  computeJwkThumbprint,
  revocationProofPayload,
  type ClaimRevocation,
  type ClaimSemanticBody,
  type ClaimVerificationContext,
  type JsonValue,
  type VerifiedClaimArtifact,
} from "../claims.js";
import { snapshotClosedDataTree } from "../closed-data.js";
import { bytesToHex, hexToBytes, utf8Bytes } from "../hex.js";
import { jcsCanonicalize } from "../jcs.js";
import { signEvent } from "../nostr.js";
import { AUX_RAND } from "../vector-helpers.js";

export type CurrentRevocationProofSuite =
  | "nostr-bip340"
  | "radicle-ed25519"
  | "jwk-jws";

export type CurrentRevocationExecutionFixture = Readonly<{
  left: readonly LedgerRecord[];
  right: readonly LedgerRecord[];
  checkpoint: Parameters<typeof buildLedgerRepositoryEvidence>[0] extends never
    ? never
    : ReturnType<typeof buildLedgerRepositoryEvidence>["checkpoint"];
  context: LedgerValidationContext;
  reader_nid?: string;
  reader_request?: ReaderAccessRequest;
  target_verified_claim?: VerifiedClaimArtifact;
  target_verification_context?: ClaimVerificationContext;
}>;

export type CurrentRevocationProfileFixture = Readonly<{
  artifact: RevocationArtifact;
  execution: CurrentRevocationExecutionFixture;
}>;

function revocationArtifactFromRecord(record: LedgerRecord): RevocationArtifact {
  const payload = record.payload as unknown as {
    revocation_artifact: RevocationArtifact;
  };
  return payload.revocation_artifact;
}

async function signedArtifact(
  ledger: ClaimLedgerScenario,
  semantic: ClaimRevocation,
): Promise<RevocationArtifact> {
  const event = await signEvent({
    secretKey: ledger.issuer.private_key,
    auxRand: AUX_RAND,
    created_at: semantic.revoked_at,
    kind: 31014,
    tags: [["d", semantic.claim_id]],
    content: jcsCanonicalize(semantic),
  });
  return snapshotClosedDataTree({
    event,
    semantic: semantic as unknown as JsonValue,
  } satisfies RevocationArtifact, "current revocation profile artifact");
}

function withRevocationEvidence(
  context: LedgerValidationContext,
  record: LedgerRecord,
  claimsById: ReadonlyMap<string, ClaimSemanticBody>,
  verification: ClaimVerificationContext,
): LedgerValidationContext {
  context.record_evidence.set(record.record_id, {
    record_id: record.record_id,
    payload_digest: record.payload_digest,
    claims_by_id: new Map(claimsById),
    claim_verification_context: verification,
  });
  return context;
}

async function readerRevocationFixture(
  ledger: ClaimLedgerScenario,
  suite: "nostr-bip340" | "radicle-ed25519",
): Promise<CurrentRevocationProfileFixture> {
  let artifact: RevocationArtifact;
  if (suite === "nostr-bip340") {
    artifact = snapshotClosedDataTree(
      revocationArtifactFromRecord(ledger.revocationRecord),
      "current Nostr revocation profile artifact",
    );
  } else {
    const unsigned = {
      ...CLAIM_REVOCATION_PROFILE,
      claim_id: ledger.claimOne.artifact.semantic.claim_id,
      revoked_at: ledger.now + 30,
      reason_code: "claim-revoked",
    };
    const semantic: ClaimRevocation = {
      ...unsigned,
      revoker: {
        type: "radicle-ed25519-nid",
        value: ledger.writerOne.did_key,
      },
      proof: {
        type: "radicle-ed25519",
        public_key: ledger.writerOne.public_key,
        signature: bytesToHex(ed25519.sign(
          revocationProofPayload(unsigned),
          hexToBytes(ledger.writerOne.private_key),
        )),
      },
    };
    artifact = await signedArtifact(ledger, semantic);
  }
  const revocationRecord = ledger.signRecord(
    "revocation",
    { revocation_artifact: artifact } as unknown as JsonValue,
    ledger.writerTwo,
    [ledger.claimRecordOne.record_id],
    ledger.now + 31,
  );
  const left = [ledger.claimRecordOne, ledger.claimRecordTwo, ledger.grantOne];
  const right = [ledger.claimRecordOne, ledger.claimRecordTwo, revocationRecord];
  const repository = buildLedgerRepositoryEvidence({
    repository_rid: ledger.rid,
    confirmed_records: [...left, revocationRecord],
    observed_at: ledger.now + 60,
    prior: ledger.baseRepository.repository,
  });
  const verification = ledger.makeVerification(ledger.claimOne);
  verification.now = repository.checkpoint.observed_at;
  const context = withRevocationEvidence(
    ledger.makeContext(repository.repository),
    revocationRecord,
    ledger.allClaims,
    verification,
  );
  const request = ledger.requestFor(ledger.claimRecordOne, ledger.claimOne);
  request.verification_context.now = repository.checkpoint.observed_at;
  return {
    artifact,
    execution: {
      left,
      right,
      checkpoint: repository.checkpoint,
      context,
      reader_nid: ledger.writerOne.did_key,
      reader_request: request,
    },
  };
}

async function jwkRevocationFixture(
  ledger: ClaimLedgerScenario,
): Promise<CurrentRevocationProfileFixture> {
  const publicJwk: Record<string, JsonValue> = {
    crv: "Ed25519",
    kty: "OKP",
    x: Buffer.from(ledger.writerOne.public_key, "hex").toString("base64url"),
  };
  const revoker = {
    type: "jwk-thumbprint" as const,
    value: computeJwkThumbprint(publicJwk),
  };
  const target = await ledger.makeClaim(ledger.writerOne, {
    claim_class: "descriptive",
    credential_ledger_persona: null,
    credential_ledger_generation: null,
    namespace: "heterodyne.current-profile",
    name: "revocation-proof",
    value: "jwk-jws",
    revokers: [revoker],
  });
  const targetRecord = ledger.signRecord(
    "claim",
    { claim_artifact: target.artifact } as unknown as JsonValue,
    ledger.writerOne,
  );
  const unsigned = {
    ...CLAIM_REVOCATION_PROFILE,
    claim_id: target.artifact.semantic.claim_id,
    revoked_at: ledger.now + 30,
    reason_code: "claim-revoked",
  };
  const protectedHeader = Buffer.from(jcsCanonicalize({ alg: "EdDSA" }), "utf8")
    .toString("base64url");
  const signingInput = utf8Bytes(
    `${protectedHeader}.${Buffer.from(revocationProofPayload(unsigned)).toString("base64url")}`,
  );
  const semantic: ClaimRevocation = {
    ...unsigned,
    revoker,
    proof: {
      type: "jwk-jws",
      jwk: publicJwk,
      protected: protectedHeader,
      signature: Buffer.from(ed25519.sign(
        signingInput,
        hexToBytes(ledger.writerOne.private_key),
      )).toString("base64url"),
    },
  };
  const artifact = await signedArtifact(ledger, semantic);
  const revocationRecord = ledger.signRecord(
    "revocation",
    { revocation_artifact: artifact } as unknown as JsonValue,
    ledger.writerTwo,
    [targetRecord.record_id],
    ledger.now + 31,
  );
  const left = [targetRecord];
  const right = [targetRecord, revocationRecord];
  const repository = buildLedgerRepositoryEvidence({
    repository_rid: ledger.rid,
    confirmed_records: right,
    observed_at: ledger.now + 60,
  });
  const verification = ledger.makeVerification(target);
  verification.now = repository.checkpoint.observed_at;
  verification.repository_confirmed = new Set([target.artifact.semantic.claim_id]);
  const claimsById = new Map([
    [target.artifact.semantic.claim_id, target.artifact.semantic],
  ]);
  const context = ledger.makeContext(repository.repository);
  context.record_evidence.set(targetRecord.record_id, {
    record_id: targetRecord.record_id,
    payload_digest: targetRecord.payload_digest,
    claim_envelope_context: {
      profile_revision: 2,
      credential_ledger: {
        credential_ledger_persona: ledger.persona,
        credential_ledger_generation: 0,
      },
    },
    claims_by_id: claimsById,
    claim_verification_context: verification,
  });
  withRevocationEvidence(
    context,
    revocationRecord,
    claimsById,
    verification,
  );
  return {
    artifact,
    execution: {
      left,
      right,
      checkpoint: repository.checkpoint,
      context,
      target_verified_claim: target.verified_artifact,
      target_verification_context: verification,
    },
  };
}

export async function buildCurrentRevocationProfileFixtures(
  ledger: ClaimLedgerScenario,
): Promise<ReadonlyMap<CurrentRevocationProofSuite, CurrentRevocationProfileFixture>> {
  return new Map([
    ["nostr-bip340", await readerRevocationFixture(ledger, "nostr-bip340")],
    ["radicle-ed25519", await readerRevocationFixture(ledger, "radicle-ed25519")],
    ["jwk-jws", await jwkRevocationFixture(ledger)],
  ]);
}
