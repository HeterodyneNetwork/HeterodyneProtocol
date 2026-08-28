import { sha256 } from "@noble/hashes/sha2";
import * as claimLedger from "../claim-ledger.js";
import * as claims from "../claims.js";
import { snapshotClosedDataTree } from "../closed-data.js";
import { bytesToHex, utf8Bytes } from "../hex.js";
import { jcsCanonicalize } from "../jcs.js";
import { currentProfileOracleForVector } from "./profile-oracles.js";
import type {
  CurrentRevocationExecutionFixture,
  CurrentRevocationProofSuite,
} from "./revocation-profile-fixtures.js";

type RevocationArtifact = Readonly<{
  event: Parameters<typeof claims.validateClaimRevocationEnvelope>[0];
  semantic: claims.ClaimRevocation;
}>;

type RevocationRecord = claimLedger.LedgerRecord & Readonly<{
  payload: Readonly<{ revocation_artifact: RevocationArtifact }>;
}>;

function reject(reasonCode: string): Readonly<{
  raw_result: Readonly<{ verdict: "reject"; reason_code: string }>;
  projected_output: Readonly<{ verdict: "reject"; reason_code: string }>;
}> {
  const result = Object.freeze({ verdict: "reject" as const, reason_code: reasonCode });
  return { raw_result: result, projected_output: result };
}

function reasonFromError(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  return message.match(/^([a-z][a-z0-9_-]*)(?::|$)/u)?.[1]
    ?? "claim-subject-proof-invalid";
}

function proofSuite(semantic: claims.ClaimRevocation): CurrentRevocationProofSuite | null {
  if (semantic.revoker.type === "nostr-secp256k1" && semantic.proof === undefined) {
    return "nostr-bip340";
  }
  if (semantic.proof?.type === "radicle-ed25519") return "radicle-ed25519";
  if (semantic.proof?.type === "jwk-jws") return "jwk-jws";
  return null;
}

function freezeExistingTree(value: unknown): void {
  if (value === null || typeof value !== "object" || Object.isFrozen(value)) return;
  for (const member of Object.values(value)) freezeExistingTree(member);
  Object.freeze(value);
}

function freezeExactArtifact(value: unknown): Readonly<{
  artifact: RevocationArtifact;
  artifact_digest: string;
}> {
  const snapshot = snapshotClosedDataTree(value, "current revocation profile artifact");
  const canonical = jcsCanonicalize(snapshot);
  if (jcsCanonicalize(value) !== canonical) {
    throw new Error("claim-id-mismatch: revocation artifact changed during snapshot");
  }
  freezeExistingTree(value);
  if (jcsCanonicalize(value) !== canonical) {
    throw new Error("claim-id-mismatch: frozen revocation artifact differs from snapshot");
  }
  return {
    artifact: value as RevocationArtifact,
    artifact_digest: bytesToHex(sha256(utf8Bytes(
      "heterodyne-current-revocation-artifact-v1\0" + canonical,
    ))),
  };
}

function exactRevocationSemantic(
  verified: claims.VerifiedRevocation,
): claims.ClaimRevocation {
  const {
    signer: _signer,
    event_id: _eventId,
    event_created_at: _eventCreatedAt,
    ...semantic
  } = verified;
  return semantic;
}

function revocationRecord(
  execution: CurrentRevocationExecutionFixture,
): RevocationRecord | null {
  const record = execution.right.find(({ record_type }) => record_type === "revocation");
  if (
    record === undefined
    || record.payload === null
    || typeof record.payload !== "object"
    || Array.isArray(record.payload)
    || !("revocation_artifact" in record.payload)
  ) return null;
  return record as RevocationRecord;
}

/**
 * Validates the exact row-fixed proof artifact and passes that same frozen
 * record into the canonical ledger merge before applying its fixed effect.
 */
export function evaluateCurrentRevocationProfile(
  vectorId: string,
  input: Readonly<Record<string, unknown>>,
  execution: CurrentRevocationExecutionFixture,
): Readonly<{ raw_result: unknown; projected_output: unknown }> {
  const expectation = currentProfileOracleForVector(vectorId)?.claim_proof_expectation;
  if (expectation?.purpose !== "claim-revoker") {
    return reject("claim-subject-proof-invalid");
  }
  if (["proof_purpose", "proof_suite", "message"].some((member) =>
    Object.hasOwn(input, member)
  )) return reject("claim-subject-proof-invalid");
  const record = revocationRecord(execution);
  if (record === null) return reject("claim-subject-proof-invalid");
  const recordArtifact = record.payload.revocation_artifact;
  if (input.revocation_artifact !== recordArtifact) {
    return reject("claim-subject-proof-invalid");
  }

  try {
    const frozen = freezeExactArtifact(recordArtifact);
    const artifact = frozen.artifact;
    if (proofSuite(artifact.semantic) !== expectation.suite) {
      return reject("claim-subject-proof-invalid");
    }
    const verified = claims.validateClaimRevocationEnvelope(artifact.event);
    if (
      jcsCanonicalize(exactRevocationSemantic(verified))
      !== jcsCanonicalize(artifact.semantic)
    ) return reject("claim-id-mismatch");
    const proofPayloadDigest = bytesToHex(sha256(
      claims.revocationProofPayload(artifact.semantic),
    ));
    const state = claimLedger.mergeClaimLedger(
      [...execution.left],
      [...execution.right],
      execution.checkpoint,
      execution.context,
    );
    const mergedRecord = state.records.find(({ record_id }) =>
      record_id === record.record_id
    );
    if (mergedRecord !== record) {
      return reject("claim-repository-unconfirmed");
    }
    const mergedArtifact = (mergedRecord as RevocationRecord)
      .payload.revocation_artifact;
    if (mergedArtifact !== artifact) return reject("claim-repository-conflict");

    let effect:
      | Readonly<{ kind: "reader-denied"; result: ReturnType<typeof claimLedger.evaluateReaderAccess> }>
      | Readonly<{ kind: "descriptive-claim-revoked"; result: ReturnType<typeof claims.authorizeWithClaim> }>;
    if (expectation.suite === "jwk-jws") {
      if (
        execution.target_claim === undefined
        || execution.target_verification_context === undefined
      ) return reject("claim-revoker-unauthorized");
      const decision = claims.authorizeWithClaim(
        execution.target_claim,
        [execution.target_claim],
        {
          ...execution.target_verification_context,
          now: state.checkpoint.observed_at,
          revocations: state.authenticated_revocations ?? [],
        },
      );
      if (decision.state !== "revoked" || decision.reason_code !== "claim-revoked") {
        return reject("claim-revoker-unauthorized");
      }
      effect = { kind: "descriptive-claim-revoked", result: decision };
    } else {
      if (execution.reader_nid === undefined || execution.reader_request === undefined) {
        return reject("claim-revoker-unauthorized");
      }
      const decision = claimLedger.evaluateReaderAccess(
        execution.reader_nid,
        state,
        execution.reader_request,
      );
      if (
        decision.allowed
        || decision.state !== "revoked"
        || decision.reason_code !== "claim-revoked"
      ) return reject("claim-revoker-unauthorized");
      effect = { kind: "reader-denied", result: decision };
    }
    const artifactDigestAfterMerge = bytesToHex(sha256(utf8Bytes(
      "heterodyne-current-revocation-artifact-v1\0"
        + jcsCanonicalize(mergedArtifact),
    )));
    if (artifactDigestAfterMerge !== frozen.artifact_digest) {
      return reject("claim-repository-conflict");
    }
    const revocationEvidence = Object.freeze({
      expected_suite: expectation.suite,
      expected_purpose: expectation.purpose,
      artifact_object_identity: input.revocation_artifact === record.payload.revocation_artifact,
      merged_record_object_identity: mergedRecord === record,
      merged_artifact_object_identity: mergedArtifact === artifact,
      artifact_digest: frozen.artifact_digest,
      artifact_digest_after_merge: artifactDigestAfterMerge,
      proof_payload_digest: proofPayloadDigest,
      verified_event_id: verified.event_id,
      merged_record_id: record.record_id,
      irreversible_effect: effect.kind,
    });
    const raw = Object.freeze({
      verdict: "accept" as const,
      verified,
      state,
      effect,
      revocation_evidence: revocationEvidence,
    });
    return {
      raw_result: raw,
      projected_output: Object.freeze({
        verdict: "accept" as const,
        proof_suite: expectation.suite,
        proof_purpose: expectation.purpose,
        revocation_event_id: verified.event_id,
        irreversible_effect: effect.kind,
        effect_result: effect.result,
      }),
    };
  } catch (error) {
    return reject(reasonFromError(error));
  }
}
