import { createHash } from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519";
import { describe, expect, it } from "vitest";
import {
  evaluateCredentialGeneration,
  purgePriorGenerationTransactions,
  type CredentialLedgerBinding,
} from "./credential-generation.js";
import {
  createSignedLedgerRecord,
  type LedgerRecord,
} from "./claim-ledger.js";
import { bytesToHex } from "./hex.js";
import { jcsCanonicalize } from "./jcs.js";
import { didKeyFromEd25519 } from "./radicle.js";
import {
  validateClaimLedgerRecordSchemaOrThrow,
  validateKeyClaimSchemaOrThrow,
  validateOidcIssuanceRecordSchemaOrThrow,
} from "./schema.js";

const PERSONA = "11".repeat(32);
const CURRENT: CredentialLedgerBinding = {
  credential_ledger_persona: PERSONA,
  credential_ledger_generation: 4,
};

describe("credential-ledger generation binding", () => {
  it("gives a missing generation precedence over a recognizable empty roster", () => {
    expect(evaluateCredentialGeneration({
      credential_ledger_persona: PERSONA,
      node_roster: [],
    }, CURRENT)).toEqual({
      valid: false,
      reason_code: "credential_generation_missing",
    });
  });

  it("keeps wrong-typed generation and roster inputs in the generic schema result", () => {
    expect(evaluateCredentialGeneration({
      credential_ledger_persona: PERSONA,
      credential_ledger_generation: "4",
      node_roster: [],
    }, CURRENT)).toEqual({
      valid: false,
      reason_code: "credential_schema_invalid",
    });
    expect(evaluateCredentialGeneration({
      ...CURRENT,
      node_roster: "not-an-array",
    }, CURRENT)).toEqual({
      valid: false,
      reason_code: "credential_schema_invalid",
    });
  });

  it("orders persona, generation, KEL, checkpoint, and reset failures after structural validation", () => {
    expect(evaluateCredentialGeneration({
      ...CURRENT,
      credential_ledger_persona: "22".repeat(32),
    }, CURRENT, {
      current_kel: false,
      checkpoint_valid: false,
      reset_valid: false,
    }).reason_code).toBe("credential_ledger_persona_mismatch");

    expect(evaluateCredentialGeneration({
      ...CURRENT,
      credential_ledger_generation: CURRENT.credential_ledger_generation - 1,
    }, CURRENT, {
      current_kel: false,
      checkpoint_valid: false,
      reset_valid: false,
    }).reason_code).toBe("credential_generation_stale");

    expect(evaluateCredentialGeneration(CURRENT, CURRENT, {
      current_kel: false,
      checkpoint_valid: false,
      reset_valid: false,
    }).reason_code).toBe("credential_checkpoint_stale_kel");
    expect(evaluateCredentialGeneration(CURRENT, CURRENT, {
      checkpoint_valid: false,
      reset_valid: false,
    }).reason_code).toBe("credential_checkpoint_invalid");
    expect(evaluateCredentialGeneration(CURRENT, CURRENT, {
      reset_valid: false,
    }).reason_code).toBe("credential_reset_invalid");
  });

  it("purges every prior-generation transaction while preserving only exact-current bindings", () => {
    const transactions = [
      { id: "code-old", ...CURRENT, credential_ledger_generation: 3 },
      { id: "device-old-denied", ...CURRENT, credential_ledger_generation: 3 },
      { id: "code-current", ...CURRENT },
      { id: "other-persona", ...CURRENT, credential_ledger_persona: "22".repeat(32) },
    ];
    expect(purgePriorGenerationTransactions(transactions, CURRENT)).toEqual({
      retained: [transactions[2]],
      purged_ids: ["code-old", "device-old-denied", "other-persona"],
      requires_authority_reissue: true,
      requires_status_reissue: true,
    });
  });

});

describe("claim-ledger domain-separated identifiers", () => {
  it("hashes payload and complete signed record under the accepted zero-separated domains", () => {
    const secretKey = "33".repeat(32);
    const writerNid = didKeyFromEd25519(bytesToHex(ed25519.getPublicKey(secretKey)));
    const record = createSignedLedgerRecord({
      record_type: "status-invalidation",
      persona: PERSONA,
      credential_ledger_generation: 4,
      writer_nid: writerNid,
      created_at: 10,
      parents: [],
      payload: {
        cause: "signing-key-compromised",
        jti: "credential-jti-0001",
        signing_key_id: "A".repeat(43),
        compromise_evidence: {
          detected_at: 9,
          evidence_digest: "44".repeat(32),
        },
        writer_authority_claim_id: "55".repeat(32),
        authority_checkpoint: {
          repository_rid: "rad:z111111111111111111111111111111111",
          branch: "main",
          commit_oid: "66".repeat(32),
          observed_at: 8,
        },
        issuer_key_epoch: 1,
        issuer_key_digest: "B".repeat(43),
      },
    }, secretKey);

    const payloadDigest = createHash("sha256")
      .update("heterodyne-claim-ledger-payload-v1", "utf8")
      .update(Uint8Array.of(0))
      .update(jcsCanonicalize(record.payload), "utf8")
      .digest("hex");
    expect(record.payload_digest).toBe(payloadDigest);

    const { record_id: _recordId, ...withoutId } = record;
    const recordId = createHash("sha256")
      .update("heterodyne-claim-ledger-record-id-v1", "utf8")
      .update(Uint8Array.of(0))
      .update(jcsCanonicalize(withoutId), "utf8")
      .digest("hex");
    expect(record.record_id).toBe(recordId);
  });

  it("places generation in the signed record while leaving the payload digest payload-only", () => {
    const record = {
      record_id: "00".repeat(32),
      record_type: "status-invalidation",
      persona: PERSONA,
      credential_ledger_generation: 4,
      writer_nid: "did:key:z6Mkh",
      created_at: 1,
      parents: [],
      payload: { value: true },
      payload_digest: "11".repeat(32),
      signature: "22".repeat(64),
    } satisfies LedgerRecord;
    expect("credential_ledger_generation" in record.payload).toBe(false);
    expect(record.credential_ledger_generation).toBe(4);
  });
});

describe("existing credential-bearing schemas", () => {
  const claimBody = {
    claim_id: "aa".repeat(32),
    issuer: { type: "nostr-secp256k1", value: "bb".repeat(32) },
    subject: { type: "nostr-secp256k1", value: "cc".repeat(32) },
    claim_class: "authorization",
    credential_ledger_persona: PERSONA,
    credential_ledger_generation: 4,
    namespace: "heterodyne.device",
    name: "claim-ledger-reader",
    value: true,
    issued_at: 1,
    not_before: 1,
    expires_at: 2,
    audience: ["reader"],
    resources: ["ledger"],
    visibility: "repository-private",
    spec_version: "heterodyne/0.6.0",
    profile_revision: 2,
  };

  it("requires exact persona/generation fields in all decoded key-claim content profiles", () => {
    expect(() => validateKeyClaimSchemaOrThrow(claimBody)).not.toThrow();
    expect(() => validateKeyClaimSchemaOrThrow({
      ...claimBody,
      credential_ledger_generation: undefined,
    })).toThrow(/credential_ledger_generation|required/);
    const descriptive = {
      ...claimBody,
      claim_class: "descriptive",
      credential_ledger_persona: null,
      credential_ledger_generation: null,
    };
    delete (descriptive as Partial<typeof descriptive>).expires_at;
    expect(() => validateKeyClaimSchemaOrThrow(descriptive)).not.toThrow();
    expect(() => validateKeyClaimSchemaOrThrow({
      ...claimBody,
      claim_class: "descriptive",
    })).toThrow(/credential_ledger/);
  });

  it("requires the claim-ledger record generation outside the payload", () => {
    const record = {
      record_id: "aa".repeat(32),
      record_type: "status-invalidation",
      persona: PERSONA,
      credential_ledger_generation: 4,
      writer_nid: "did:key:z6Mkh",
      created_at: 1,
      parents: [],
      payload: {
        cause: "signing-key-compromised",
        jti: "credential-jti-0001",
        signing_key_id: "A".repeat(43),
        compromise_evidence: { detected_at: 1, evidence_digest: "bb".repeat(32) },
        writer_authority_claim_id: "cc".repeat(32),
        authority_checkpoint: {
          repository_rid: "rad:z111111111111111111111111111111111",
          branch: "main",
          commit_oid: "dd".repeat(32),
          observed_at: 1,
        },
        issuer_key_epoch: 1,
        issuer_key_digest: "B".repeat(43),
      },
      payload_digest: "ee".repeat(32),
      signature: "ff".repeat(64),
    };
    expect(() => validateClaimLedgerRecordSchemaOrThrow(record)).not.toThrow();
    const { credential_ledger_generation: _generation, ...missing } = record;
    expect(() => validateClaimLedgerRecordSchemaOrThrow(missing)).toThrow(/credential_ledger_generation|required/);
  });

  it("requires issuance generation in the decoded issuance payload", () => {
    const issuance = {
      credential_ledger_generation: 4,
      jti: "credential-jti-0001",
      reservation: {
        uri: "status-lists/0/00112233445566778899aabbccddeeff/0.jwt",
        idx: 0,
        expiry_bucket: "0",
        writer_nid_fingerprint: "00".repeat(16),
        list_sequence: 0,
      },
      checkpoint: {
        repository_rid: "rad:z111111111111111111111111111111111",
        branch: "main",
        commit_oid: "aa".repeat(32),
        observed_at: 1,
      },
      manifest_max_age_seconds: 300,
      signing_key_id: "A".repeat(43),
      client_id: "client",
      authorization_request_digest: "bb".repeat(32),
      release_digest: "cc".repeat(32),
      source_claim_ids: ["dd".repeat(32)],
      issued_at: 1,
      expires_at: 2,
    };
    expect(() => validateOidcIssuanceRecordSchemaOrThrow(issuance)).not.toThrow();
    const { credential_ledger_generation: _generation, ...missing } = issuance;
    expect(() => validateOidcIssuanceRecordSchemaOrThrow(missing)).toThrow(/credential_ledger_generation|required/);
  });
});
