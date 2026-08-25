import { createHash } from "node:crypto";
import { schnorr } from "@noble/curves/secp256k1";
import { Ajv, type AnySchema } from "ajv";
import trustedSeedAclSchema from "../../../schemas/comms/trusted-seed-acl-v1.schema.json" with { type: "json" };
import { hexToBytes, utf8Bytes } from "./hex.js";
import { jcsCanonicalize } from "./jcs.js";
import { proofBytes } from "./proof-bytes.js";

export type TrustedSeedRole = "read" | "write";

export type TrustedSeedAcl = {
  profile: "heterodyne.trusted-seed-acl.v1";
  spec_version: "heterodyne/0.5.0";
  administrator_account: string;
  accounts: Array<{
    account_key: string;
    roles: TrustedSeedRole[];
  }>;
  h: string;
  private_rid: string;
  seed_grants: Array<{
    seed_nid: string;
    relay_endpoint: string;
    radicle_endpoint: string;
    writer_ref: string;
    roles: TrustedSeedRole[];
    state: "active" | "revoked";
  }>;
  sequence: number;
  predecessor: string | null;
  group_transition: {
    generation: number;
    marmot_routing_event_id: string;
    routing_binding_sha256: string;
  };
  issued_at: number;
  expires_at: number;
  signature: string;
};

export type TrustedSeedAdmissionInput = {
  acl_candidates: unknown[];
  expected_administrator_account: string;
  authenticated_account: string;
  nip42_authenticated: boolean;
  operation: TrustedSeedRole;
  seed_nid: string;
  h: string;
  private_rid: string;
  writer_ref?: string;
  group_transition: TrustedSeedAcl["group_transition"];
  now: number;
  nip01_raw?: string;
  previous_acl?: unknown;
};

export type TrustedSeedAdmissionResult =
  | {
      verdict: "accept";
      acl_digest: string;
      seed_nid: string;
      writer_ref: string;
      nip01_raw?: string;
    }
  | {
      verdict: "reject";
      reason_code: string;
    };

const ajv = new Ajv({ allErrors: true, strict: false });
const validateAcl = ajv.compile<TrustedSeedAcl>(trustedSeedAclSchema as AnySchema);
const FORBIDDEN_SECRET_MEMBERS = new Set([
  "mls_leaf_secret",
  "plaintext",
  "content_decryption_key",
]);

export function trustedSeedAclProofBytes(
  value: Omit<TrustedSeedAcl, "signature"> | Record<string, unknown>,
): Uint8Array {
  const { signature: _signature, ...unsigned } = value as Record<string, unknown>;
  return proofBytes("heterodyne-trusted-seed-acl-v1", unsigned);
}

export function trustedSeedAclDigest(value: unknown): string {
  return createHash("sha256")
    .update(utf8Bytes(jcsCanonicalize(value)))
    .digest("hex");
}

export function evaluateTrustedSeedAdmission(
  value: unknown,
): TrustedSeedAdmissionResult {
  if (!isRecord(value)) return denied("trusted-seed-acl-invalid");
  if ([...FORBIDDEN_SECRET_MEMBERS].some((member) => member in value)) {
    return denied("trusted-seed-secret-material-forbidden");
  }
  const input = value as TrustedSeedAdmissionInput;
  if (!input.nip42_authenticated) return denied("trusted-seed-nip42-required");
  if (!Array.isArray(input.acl_candidates) || input.acl_candidates.length === 0) {
    return denied("trusted-seed-acl-missing");
  }
  if (
    !Number.isSafeInteger(input.now)
    || !["read", "write"].includes(input.operation)
    || typeof input.expected_administrator_account !== "string"
    || typeof input.authenticated_account !== "string"
    || typeof input.seed_nid !== "string"
    || typeof input.h !== "string"
    || typeof input.private_rid !== "string"
    || !isGroupTransition(input.group_transition)
  ) {
    return denied("trusted-seed-acl-invalid");
  }

  const candidates: TrustedSeedAcl[] = [];
  for (const candidate of input.acl_candidates) {
    if (!validateAcl(candidate)) return denied("trusted-seed-acl-invalid");
    candidates.push(candidate as TrustedSeedAcl);
  }
  if (candidates.some((candidate) =>
    candidate.h !== input.h || candidate.private_rid !== input.private_rid
  )) {
    return denied("trusted-seed-route-mismatch");
  }
  if (candidates.some((candidate) =>
    candidate.administrator_account !== input.expected_administrator_account
      || !verifyAclSignature(candidate)
  )) {
    return denied("trusted-seed-unauthorized");
  }

  const greatestSequence = Math.max(...candidates.map(({ sequence }) => sequence));
  const heads = deduplicateAcls(
    candidates.filter(({ sequence }) => sequence === greatestSequence),
  );
  if (heads.length !== 1) return denied("trusted-seed-acl-conflict");
  const acl = heads[0];

  if (acl.issued_at > input.now || acl.expires_at <= acl.issued_at) {
    return denied("trusted-seed-acl-invalid");
  }
  if (input.now >= acl.expires_at) return denied("trusted-seed-acl-expired");
  if (
    hasDuplicate(acl.accounts.map(({ account_key }) => account_key))
    || hasDuplicate(acl.seed_grants.map(({ seed_nid }) => seed_nid))
    || hasDuplicate(acl.seed_grants.map(({ writer_ref }) => writer_ref))
  ) {
    return denied("trusted-seed-acl-ambiguous");
  }

  if (input.previous_acl === undefined) {
    if (acl.sequence !== 0 || acl.predecessor !== null) {
      return denied("trusted-seed-acl-ambiguous");
    }
  } else {
    if (
      !validateAcl(input.previous_acl)
      || !verifyAclSignature(input.previous_acl as TrustedSeedAcl)
    ) {
      return denied("trusted-seed-acl-invalid");
    }
    const previous = input.previous_acl as TrustedSeedAcl;
    if (acl.sequence <= previous.sequence) return denied("trusted-seed-acl-stale");
    if (
      acl.sequence !== previous.sequence + 1
      || acl.predecessor !== trustedSeedAclDigest(previous)
    ) {
      return denied("trusted-seed-acl-ambiguous");
    }
  }

  if (acl.group_transition.generation < input.group_transition.generation) {
    return denied("trusted-seed-acl-stale");
  }
  if (
    acl.group_transition.generation !== input.group_transition.generation
    || acl.group_transition.marmot_routing_event_id
      !== input.group_transition.marmot_routing_event_id
    || acl.group_transition.routing_binding_sha256
      !== input.group_transition.routing_binding_sha256
  ) {
    return denied("trusted-seed-route-mismatch");
  }

  const grant = acl.seed_grants.find(({ seed_nid }) => seed_nid === input.seed_nid);
  if (grant?.state === "revoked") return denied("trusted-seed-revoked");
  if (grant === undefined || !grant.roles.includes(input.operation)) {
    return denied("trusted-seed-unauthorized");
  }
  const account = acl.accounts.find(
    ({ account_key }) => account_key === input.authenticated_account,
  );
  if (account === undefined || !account.roles.includes(input.operation)) {
    return denied("trusted-seed-unauthorized");
  }
  if (input.operation === "write") {
    if (
      input.writer_ref !== grant.writer_ref
      || typeof input.nip01_raw !== "string"
      || input.nip01_raw.length === 0
    ) {
      return denied("trusted-seed-unauthorized");
    }
  }

  return {
    verdict: "accept",
    acl_digest: trustedSeedAclDigest(acl),
    seed_nid: grant.seed_nid,
    writer_ref: grant.writer_ref,
    ...(input.nip01_raw === undefined ? {} : { nip01_raw: input.nip01_raw }),
  };
}

function verifyAclSignature(acl: TrustedSeedAcl): boolean {
  try {
    return schnorr.verify(
      hexToBytes(acl.signature),
      trustedSeedAclProofBytes(acl),
      hexToBytes(acl.administrator_account),
    );
  } catch {
    return false;
  }
}

function deduplicateAcls(acls: TrustedSeedAcl[]): TrustedSeedAcl[] {
  return [...new Map(acls.map((acl) => [trustedSeedAclDigest(acl), acl])).values()];
}

function hasDuplicate(values: string[]): boolean {
  return new Set(values).size !== values.length;
}

function isGroupTransition(value: unknown): value is TrustedSeedAcl["group_transition"] {
  return isRecord(value)
    && Number.isSafeInteger(value.generation)
    && typeof value.marmot_routing_event_id === "string"
    && typeof value.routing_binding_sha256 === "string";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function denied(reason_code: string): TrustedSeedAdmissionResult {
  return { verdict: "reject", reason_code };
}
