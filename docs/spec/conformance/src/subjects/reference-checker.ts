import { Ajv2020 } from "ajv/dist/2020.js";
import { resolveJsonPointer } from "../json-pointer.js";
import type { ConformanceCheckDocument, VectorDocument } from "../types.js";
import coreVerificationContextSchema from "../../schema/core-verification-context-v1.schema.json" with { type: "json" };
import {
  bindNip01Raw,
  computeNip01Digest,
  isNostrSignedEvent,
  verifyNip01Signature,
} from "./nip01.js";
import type { CheckerStage, NostrSignedEvent, SubjectResult } from "./types.js";

type StageResult = SubjectResult["stages"][number];
type CoreVerificationContextV1 = {
  active_persona_key: string;
  assurance?: {
    requested: boolean;
    verified: boolean;
  };
};

const ajv = new Ajv2020({ allErrors: true, strict: true });
const validateCoreContext = ajv.compile<CoreVerificationContextV1>(
  coreVerificationContextSchema,
);

function reject(
  stages: StageResult[],
  stage: CheckerStage,
  reasonCode: string,
): SubjectResult {
  const terminal: StageResult = { stage, verdict: "reject", reasonCode };
  return {
    terminalStage: stage,
    verdict: "reject",
    reasonCode,
    stages: [...stages, terminal],
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function resolveContext(
  vector: VectorDocument,
  check: ConformanceCheckDocument,
): CoreVerificationContextV1 | undefined {
  if (check.context_pointer === undefined) {
    return undefined;
  }

  let resolved;
  try {
    resolved = resolveJsonPointer(vector, check.context_pointer);
  } catch {
    return undefined;
  }
  if (!resolved.found || !isRecord(resolved.value)) {
    return undefined;
  }

  const assurance = resolved.value.assurance;
  const baselineCandidate = { ...resolved.value };
  delete baselineCandidate.assurance;
  if (!validateCoreContext(baselineCandidate)) {
    return undefined;
  }

  const assuranceRequested = isRecord(assurance) && assurance.requested === true;
  if (
    assuranceRequested
    && (!validateCoreContext(resolved.value) || resolved.value.assurance?.verified !== true)
  ) {
    return undefined;
  }

  return baselineCandidate as CoreVerificationContextV1;
}

export function checkCoreSignedEvent(
  vector: VectorDocument,
  check: ConformanceCheckDocument,
): SubjectResult {
  const stages: StageResult[] = [];

  let resolved;
  try {
    resolved = resolveJsonPointer(vector, check.event_pointer);
  } catch {
    return reject(stages, "event_structure", "bad_signature");
  }
  if (!resolved.found || !isNostrSignedEvent(resolved.value)) {
    return reject(stages, "event_structure", "bad_signature");
  }
  const event: NostrSignedEvent = resolved.value;
  stages.push({ stage: "event_structure", verdict: "pass" });

  let rawResolved;
  try {
    rawResolved = resolveJsonPointer(vector, check.nip01_raw_pointer);
  } catch {
    return reject(stages, "nip01_raw", "nip01_raw_mismatch");
  }
  const bound = bindNip01Raw(event, rawResolved.found ? rawResolved.value : undefined);
  if (bound === undefined) {
    return reject(stages, "nip01_raw", "nip01_raw_mismatch");
  }
  stages.push({ stage: "nip01_raw", verdict: "pass" });

  const digest = computeNip01Digest(bound.bytes);
  const identifier = Buffer.from(digest).toString("hex");
  if (identifier !== event.id) {
    return reject(stages, "identifier", "bad_signature");
  }
  stages.push({ stage: "identifier", verdict: "pass" });

  if (!verifyNip01Signature(event, digest)) {
    return reject(stages, "signature", "bad_signature");
  }
  stages.push({ stage: "signature", verdict: "pass" });

  const context = resolveContext(vector, check);
  if (context === undefined || event.pubkey !== context.active_persona_key) {
    return reject(stages, "persona_resolution", "delegation_mismatch");
  }
  stages.push({ stage: "persona_resolution", verdict: "pass" });
  stages.push({ stage: "accept", verdict: "pass" });
  return {
    terminalStage: "accept",
    verdict: "accept",
    stages,
  };
}
