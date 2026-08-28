import type { AuthoredVector } from "../types.js";
import { buildAssuranceCases } from "./assurance.js";
import { buildCommsCases } from "./comms.js";
import { buildControlCases } from "./control.js";
import { buildCoreCases } from "./core.js";
import { buildSocialCases } from "./social.js";
import { buildProfileCases } from "./profiles.js";
import {
  authorCurrentCase,
  type CurrentCaseFixture,
  type CurrentVectorCase,
} from "./types.js";
import { buildWorkspaceCases } from "./workspace.js";
import { invokeCurrentBoundary } from "./boundary-runners.js";
import {
  currentCaseContract,
  currentCaseIds,
  type CurrentCaseContract,
} from "./case-contracts.js";
import { currentProfileOracleForVector } from "./profile-oracles.js";

type CurrentCaseEvidence = Readonly<{
  contract: CurrentCaseContract;
  /** Exact evaluator result retained privately; never serialized as evidence. */
  raw_result: unknown;
}>;

const evidenceByCase = new WeakMap<CurrentVectorCase, CurrentCaseEvidence>();

function deepFreeze<T>(value: T, seen = new WeakSet<object>()): T {
  if (value === null || typeof value !== "object") return value;
  const object = value as object;
  if (seen.has(object)) return value;
  seen.add(object);
  for (const key of Reflect.ownKeys(object)) {
    deepFreeze((object as Record<PropertyKey, unknown>)[key], seen);
  }
  if (!ArrayBuffer.isView(object)) Object.freeze(object);
  return value;
}

function sameStrings(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length
    && left.every((value, index) => value === right[index]);
}

function requireRecordResult(vectorId: string, value: unknown): Readonly<Record<string, unknown>> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`current evaluator returned a non-record result: ${vectorId}`);
  }
  return value as Readonly<Record<string, unknown>>;
}

async function bindExecutedCase(raw: CurrentCaseFixture): Promise<CurrentVectorCase> {
  const contract = currentCaseContract(raw.vector_id);
  const expectedPath = `${raw.vector_id}.json`;
  let execution: Awaited<ReturnType<typeof invokeCurrentBoundary>>;
  try {
    execution = await invokeCurrentBoundary(contract.boundary_id, raw);
  } catch (error) {
    throw new Error(
      `current boundary execution failed: ${raw.vector_id} -> ${contract.boundary_id}`,
      { cause: error },
    );
  }
  const rawResult = deepFreeze(execution.raw_result);
  const profileOracle = currentProfileOracleForVector(raw.vector_id);
  if (profileOracle !== undefined) {
    if (
      rawResult === null
      || typeof rawResult !== "object"
      || Array.isArray(rawResult)
    ) {
      throw new Error(`current profile evidence is not a closed execution record: ${raw.vector_id}`);
    }
    const profileEvidence = rawResult as Readonly<Record<string, unknown>>;
    const registryComparison = profileEvidence.registry_comparison;
    if (
      profileEvidence.semantic_boundary !== profileOracle.semantic_boundary
      || registryComparison === null
      || typeof registryComparison !== "object"
      || Array.isArray(registryComparison)
      || (registryComparison as Readonly<Record<string, unknown>>).verdict !== "accept"
      || !Object.hasOwn(profileEvidence, "semantic_result")
    ) {
      throw new Error(`current profile evidence/oracle mismatch: ${raw.vector_id}`);
    }
  }
  const projected = deepFreeze(requireRecordResult(raw.vector_id, execution.projected_output));
  const expectedReason = projected.verdict === "reject"
    ? projected.reason_code
    : undefined;
  if (projected.verdict === "reject" && expectedReason === undefined) {
    throw new Error(`current reject result lacks an exact reason: ${raw.vector_id}`);
  }
  if (
    expectedReason !== undefined
    && (
      typeof expectedReason !== "string"
      || !sameStrings(contract.reason_codes, [expectedReason])
    )
  ) {
    throw new Error(`current evaluator reason/contract mismatch: ${raw.vector_id}`);
  }
  if (expectedReason === undefined && contract.reason_codes.length !== 0) {
    throw new Error(`current non-reject contract carries wire reasons: ${raw.vector_id}`);
  }
  const semanticReasons = contract.semantic_reason_codes ?? contract.reason_codes;
  const diagnosticReason = projected.reason_code;
  if (
    diagnosticReason !== undefined
    && (
      typeof diagnosticReason !== "string"
      || !semanticReasons.includes(diagnosticReason)
    )
  ) {
    throw new Error(`current evaluator diagnostic/contract mismatch: ${raw.vector_id}`);
  }

  const bound = deepFreeze<CurrentVectorCase>({
    relativePath: expectedPath,
    semantic_boundary: contract.boundary_id,
    vector_id: raw.vector_id,
    owner_document: contract.owner_document,
    ...(contract.profile === undefined ? {} : { profile: contract.profile }),
    spec_refs: contract.spec_refs,
    invariants: contract.invariants,
    reason_codes: contract.reason_codes,
    description: raw.description,
    direction: raw.direction,
    input: deepFreeze(raw.input),
    expected_output: projected,
  });
  evidenceByCase.set(bound, Object.freeze({ contract, raw_result: rawResult }));
  return bound;
}

export function semanticEvidenceForCase(value: CurrentVectorCase): Readonly<{
  boundary_id: string;
  owner_document: CurrentVectorCase["owner_document"];
  profile?: string;
  spec_refs: readonly string[];
  invariants: readonly string[];
  reason_codes: readonly string[];
}> {
  const evidence = evidenceByCase.get(value);
  if (evidence === undefined) {
    throw new Error(`unbranded semantic evidence: ${value.vector_id}`);
  }
  const { contract } = evidence;
  return Object.freeze({
    boundary_id: contract.boundary_id,
    owner_document: contract.owner_document,
    ...(contract.profile === undefined ? {} : { profile: contract.profile }),
    spec_refs: contract.spec_refs,
    invariants: contract.invariants,
    reason_codes: contract.semantic_reason_codes ?? contract.reason_codes,
  });
}

export async function buildCurrentCases(): Promise<CurrentVectorCase[]> {
  const rawCases = [
    ...await buildCoreCases(),
    ...await buildAssuranceCases(),
    ...await buildCommsCases(),
    ...await buildControlCases(),
    ...await buildSocialCases(),
    ...buildWorkspaceCases(),
    ...await buildProfileCases(),
  ];
  const cases: CurrentVectorCase[] = [];
  for (const raw of rawCases) cases.push(await bindExecutedCase(raw));
  const registered = new Set(currentCaseIds());
  const built = new Set(cases.map(({ vector_id }) => vector_id));
  const missing = [...registered].filter((id) => !built.has(id));
  const unexpected = [...built].filter((id) => !registered.has(id));
  if (missing.length > 0 || unexpected.length > 0) {
    throw new Error(
      `current case contract mismatch: missing=[${missing.join(",")}] unexpected=[${unexpected.join(",")}]`,
    );
  }
  return cases;
}

export async function buildCurrentVectors(): Promise<AuthoredVector[]> {
  const cases = await buildCurrentCases();
  const authored = cases.map(authorCurrentCase).sort((left, right) =>
    left.relativePath.localeCompare(right.relativePath, "en")
  );
  const paths = new Set<string>();
  const ids = new Set<string>();
  for (const { relativePath, vector } of authored) {
    if (paths.has(relativePath)) throw new Error(`duplicate current vector path: ${relativePath}`);
    if (ids.has(vector.vector_id)) throw new Error(`duplicate current vector id: ${vector.vector_id}`);
    paths.add(relativePath);
    ids.add(vector.vector_id);
  }
  return authored;
}

export type { CurrentVectorCase } from "./types.js";
