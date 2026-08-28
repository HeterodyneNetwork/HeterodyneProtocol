import { FAMILY_VERSION, QUALIFIED_VERSION } from "../family.js";
import { CURRENT_VECTOR_SCHEMA_VERSION } from "../schema.js";
import type {
  AuthoredVector,
  DocumentId,
  VectorDirection,
} from "../types.js";

export type CurrentVectorCase = Readonly<{
  relativePath: string;
  /** Executed production boundary that produced this case's expected result. */
  semantic_boundary: string;
  vector_id: string;
  owner_document: DocumentId;
  profile?: string;
  spec_refs: readonly string[];
  invariants: readonly string[];
  reason_codes: readonly string[];
  description: string;
  direction: VectorDirection;
  input: Readonly<Record<string, unknown>>;
  expected_output: Readonly<Record<string, unknown>>;
}>;

export function currentSpecRef(anchor: string): string {
  return `heterodyne:${FAMILY_VERSION}#${anchor}`;
}

/**
 * The only current-catalog constructor. Family modules describe behavior;
 * this boundary injects the rolling vector and family versions.
 */
export function authorCurrentCase(value: CurrentVectorCase): AuthoredVector {
  return {
    relativePath: value.relativePath,
    vector: {
      vector_id: value.vector_id,
      vector_schema_version: CURRENT_VECTOR_SCHEMA_VERSION,
      owner_document: value.owner_document,
      spec_version: QUALIFIED_VERSION,
      ...(value.profile === undefined ? {} : { profile: value.profile }),
      spec_refs: [...value.spec_refs].sort(),
      invariants: [...value.invariants].sort(),
      reason_codes: [...value.reason_codes].sort(),
      description: value.description,
      direction: value.direction,
      input: structuredClone(value.input),
      expected_output: structuredClone(value.expected_output),
    },
  };
}
