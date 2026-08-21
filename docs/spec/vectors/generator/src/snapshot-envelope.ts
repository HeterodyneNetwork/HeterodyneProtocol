import { isDeepStrictEqual } from "node:util";
import { Ajv, type AnySchema, type ErrorObject } from "ajv";
import snapshotVectorSchema from "../../schema/vector.schema.json" with { type: "json" };
import type {
  DocumentId,
  RawVector,
  SnapshotVector,
} from "./types.js";

const SNAPSHOT_SCHEMA_VERSION = "2.0.0" as const;
const OWNER_DOCUMENTS = new Set<DocumentId>([
  "core",
  "comms",
  "control",
  "social",
  "workspace",
]);
const LEGACY_REF = /^heterodyne:[^#]+#([a-z0-9][a-z0-9-]*)$/;

const validateDefaultSnapshot = snapshotVectorValidator(snapshotVectorSchema);

export function validateRawVector(
  raw: unknown,
  sourceSchema: AnySchema,
): asserts raw is RawVector {
  const rawAjv = new Ajv({ allErrors: true, strict: false });
  const validate = rawAjv.compile(sourceSchema);
  if (!validate(raw)) {
    throw new Error(`raw-vector-invalid: ${formatErrors(validate.errors ?? [])}`);
  }
}

export function validateSnapshotVector(
  packaged: unknown,
): asserts packaged is SnapshotVector {
  validateDefaultSnapshot(packaged);
}

export function snapshotVectorValidator(sourceSchema: AnySchema): (packaged: unknown) => void {
  const ajv = new Ajv({ allErrors: true, strict: false });
  const validate = ajv.compile(sourceSchema);
  return (packaged: unknown): void => {
    if (!validate(packaged)) {
      throw new Error(
        `snapshot-vector-invalid: ${formatErrors(validate.errors ?? [])}`,
      );
    }
  };
}

export function buildSnapshotVectorSchema(sourceSchema: unknown): AnySchema {
  if (!isRecord(sourceSchema) || !isRecord(sourceSchema.properties)) {
    throw new Error("raw-vector-schema-invalid: schema must define properties");
  }
  const schema = structuredClone(sourceSchema);
  if (!isRecord(schema) || !isRecord(schema.properties)) {
    throw new Error("raw-vector-schema-invalid: schema must define properties");
  }
  const properties = schema.properties;
  delete properties.spec_version;
  properties.vector_schema_version = { const: SNAPSHOT_SCHEMA_VERSION };
  const sourceRefs = isRecord(properties.spec_refs) ? properties.spec_refs : {};
  properties.spec_refs = {
    ...sourceRefs,
    items: {
      type: "string",
      pattern: "^heterodyne:(core|comms|control|social|workspace)#[a-z0-9][a-z0-9-]*$",
    },
  };
  if (Array.isArray(schema.required)) {
    schema.required = schema.required.filter((name) => name !== "spec_version");
  }
  return schema;
}

export function normalizeSnapshotVector(raw: unknown): SnapshotVector {
  if (!isRecord(raw)) throw new Error("raw-vector-invalid: vector must be an object");
  const ownerDocument = raw.owner_document;
  if (typeof ownerDocument !== "string" || !OWNER_DOCUMENTS.has(ownerDocument as DocumentId)) {
    throw new Error("raw-vector-invalid: owner_document must be a known document");
  }
  if (!Array.isArray(raw.spec_refs) || raw.spec_refs.length !== 1) {
    throw new Error("raw-vector-invalid: spec_refs must contain exactly one legacy ref");
  }
  const legacyRef = raw.spec_refs[0];
  const match = typeof legacyRef === "string" ? LEGACY_REF.exec(legacyRef) : null;
  if (match === null) {
    throw new Error("raw-vector-invalid: spec_refs must contain a well-formed legacy ref");
  }

  const { spec_version: _draftVersion, ...withoutDraftVersion } = raw;
  return {
    ...withoutDraftVersion,
    vector_schema_version: SNAPSHOT_SCHEMA_VERSION,
    owner_document: ownerDocument as DocumentId,
    spec_refs: [`heterodyne:${ownerDocument}#${match[1]}`],
  } as SnapshotVector;
}

export function normalizeSnapshotFixtures(raw: unknown): Record<string, unknown> {
  if (!isRecord(raw)) throw new Error("raw-fixtures-invalid: fixtures must be an object");
  const { spec_version: _draftVersion, ...fixtures } = raw;
  return { ...fixtures, vector_schema_version: SNAPSHOT_SCHEMA_VERSION };
}

export function preservesVectorBehavior(
  raw: Pick<
    RawVector,
    | "vector_id"
    | "input"
    | "expected_output"
    | "direction"
    | "profile"
    | "conformance_checks"
  >,
  packaged: Pick<
    SnapshotVector,
    | "vector_id"
    | "input"
    | "expected_output"
    | "direction"
    | "profile"
    | "conformance_checks"
  >,
): boolean {
  return raw.vector_id === packaged.vector_id
    && raw.direction === packaged.direction
    && isDeepStrictEqual(raw.input, packaged.input)
    && isDeepStrictEqual(raw.expected_output, packaged.expected_output)
    && optionalFieldMatches(raw, packaged, "profile")
    && optionalFieldMatches(raw, packaged, "conformance_checks");
}

function optionalFieldMatches(
  raw: Pick<RawVector, "profile" | "conformance_checks">,
  packaged: Pick<SnapshotVector, "profile" | "conformance_checks">,
  field: "profile" | "conformance_checks",
): boolean {
  if (Object.hasOwn(raw, field) !== Object.hasOwn(packaged, field)) return false;
  return !Object.hasOwn(raw, field)
    || isDeepStrictEqual(raw[field], packaged[field]);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function formatErrors(errors: ErrorObject[]): string {
  return errors
    .map((error) => {
      const at = error.instancePath || "/";
      return `${at} ${error.message ?? "failed validation"}`;
    })
    .join("; ");
}
