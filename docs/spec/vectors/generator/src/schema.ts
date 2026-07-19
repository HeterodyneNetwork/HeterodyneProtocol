import { Ajv, type ErrorObject, type JSONSchemaType } from "ajv";
import { reasonCodeValues } from "./reason-codes.js";
import { assertAllowedDependency, parseQualifiedVersion } from "./family.js";
import type { DocumentId, Vector } from "./types.js";

const REGISTRY_REASON_CODES = reasonCodeValues();

export const VECTOR_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: [
    "vector_id",
    "vector_schema_version",
    "owner_document",
    "owner_version",
    "dependency_versions",
    "registry_revision",
    "spec_refs",
    "description",
    "direction",
    "input",
    "expected_output",
  ],
  properties: {
    vector_id: { type: "string", minLength: 1 },
    vector_schema_version: { type: "string", pattern: "^\\d+\\.\\d+\\.\\d+$" },
    owner_document: { type: "string", enum: ["core", "comms", "control", "social"] },
    owner_version: {
      type: "string",
      pattern: "^(core|comms|control|social)/(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\\+[0-9A-Za-z.-]+)?$",
    },
    dependency_versions: {
      type: "object",
      required: [],
      additionalProperties: false,
      properties: {
        core: { type: "string" },
        comms: { type: "string" },
        control: { type: "string" },
        social: { type: "string" },
      },
    },
    registry_revision: { type: "integer", minimum: 1 },
    profile: { type: "string", minLength: 1 },
    spec_refs: {
      type: "array",
      minItems: 1,
      items: {
        type: "string",
        pattern: "^heterodyne:(core|comms|control|social)/(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\\+[0-9A-Za-z.-]+)?#[a-z0-9]+(?:-[a-z0-9]+)*$",
      },
    },
    description: { type: "string", minLength: 1 },
    direction: { type: "string", enum: ["produce", "consume", "round-trip"] },
    input: { type: "object", additionalProperties: true, required: [] },
    expected_output: { type: "object", additionalProperties: true, required: [] },
  },
  allOf: [
    {
      if: {
        properties: {
          direction: { const: "consume" },
          expected_output: {
            type: "object",
            properties: {
              verdict: { const: "reject" },
            },
            required: ["verdict"],
          },
        },
        required: ["direction", "expected_output"],
      },
      then: {
        properties: {
          expected_output: {
            type: "object",
            required: ["verdict", "reason_code"],
            properties: {
              verdict: { const: "reject" },
              reason_code: { type: "string", enum: REGISTRY_REASON_CODES },
            },
            additionalProperties: true,
          },
        },
      },
    },
  ],
} as unknown as JSONSchemaType<Vector>;

const ajv = new Ajv({ allErrors: true });
const validate = ajv.compile(VECTOR_SCHEMA);

export function validateVectorOrThrow(value: unknown): asserts value is Vector {
  if (!validate(value)) {
    throw new Error(formatErrors(validate.errors ?? []));
  }
  validateFamilyMetadata(value);
}

function validateFamilyMetadata(vector: Vector): void {
  const ownerVersion = parseQualifiedVersion(vector.owner_version);
  if (ownerVersion.document !== vector.owner_document) {
    throw new Error("owner_version does not match owner_document");
  }
  for (const [dependency, version] of Object.entries(vector.dependency_versions)) {
    const document = dependency as DocumentId;
    assertAllowedDependency(vector.owner_document, document);
    let parsed;
    try {
      parsed = parseQualifiedVersion(version);
    } catch {
      throw new Error(`dependency version is not qualified: ${document}`);
    }
    if (parsed.document !== document) {
      throw new Error(`dependency version does not match ${document}`);
    }
  }
}

function formatErrors(errors: ErrorObject[]): string {
  return errors
    .map((error) => {
      const at = error.instancePath || "/";
      return `${at} ${error.message ?? "failed validation"}`;
    })
    .join("; ");
}
