import { Ajv, type ErrorObject, type JSONSchemaType } from "ajv";
import { reasonCodeValues } from "./reason-codes.js";
import { parseQualifiedVersion } from "./family.js";
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
      enum: ["core/0.5.0", "comms/0.5.0", "control/0.5.0", "social/0.5.0"],
    },
    dependency_versions: {
      type: "object",
      required: [],
      additionalProperties: false,
      properties: {
        core: { type: "string", const: "core/0.5.0" },
        comms: { type: "string", const: "comms/0.5.0" },
        control: { type: "string", const: "control/0.5.0" },
        social: { type: "string", const: "social/0.5.0" },
      },
    },
    registry_revision: { type: "integer", minimum: 1 },
    profile: { type: "string", minLength: 1 },
    spec_refs: {
      type: "array",
      minItems: 1,
      items: {
        type: "string",
        pattern: "^heterodyne:(core|comms|control|social)/0\\.5\\.0#[a-z0-9]+(?:-[a-z0-9]+)*$",
      },
    },
    description: { type: "string", minLength: 1 },
    direction: { type: "string", enum: ["produce", "consume", "round-trip"] },
    input: { type: "object", additionalProperties: true, required: [] },
    expected_output: { type: "object", additionalProperties: true, required: [] },
  },
  allOf: [
    ...([
      ["core", "core/0.5.0", {}],
      ["comms", "comms/0.5.0", { core: "core/0.5.0" }],
      ["social", "social/0.5.0", { core: "core/0.5.0", comms: "comms/0.5.0" }],
      ["control", "control/0.5.0", { core: "core/0.5.0", comms: "comms/0.5.0" }],
    ] as const).map(([owner, ownerVersion, dependencies]) => ({
      if: { properties: { owner_document: { const: owner } }, required: ["owner_document"] },
      then: {
        properties: {
          owner_version: { const: ownerVersion },
          dependency_versions: { const: dependencies },
        },
      },
    })),
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
  const exactDependencies: Record<DocumentId, Partial<Record<DocumentId, string>>> = {
    core: {},
    comms: { core: "core/0.5.0" },
    social: { core: "core/0.5.0", comms: "comms/0.5.0" },
    control: { core: "core/0.5.0", comms: "comms/0.5.0" },
  };
  const ownerVersion = parseQualifiedVersion(vector.owner_version);
  if (ownerVersion.document !== vector.owner_document || vector.owner_version !== `${vector.owner_document}/0.5.0`) {
    throw new Error("owner_version does not match owner_document");
  }
  const expected = exactDependencies[vector.owner_document];
  if (JSON.stringify(vector.dependency_versions) !== JSON.stringify(expected)) {
    throw new Error(`dependency_versions do not exactly match ${vector.owner_document}`);
  }
  const allowedRefs = new Set([vector.owner_document, ...Object.keys(expected)]);
  for (const ref of vector.spec_refs) {
    const match = /^heterodyne:(core|comms|control|social)\/0\.5\.0#[a-z0-9]+(?:-[a-z0-9]+)*$/.exec(ref);
    if (match === null || !allowedRefs.has(match[1])) {
      throw new Error(`spec_ref is outside the owner dependency closure: ${ref}`);
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
