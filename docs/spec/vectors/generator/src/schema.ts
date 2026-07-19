import { Ajv, type ErrorObject, type JSONSchemaType } from "ajv";
import { reasonCodeValues } from "./reason-codes.js";
import type { Vector } from "./types.js";

const REGISTRY_REASON_CODES = reasonCodeValues();

export const VECTOR_SCHEMA: JSONSchemaType<Vector> = {
  type: "object",
  additionalProperties: false,
  required: [
    "vector_id",
    "vector_schema_version",
    "spec_version",
    "spec_refs",
    "description",
    "direction",
    "input",
    "expected_output",
  ],
  properties: {
    vector_id: { type: "string", minLength: 1 },
    vector_schema_version: { type: "string", pattern: "^\\d+\\.\\d+\\.\\d+$" },
    spec_version: { type: "string", pattern: "^\\d+\\.\\d+\\.\\d+$" },
    spec_refs: {
      type: "array",
      minItems: 1,
      items: { type: "string", minLength: 1 },
    },
    description: { type: "string", minLength: 1 },
    direction: { type: "string", enum: ["produce", "consume", "round-trip"] },
    input: { type: "object", additionalProperties: true, required: [] },
    expected_output: { type: "object", additionalProperties: true, required: [] },
    fixtures: {
      type: "object",
      additionalProperties: true,
      required: [],
      nullable: true,
    },
    simulated_clock: { type: "number", nullable: true },
    decision_trace: {
      type: "array",
      items: { type: "string" },
      nullable: true,
    },
    transport_context: {
      type: "object",
      additionalProperties: true,
      required: [],
      nullable: true,
    },
    notes: { type: "string", nullable: true },
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
};

const ajv = new Ajv({ allErrors: true });
const validate = ajv.compile(VECTOR_SCHEMA);

export function validateVectorOrThrow(value: unknown): asserts value is Vector {
  if (!validate(value)) {
    throw new Error(formatErrors(validate.errors ?? []));
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
