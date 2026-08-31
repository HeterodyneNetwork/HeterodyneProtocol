import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Ajv, type AnySchema, type ErrorObject, type JSONSchemaType } from "ajv";
import { reasonCodeValues } from "./reason-codes.js";
import {
  assertCurrentFamilyVersion,
  DOCUMENT_LAYERING,
  FAMILY_VERSION,
  QUALIFIED_VERSION,
} from "./family.js";
import { jcsCanonicalize } from "./jcs.js";
import type { DocumentId, Vector } from "./types.js";

const REGISTRY_REASON_CODES = reasonCodeValues();
const REGISTRY_INVARIANTS = (
  JSON.parse(readFileSync(resolve(
    dirname(fileURLToPath(import.meta.url)),
    "../../../registry/security-invariants.json",
  ), "utf8")) as {
    security_invariants: Array<{ id: string; owner: DocumentId }>;
  }
).security_invariants;
const REGISTRY_INVARIANT_IDS = REGISTRY_INVARIANTS.map(({ id }) => id);
const INVARIANT_OWNER = new Map(REGISTRY_INVARIANTS.map(({ id, owner }) => [id, owner]));

export const CURRENT_VECTOR_SCHEMA_VERSION = "3.0.0" as const;

export const VECTOR_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: [
    "vector_id",
    "vector_schema_version",
    "owner_document",
    "spec_version",
    "spec_refs",
    "invariants",
    "reason_codes",
    "description",
    "direction",
    "input",
    "expected_output",
  ],
  properties: {
    vector_id: { type: "string", minLength: 1 },
    vector_schema_version: { const: CURRENT_VECTOR_SCHEMA_VERSION },
    owner_document: {
      type: "string",
      enum: ["core", "assurance", "comms", "control", "social", "workspace"],
    },
    spec_version: { type: "string", const: QUALIFIED_VERSION },
    profile: { type: "string", minLength: 1 },
    conformance_checks: {
      type: "array",
      uniqueItems: true,
      items: {
        type: "object",
        additionalProperties: false,
        required: [
          "profile",
          "event_pointer",
          "nip01_raw_pointer",
          "expected_terminal_stage",
        ],
        properties: {
          profile: { const: "core-signed-event-v1" },
          event_pointer: { type: "string", pattern: "^(?:/(?:[^~/]|~[01])*)+$" },
          nip01_raw_pointer: { type: "string", pattern: "^(?:/(?:[^~/]|~[01])*)+$" },
          context_pointer: { type: "string", pattern: "^(?:/(?:[^~/]|~[01])*)+$" },
          expected_terminal_stage: {
            type: "string",
            enum: [
              "event_structure",
              "nip01_raw",
              "identifier",
              "signature",
              "persona_resolution",
              "version_stamp",
              "kel_head",
              "epoch_authority",
              "subtype_nid",
              "accept",
            ],
          },
        },
        allOf: [{
          if: {
            properties: {
              expected_terminal_stage: {
                enum: [
                  "persona_resolution",
                  "version_stamp",
                  "kel_head",
                  "epoch_authority",
                  "subtype_nid",
                  "accept",
                ],
              },
            },
            required: ["expected_terminal_stage"],
          },
          then: { required: ["context_pointer"] },
        }],
      },
    },
    spec_refs: {
      type: "array",
      minItems: 1,
      maxItems: 1,
      items: {
        type: "string",
        pattern: `^heterodyne:${FAMILY_VERSION.replaceAll(".", "\\.")}#[a-z0-9]+(?:-[a-z0-9]+)*$`,
      },
    },
    invariants: {
      type: "array",
      minItems: 1,
      uniqueItems: true,
      items: { type: "string", enum: REGISTRY_INVARIANT_IDS },
    },
    reason_codes: {
      type: "array",
      maxItems: 1,
      uniqueItems: true,
      items: { type: "string", enum: REGISTRY_REASON_CODES },
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
          expected_output: {
            type: "object",
            properties: {
              verdict: { const: "reject" },
            },
            required: ["verdict"],
          },
        },
        required: ["expected_output"],
      },
      then: {
        properties: {
          reason_codes: { type: "array", minItems: 1, maxItems: 1 },
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
      else: {
        properties: {
          reason_codes: { type: "array", maxItems: 0 },
        },
      },
    },
  ],
} as unknown as JSONSchemaType<Vector>;

const ajv = new Ajv({ allErrors: true });
const validate = ajv.compile(VECTOR_SCHEMA);

const schemasRoot = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../../../schemas/comms",
);
const coreSchemasRoot = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../../../schemas/core",
);
const controlSchemasRoot = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../../../schemas/control",
);

function readSchema(name: string): AnySchema {
  return JSON.parse(readFileSync(resolve(schemasRoot, name), "utf8")) as AnySchema;
}

function readCoreSchema(name: string): AnySchema {
  return JSON.parse(
    readFileSync(resolve(coreSchemasRoot, name), "utf8"),
  ) as AnySchema;
}

function readControlSchema(name: string): AnySchema {
  return JSON.parse(
    readFileSync(resolve(controlSchemasRoot, name), "utf8"),
  ) as AnySchema;
}

export const KEY_CLAIM_SCHEMA = readSchema("key-claim-v1.schema.json");
export const REPOSITORY_WRITER_BINDING_SCHEMA = readCoreSchema(
  "repository-writer-binding-v1.schema.json",
);
export const KEY_CLAIM_REVOCATION_SCHEMA = readSchema("key-claim-revocation-v1.schema.json");
export const CLAIM_LEDGER_RECORD_SCHEMA = readSchema("claim-ledger-record-v1.schema.json");
export const OIDC_ISSUANCE_RECORD_SCHEMA = readSchema("oidc-issuance-record-v1.schema.json");
export const OIDC_ISSUER_METADATA_SCHEMA = readSchema("oidc-issuer-metadata-v1.schema.json");
export const OIDC_CONTINUITY_MANIFEST_SCHEMA = readSchema("oidc-continuity-manifest-v1.schema.json");
export const ONE_TIME_INVITE_SCHEMA = readSchema("one-time-invite-v1.schema.json");
export const ONE_TIME_INVITE_RESPONSE_SCHEMA = readSchema("one-time-invite-response-v1.schema.json");
export const CONTROL_FRAME_SCHEMA = readControlSchema("control-frame-v1.schema.json");
export const CONTROL_CLIENT_AUTHORIZATION_SCHEMA = readControlSchema("control-client-authorization-v1.schema.json");
export const CONTROL_OPERATION_RECORD_SCHEMA = readControlSchema("control-operation-record-v1.schema.json");
export const CONTROL_EPOCH_REGISTRATION_SCHEMA = readControlSchema("control-epoch-registration-v1.schema.json");
export const CONTROL_PREPARED_ACTIVATION_SCHEMA = readControlSchema("control-prepared-activation-v1.schema.json");
export const CONTROL_RECOVERY_GRANT_SCHEMA = readControlSchema("control-recovery-grant-v1.schema.json");
export const CONTROL_RECOVERY_COMPLETION_SCHEMA = readControlSchema("control-recovery-completion-v1.schema.json");
export const CONTROL_SFTP_GRANT_SCHEMA = readControlSchema("control-sftp-grant-v1.schema.json");
export const CONTROL_CAPABILITY_SET_SCHEMA = readControlSchema("control-capability-set-v1.schema.json");
export const CONTROL_MCP_FRAME_SCHEMA = readControlSchema("control-mcp-frame-v1.schema.json");
export const CONTROL_RPC_REQUEST_SCHEMA = readControlSchema("control-rpc-request-v1.schema.json");
export const CONTROL_RPC_RESPONSE_SCHEMA = readControlSchema("control-rpc-response-v1.schema.json");
export const CONTROL_INVITATION_POLICY_SCHEMA = readControlSchema("control-invitation-policy-v1.schema.json");
export const CONTROL_DEVICE_AUTHORIZATION_STATE_SCHEMA = readControlSchema("control-device-authorization-state-v1.schema.json");

export const CREDENTIAL_CONTINUITY_SCHEMA_FILES = [
  "repository-retention-inventory-v1.schema.json",
  "governed-decrypt-key-binding-v1.schema.json",
  "historical-decrypt-obligation-v1.schema.json",
  "credential-ledger-checkpoint-v1.schema.json",
  "credential-ledger-checkpoint-receipt-v1.schema.json",
  "credential-ledger-removal-observation-v1.schema.json",
  "credential-ledger-candidate-abandonment-v1.schema.json",
  "credential-ledger-staging-ref-cleanup-v1.schema.json",
  "credential-ledger-config-key-bootstrap-recipient-array-v1.schema.json",
  "credential-ledger-emergency-reset-v1.schema.json",
  "credential-ledger-reset-recipient-array-v1.schema.json",
  "node-secret-source-v1.schema.json",
  "node-secret-exposure-v1.schema.json",
  "credential-ledger-secret-transition-v1.schema.json",
  "node-secret-transition-action-v1.schema.json",
  "credential-ledger-lost-generation-path-v1.schema.json",
  "config-repository-git-structure-v1.schema.json",
] as const;

export type CredentialContinuitySchemaFile =
  (typeof CREDENTIAL_CONTINUITY_SCHEMA_FILES)[number];

export const CREDENTIAL_CONTINUITY_SCHEMAS = Object.fromEntries(
  CREDENTIAL_CONTINUITY_SCHEMA_FILES.map((file) => [file, readSchema(file)]),
) as Record<CredentialContinuitySchemaFile, AnySchema>;

const commsSchemaAjv = new Ajv({ allErrors: true, strict: false });
commsSchemaAjv.addSchema(KEY_CLAIM_SCHEMA);
commsSchemaAjv.addSchema(KEY_CLAIM_REVOCATION_SCHEMA);
commsSchemaAjv.addSchema(OIDC_ISSUANCE_RECORD_SCHEMA);
const validateKeyClaim = commsSchemaAjv.getSchema("https://heterodyne.network/schemas/comms/key-claim-v1.schema.json")!;
const validateClaimRevocation = commsSchemaAjv.getSchema("https://heterodyne.network/schemas/comms/key-claim-revocation-v1.schema.json")!;
const validateClaimLedgerRecord = commsSchemaAjv.compile(CLAIM_LEDGER_RECORD_SCHEMA);
const validateOidcIssuanceRecord = commsSchemaAjv.getSchema("https://heterodyne.network/schemas/comms/oidc-issuance-record-v1.schema.json")!;
const validateOidcIssuerMetadata = commsSchemaAjv.compile(OIDC_ISSUER_METADATA_SCHEMA);
const validateOidcContinuityManifest = commsSchemaAjv.compile(OIDC_CONTINUITY_MANIFEST_SCHEMA);
const validateOneTimeInvite = commsSchemaAjv.compile(ONE_TIME_INVITE_SCHEMA);
const validateOneTimeInviteResponse = commsSchemaAjv.compile(ONE_TIME_INVITE_RESPONSE_SCHEMA);

const coreSchemaAjv = new Ajv({ allErrors: true, strict: false });
const validateRepositoryWriterBinding = coreSchemaAjv.compile(
  REPOSITORY_WRITER_BINDING_SCHEMA,
);

const controlSchemaAjv = new Ajv({ allErrors: true, strict: false });
controlSchemaAjv.addSchema(CONTROL_CAPABILITY_SET_SCHEMA);
const validateControlCapabilitySet = controlSchemaAjv.getSchema(
  "https://heterodyne.network/schemas/control/control-capability-set-v1.schema.json",
)!;
const validateControlFrame = controlSchemaAjv.compile(CONTROL_FRAME_SCHEMA);
const validateControlClientAuthorization = controlSchemaAjv.compile(CONTROL_CLIENT_AUTHORIZATION_SCHEMA);
const validateControlOperationRecord = controlSchemaAjv.compile(CONTROL_OPERATION_RECORD_SCHEMA);
const validateControlEpochRegistration = controlSchemaAjv.compile(CONTROL_EPOCH_REGISTRATION_SCHEMA);
const validateControlPreparedActivation = controlSchemaAjv.compile(CONTROL_PREPARED_ACTIVATION_SCHEMA);
const validateControlRecoveryGrant = controlSchemaAjv.compile(CONTROL_RECOVERY_GRANT_SCHEMA);
const validateControlRecoveryCompletion = controlSchemaAjv.compile(CONTROL_RECOVERY_COMPLETION_SCHEMA);
const validateControlSftpGrant = controlSchemaAjv.compile(CONTROL_SFTP_GRANT_SCHEMA);
const validateControlMcpFrame = controlSchemaAjv.compile(
  CONTROL_MCP_FRAME_SCHEMA,
);
const validateControlRpcRequest = controlSchemaAjv.compile(
  CONTROL_RPC_REQUEST_SCHEMA,
);
const validateControlRpcResponse = controlSchemaAjv.compile(
  CONTROL_RPC_RESPONSE_SCHEMA,
);
const validateControlInvitationPolicy = controlSchemaAjv.compile(CONTROL_INVITATION_POLICY_SCHEMA);
const validateControlDeviceAuthorizationState = controlSchemaAjv.compile(CONTROL_DEVICE_AUTHORIZATION_STATE_SCHEMA);

export function validateControlInvitationPolicySchemaOrThrow(value: unknown): void {
  assertJcsInput(value);
  if (!validateControlInvitationPolicy(value)) {
    throw new Error(`control-invitation-policy-invalid: ${formatErrors(validateControlInvitationPolicy.errors ?? [])}`);
  }
}

export function validateControlDeviceAuthorizationStateSchemaOrThrow(value: unknown): void {
  assertJcsInput(value);
  if (!validateControlDeviceAuthorizationState(value)) {
    throw new Error(`control-device-authorization-state-invalid: ${formatErrors(validateControlDeviceAuthorizationState.errors ?? [])}`);
  }
}

const credentialContinuitySchemaAjv = new Ajv({
  allErrors: true,
  strict: false,
});
const validateCredentialContinuity = Object.fromEntries(
  CREDENTIAL_CONTINUITY_SCHEMA_FILES.map((file) => [
    file,
    credentialContinuitySchemaAjv.compile(
      CREDENTIAL_CONTINUITY_SCHEMAS[file],
    ),
  ]),
) as Record<
  CredentialContinuitySchemaFile,
  ReturnType<Ajv["compile"]>
>;

export function validateVectorOrThrow(value: unknown): asserts value is Vector {
  if (!validate(value)) {
    throw new Error(formatErrors(validate.errors ?? []));
  }
  validateTraceability(value);
  validateFamilyMetadata(value);
}

function validateTraceability(vector: Vector): void {
  if (!isStrictlySorted(vector.invariants)) {
    throw new Error("invariants must be sorted and unique");
  }
  if (vector.invariants.some((id) => INVARIANT_OWNER.get(id) !== vector.owner_document)) {
    throw new Error("invariant owner must match owner_document");
  }
  if (!isStrictlySorted(vector.reason_codes)) {
    throw new Error("reason_codes must be sorted and unique");
  }
  const expectedReason = vector.expected_output.verdict === "reject"
    ? vector.expected_output.reason_code
    : undefined;
  if (
    expectedReason === undefined && vector.reason_codes.length !== 0
    || typeof expectedReason === "string"
      && (vector.reason_codes.length !== 1 || vector.reason_codes[0] !== expectedReason)
  ) {
    throw new Error("reason_codes must equal the exact expected rejection reason");
  }
}

function isStrictlySorted(values: readonly string[]): boolean {
  return values.every((value, index) => index === 0 || values[index - 1]! < value);
}

export function validateOneTimeInviteSchemaOrThrow(value: unknown): void {
  assertJcsInput(value);
  if (!validateOneTimeInvite(value)) {
    throw new Error(`one-time-invite-invalid: ${formatErrors(validateOneTimeInvite.errors ?? [])}`);
  }
}

export function validateOneTimeInviteResponseSchemaOrThrow(value: unknown): void {
  assertJcsInput(value);
  if (!validateOneTimeInviteResponse(value)) {
    throw new Error(`one-time-invite-response-invalid: ${formatErrors(validateOneTimeInviteResponse.errors ?? [])}`);
  }
}

export function validateRepositoryWriterBindingSchemaOrThrow(
  value: unknown,
): void {
  try {
    jcsCanonicalize(value);
  } catch (error) {
    throw new Error(
      `repository-writer-binding-invalid: ${
        error instanceof Error ? error.message : "invalid JCS value"
      }`,
    );
  }
  if (!validateRepositoryWriterBinding(value)) {
    throw new Error(
      `repository-writer-binding-invalid: ${formatErrors(
        validateRepositoryWriterBinding.errors ?? [],
      )}`,
    );
  }
  const binding = value as Readonly<{
    issued_at: number;
    expires_at: number;
    operations: readonly string[];
  }>;
  if (!Number.isSafeInteger(binding.issued_at) ||
      !Number.isSafeInteger(binding.expires_at) ||
      binding.expires_at <= binding.issued_at) {
    throw new Error(
      "repository-writer-binding-invalid: expires_at must be greater than issued_at and both times must be safe integers",
    );
  }
  if (!isStrictlySorted(binding.operations)) {
    throw new Error(
      "repository-writer-binding-invalid: operations must be sorted and unique",
    );
  }
}

export function validateKeyClaimSchemaOrThrow(value: unknown): void {
  assertJcsInput(value);
  if (!validateKeyClaim(value)) {
    throw new Error(`claim-schema-invalid: ${formatErrors(validateKeyClaim.errors ?? [])}`);
  }
  const claim = value as { issued_at: number; not_before: number; expires_at?: number };
  if (claim.not_before < claim.issued_at) {
    throw new Error("claim-schema-invalid: not_before must be greater than or equal to issued_at");
  }
  if (claim.expires_at !== undefined && claim.expires_at <= claim.not_before) {
    throw new Error("claim-schema-invalid: expires_at must be greater than not_before");
  }
}

export function validateClaimRevocationSchemaOrThrow(value: unknown): void {
  assertJcsInput(value);
  if (!validateClaimRevocation(value)) {
    throw new Error(`claim-schema-invalid: ${formatErrors(validateClaimRevocation.errors ?? [])}`);
  }
  const reasonCode = (value as { reason_code: string }).reason_code;
  if (!REGISTRY_REASON_CODES.includes(reasonCode)) {
    throw new Error(`claim-schema-invalid: reason_code is not registered: ${reasonCode}`);
  }
}

export function validateClaimLedgerRecordSchemaOrThrow(value: unknown): void {
  assertJcsInput(value);
  if (!validateClaimLedgerRecord(value)) {
    throw new Error(`claim-schema-invalid: ${formatErrors(validateClaimLedgerRecord.errors ?? [])}`);
  }
}

export function validateOidcIssuanceRecordSchemaOrThrow(value: unknown): void {
  assertJcsInput(value);
  if (!validateOidcIssuanceRecord(value)) {
    throw new Error(`claim-schema-invalid: ${formatErrors(validateOidcIssuanceRecord.errors ?? [])}`);
  }
}

export function validateOidcIssuerMetadataSchemaOrThrow(value: unknown): void {
  assertJcsInput(value);
  if (!validateOidcIssuerMetadata(value)) {
    throw new Error(`claim-schema-invalid: ${formatErrors(validateOidcIssuerMetadata.errors ?? [])}`);
  }
}

export function validateOidcContinuityManifestSchemaOrThrow(value: unknown): void {
  assertJcsInput(value);
  if (!validateOidcContinuityManifest(value)) {
    throw new Error(`claim-schema-invalid: ${formatErrors(validateOidcContinuityManifest.errors ?? [])}`);
  }
}

export function validateCredentialContinuitySchemaOrThrow(
  file: CredentialContinuitySchemaFile,
  value: unknown,
): void {
  assertJcsInput(value);
  const validator = validateCredentialContinuity[file];
  if (!validator(value)) {
    throw new Error(
      `credential-continuity-schema-invalid: ${formatErrors(
        validator.errors ?? [],
      )}`,
    );
  }
}

export function validateControlFrameSchemaOrThrow(value: unknown): void {
  validateControlSchemaOrThrow(value, validateControlFrame);
}

export function validateControlClientAuthorizationSchemaOrThrow(value: unknown): void {
  validateControlSchemaOrThrow(value, validateControlClientAuthorization);
}

export function validateControlOperationRecordSchemaOrThrow(value: unknown): void {
  validateControlSchemaOrThrow(value, validateControlOperationRecord);
}

export function validateControlEpochRegistrationSchemaOrThrow(value: unknown): void {
  validateControlSchemaOrThrow(value, validateControlEpochRegistration);
}

export function validateControlPreparedActivationSchemaOrThrow(value: unknown): void {
  validateControlSchemaOrThrow(value, validateControlPreparedActivation);
}

export function validateControlRecoveryGrantSchemaOrThrow(value: unknown): void {
  validateControlSchemaOrThrow(value, validateControlRecoveryGrant);
}

export function validateControlRecoveryCompletionSchemaOrThrow(value: unknown): void {
  validateControlSchemaOrThrow(value, validateControlRecoveryCompletion);
}

export function validateControlSftpGrantSchemaOrThrow(value: unknown): void {
  validateControlSchemaOrThrow(value, validateControlSftpGrant);
}

export function validateControlCapabilitySetSchemaOrThrow(value: unknown): void {
  validateControlSchemaOrThrow(value, validateControlCapabilitySet);
  const names = (value as { tools: Array<{ name: string }> }).tools.map(
    ({ name }) => name,
  );
  if (new Set(names).size !== names.length) {
    throw new Error(
      "control-schema-invalid: capability tool names must be unique",
    );
  }
}

export function validateControlMcpFrameSchemaOrThrow(value: unknown): void {
  validateControlSchemaOrThrow(value, validateControlMcpFrame);
}

export function validateControlRpcRequestSchemaOrThrow(value: unknown): void {
  validateControlSchemaOrThrow(value, validateControlRpcRequest);
}

export function validateControlRpcResponseSchemaOrThrow(value: unknown): void {
  validateControlSchemaOrThrow(value, validateControlRpcResponse);
}

function validateControlSchemaOrThrow(
  value: unknown,
  validator: {
    (data: unknown): boolean;
    errors?: ErrorObject[] | null;
  },
): void {
  try {
    jcsCanonicalize(value);
  } catch (error) {
    throw new Error(
      `control-schema-invalid: ${
        error instanceof Error ? error.message : "invalid JCS value"
      }`,
    );
  }
  if (!validator(value)) {
    throw new Error(
      `control-schema-invalid: ${formatErrors(validator.errors ?? [])}`,
    );
  }
}

function assertJcsInput(value: unknown): void {
  try {
    jcsCanonicalize(value);
  } catch (error) {
    throw new Error(`claim-schema-invalid: ${error instanceof Error ? error.message : "invalid JCS value"}`);
  }
}

function validateFamilyMetadata(vector: Vector): void {
  assertCurrentFamilyVersion(vector.spec_version);
  // Anchors are prefixed with their owning document, so a reference outside
  // the owner's layering closure is detectable from the anchor alone.
  const allowed = new Set<string>([
    vector.owner_document,
    ...DOCUMENT_LAYERING[vector.owner_document],
  ]);
  for (const ref of vector.spec_refs) {
    const anchor = /#([a-z0-9]+(?:-[a-z0-9]+)*)$/.exec(ref)?.[1];
    const referencedDocument = anchor?.split("-", 1)[0];
    if (referencedDocument === undefined || !allowed.has(referencedDocument)) {
      throw new Error(`spec_ref is outside the owner layering closure: ${ref}`);
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
