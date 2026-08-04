export type CredentialLedgerBinding = {
  credential_ledger_persona: string;
  credential_ledger_generation: number;
};

export type CredentialGenerationDraftReason =
  | "credential_generation_missing"
  | "credential_roster_empty"
  | "credential_ledger_persona_mismatch"
  | "credential_generation_stale"
  | "credential_checkpoint_stale_kel"
  | "credential_checkpoint_invalid"
  | "credential_reset_invalid"
  | "credential_schema_invalid";

export type CredentialGenerationDecision =
  | { valid: true; reason_code: null }
  | { valid: false; reason_code: CredentialGenerationDraftReason };

export type CredentialGenerationValidationOptions = {
  current_kel?: boolean;
  checkpoint_valid?: boolean;
  reset_valid?: boolean;
};

const PERSONA = /^[0-9a-f]{64}$/;
const MAX_SAFE = 9_007_199_254_740_991;

export function evaluateCredentialGeneration(
  artifact: unknown,
  expected: CredentialLedgerBinding,
  options: CredentialGenerationValidationOptions = {},
): CredentialGenerationDecision {
  if (!isPlainObject(artifact)) return invalid("credential_schema_invalid");
  if (!Object.prototype.hasOwnProperty.call(artifact, "credential_ledger_generation")) {
    return invalid("credential_generation_missing");
  }
  const generation = artifact.credential_ledger_generation;
  const persona = artifact.credential_ledger_persona;
  if (!isBinding(expected) || !PERSONA.test(String(persona)) || !isGeneration(generation) ||
      (Object.prototype.hasOwnProperty.call(artifact, "node_roster") && !Array.isArray(artifact.node_roster))) {
    return invalid("credential_schema_invalid");
  }
  if (Array.isArray(artifact.node_roster) && artifact.node_roster.length === 0) {
    return invalid("credential_roster_empty");
  }
  if (persona !== expected.credential_ledger_persona) {
    return invalid("credential_ledger_persona_mismatch");
  }
  if (generation !== expected.credential_ledger_generation) {
    return invalid("credential_generation_stale");
  }
  if (options.current_kel === false) return invalid("credential_checkpoint_stale_kel");
  if (options.checkpoint_valid === false) return invalid("credential_checkpoint_invalid");
  if (options.reset_valid === false) return invalid("credential_reset_invalid");
  return { valid: true, reason_code: null };
}

export function assertCurrentCredentialGeneration(
  artifact: unknown,
  expected: CredentialLedgerBinding,
  options?: CredentialGenerationValidationOptions,
): asserts artifact is CredentialLedgerBinding {
  const decision = evaluateCredentialGeneration(artifact, expected, options);
  if (!decision.valid) throw new Error(decision.reason_code);
}

export function purgePriorGenerationTransactions<
  T extends CredentialLedgerBinding & { id: string },
>(
  transactions: readonly T[],
  current: CredentialLedgerBinding,
): {
  retained: T[];
  purged_ids: string[];
  requires_authority_reissue: true;
  requires_status_reissue: true;
} {
  const retained: T[] = [];
  const purgedIds: string[] = [];
  for (const transaction of transactions) {
    const decision = evaluateCredentialGeneration(transaction, current);
    if (decision.valid) retained.push(transaction);
    else purgedIds.push(transaction.id);
  }
  return {
    retained,
    purged_ids: purgedIds.sort(),
    requires_authority_reissue: true,
    requires_status_reissue: true,
  };
}

export function isCredentialLedgerBinding(value: unknown): value is CredentialLedgerBinding {
  return isPlainObject(value) &&
    PERSONA.test(String(value.credential_ledger_persona)) &&
    isGeneration(value.credential_ledger_generation);
}

function isBinding(value: CredentialLedgerBinding): boolean {
  return PERSONA.test(value.credential_ledger_persona) &&
    isGeneration(value.credential_ledger_generation);
}

function isGeneration(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && value <= MAX_SAFE;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function invalid(reason_code: CredentialGenerationDraftReason): CredentialGenerationDecision {
  return { valid: false, reason_code };
}
