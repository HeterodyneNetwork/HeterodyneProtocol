import { createHash } from "node:crypto";
import { jcsCanonicalize } from "./jcs.js";

const HEX16 = /^[0-9a-f]{32}$/;
const HEX20 = /^[0-9a-f]{40}$/;
const HEX32 = /^[0-9a-f]{64}$/;
const SAFE_INTEGER_MAX = Number.MAX_SAFE_INTEGER;
const CANONICAL_NID = /^did:key:z[1-9A-HJ-NP-Za-km-z]+$/;
const BASE64URL = /^[A-Za-z0-9_-]*$/;

export const SECRET_CLASSES = [
  "cold-root",
  "epoch",
  "device-signing",
  "agent-signing",
  "core-protected",
  "config-audience",
  "tier3-audience",
  "claim-ledger-audience",
  "object-dek",
  "double-ratchet",
  "radicle-access",
  "oauth-signing",
  "oauth-pairwise",
  "bearer-credential",
  "ssh-client",
  "ssh-host",
  "recovery-wrap",
  "onion-service-identity",
  "tls-serving",
] as const;

export type SecretClass = (typeof SECRET_CLASSES)[number];
export type TypedGitObject = {
  object_format: "sha1" | "sha256";
  oid: string;
};
export type KelHead = { event_id: string; seq: number };
export type SecretTuple = {
  secret_class: SecretClass;
  secret_id: string;
  instance_commitment: string;
};

export function domainSeparatedJcsDigest(
  domain: string,
  value: unknown,
): string {
  if (domain.length === 0 || domain.includes("\0")) {
    throw new Error("credential-domain-invalid: domain must be nonempty and NUL-free");
  }
  return sha256Hex(
    concatBytes(
      new TextEncoder().encode(domain),
      Uint8Array.of(0),
      new TextEncoder().encode(jcsCanonicalize(value)),
    ),
  );
}

export function validateSecretInstance(input: {
  secret_class: SecretClass;
  secret_id: string;
  secret_bytes: Uint8Array;
}): { secret_id: string; instance_commitment: string } {
  if (!SECRET_CLASSES.includes(input.secret_class)) {
    throw new Error("credential-secret-class-invalid");
  }
  if (
    input.secret_class === "config-audience" &&
    !HEX16.test(input.secret_id)
  ) {
    throw new Error(
      "credential-secret-id-invalid: config-audience requires 32 lowercase hexadecimal characters",
    );
  }
  if (
    input.secret_class !== "config-audience" &&
    !HEX32.test(input.secret_id)
  ) {
    throw new Error(
      "credential-secret-id-invalid: generic secret IDs require 64 lowercase hexadecimal characters",
    );
  }
  if (!(input.secret_bytes instanceof Uint8Array)) {
    throw new Error("credential-secret-bytes-invalid");
  }
  return {
    secret_id: input.secret_id,
    instance_commitment: sha256Hex(
      concatBytes(
        new TextEncoder().encode("heterodyne-node-secret-instance-v1"),
        Uint8Array.of(0),
        input.secret_bytes,
      ),
    ),
  };
}

export type SecretSource = SecretTuple & {
  record_digest: string;
  persona: string;
  holder_nid: string;
};

export type SecretAssignment = {
  record_digest: string;
  assignment_id: string;
  action: "assign" | "retire";
  holder_nid: string;
  secret_class: SecretClass;
  secret_id: string;
  secret_commitment: string;
  source_record_digest: string;
  transition_id: string | null;
  supersedes: string | null;
};

export type ExposureItem = {
  secret_class: SecretClass;
  secret_id: string;
  secret_commitment: string;
  holder_nids: string[];
  assignment_record_digests: string[];
};

export function replayExposureSet(input: {
  sources: SecretSource[];
  assignments: SecretAssignment[];
  accepted_transition_ids: string[];
}): {
  items: ExposureItem[];
  conflicted_assignment_ids: string[];
  operational_assignment_ids: string[];
} {
  const sources = new Map<string, SecretSource>();
  for (const candidate of input.sources) {
    assertHex32(candidate.record_digest, "source record digest");
    assertHex32(candidate.persona, "source persona");
    assertCanonicalNid(candidate.holder_nid);
    assertSecretId(candidate.secret_class, candidate.secret_id);
    assertHex32(candidate.instance_commitment, "source commitment");
    const prior = sources.get(candidate.record_digest);
    if (
      prior !== undefined &&
      jcsCanonicalize(prior) !== jcsCanonicalize(candidate)
    ) {
      throw new Error("credential-source-digest-collision");
    }
    sources.set(candidate.record_digest, candidate);
  }

  const acceptedTransitions = new Set(input.accepted_transition_ids);
  for (const id of acceptedTransitions) {
    assertHex16(id, "accepted transition id");
  }

  const assignsByDigest = new Map<string, SecretAssignment>();
  const assignsById = new Map<string, SecretAssignment[]>();
  const retirements: SecretAssignment[] = [];
  for (const candidate of input.assignments) {
    validateAssignmentShape(candidate);
    if (candidate.action === "assign") {
      if (candidate.supersedes !== null) {
        throw new Error("credential-assignment-invalid: assign supersedes must be null");
      }
      const source = sources.get(candidate.source_record_digest);
      if (source === undefined) {
        throw new Error("credential-assignment-source-missing");
      }
      if (
        source.holder_nid !== candidate.holder_nid ||
        source.secret_class !== candidate.secret_class ||
        source.secret_id !== candidate.secret_id ||
        source.instance_commitment !== candidate.secret_commitment
      ) {
        throw new Error("credential-assignment source tuple mismatch");
      }
      const prior = assignsByDigest.get(candidate.record_digest);
      if (
        prior !== undefined &&
        jcsCanonicalize(prior) !== jcsCanonicalize(candidate)
      ) {
        throw new Error("credential-assignment-digest-collision");
      }
      assignsByDigest.set(candidate.record_digest, candidate);
      const variants = assignsById.get(candidate.assignment_id) ?? [];
      if (
        !variants.some(
          (variant) =>
            jcsCanonicalize(variant) === jcsCanonicalize(candidate),
        )
      ) {
        variants.push(candidate);
      }
      assignsById.set(candidate.assignment_id, variants);
    } else {
      retirements.push(candidate);
    }
  }

  const retiredDigests = new Set<string>();
  for (const retirement of retirements) {
    if (
      retirement.transition_id === null ||
      !acceptedTransitions.has(retirement.transition_id)
    ) {
      continue;
    }
    if (retirement.supersedes === null) {
      throw new Error("credential-retirement-invalid: supersedes is required");
    }
    const assigned = assignsByDigest.get(retirement.supersedes);
    if (assigned === undefined) {
      throw new Error("credential-retirement-invalid: assign is missing");
    }
    if (
      retirement.assignment_id !== assigned.assignment_id ||
      retirement.holder_nid !== assigned.holder_nid ||
      retirement.secret_class !== assigned.secret_class ||
      retirement.secret_id !== assigned.secret_id ||
      retirement.secret_commitment !== assigned.secret_commitment ||
      retirement.source_record_digest !== assigned.source_record_digest
    ) {
      throw new Error("credential-retirement-invalid: tuple mismatch");
    }
    retiredDigests.add(assigned.record_digest);
  }

  const conflicts = [...assignsById.entries()]
    .filter(([, variants]) => variants.length > 1)
    .map(([id]) => id)
    .sort(compareHex);
  const conflictSet = new Set(conflicts);
  const active = [...assignsByDigest.values()].filter(
    (candidate) => !retiredDigests.has(candidate.record_digest),
  );
  const grouped = new Map<string, ExposureItem>();
  for (const candidate of active) {
    const key = [
      candidate.secret_class,
      candidate.secret_id,
      candidate.secret_commitment,
    ].join("\0");
    const item = grouped.get(key) ?? {
      secret_class: candidate.secret_class,
      secret_id: candidate.secret_id,
      secret_commitment: candidate.secret_commitment,
      holder_nids: [],
      assignment_record_digests: [],
    };
    item.holder_nids.push(candidate.holder_nid);
    item.assignment_record_digests.push(candidate.record_digest);
    grouped.set(key, item);
  }
  const items = [...grouped.values()]
    .map((item) => ({
      ...item,
      holder_nids: uniqueSorted(item.holder_nids, compareUtf8),
      assignment_record_digests: uniqueSorted(
        item.assignment_record_digests,
        compareHex,
      ),
    }))
    .sort(compareExposure);
  const operational = active
    .filter((candidate) => !conflictSet.has(candidate.assignment_id))
    .map(({ assignment_id }) => assignment_id);
  return {
    items,
    conflicted_assignment_ids: conflicts,
    operational_assignment_ids: uniqueSorted(operational, compareHex),
  };
}

export type CredentialCheckpoint = {
  persona: string;
  generation?: number;
  sequence: number;
  previous_checkpoint: string | null;
  generation_transition: string | null;
  node_roster: string[];
  config_key_id: string;
  config_key_sha256: string;
  pairwise_secret_sha256: string;
  exposure_set_sha256: string;
  governed_decrypt_key_bindings_sha256: string;
  historical_decrypt_obligations_sha256: string;
  epoch_pubkey: string;
  kel_head: KelHead;
};

export type CheckpointCandidateInput = {
  candidate: CredentialCheckpoint;
  candidate_digest: string;
  predecessor: CredentialCheckpoint | null;
  predecessor_digest: string | null;
  expected_persona: string;
  current_generation: number;
  current_epoch: { epoch_pubkey: string; kel_head: KelHead };
  active_delegation_nids: string[];
  receipt_nids: string[];
  recomputed: Pick<
    CredentialCheckpoint,
    | "exposure_set_sha256"
    | "governed_decrypt_key_bindings_sha256"
    | "historical_decrypt_obligations_sha256"
  >;
  operational_pairwise_tuples: Array<{
    secret_id: string;
    instance_commitment: string;
  }>;
  operational_epoch_tuples: Array<{
    secret_id: string;
    instance_commitment: string;
  }>;
  mutation_after_basis: boolean;
  reset_valid?: boolean;
};

export type CredentialContinuityDraftReason =
  | "credential_generation_missing"
  | "credential_roster_empty"
  | "credential_ledger_persona_mismatch"
  | "credential_generation_stale"
  | "credential_checkpoint_stale_kel"
  | "credential_checkpoint_invalid"
  | "credential_reset_invalid";

export function evaluateCheckpointCandidate(
  input: CheckpointCandidateInput,
):
  | {
      verdict: "accept";
      continuity: "genesis" | "same-generation" | "reset";
    }
  | { verdict: "reject"; reason: CredentialContinuityDraftReason } {
  const candidate = input.candidate;
  if (candidate.generation === undefined) {
    return { verdict: "reject", reason: "credential_generation_missing" };
  }
  if (
    !Number.isSafeInteger(candidate.generation) ||
    candidate.generation < 0 ||
    candidate.generation > SAFE_INTEGER_MAX ||
    !Array.isArray(candidate.node_roster)
  ) {
    return { verdict: "reject", reason: "credential_checkpoint_invalid" };
  }
  if (candidate.node_roster.length === 0) {
    return { verdict: "reject", reason: "credential_roster_empty" };
  }
  try {
    validateCheckpointShape(candidate);
    assertHex32(input.candidate_digest, "checkpoint digest");
  } catch {
    return { verdict: "reject", reason: "credential_checkpoint_invalid" };
  }
  if (candidate.persona !== input.expected_persona) {
    return {
      verdict: "reject",
      reason: "credential_ledger_persona_mismatch",
    };
  }
  if (candidate.generation !== input.current_generation) {
    return { verdict: "reject", reason: "credential_generation_stale" };
  }
  if (
    candidate.epoch_pubkey !== input.current_epoch.epoch_pubkey ||
    !equalKelHead(candidate.kel_head, input.current_epoch.kel_head)
  ) {
    return {
      verdict: "reject",
      reason: "credential_checkpoint_stale_kel",
    };
  }

  let continuity: "genesis" | "same-generation" | "reset";
  if (
    input.predecessor === null &&
    input.predecessor_digest === null &&
    candidate.generation === 0 &&
    candidate.sequence === 0 &&
    candidate.previous_checkpoint === null &&
    candidate.generation_transition === null
  ) {
    continuity = "genesis";
  } else if (
    input.predecessor !== null &&
    input.predecessor_digest !== null &&
    candidate.generation === input.predecessor.generation &&
    candidate.sequence === input.predecessor.sequence + 1 &&
    candidate.previous_checkpoint === input.predecessor_digest &&
    candidate.generation_transition === null
  ) {
    continuity = "same-generation";
  } else if (
    input.predecessor !== null &&
    input.predecessor_digest !== null &&
    input.predecessor.generation !== undefined &&
    candidate.generation === input.predecessor.generation + 1 &&
    candidate.sequence === 0 &&
    candidate.previous_checkpoint === null &&
    candidate.generation_transition !== null &&
    HEX32.test(candidate.generation_transition)
  ) {
    continuity = "reset";
  } else {
    return { verdict: "reject", reason: "credential_checkpoint_invalid" };
  }

  const roster = candidate.node_roster;
  if (!isSortedUnique(roster, compareUtf8)) {
    return { verdict: "reject", reason: "credential_checkpoint_invalid" };
  }
  for (const nid of roster) {
    if (!CANONICAL_NID.test(nid)) {
      return { verdict: "reject", reason: "credential_checkpoint_invalid" };
    }
  }
  if (
    !sameStringSet(roster, input.active_delegation_nids) ||
    !sameStringSet(roster, input.receipt_nids)
  ) {
    return { verdict: "reject", reason: "credential_checkpoint_invalid" };
  }
  if (
    input.recomputed.exposure_set_sha256 !== candidate.exposure_set_sha256 ||
    input.recomputed.governed_decrypt_key_bindings_sha256 !==
      candidate.governed_decrypt_key_bindings_sha256 ||
    input.recomputed.historical_decrypt_obligations_sha256 !==
      candidate.historical_decrypt_obligations_sha256 ||
    input.mutation_after_basis
  ) {
    return { verdict: "reject", reason: "credential_checkpoint_invalid" };
  }
  if (
    input.operational_pairwise_tuples.length !== 1 ||
    input.operational_pairwise_tuples[0]?.instance_commitment !==
      candidate.pairwise_secret_sha256
  ) {
    return { verdict: "reject", reason: "credential_checkpoint_invalid" };
  }
  const expectedEpochCommitment = domainSeparatedJcsDigest(
    "heterodyne-node-secret-instance-v1",
    {
      epoch_pubkey: candidate.epoch_pubkey,
      kel_head: candidate.kel_head,
    },
  );
  if (
    input.operational_epoch_tuples.length !== 1 ||
    input.operational_epoch_tuples[0]?.secret_id !== candidate.epoch_pubkey ||
    input.operational_epoch_tuples[0]?.instance_commitment !==
      expectedEpochCommitment
  ) {
    return { verdict: "reject", reason: "credential_checkpoint_invalid" };
  }
  if (continuity === "reset" && input.reset_valid === false) {
    return { verdict: "reject", reason: "credential_reset_invalid" };
  }
  return { verdict: "accept", continuity };
}

export type RepositoryRetentionRef = {
  repository_ref_id: string;
  repository_class: "config" | "private" | "public";
  repository_rid: string;
  ref_name: string;
  object_format: "sha1" | "sha256";
  retired: boolean;
  scan_head: TypedGitObject;
};

export type RetentionInventoryRecord = {
  record_digest: string;
  inventory_sequence: number;
  previous_records: Array<{
    inventory_sequence: number;
    record_digest: string;
  }>;
  basis_checkpoint_digest: string | null;
  target_generation: number;
  target_sequence: number;
  repository_refs: RepositoryRetentionRef[];
};

export function evaluateRetentionInventory(input: {
  parents: RetentionInventoryRecord[];
  candidate: RetentionInventoryRecord;
  activated_generation: number;
  activated_sequence: number;
  is_descendant_or_equal: (
    candidate: TypedGitObject,
    prior: TypedGitObject,
  ) => boolean;
  config_deregistration?: {
    old_repository_ref_ids: string[];
    new_repository_ref_id: string;
  };
}):
  | { verdict: "accept"; effective_refs: RepositoryRetentionRef[] }
  | { verdict: "reject"; reason: string } {
  try {
    validateInventoryRecord(input.candidate);
    for (const parent of input.parents) validateInventoryRecord(parent);
  } catch (error) {
    return { verdict: "reject", reason: errorMessage(error) };
  }
  const candidate = input.candidate;
  if (
    candidate.target_generation !== input.activated_generation ||
    candidate.target_sequence !== input.activated_sequence
  ) {
    return { verdict: "reject", reason: "inventory-target-mismatch" };
  }
  if (input.parents.length === 0) {
    if (
      candidate.inventory_sequence !== 0 ||
      candidate.previous_records.length !== 0 ||
      candidate.basis_checkpoint_digest !== null ||
      candidate.target_generation !== 0 ||
      candidate.target_sequence !== 0
    ) {
      return { verdict: "reject", reason: "inventory-genesis-invalid" };
    }
  } else {
    const maximum = Math.max(
      ...input.parents.map(({ inventory_sequence }) => inventory_sequence),
    );
    if (
      candidate.inventory_sequence !== maximum + 1 ||
      candidate.basis_checkpoint_digest === null
    ) {
      return { verdict: "reject", reason: "inventory-sequence-invalid" };
    }
    const expectedParents = input.parents
      .map(({ inventory_sequence, record_digest }) => ({
        inventory_sequence,
        record_digest,
      }))
      .sort(compareInventoryParent);
    if (
      jcsCanonicalize(candidate.previous_records) !==
      jcsCanonicalize(expectedParents)
    ) {
      return {
        verdict: "reject",
        reason: "inventory-parent-frontier-incomplete",
      };
    }
  }

  const candidateById = new Map(
    candidate.repository_refs.map((entry) => [entry.repository_ref_id, entry]),
  );
  const oldDeregistered = input.config_deregistration?.old_repository_ref_ids;
  const newRegistered = input.config_deregistration?.new_repository_ref_id;
  const oldDeregisteredSet = new Set(oldDeregistered ?? []);
  const newRegisteredRef =
    newRegistered === undefined ? undefined : candidateById.get(newRegistered);
  if (
    (oldDeregistered === undefined) !== (newRegistered === undefined) ||
    (oldDeregistered !== undefined &&
      (oldDeregistered.length === 0 ||
        !isSortedUnique(oldDeregistered, compareHex) ||
        oldDeregistered.some((id) => !HEX32.test(id) || candidateById.has(id)))) ||
    (newRegistered !== undefined &&
      newRegisteredRef?.repository_class !== "config")
  ) {
    return { verdict: "reject", reason: "inventory-config-deregistration-invalid" };
  }
  const observedDeregistered = new Set<string>();
  for (const parent of input.parents) {
    for (const previous of parent.repository_refs) {
      const next = candidateById.get(previous.repository_ref_id);
      if (next === undefined) {
        if (
          !oldDeregisteredSet.has(previous.repository_ref_id) ||
          previous.repository_class !== "config"
        ) {
          return { verdict: "reject", reason: "inventory-row-omitted" };
        }
        observedDeregistered.add(previous.repository_ref_id);
        continue;
      }
      if (!sameRetentionIdentity(previous, next)) {
        return { verdict: "reject", reason: "inventory-row-identity-changed" };
      }
      if (previous.retired && !next.retired) {
        return { verdict: "reject", reason: "inventory-retirement-reactivated" };
      }
      if (!input.is_descendant_or_equal(next.scan_head, previous.scan_head)) {
        return { verdict: "reject", reason: "inventory-scan-head-regression" };
      }
    }
  }
  if (
    oldDeregistered !== undefined &&
    !sameStringSet([...observedDeregistered], oldDeregistered)
  ) {
    return { verdict: "reject", reason: "inventory-config-deregistration-invalid" };
  }
  return {
    verdict: "accept",
    effective_refs: [...candidate.repository_refs],
  };
}

export type RetainedCiphertextLocator = {
  storage_class: string;
  owner: string;
  repository_rid: string;
  repository_head: TypedGitObject;
  ref_name: string;
  path: string;
  git_blob_oid: TypedGitObject;
  object_id: string | null;
  ciphertext_sha256: string;
  ciphertext_length: number;
};

export type HistoricalObligationRecord = SecretTuple & {
  record_digest: string;
  obligation_id: string;
  lineage_sequence: number;
  previous_record: string | null;
  action: "retain" | "close";
  retained_ciphertexts: RetainedCiphertextLocator[];
  retired_provenance_lineages: unknown[];
};

export function evaluateHistoricalObligations(input: {
  records: HistoricalObligationRecord[];
  governed_dependencies: Array<{
    locator: RetainedCiphertextLocator;
    tuple: SecretTuple;
  }>;
  ordinary_acceptance: boolean;
}):
  | {
      verdict: "accept";
      active_obligations: string[];
      frontier_digest: string;
    }
  | { verdict: "reject"; reason: string } {
  const byDigest = new Map<string, HistoricalObligationRecord>();
  const byId = new Map<string, HistoricalObligationRecord[]>();
  try {
    for (const record of input.records) {
      validateObligationRecord(record);
      byDigest.set(record.record_digest, record);
      const lineage = byId.get(record.obligation_id) ?? [];
      lineage.push(record);
      byId.set(record.obligation_id, lineage);
    }
  } catch (error) {
    return { verdict: "reject", reason: errorMessage(error) };
  }

  const active: HistoricalObligationRecord[] = [];
  const frontier: Array<{
    obligation_id: string;
    lineage_sequence: number;
    action: "retain" | "close";
    record_digest: string;
  }> = [];
  for (const [obligationId, records] of byId) {
    const childDigests = new Set(
      records
        .map(({ previous_record }) => previous_record)
        .filter((digest): digest is string => digest !== null),
    );
    for (const record of records) {
      if (record.lineage_sequence === 0) {
        if (record.previous_record !== null || record.action !== "retain") {
          return { verdict: "reject", reason: "obligation-root-invalid" };
        }
      } else {
        const previous =
          record.previous_record === null
            ? undefined
            : byDigest.get(record.previous_record);
        if (
          previous === undefined ||
          previous.obligation_id !== obligationId ||
          record.lineage_sequence !== previous.lineage_sequence + 1
        ) {
          return { verdict: "reject", reason: "obligation-lineage-invalid" };
        }
        if (previous.action === "close") {
          return { verdict: "reject", reason: "obligation-close-not-absorbing" };
        }
      }
    }
    const maxima = records.filter(
      ({ record_digest }) => !childDigests.has(record_digest),
    );
    if (maxima.length !== 1 && input.ordinary_acceptance) {
      return { verdict: "reject", reason: "fork" };
    }
    for (const maximum of maxima) {
      frontier.push({
        obligation_id: maximum.obligation_id,
        lineage_sequence: maximum.lineage_sequence,
        action: maximum.action,
        record_digest: maximum.record_digest,
      });
      if (maximum.action === "retain") active.push(maximum);
    }
  }

  const obligationPairs: string[] = [];
  const coveredLocators = new Set<string>();
  for (const record of active) {
    for (const locator of record.retained_ciphertexts) {
      const locatorKey = jcsCanonicalize(locator);
      if (coveredLocators.has(locatorKey)) {
        return { verdict: "reject", reason: "obligation-duplicate-coverage" };
      }
      coveredLocators.add(locatorKey);
      obligationPairs.push(
        jcsCanonicalize({
          locator,
          tuple: {
            secret_class: record.secret_class,
            secret_id: record.secret_id,
            instance_commitment: record.instance_commitment,
          },
        }),
      );
    }
  }
  const governedPairs = input.governed_dependencies.map(({ locator, tuple }) =>
    jcsCanonicalize({ locator, tuple }),
  );
  obligationPairs.sort(compareUtf8);
  governedPairs.sort(compareUtf8);
  if (jcsCanonicalize(obligationPairs) !== jcsCanonicalize(governedPairs)) {
    return { verdict: "reject", reason: "governed-obligation-mismatch" };
  }
  frontier.sort(compareObligationFrontier);
  return {
    verdict: "accept",
    active_obligations: active
      .map(({ record_digest }) => record_digest)
      .sort(compareHex),
    frontier_digest: domainSeparatedJcsDigest(
      "heterodyne-historical-decrypt-obligation-set-v1",
      frontier,
    ),
  };
}

export type SecretTransitionMode =
  | "routine-key-rotation"
  | "routine-addition"
  | "routine-removal"
  | "emergency-reset";

export function evaluateSecretTransition(input: {
  mode: SecretTransitionMode;
  old_roster: string[];
  new_roster: string[];
  added_nids: string[];
  removed_nids: string[];
  exposure_classes: SecretClass[];
  action_classes: SecretClass[];
  removal_observation_nids: string[];
  transition_authority: "epoch" | "cold-root";
}):
  | {
      verdict: "accept";
      required_authority: "epoch" | "cold-root";
    }
  | {
      verdict: "reject";
      reason: string;
      required_authority: "epoch" | "cold-root";
    } {
  const requiredAuthority =
    input.mode === "emergency-reset" ||
    input.exposure_classes.some((value) =>
      ["epoch", "core-protected", "recovery-wrap"].includes(value),
    )
      ? "cold-root"
      : "epoch";
  if (input.exposure_classes.includes("cold-root")) {
    return {
      verdict: "reject",
      reason: "persona-migration-required",
      required_authority: "cold-root",
    };
  }
  if (
    !isSortedUnique(input.old_roster, compareUtf8) ||
    !isSortedUnique(input.new_roster, compareUtf8)
  ) {
    return {
      verdict: "reject",
      reason: "transition-roster-invalid",
      required_authority: requiredAuthority,
    };
  }
  const expectedAdded = setDifference(input.new_roster, input.old_roster);
  const expectedRemoved = setDifference(input.old_roster, input.new_roster);
  if (
    !sameStringSet(expectedAdded, input.added_nids) ||
    !sameStringSet(expectedRemoved, input.removed_nids)
  ) {
    return {
      verdict: "reject",
      reason: "transition-roster-delta-invalid",
      required_authority: requiredAuthority,
    };
  }
  if (
    (input.mode === "routine-key-rotation" &&
      (expectedAdded.length !== 0 || expectedRemoved.length !== 0)) ||
    (input.mode === "routine-addition" &&
      (expectedAdded.length === 0 || expectedRemoved.length !== 0)) ||
    (input.mode === "routine-removal" &&
      (expectedRemoved.length === 0 || expectedAdded.length !== 0))
  ) {
    return {
      verdict: "reject",
      reason: "transition-mode-invalid",
      required_authority: requiredAuthority,
    };
  }
  const mandatory: SecretClass[] =
    input.mode === "routine-key-rotation"
      ? ["config-audience"]
      : input.mode === "routine-addition" ||
          input.mode === "routine-removal"
        ? ["config-audience", "oauth-pairwise"]
        : [];
  const exposures = uniqueSorted(input.exposure_classes, compareUtf8);
  const actions = uniqueSorted(input.action_classes, compareUtf8);
  if (
    mandatory.some((value) => !exposures.includes(value)) ||
    jcsCanonicalize(exposures) !== jcsCanonicalize(actions)
  ) {
    return {
      verdict: "reject",
      reason: "transition-action-incomplete",
      required_authority: requiredAuthority,
    };
  }
  if (
    input.mode === "routine-removal" &&
    !sameStringSet(input.removed_nids, input.removal_observation_nids)
  ) {
    return {
      verdict: "reject",
      reason: "transition-removal-observation-incomplete",
      required_authority: requiredAuthority,
    };
  }
  if (input.transition_authority !== requiredAuthority) {
    return {
      verdict: "reject",
      reason: "transition-authority-invalid",
      required_authority: requiredAuthority,
    };
  }
  return { verdict: "accept", required_authority: requiredAuthority };
}

export type CandidateState = {
  status: "pending" | "accepted" | "abandoned" | "reset";
  tip: string;
  partial_record_digests: string[];
};

export type CandidateOperation =
  | {
      kind: "append";
      expected_tip: string;
      new_tip: string;
      record_digests: string[];
    }
  | {
      kind: "accept" | "abandon" | "reset";
      expected_tip: string;
      new_tip: string;
    };

export function advanceCandidate(
  state: CandidateState,
  operation: CandidateOperation,
): CandidateState {
  if (state.status !== "pending") {
    throw new Error("credential-candidate-terminal");
  }
  if (operation.expected_tip !== state.tip) {
    throw new Error("credential-candidate-stale-tip");
  }
  if (operation.new_tip === state.tip) {
    throw new Error("credential-candidate-tip-must-advance");
  }
  assertGitOid(operation.new_tip, "candidate new tip");
  if (operation.kind === "append") {
    if (operation.record_digests.length === 0) {
      throw new Error("credential-candidate-append-empty");
    }
    for (const digest of operation.record_digests) {
      assertHex32(digest, "candidate record digest");
      if (state.partial_record_digests.includes(digest)) {
        throw new Error("credential-candidate-record-already-reachable");
      }
    }
    return {
      status: "pending",
      tip: operation.new_tip,
      partial_record_digests: uniqueSorted(
        [...state.partial_record_digests, ...operation.record_digests],
        compareHex,
      ),
    };
  }
  return {
    status:
      operation.kind === "accept"
        ? "accepted"
        : operation.kind === "abandon"
          ? "abandoned"
          : "reset",
    tip: operation.new_tip,
    partial_record_digests: [...state.partial_record_digests],
  };
}

export function selectDrTombstoneReason(input: {
  old_holder_nids: string[];
  removed_nids: string[];
}): "persona_node_removed" | "candidate_material_retired" {
  const removed = new Set(input.removed_nids);
  return input.old_holder_nids.some((nid) => removed.has(nid))
    ? "persona_node_removed"
    : "candidate_material_retired";
}

export type ConfigGitProjection = {
  type: "heterodyne.config-repository-git-structure.v1";
  object_format: "sha1" | "sha256";
  commit_oid: string;
  commit_raw_base64url: string;
  tree_objects: Array<{ oid: string; raw_base64url: string }>;
};

export function validateConfigGitProjection(
  input: ConfigGitProjection,
): {
  kind: "ordinary" | "retention-resolution";
  parent_oids: string[];
  tree_oid: string;
} {
  if (input.type !== "heterodyne.config-repository-git-structure.v1") {
    throw new Error("config-git-profile-invalid");
  }
  assertObjectOid(input.object_format, input.commit_oid, "commit oid");
  const commitRaw = decodeCanonicalBase64url(input.commit_raw_base64url);
  if (
    gitObjectOid(input.object_format, "commit", commitRaw) !== input.commit_oid
  ) {
    throw new Error("config-git commit object id mismatch");
  }
  if (
    !isSortedUnique(
      input.tree_objects.map(({ oid }) => oid),
      compareHex,
    )
  ) {
    throw new Error("config-git tree objects must be sorted and unique");
  }
  const trees = new Map<string, Uint8Array>();
  for (const tree of input.tree_objects) {
    assertObjectOid(input.object_format, tree.oid, "tree oid");
    const raw = decodeCanonicalBase64url(tree.raw_base64url);
    if (gitObjectOid(input.object_format, "tree", raw) !== tree.oid) {
      throw new Error("config-git tree object id mismatch");
    }
    trees.set(tree.oid, raw);
  }

  const commitText = new TextDecoder("utf-8", { fatal: true }).decode(commitRaw);
  const separator = commitText.indexOf("\n\n");
  if (separator < 0) throw new Error("config-git commit separator missing");
  const headers = commitText.slice(0, separator).split("\n");
  const message = commitText.slice(separator + 2);
  const treeHeaders = headers.filter((line) => line.startsWith("tree "));
  const parentHeaders = headers.filter((line) => line.startsWith("parent "));
  const fixedAuthor =
    "author Heterodyne <protocol@heterodyne.network> 0 +0000";
  const fixedCommitter =
    "committer Heterodyne <protocol@heterodyne.network> 0 +0000";
  const allowedHeaderCount = 3 + parentHeaders.length;
  if (
    treeHeaders.length !== 1 ||
    headers.length !== allowedHeaderCount ||
    headers[0] !== treeHeaders[0] ||
    headers[1 + parentHeaders.length] !== fixedAuthor ||
    headers[2 + parentHeaders.length] !== fixedCommitter
  ) {
    throw new Error("config-git commit headers are not canonical");
  }
  for (let index = 0; index < parentHeaders.length; index += 1) {
    if (headers[index + 1] !== parentHeaders[index]) {
      throw new Error("config-git parent headers are not contiguous");
    }
  }
  const treeOid = treeHeaders[0]!.slice(5);
  assertObjectOid(input.object_format, treeOid, "commit tree oid");
  const parentOids = parentHeaders.map((line) => line.slice(7));
  for (const oid of parentOids) assertObjectOid(input.object_format, oid, "parent oid");

  let kind: "ordinary" | "retention-resolution";
  if (message === "heterodyne-config-v1\n" && parentOids.length <= 1) {
    kind = "ordinary";
  } else if (
    message === "heterodyne-config-retention-resolution-v1\n" &&
    parentOids.length >= 1 &&
    isSortedUnique(parentOids, compareHex)
  ) {
    kind = "retention-resolution";
  } else {
    throw new Error("config-git commit parent/message branch invalid");
  }
  if (!trees.has(treeOid)) {
    throw new Error("config-git root tree missing");
  }
  const visited = new Set<string>();
  validateTreeRecursively(input.object_format, treeOid, trees, "", visited);
  if (visited.size !== trees.size) {
    throw new Error("config-git tree projection contains unreachable trees");
  }
  return { kind, parent_oids: parentOids, tree_oid: treeOid };
}

function validateCheckpointShape(candidate: CredentialCheckpoint): void {
  assertHex32(candidate.persona, "checkpoint persona");
  assertSafeInteger(candidate.generation, "checkpoint generation");
  assertSafeInteger(candidate.sequence, "checkpoint sequence");
  if (
    candidate.previous_checkpoint !== null &&
    !HEX32.test(candidate.previous_checkpoint)
  ) {
    throw new Error("checkpoint previous digest invalid");
  }
  if (
    candidate.generation_transition !== null &&
    !HEX32.test(candidate.generation_transition)
  ) {
    throw new Error("checkpoint transition digest invalid");
  }
  assertHex16(candidate.config_key_id, "checkpoint config key id");
  for (const [name, value] of Object.entries({
    config_key_sha256: candidate.config_key_sha256,
    pairwise_secret_sha256: candidate.pairwise_secret_sha256,
    exposure_set_sha256: candidate.exposure_set_sha256,
    governed_decrypt_key_bindings_sha256:
      candidate.governed_decrypt_key_bindings_sha256,
    historical_decrypt_obligations_sha256:
      candidate.historical_decrypt_obligations_sha256,
    epoch_pubkey: candidate.epoch_pubkey,
  })) {
    assertHex32(value, name);
  }
  validateKelHead(candidate.kel_head);
}

function validateInventoryRecord(record: RetentionInventoryRecord): void {
  assertHex32(record.record_digest, "inventory record digest");
  assertSafeInteger(record.inventory_sequence, "inventory sequence");
  assertSafeInteger(record.target_generation, "inventory target generation");
  assertSafeInteger(record.target_sequence, "inventory target sequence");
  if (
    record.basis_checkpoint_digest !== null &&
    !HEX32.test(record.basis_checkpoint_digest)
  ) {
    throw new Error("inventory basis checkpoint invalid");
  }
  if (!isSortedUnique(record.previous_records, compareInventoryParent)) {
    throw new Error("inventory parents not sorted and unique");
  }
  for (const parent of record.previous_records) {
    assertSafeInteger(parent.inventory_sequence, "inventory parent sequence");
    assertHex32(parent.record_digest, "inventory parent digest");
  }
  const ids = new Set<string>();
  for (const entry of record.repository_refs) {
    assertHex32(entry.repository_ref_id, "inventory repository ref id");
    if (ids.has(entry.repository_ref_id)) {
      throw new Error("inventory repository ref duplicate");
    }
    ids.add(entry.repository_ref_id);
    validateTypedGitObject(entry.scan_head);
    if (entry.object_format !== entry.scan_head.object_format) {
      throw new Error("inventory object format mismatch");
    }
  }
}

function validateObligationRecord(record: HistoricalObligationRecord): void {
  assertHex32(record.record_digest, "obligation record digest");
  assertHex16(record.obligation_id, "obligation id");
  assertSafeInteger(record.lineage_sequence, "obligation sequence");
  assertSecretId(record.secret_class, record.secret_id);
  assertHex32(record.instance_commitment, "obligation commitment");
  if (
    record.previous_record !== null &&
    !HEX32.test(record.previous_record)
  ) {
    throw new Error("obligation predecessor invalid");
  }
  if (
    (record.action === "retain" && record.retained_ciphertexts.length === 0) ||
    (record.action === "close" && record.retained_ciphertexts.length !== 0)
  ) {
    throw new Error("obligation action/ciphertext mismatch");
  }
  const locators = record.retained_ciphertexts.map((locator) => {
    validateLocator(locator);
    return jcsCanonicalize(locator);
  });
  if (!isSortedUnique(locators, compareUtf8)) {
    throw new Error("obligation locators not sorted and unique");
  }
}

function validateLocator(locator: RetainedCiphertextLocator): void {
  validateTypedGitObject(locator.repository_head);
  validateTypedGitObject(locator.git_blob_oid);
  if (
    locator.repository_head.object_format !==
    locator.git_blob_oid.object_format
  ) {
    throw new Error("obligation locator object formats differ");
  }
  if (locator.object_id !== null) assertHex32(locator.object_id, "object id");
  assertHex32(locator.ciphertext_sha256, "ciphertext digest");
  assertSafeInteger(locator.ciphertext_length, "ciphertext length");
}

function validateAssignmentShape(candidate: SecretAssignment): void {
  assertHex32(candidate.record_digest, "assignment record digest");
  assertHex16(candidate.assignment_id, "assignment id");
  assertCanonicalNid(candidate.holder_nid);
  assertSecretId(candidate.secret_class, candidate.secret_id);
  assertHex32(candidate.secret_commitment, "assignment commitment");
  assertHex32(candidate.source_record_digest, "assignment source digest");
  if (
    candidate.transition_id !== null &&
    !HEX16.test(candidate.transition_id)
  ) {
    throw new Error("credential-assignment transition id invalid");
  }
  if (candidate.supersedes !== null && !HEX32.test(candidate.supersedes)) {
    throw new Error("credential-assignment supersedes invalid");
  }
}

function validateTypedGitObject(value: TypedGitObject): void {
  assertObjectOid(value.object_format, value.oid, "typed Git object");
}

function validateKelHead(value: KelHead): void {
  assertHex32(value.event_id, "KEL event id");
  assertSafeInteger(value.seq, "KEL sequence");
}

function equalKelHead(left: KelHead, right: KelHead): boolean {
  return left.event_id === right.event_id && left.seq === right.seq;
}

function assertSafeInteger(
  value: number | undefined,
  label: string,
): asserts value is number {
  if (
    !Number.isSafeInteger(value) ||
    value === undefined ||
    value < 0 ||
    value > SAFE_INTEGER_MAX
  ) {
    throw new Error(`${label} must be a JSON-safe nonnegative integer`);
  }
}

function assertHex16(value: string, label: string): void {
  if (!HEX16.test(value)) throw new Error(`${label} must be 32 lowercase hexadecimal characters`);
}

function assertHex32(value: string, label: string): void {
  if (!HEX32.test(value)) throw new Error(`${label} must be 64 lowercase hexadecimal characters`);
}

function assertSecretId(secretClass: SecretClass, value: string): void {
  if (secretClass === "config-audience") {
    assertHex16(value, "config-audience secret id");
  } else {
    assertHex32(value, `${secretClass} secret id`);
  }
}

function assertCanonicalNid(value: string): void {
  if (!CANONICAL_NID.test(value)) {
    throw new Error("credential NID is not canonical did:key");
  }
}

function assertGitOid(value: string, label: string): void {
  if (!HEX20.test(value) && !HEX32.test(value)) {
    throw new Error(`${label} is not a typed Git OID`);
  }
}

function assertObjectOid(
  format: "sha1" | "sha256",
  value: string,
  label: string,
): void {
  if ((format === "sha1" && !HEX20.test(value)) || (format === "sha256" && !HEX32.test(value))) {
    throw new Error(`${label} does not match object format`);
  }
}

function sameRetentionIdentity(
  left: RepositoryRetentionRef,
  right: RepositoryRetentionRef,
): boolean {
  return (
    left.repository_ref_id === right.repository_ref_id &&
    left.repository_class === right.repository_class &&
    left.repository_rid === right.repository_rid &&
    left.ref_name === right.ref_name &&
    left.object_format === right.object_format
  );
}

function compareInventoryParent(
  left: { inventory_sequence: number; record_digest: string },
  right: { inventory_sequence: number; record_digest: string },
): number {
  return (
    left.inventory_sequence - right.inventory_sequence ||
    compareHex(left.record_digest, right.record_digest)
  );
}

function compareObligationFrontier(
  left: {
    obligation_id: string;
    lineage_sequence: number;
    action: "retain" | "close";
    record_digest: string;
  },
  right: {
    obligation_id: string;
    lineage_sequence: number;
    action: "retain" | "close";
    record_digest: string;
  },
): number {
  return (
    compareHex(left.obligation_id, right.obligation_id) ||
    left.lineage_sequence - right.lineage_sequence ||
    (left.action === right.action ? 0 : left.action === "retain" ? -1 : 1) ||
    compareHex(left.record_digest, right.record_digest)
  );
}

function compareExposure(left: ExposureItem, right: ExposureItem): number {
  return (
    compareUtf8(left.secret_class, right.secret_class) ||
    compareHex(left.secret_id, right.secret_id) ||
    compareHex(left.secret_commitment, right.secret_commitment)
  );
}

function compareHex(left: string, right: string): number {
  return Buffer.compare(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}

function compareUtf8(left: string, right: string): number {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

function uniqueSorted<T>(
  values: T[],
  comparator: (left: T, right: T) => number,
): T[] {
  const sorted = [...values].sort(comparator);
  return sorted.filter(
    (value, index) => index === 0 || comparator(sorted[index - 1]!, value) !== 0,
  );
}

function isSortedUnique<T>(
  values: T[],
  comparator: (left: T, right: T) => number,
): boolean {
  for (let index = 1; index < values.length; index += 1) {
    if (comparator(values[index - 1]!, values[index]!) >= 0) return false;
  }
  return true;
}

function sameStringSet(left: string[], right: string[]): boolean {
  return (
    jcsCanonicalize(uniqueSorted(left, compareUtf8)) ===
    jcsCanonicalize(uniqueSorted(right, compareUtf8))
  );
}

function setDifference(left: string[], right: string[]): string[] {
  const rightSet = new Set(right);
  return left.filter((value) => !rightSet.has(value)).sort(compareUtf8);
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const length = parts.reduce((sum, part) => sum + part.length, 0);
  const result = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function decodeCanonicalBase64url(value: string): Uint8Array {
  if (!BASE64URL.test(value)) {
    throw new Error("config-git raw bytes are not canonical unpadded base64url");
  }
  const bytes = Buffer.from(value, "base64url");
  if (bytes.toString("base64url") !== value) {
    throw new Error("config-git raw bytes are not canonical unpadded base64url");
  }
  return bytes;
}

function gitObjectOid(
  format: "sha1" | "sha256",
  type: "commit" | "tree",
  raw: Uint8Array,
): string {
  const header = Buffer.from(`${type} ${raw.length}\0`, "utf8");
  return createHash(format).update(header).update(raw).digest("hex");
}

function validateTreeRecursively(
  format: "sha1" | "sha256",
  oid: string,
  trees: ReadonlyMap<string, Uint8Array>,
  prefix: string,
  visited: Set<string>,
): void {
  if (visited.has(oid)) return;
  visited.add(oid);
  const raw = trees.get(oid);
  if (raw === undefined) throw new Error("config-git referenced tree missing");
  const oidLength = format === "sha1" ? 20 : 32;
  let offset = 0;
  let priorSortKey: Buffer | null = null;
  while (offset < raw.length) {
    const space = raw.indexOf(0x20, offset);
    const nul = raw.indexOf(0, space + 1);
    if (space < 0 || nul < 0 || nul + 1 + oidLength > raw.length) {
      throw new Error("config-git tree entry is truncated");
    }
    const mode = Buffer.from(raw.subarray(offset, space)).toString("ascii");
    if (mode !== "100644" && mode !== "40000") {
      throw new Error("config-git tree mode is not allowed");
    }
    const nameBytes = raw.subarray(space + 1, nul);
    const name = new TextDecoder("utf-8", { fatal: true }).decode(nameBytes);
    if (
      name.length === 0 ||
      name === "." ||
      name === ".." ||
      name.includes("/") ||
      name.includes("\0")
    ) {
      throw new Error("config-git tree path component is invalid");
    }
    const entryOid = Buffer.from(
      raw.subarray(nul + 1, nul + 1 + oidLength),
    ).toString("hex");
    const sortKey = Buffer.concat([
      Buffer.from(nameBytes),
      mode === "40000" ? Buffer.from("/") : Buffer.alloc(0),
    ]);
    if (priorSortKey !== null && Buffer.compare(priorSortKey, sortKey) >= 0) {
      throw new Error("config-git tree order is not canonical");
    }
    priorSortKey = sortKey;
    const path = prefix.length === 0 ? name : `${prefix}/${name}`;
    if (mode === "40000") {
      if (!trees.has(entryOid)) {
        throw new Error("config-git referenced subtree is absent");
      }
      validateTreeRecursively(format, entryOid, trees, path, visited);
    } else {
      validateConfigPath(path);
    }
    offset = nul + 1 + oidLength;
  }
}

function validateConfigPath(path: string): void {
  if (/^config-data\/[0-9a-f]{64}\.bin$/.test(path)) return;
  const components = path.split("/");
  if (
    components.every(
      (component) =>
        /^[a-z0-9][a-z0-9._-]{0,127}$/.test(component) &&
        !component.startsWith("."),
    )
  ) {
    return;
  }
  throw new Error("config-git path is not a canonical public template");
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
