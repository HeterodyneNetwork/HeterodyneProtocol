import { ed25519 } from "@noble/curves/ed25519";
import { schnorr } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha2";
import { base58 } from "@scure/base";
import { bytesToHex, hexToBytes, utf8Bytes } from "./hex.js";

// This module intentionally does not import the vector generator's Nostr or
// KEL serialization helpers. It parses and authenticates the supplied wire
// bytes independently so generated fixtures cannot validate themselves.

const HEX_32 = /^[0-9a-f]{64}$/u;
const HEX_SIG = /^[0-9a-f]{128}$/u;
const POSITIVE_DECIMAL = /^[1-9][0-9]*$/u;
const NONNEGATIVE_DECIMAL = /^(?:0|[1-9][0-9]*)$/u;
const ED25519_MULTICODEC = Uint8Array.from([0xed, 0x01]);

export type KelCandidateSource = "repo" | "relay";

export type KelWireCandidate = {
  nip01_raw: string;
  id: string;
  sig: string;
  source: KelCandidateSource;
  observed_order?: number;
};

export type ParsedNip01Event = {
  pubkey: string;
  created_at: number;
  kind: 31002 | 31003;
  tags: string[][];
  content: string;
};

type Witness = { id: string; weight: number };

type RotationReceipt = {
  witness_id: string;
  scheme: "bip340" | "did:key" | "atproto";
  sig: string;
};

type ParsedInception = {
  type: "inception";
  seq: 0;
  coldRoot: string;
  epochKey: string;
  witnesses: Witness[];
  threshold: number;
};

type ParsedRotation = {
  type: "rotation";
  seq: number;
  coldRoot: string;
  priorDigest: string;
  strategy: "committed" | "none";
  epochKey: string;
  witnesses: Witness[];
  threshold: number;
  receipts: RotationReceipt[];
};

export type ParsedKelCandidate = {
  wire: KelWireCandidate;
  event: ParsedNip01Event;
  body: ParsedInception | ParsedRotation;
};

export type ReplayedKelState = {
  cold_root: string;
  s: number;
  epoch_key: string;
  witnesses: Array<{ id: string; weight: number }>;
  threshold: number;
  producing_event_id: string;
};

export type ReplayedKelEntry = {
  event_id: string;
  created_at: number;
  nip01_raw: string;
  state: ReplayedKelState;
};

export type KelReplayRejection = {
  id: string;
  error: string;
};

export type KelReplayResult = {
  status: "accepted" | "stalled";
  entries: ReplayedKelEntry[];
  state: ReplayedKelState | null;
  head: { id: string; seq: number } | null;
  rejected: KelReplayRejection[];
  duplicity: boolean;
  stalled_at?: number;
  competing_ids?: string[];
};

export type KelReplayOptions = {
  verifyDidKeyReceipt?: (
    witnessId: string,
    digest: Uint8Array,
    signature: Uint8Array,
  ) => boolean;
  verifyAtprotoReceipt?: (
    witnessId: string,
    digest: Uint8Array,
    signature: Uint8Array,
  ) => boolean;
};

export class KelReplayError extends Error {
  constructor(readonly code: string) {
    super(code);
    this.name = "KelReplayError";
  }
}

function fail(code: string): never {
  throw new KelReplayError(code);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseUnsignedRaw(raw: string): ParsedNip01Event {
  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch {
    fail("invalid_nip01_json");
  }
  if (JSON.stringify(value) !== raw) {
    fail("non_canonical_nip01");
  }
  if (!Array.isArray(value) || value.length !== 6 || value[0] !== 0) {
    fail("invalid_nip01_shape");
  }

  const [, pubkey, createdAt, kind, tags, content] = value;
  if (
    typeof pubkey !== "string"
    || !HEX_32.test(pubkey)
    || !Number.isSafeInteger(createdAt)
    || (createdAt as number) < 0
    || (kind !== 31002 && kind !== 31003)
    || !Array.isArray(tags)
    || typeof content !== "string"
  ) {
    fail("invalid_nip01_shape");
  }
  for (const tag of tags) {
    if (
      !Array.isArray(tag)
      || tag.length === 0
      || tag.some((part) => typeof part !== "string")
    ) {
      fail("invalid_nip01_tags");
    }
  }

  return {
    pubkey,
    created_at: createdAt as number,
    kind,
    tags: tags as string[][],
    content,
  };
}

function requireTag(
  tags: string[][],
  index: number,
  name: string,
  length = 2,
): string[] {
  const tag = tags[index];
  if (tag?.[0] !== name || tag.length !== length) {
    fail("invalid_kel_tag_schema");
  }
  return tag;
}

function parseWitnessConfiguration(
  tags: string[][],
  start: number,
  finalExclusive: number,
): { witnesses: Witness[]; threshold: number } {
  const witnesses: Witness[] = [];
  const seen = new Set<string>();
  let index = start;
  while (index < finalExclusive && tags[index]?.[0] === "witness") {
    const tag = requireTag(tags, index, "witness", 3);
    if (tag[1].length === 0 || !POSITIVE_DECIMAL.test(tag[2]) || seen.has(tag[1])) {
      fail("invalid_witness_configuration");
    }
    seen.add(tag[1]);
    witnesses.push({ id: tag[1], weight: Number(tag[2]) });
    index += 1;
  }

  let threshold = 0;
  if (index < finalExclusive && tags[index]?.[0] === "threshold") {
    const tag = requireTag(tags, index, "threshold");
    if (!NONNEGATIVE_DECIMAL.test(tag[1])) {
      fail("invalid_witness_threshold");
    }
    threshold = Number(tag[1]);
    index += 1;
  } else if (witnesses.length > 0) {
    fail("missing_witness_threshold");
  }

  if (index !== finalExclusive) {
    fail("invalid_kel_tag_schema");
  }
  const totalWeight = witnesses.reduce((total, witness) => total + witness.weight, 0);
  if (!Number.isSafeInteger(totalWeight) || threshold > totalWeight) {
    fail("invalid_witness_threshold");
  }
  return { witnesses, threshold };
}

function parseInception(event: ParsedNip01Event): ParsedInception {
  if (event.content !== "" || event.tags.length < 5) {
    fail("invalid_inception_schema");
  }
  if (
    event.tags.at(-1)?.[0] !== "spec_version"
    || event.tags.at(-1)?.[1] !== "core/0.5.0"
    || event.tags.at(-1)?.length !== 2
  ) {
    fail("missing_or_invalid_spec_version");
  }
  const d = requireTag(event.tags, 0, "d");
  const marker = requireTag(event.tags, 1, "heterodyne");
  const owner = requireTag(event.tags, 2, "p");
  const sequence = requireTag(event.tags, 3, "s");
  const epochKey = requireTag(event.tags, 4, "epoch_key");
  requireTag(event.tags, event.tags.length - 1, "spec_version");
  if (
    d[1] !== ""
    || marker[1] !== "keri_inception"
    || owner[1] !== event.pubkey
    || sequence[1] !== "0"
    || !HEX_32.test(epochKey[1])
  ) {
    fail("invalid_inception_schema");
  }
  const configuration = parseWitnessConfiguration(
    event.tags,
    5,
    event.tags.length - 1,
  );
  return {
    type: "inception",
    seq: 0,
    coldRoot: owner[1],
    epochKey: epochKey[1],
    ...configuration,
  };
}

function parseRotationContent(content: string): RotationReceipt[] {
  let value: unknown;
  try {
    value = JSON.parse(content);
  } catch {
    fail("invalid_rotation_content");
  }
  if (
    !isRecord(value)
    || Object.keys(value).join(",") !== "spec_version,receipts"
    || value.spec_version !== "core/0.5.0"
    || !Array.isArray(value.receipts)
  ) {
    fail("invalid_rotation_content");
  }

  const receipts: RotationReceipt[] = [];
  let priorId: string | undefined;
  for (const item of value.receipts) {
    if (
      !isRecord(item)
      || Object.keys(item).join(",") !== "witness_id,scheme,sig"
      || typeof item.witness_id !== "string"
      || item.witness_id.length === 0
      || !["bip340", "did:key", "atproto"].includes(String(item.scheme))
      || typeof item.sig !== "string"
      || !HEX_SIG.test(item.sig)
    ) {
      fail("invalid_rotation_content");
    }
    if (
      priorId !== undefined
      && Buffer.compare(Buffer.from(priorId, "utf8"), Buffer.from(item.witness_id, "utf8")) > 0
    ) {
      fail("invalid_rotation_content");
    }
    priorId = item.witness_id;
    receipts.push({
      witness_id: item.witness_id,
      scheme: item.scheme as RotationReceipt["scheme"],
      sig: item.sig,
    });
  }
  if (
    JSON.stringify({
      spec_version: "core/0.5.0",
      receipts,
    }) !== content
  ) {
    fail("invalid_rotation_content");
  }
  return receipts;
}

function parseRotation(event: ParsedNip01Event): ParsedRotation {
  if (event.tags.length < 7) {
    fail("invalid_rotation_schema");
  }
  const d = requireTag(event.tags, 0, "d");
  const marker = requireTag(event.tags, 1, "heterodyne");
  const owner = requireTag(event.tags, 2, "p");
  const sequence = requireTag(event.tags, 3, "s");
  const prior = requireTag(event.tags, 4, "prior_digest");
  const strategy = requireTag(event.tags, 5, "strategy");
  const epochKey = requireTag(event.tags, 6, "epoch_key");
  if (
    marker[1] !== "keri_rotation"
    || !HEX_32.test(owner[1])
    || !POSITIVE_DECIMAL.test(sequence[1])
    || d[1] !== sequence[1]
    || !HEX_32.test(prior[1])
    || (strategy[1] !== "committed" && strategy[1] !== "none")
    || !HEX_32.test(epochKey[1])
  ) {
    fail("invalid_rotation_schema");
  }
  const configuration = parseWitnessConfiguration(
    event.tags,
    7,
    event.tags.length,
  );
  return {
    type: "rotation",
    seq: Number(sequence[1]),
    coldRoot: owner[1],
    priorDigest: prior[1],
    strategy: strategy[1],
    epochKey: epochKey[1],
    receipts: parseRotationContent(event.content),
    ...configuration,
  };
}

export function parseKelCandidate(wire: KelWireCandidate): ParsedKelCandidate {
  const event = parseUnsignedRaw(wire.nip01_raw);
  if (!HEX_32.test(wire.id) || !HEX_SIG.test(wire.sig)) {
    fail("invalid_event_authentication_shape");
  }
  const computedId = bytesToHex(sha256(utf8Bytes(wire.nip01_raw)));
  if (computedId !== wire.id) {
    fail("event_id_mismatch");
  }
  let signatureValid = false;
  try {
    signatureValid = schnorr.verify(wire.sig, wire.id, event.pubkey);
  } catch {
    signatureValid = false;
  }
  if (!signatureValid) {
    fail("invalid_outer_signature");
  }
  return {
    wire,
    event,
    body: event.kind === 31002 ? parseInception(event) : parseRotation(event),
  };
}

function decodeDidKeyEd25519(identifier: string): Uint8Array | null {
  if (!identifier.startsWith("did:key:z")) {
    return null;
  }
  let decoded: Uint8Array;
  try {
    decoded = base58.decode(identifier.slice("did:key:z".length));
  } catch {
    return null;
  }
  if (
    decoded.length !== ED25519_MULTICODEC.length + 32
    || decoded[0] !== ED25519_MULTICODEC[0]
    || decoded[1] !== ED25519_MULTICODEC[1]
  ) {
    return null;
  }
  return decoded.slice(ED25519_MULTICODEC.length);
}

function receiptDigest(candidate: ParsedKelCandidate): Uint8Array {
  const event = candidate.event;
  return sha256(utf8Bytes(JSON.stringify([
    0,
    event.pubkey,
    event.created_at,
    event.kind,
    event.tags,
    "",
  ])));
}

function validReceiptWitnessIds(
  candidate: ParsedKelCandidate & { body: ParsedRotation },
  priorState: ReplayedKelState,
  options: KelReplayOptions,
): Set<string> {
  const configured = new Map(priorState.witnesses.map((witness) => [witness.id, witness.weight]));
  const counted = new Set<string>();
  const validWitnesses = new Set<string>();
  const digest = receiptDigest(candidate);

  for (const receipt of candidate.body.receipts) {
    if (counted.has(receipt.witness_id)) {
      continue;
    }
    counted.add(receipt.witness_id);
    const configuredWeight = configured.get(receipt.witness_id);
    if (configuredWeight === undefined) {
      continue;
    }

    let valid = false;
    try {
      const signature = hexToBytes(receipt.sig);
      if (receipt.scheme === "bip340" && HEX_32.test(receipt.witness_id)) {
        valid = schnorr.verify(signature, digest, receipt.witness_id);
      } else if (receipt.scheme === "did:key") {
        const publicKey = decodeDidKeyEd25519(receipt.witness_id);
        valid = publicKey !== null
          ? ed25519.verify(signature, digest, publicKey)
          : receipt.witness_id.startsWith("did:key:")
            && options.verifyDidKeyReceipt?.(receipt.witness_id, digest, signature) === true;
      } else if (
        receipt.scheme === "atproto"
        && /^(?:did:web:|did:plc:)/u.test(receipt.witness_id)
        && options.verifyAtprotoReceipt !== undefined
      ) {
        valid = options.verifyAtprotoReceipt(receipt.witness_id, digest, signature);
      }
    } catch {
      valid = false;
    }
    if (valid) {
      validWitnesses.add(receipt.witness_id);
    }
  }
  return validWitnesses;
}

function receiptWeight(
  witnessIds: Set<string>,
  priorState: ReplayedKelState,
): number {
  const configured = new Map(priorState.witnesses.map((witness) => [witness.id, witness.weight]));
  let weight = 0;
  for (const witnessId of witnessIds) {
    weight += configured.get(witnessId) ?? 0;
  }
  return weight;
}

function stateFor(
  candidate: ParsedKelCandidate,
  coldRoot: string,
): ReplayedKelState {
  return {
    cold_root: coldRoot,
    s: candidate.body.seq,
    epoch_key: candidate.body.epochKey,
    witnesses: candidate.body.witnesses.map((witness) => ({ ...witness })),
    threshold: candidate.body.threshold,
    producing_event_id: candidate.wire.id,
  };
}

function entryFor(
  candidate: ParsedKelCandidate,
  state: ReplayedKelState,
): ReplayedKelEntry {
  return {
    event_id: candidate.wire.id,
    created_at: candidate.event.created_at,
    nip01_raw: candidate.wire.nip01_raw,
    state,
  };
}

function statefulRotationError(
  candidate: ParsedKelCandidate & { body: ParsedRotation },
  priorState: ReplayedKelState,
  priorId: string,
  expectedSequence: number,
  options: KelReplayOptions,
): string | null {
  if (candidate.body.seq !== expectedSequence) {
    return "broken_sequence";
  }
  if (candidate.body.priorDigest !== priorId) {
    return "broken_prior_digest";
  }
  if (candidate.body.coldRoot !== priorState.cold_root) {
    return "cold_root_mismatch";
  }
  const expectedController = candidate.body.strategy === "committed"
    ? priorState.cold_root
    : priorState.epoch_key;
  if (candidate.event.pubkey !== expectedController) {
    return "invalid_rotation_controller";
  }
  if (candidate.body.strategy === "none" && priorState.threshold < 1) {
    return "none_requires_positive_prior_threshold";
  }
  return null;
}

function rejectedId(wire: KelWireCandidate): string {
  return typeof wire.id === "string" ? wire.id : "";
}

export function replayKel(
  wires: KelWireCandidate[],
  options: KelReplayOptions = {},
): KelReplayResult {
  const parsedById = new Map<string, ParsedKelCandidate>();
  const rejected: KelReplayRejection[] = [];
  for (const [inputOrder, wire] of wires.entries()) {
    try {
      const parsed = parseKelCandidate({
        ...wire,
        observed_order: wire.observed_order ?? inputOrder,
      });
      const existing = parsedById.get(parsed.wire.id);
      if (existing === undefined) {
        parsedById.set(parsed.wire.id, parsed);
      } else {
        parsedById.set(parsed.wire.id, {
          ...existing,
          wire: {
            ...existing.wire,
            source: existing.wire.source === "repo" || parsed.wire.source === "repo"
              ? "repo"
              : "relay",
            observed_order: Math.min(
              existing.wire.observed_order ?? inputOrder,
              parsed.wire.observed_order ?? inputOrder,
            ),
          },
        });
      }
    } catch (error) {
      rejected.push({
        id: rejectedId(wire),
        error: error instanceof KelReplayError ? error.code : "invalid_kel_candidate",
      });
    }
  }
  const parsed = [...parsedById.values()];

  const inceptions = parsed.filter(
    (candidate): candidate is ParsedKelCandidate & { body: ParsedInception } =>
      candidate.body.type === "inception",
  );
  if (inceptions.length === 0) {
    return {
      status: "accepted",
      entries: [],
      state: null,
      head: null,
      rejected,
      duplicity: false,
    };
  }
  if (inceptions.length > 1) {
    const competingIds = inceptions.map((candidate) => candidate.wire.id).sort();
    return {
      status: "stalled",
      entries: [],
      state: null,
      head: null,
      rejected,
      duplicity: true,
      stalled_at: 0,
      competing_ids: competingIds,
    };
  }

  const inception = inceptions[0];
  let state = stateFor(inception, inception.body.coldRoot);
  let head = { id: inception.wire.id, seq: 0 };
  const entries = [entryFor(inception, state)];
  const remaining = parsed.filter(
    (candidate): candidate is ParsedKelCandidate & { body: ParsedRotation } =>
      candidate.body.type === "rotation",
  );

  let duplicity = false;
  while (remaining.length > 0) {
    const expectedSequence = head.seq + 1;
    const atSequence = remaining.filter(
      (candidate) => candidate.body.seq === expectedSequence,
    );
    if (atSequence.length === 0) {
      for (const candidate of remaining) {
        rejected.push({ id: candidate.wire.id, error: "broken_sequence" });
      }
      break;
    }

    const valid: Array<ParsedKelCandidate & { body: ParsedRotation }> = [];
    for (const candidate of atSequence) {
      const error = statefulRotationError(
        candidate,
        state,
        head.id,
        expectedSequence,
        options,
      );
      if (error === null) {
        valid.push(candidate);
      } else {
        rejected.push({ id: candidate.wire.id, error });
      }
    }
    for (const candidate of atSequence) {
      remaining.splice(remaining.indexOf(candidate), 1);
    }

    if (valid.length === 0) {
      continue;
    }
    const selection = selectRotation(valid, state, options);
    if (selection.kind === "stalled") {
      return {
        status: "stalled",
        entries,
        state,
        head,
        rejected,
        duplicity: selection.duplicity,
        stalled_at: expectedSequence,
        competing_ids: selection.competingIds,
      };
    }

    const accepted = selection.candidate;
    duplicity ||= selection.duplicity;
    state = stateFor(accepted, state.cold_root);
    head = { id: accepted.wire.id, seq: accepted.body.seq };
    entries.push(entryFor(accepted, state));
  }

  return {
    status: "accepted",
    entries,
    state,
    head,
    rejected,
    duplicity,
  };
}

type RotationCandidate = ParsedKelCandidate & { body: ParsedRotation };

type RotationSelection =
  | { kind: "accepted"; candidate: RotationCandidate; duplicity: boolean }
  | { kind: "stalled"; competingIds: string[]; duplicity: boolean };

function selectRotation(
  candidates: RotationCandidate[],
  priorState: ReplayedKelState,
  options: KelReplayOptions,
): RotationSelection {
  const competingIds = candidates.map((candidate) => candidate.wire.id).sort();
  const committed = candidates.filter(({ body }) => body.strategy === "committed");
  if (committed.length > 1) {
    return { kind: "stalled", competingIds, duplicity: true };
  }

  const validWitnesses = new Map<RotationCandidate, Set<string>>();
  const individuallySupported = candidates.filter((candidate) => {
    if (candidate.body.strategy === "committed") return true;
    const witnesses = validReceiptWitnessIds(candidate, priorState, options);
    validWitnesses.set(candidate, witnesses);
    return receiptWeight(witnesses, priorState) >= priorState.threshold;
  });
  const repoSupported = individuallySupported.filter(({ wire }) => wire.source === "repo");
  if (repoSupported.length === 1) {
    return {
      kind: "accepted",
      candidate: repoSupported[0],
      duplicity: candidates.length > 1,
    };
  }
  if (repoSupported.length > 1) {
    return { kind: "stalled", competingIds, duplicity: true };
  }
  if (individuallySupported.length === 1) {
    return {
      kind: "accepted",
      candidate: individuallySupported[0],
      duplicity: candidates.length > 1,
    };
  }
  if (
    individuallySupported.length > 1
    && individuallySupported.some(({ body }) => body.strategy === "committed")
  ) {
    return { kind: "stalled", competingIds, duplicity: true };
  }

  const firstCandidateByWitness = new Map<string, RotationCandidate>();
  for (const candidate of candidates) {
    for (const witnessId of validWitnesses.get(candidate) ?? []) {
      const current = firstCandidateByWitness.get(witnessId);
      if (current === undefined || compareObservation(candidate, current) < 0) {
        firstCandidateByWitness.set(witnessId, candidate);
      }
    }
  }
  const firstSeenWeight = new Map<RotationCandidate, number>();
  const configured = new Map(priorState.witnesses.map(({ id, weight }) => [id, weight]));
  for (const [witnessId, candidate] of firstCandidateByWitness) {
    firstSeenWeight.set(
      candidate,
      (firstSeenWeight.get(candidate) ?? 0) + (configured.get(witnessId) ?? 0),
    );
  }
  const firstSeenSupported = candidates.filter(
    (candidate) => (firstSeenWeight.get(candidate) ?? 0) >= priorState.threshold,
  );
  if (firstSeenSupported.length === 1) {
    return {
      kind: "accepted",
      candidate: firstSeenSupported[0],
      duplicity: candidates.length > 1,
    };
  }
  return {
    kind: "stalled",
    competingIds,
    duplicity: candidates.length > 1,
  };
}

function compareObservation(a: RotationCandidate, b: RotationCandidate): number {
  const order = (a.wire.observed_order ?? Number.MAX_SAFE_INTEGER)
    - (b.wire.observed_order ?? Number.MAX_SAFE_INTEGER);
  return order === 0 ? a.wire.id.localeCompare(b.wire.id) : order;
}
