import { Ajv2020 } from "ajv/dist/2020.js";
import { resolveJsonPointer } from "../json-pointer.js";
import type { ConformanceCheckDocument, VectorDocument } from "../types.js";
import coreVerificationContextSchema from "../../schema/core-verification-context-v1.schema.json" with { type: "json" };
import personaProfileSchema from "../../../schemas/core/persona-profile-v1.schema.json" with { type: "json" };
import {
  bindNip01Raw,
  computeNip01Digest,
  isNostrSignedEvent,
  verifyNip01Signature,
} from "./nip01.js";
import type { CheckerStage, NostrSignedEvent, SubjectResult } from "./types.js";

type StageResult = SubjectResult["stages"][number];
type CoreVerificationContextV1 = {
  active_persona_key: string;
  assurance?: {
    requested: boolean;
    verified: boolean;
  };
};
type CoreKind0ExtensionV1 = {
  profile: string;
  identity_chain?: string;
  cold_root?: string;
  succession_authority?: string;
};

const ajv = new Ajv2020({ allErrors: true, strict: true });
const validateCoreContext = ajv.compile<CoreVerificationContextV1>(
  coreVerificationContextSchema,
);
const validatePersonaProfile = ajv.compile(personaProfileSchema);
const BASE58BTC_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BECH32_ALPHABET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32_GENERATORS = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
const utf8Decoder = new TextDecoder("utf-8", { fatal: true });
const utf8Encoder = new TextEncoder();

function reject(
  stages: StageResult[],
  stage: CheckerStage,
  reasonCode: string,
): SubjectResult {
  const terminal: StageResult = { stage, verdict: "reject", reasonCode };
  return {
    terminalStage: stage,
    verdict: "reject",
    reasonCode,
    stages: [...stages, terminal],
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function decodeBase58(value: string): Uint8Array | undefined {
  let decoded = 0n;
  for (const character of value) {
    const digit = BASE58BTC_ALPHABET.indexOf(character);
    if (digit === -1) {
      return undefined;
    }
    decoded = decoded * 58n + BigInt(digit);
  }

  const suffix: number[] = [];
  while (decoded > 0n) {
    suffix.unshift(Number(decoded & 0xffn));
    decoded >>= 8n;
  }
  const leadingZeroes = value.match(/^1*/)?.[0].length ?? 0;
  return Uint8Array.from([...new Array<number>(leadingZeroes).fill(0), ...suffix]);
}

function encodeBase58(value: Uint8Array): string {
  let encoded = 0n;
  for (const byte of value) {
    encoded = (encoded << 8n) | BigInt(byte);
  }

  let suffix = "";
  while (encoded > 0n) {
    suffix = BASE58BTC_ALPHABET[Number(encoded % 58n)] + suffix;
    encoded /= 58n;
  }
  let leadingZeroes = 0;
  while (leadingZeroes < value.length && value[leadingZeroes] === 0) {
    leadingZeroes += 1;
  }
  return "1".repeat(leadingZeroes) + suffix;
}

function isCanonicalRid(value: string): boolean {
  if (!/^rad:z[1-9A-HJ-NP-Za-km-z]{20,28}$/.test(value)) {
    return false;
  }
  const encoded = value.slice("rad:z".length);
  const decoded = decodeBase58(encoded);
  return decoded !== undefined && decoded.length === 20 && encodeBase58(decoded) === encoded;
}

function bech32Polymod(values: number[]): number {
  let checksum = 1;
  for (const value of values) {
    const top = checksum >>> 25;
    checksum = (((checksum & 0x1ffffff) << 5) ^ value) >>> 0;
    for (let index = 0; index < BECH32_GENERATORS.length; index += 1) {
      if (((top >>> index) & 1) !== 0) {
        checksum = (checksum ^ BECH32_GENERATORS[index]) >>> 0;
      }
    }
  }
  return checksum;
}

function expandBech32Hrp(hrp: string): number[] {
  return [
    ...[...hrp].map((character) => character.charCodeAt(0) >>> 5),
    0,
    ...[...hrp].map((character) => character.charCodeAt(0) & 31),
  ];
}

function convertBits(
  values: Iterable<number>,
  fromBits: number,
  toBits: number,
  pad: boolean,
): number[] | undefined {
  let accumulator = 0;
  let bitCount = 0;
  const result: number[] = [];
  const outputMask = (1 << toBits) - 1;

  for (const value of values) {
    if (value < 0 || value >>> fromBits !== 0) {
      return undefined;
    }
    accumulator = (accumulator << fromBits) | value;
    bitCount += fromBits;
    while (bitCount >= toBits) {
      bitCount -= toBits;
      result.push((accumulator >>> bitCount) & outputMask);
    }
  }

  if (pad) {
    if (bitCount > 0) {
      result.push((accumulator << (toBits - bitCount)) & outputMask);
    }
  } else if (bitCount >= fromBits || ((accumulator << (toBits - bitCount)) & outputMask) !== 0) {
    return undefined;
  }
  return result;
}

function encodeBech32(hrp: string, bytes: Uint8Array): string | undefined {
  const words = convertBits(bytes, 8, 5, true);
  if (words === undefined) {
    return undefined;
  }
  const checksumSeed = [...expandBech32Hrp(hrp), ...words, 0, 0, 0, 0, 0, 0];
  const checksum = (bech32Polymod(checksumSeed) ^ 1) >>> 0;
  const checksumWords = Array.from({ length: 6 }, (_unused, index) => (
    checksum >>> (5 * (5 - index))
  ) & 31);
  return `${hrp}1${[...words, ...checksumWords]
    .map((word) => BECH32_ALPHABET[word])
    .join("")}`;
}

function decodeNaddr(value: string): Uint8Array | undefined {
  if (value !== value.toLowerCase() || value.length > 8192) {
    return undefined;
  }
  const separator = value.lastIndexOf("1");
  const hrp = value.slice(0, separator);
  const encodedWords = value.slice(separator + 1);
  if (hrp !== "naddr" || encodedWords.length < 6) {
    return undefined;
  }

  const words: number[] = [];
  for (const character of encodedWords) {
    const word = BECH32_ALPHABET.indexOf(character);
    if (word === -1) {
      return undefined;
    }
    words.push(word);
  }
  if (bech32Polymod([...expandBech32Hrp(hrp), ...words]) !== 1) {
    return undefined;
  }
  const bytes = convertBits(words.slice(0, -6), 5, 8, false);
  return bytes === undefined ? undefined : Uint8Array.from(bytes);
}

function appendTlv(target: number[], type: number, value: Uint8Array): boolean {
  if (value.length > 255) {
    return false;
  }
  target.push(type, value.length, ...value);
  return true;
}

function isCanonicalNaddr(value: string): boolean {
  if (!/^naddr1[023456789acdefghjklmnpqrstuvwxyz]+$/.test(value)) {
    return false;
  }
  const bytes = decodeNaddr(value);
  if (bytes === undefined) {
    return false;
  }

  const tlvs = new Map<number, Uint8Array[]>();
  for (let offset = 0; offset < bytes.length;) {
    if (offset + 2 > bytes.length) {
      return false;
    }
    const type = bytes[offset];
    const length = bytes[offset + 1];
    offset += 2;
    if (offset + length > bytes.length || ![0, 1, 2, 3].includes(type)) {
      return false;
    }
    const values = tlvs.get(type) ?? [];
    values.push(bytes.slice(offset, offset + length));
    tlvs.set(type, values);
    offset += length;
  }

  const identifiers = tlvs.get(0) ?? [];
  const relays = tlvs.get(1) ?? [];
  const authors = tlvs.get(2) ?? [];
  const kinds = tlvs.get(3) ?? [];
  if (
    identifiers.length !== 1
    || authors.length !== 1
    || authors[0].length !== 32
    || kinds.length !== 1
    || kinds[0].length !== 4
  ) {
    return false;
  }

  let identifier: Uint8Array;
  let canonicalRelays: Uint8Array[];
  try {
    identifier = utf8Encoder.encode(utf8Decoder.decode(identifiers[0]));
    canonicalRelays = relays.map((relay) => utf8Encoder.encode(utf8Decoder.decode(relay)));
  } catch {
    return false;
  }

  const kind = new DataView(
    kinds[0].buffer,
    kinds[0].byteOffset,
    kinds[0].byteLength,
  ).getUint32(0, false);
  const canonicalKind = new Uint8Array(4);
  new DataView(canonicalKind.buffer).setUint32(0, kind, false);
  const canonicalTlvs: number[] = [];
  if (
    !appendTlv(canonicalTlvs, 3, canonicalKind)
    || !appendTlv(canonicalTlvs, 2, authors[0])
    || canonicalRelays.some((relay) => !appendTlv(canonicalTlvs, 1, relay))
    || !appendTlv(canonicalTlvs, 0, identifier)
  ) {
    return false;
  }

  const reencoded = encodeBech32("naddr", Uint8Array.from(canonicalTlvs));
  return reencoded === value;
}

export function resolveCoreKind0Extension(content: unknown): CoreKind0ExtensionV1 | undefined {
  if (!isRecord(content) || !validatePersonaProfile(content)) {
    return undefined;
  }
  const extension = content.heterodyne;
  if (!isRecord(extension) || typeof extension.profile !== "string") {
    return undefined;
  }
  if (!isCanonicalRid(extension.profile)) {
    return undefined;
  }
  if (
    extension.identity_chain !== undefined
    && (typeof extension.identity_chain !== "string" || !isCanonicalNaddr(extension.identity_chain))
  ) {
    return undefined;
  }
  return extension as CoreKind0ExtensionV1;
}

function resolveContext(
  vector: VectorDocument,
  check: ConformanceCheckDocument,
): CoreVerificationContextV1 | undefined {
  if (check.context_pointer === undefined) {
    return undefined;
  }

  let resolved;
  try {
    resolved = resolveJsonPointer(vector, check.context_pointer);
  } catch {
    return undefined;
  }
  if (!resolved.found || !isRecord(resolved.value)) {
    return undefined;
  }

  const assurance = resolved.value.assurance;
  const baselineCandidate = { ...resolved.value };
  delete baselineCandidate.assurance;
  if (!validateCoreContext(baselineCandidate)) {
    return undefined;
  }

  const assuranceRequested = isRecord(assurance) && assurance.requested === true;
  if (
    assuranceRequested
    && (!validateCoreContext(resolved.value) || resolved.value.assurance?.verified !== true)
  ) {
    return undefined;
  }

  return baselineCandidate as CoreVerificationContextV1;
}

export function checkCoreSignedEvent(
  vector: VectorDocument,
  check: ConformanceCheckDocument,
): SubjectResult {
  const stages: StageResult[] = [];

  let resolved;
  try {
    resolved = resolveJsonPointer(vector, check.event_pointer);
  } catch {
    return reject(stages, "event_structure", "bad_signature");
  }
  if (!resolved.found || !isNostrSignedEvent(resolved.value)) {
    return reject(stages, "event_structure", "bad_signature");
  }
  const event: NostrSignedEvent = resolved.value;
  stages.push({ stage: "event_structure", verdict: "pass" });

  let rawResolved;
  try {
    rawResolved = resolveJsonPointer(vector, check.nip01_raw_pointer);
  } catch {
    return reject(stages, "nip01_raw", "nip01_raw_mismatch");
  }
  const bound = bindNip01Raw(event, rawResolved.found ? rawResolved.value : undefined);
  if (bound === undefined) {
    return reject(stages, "nip01_raw", "nip01_raw_mismatch");
  }
  stages.push({ stage: "nip01_raw", verdict: "pass" });

  const digest = computeNip01Digest(bound.bytes);
  const identifier = Buffer.from(digest).toString("hex");
  if (identifier !== event.id) {
    return reject(stages, "identifier", "bad_signature");
  }
  stages.push({ stage: "identifier", verdict: "pass" });

  if (!verifyNip01Signature(event, digest)) {
    return reject(stages, "signature", "bad_signature");
  }
  stages.push({ stage: "signature", verdict: "pass" });

  if (event.kind === 0) {
    try {
      void resolveCoreKind0Extension(JSON.parse(event.content));
    } catch {
      // Kind-0 content and its optional Heterodyne extension never gate Core event validity.
    }
  }

  const context = resolveContext(vector, check);
  if (context === undefined || event.pubkey !== context.active_persona_key) {
    return reject(stages, "persona_resolution", "delegation_mismatch");
  }
  stages.push({ stage: "persona_resolution", verdict: "pass" });
  stages.push({ stage: "accept", verdict: "pass" });
  return {
    terminalStage: "accept",
    verdict: "accept",
    stages,
  };
}
