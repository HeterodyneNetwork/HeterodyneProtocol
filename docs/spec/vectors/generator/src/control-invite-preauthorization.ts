import { createHash, timingSafeEqual } from "node:crypto";
import { types as utilTypes } from "node:util";
import { jcsCanonicalize } from "./jcs.js";
import {
  descriptorDigest,
  responseProof,
  secretCommitment,
  verifyInviteSignature,
  type InviteDescriptor,
  type InviteEnvelope,
  type InviteResponseInput,
} from "./one-time-invite.js";
import {
  authorityBindingDigest,
  captureAuthorityInput,
  type AuthorityDecision,
} from "./security-authority-support.js";

export type ControlInvitePreauthorizationAuthorityConfig = Readonly<{
  authority_id: string;
  trusted_now: () => number;
  load_revocation: (invite_id: string) => Promise<Readonly<{
    revision: number;
    state: "active" | "revoked";
  }>>;
}>;

export type ControlInviteTemplate = Readonly<{
  persona: string;
  audience: string;
  client_key: string;
  client_class: "human-light" | "automated";
  methods: readonly string[];
  event_kinds: readonly number[];
  limits: Readonly<Record<string, number>>;
  signer: string;
  expires_at: number;
}>;

export type ControlInviteRequest = Readonly<{
  purpose: "control-enrollment";
  persona: string;
  audience: string;
  client_key: string;
  client_class: "human-light" | "automated";
  response: InviteResponseInput;
  secret_proof: string;
}>;

export type VerifiedControlInvitePreauthorization = Readonly<Record<never, never>>;
export type ControlInvitePreauthorizationAuthority = Readonly<Record<never, never>>;

type AuthorityRecord = Readonly<{
  authority_id: string;
  trusted_now: ControlInvitePreauthorizationAuthorityConfig["trusted_now"];
  load_revocation: ControlInvitePreauthorizationAuthorityConfig["load_revocation"];
}>;

type RevocationState = Readonly<{ revision: number; state: "active" | "revoked" }>;

type CapturedInput = Readonly<{
  envelope: Readonly<InviteEnvelope>;
  template: ControlInviteTemplate;
  request: ControlInviteRequest;
}>;

type VerifiedRecord = Readonly<{
  authority: AuthorityRecord;
  envelope_bytes: string;
  descriptor_digest: string;
  template_digest: string;
  request_digest: string;
  invite_id: string;
  purpose: "control-enrollment";
  persona: string;
  audience: string;
  client_key: string;
  client_class: "human-light" | "automated";
  signer: string;
  methods: readonly string[];
  event_kinds: readonly number[];
  limits: Readonly<Record<string, number>>;
  expires_at: number;
  revocation_revision: number;
  binding_digest: string;
}>;

const AUTHORITIES = new WeakMap<object, AuthorityRecord>();
const VERIFIED = new WeakMap<object, VerifiedRecord>();
const HEX_32 = /^[0-9a-f]{64}$/u;
const HEX_64 = /^[0-9a-f]{128}$/u;
const MAX_STRING_BYTES = 512;
const MAX_TOTAL_STRING_BYTES = 65_536;
const MAX_ARRAY_LENGTH = 64;
const MAX_PROPERTIES = 64;
const MAX_NODES = 1_024;
const MAX_DEPTH = 8;

const ENVELOPE_KEYS = ["descriptor", "signature", "secret"] as const;
const DESCRIPTOR_KEYS = [
  "approval_mode", "expected_client_pubkey", "expires_at", "invite_id",
  "inviter_account", "issued_at", "preauthorization", "purpose", "relay_hints",
  "rendezvous_pubkey", "secret_sha256", "version",
] as const;
const TEMPLATE_KEYS = [
  "audience", "client_class", "client_key", "event_kinds", "expires_at",
  "limits", "methods", "persona", "signer",
] as const;
const REQUEST_KEYS = [
  "audience", "client_class", "client_key", "persona", "purpose", "response",
  "secret_proof",
] as const;
const RESPONSE_KEYS = [
  "capabilities_compatible", "descriptor_valid", "expires_at", "expected_purpose",
  "group_established", "keypackage_valid", "now", "proof_valid", "response_digest",
  "response_purpose", "rumor_pubkey", "seal_pubkey", "seal_valid",
  "secret_commitment_valid",
] as const;

const REJECT = Object.freeze({
  verdict: "reject" as const,
  reason_code: "invite-preauthorization-invalid" as const,
});

function isUnicodeScalarSequence(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      index += 1;
    } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
      return false;
    }
  }
  return true;
}

function boundedClosedPreflight(value: unknown): boolean {
  const active = new Set<object>();
  let nodes = 0;
  let totalStringBytes = 0;
  const visit = (current: unknown, depth: number): boolean => {
    nodes += 1;
    if (nodes > MAX_NODES || depth > MAX_DEPTH) return false;
    if (current === null || typeof current === "boolean") return true;
    if (typeof current === "number") return Number.isFinite(current);
    if (typeof current === "string") {
      if (!isUnicodeScalarSequence(current)) return false;
      const bytes = Buffer.byteLength(current, "utf8");
      totalStringBytes += bytes;
      return bytes <= MAX_STRING_BYTES && totalStringBytes <= MAX_TOTAL_STRING_BYTES;
    }
    if (typeof current !== "object" || utilTypes.isProxy(current)) return false;
    if (active.has(current)) return false;
    active.add(current);
    try {
      if (Array.isArray(current)) {
        if (Object.getPrototypeOf(current) !== Array.prototype) return false;
        const descriptors = Object.getOwnPropertyDescriptors(current) as unknown as
          Record<PropertyKey, PropertyDescriptor>;
        const lengthDescriptor = descriptors.length;
        if (lengthDescriptor === undefined || !("value" in lengthDescriptor)
          || !Number.isSafeInteger(lengthDescriptor.value) || lengthDescriptor.value < 0
          || lengthDescriptor.value > MAX_ARRAY_LENGTH
          || Reflect.ownKeys(descriptors).length !== lengthDescriptor.value + 1) return false;
        for (let index = 0; index < lengthDescriptor.value; index += 1) {
          const descriptor = descriptors[String(index)];
          if (descriptor === undefined || !("value" in descriptor)
            || descriptor.enumerable !== true || !visit(descriptor.value, depth + 1)) return false;
        }
        return true;
      }
      if (Object.getPrototypeOf(current) !== Object.prototype) return false;
      const descriptors = Object.getOwnPropertyDescriptors(current);
      const keys = Reflect.ownKeys(descriptors);
      if (keys.length > MAX_PROPERTIES || keys.some((key) => typeof key !== "string")) return false;
      for (const key of keys as string[]) {
        const descriptor = descriptors[key];
        if (descriptor === undefined || !("value" in descriptor) || descriptor.enumerable !== true
          || !visit(key, depth + 1) || !visit(descriptor.value, depth + 1)) return false;
      }
      return true;
    } finally {
      active.delete(current);
    }
  };
  return visit(value, 0);
}

function exactKeys(value: Readonly<Record<string, unknown>>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const sortedExpected = [...expected].sort();
  return actual.length === sortedExpected.length
    && sortedExpected.every((key, index) => actual[index] === key);
}

function boundedString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && isUnicodeScalarSequence(value)
    && Buffer.byteLength(value, "utf8") <= MAX_STRING_BYTES;
}

function validHex(value: unknown, pattern: RegExp): value is string {
  return typeof value === "string" && pattern.test(value);
}

function equalHex(left: string, right: string): boolean {
  return left.length === right.length && HEX_32.test(left) && HEX_32.test(right)
    && timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}

function captureStringList(value: unknown): readonly string[] | null {
  if (!Array.isArray(value) || value.length === 0 || value.length > MAX_ARRAY_LENGTH
    || !value.every(boundedString) || new Set(value).size !== value.length) return null;
  return Object.freeze([...value]);
}

function captureKindList(value: unknown): readonly number[] | null {
  if (!Array.isArray(value) || value.length === 0 || value.length > MAX_ARRAY_LENGTH
    || !value.every((kind) => Number.isSafeInteger(kind) && kind >= 0 && kind <= 65_535)
    || new Set(value).size !== value.length) return null;
  return Object.freeze([...value]);
}

function validLimits(value: unknown): value is Readonly<Record<string, number>> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const limits = value as Readonly<Record<string, unknown>>;
  const keys = Object.keys(limits);
  return keys.length > 0 && keys.length <= MAX_ARRAY_LENGTH && keys.every(boundedString)
    && Object.values(limits).every((limit) => Number.isSafeInteger(limit) && (limit as number) > 0);
}

function validRelayHint(value: string): boolean {
  try {
    const parsed = new URL(value);
    return parsed.protocol === "wss:" && parsed.hostname.length > 0
      && parsed.username === "" && parsed.password === "" && parsed.hash === ""
      && (parsed.href === value
        || (parsed.pathname === "/" && parsed.search === "" && parsed.href === `${value}/`));
  } catch {
    return false;
  }
}

function captureInputs(
  envelope: InviteEnvelope,
  template: ControlInviteTemplate,
  request: ControlInviteRequest,
): CapturedInput | null {
  try {
    const bundle = { envelope, template, request };
    if (!boundedClosedPreflight(bundle)) return null;
    const captured = captureAuthorityInput(bundle) as unknown as CapturedInput;
    const envelopeRecord = captured.envelope as unknown as Readonly<Record<string, unknown>>;
    const descriptor = envelopeRecord.descriptor as Readonly<Record<string, unknown>>;
    const templateRecord = captured.template as unknown as Readonly<Record<string, unknown>>;
    const requestRecord = captured.request as unknown as Readonly<Record<string, unknown>>;
    const responseRecord = requestRecord.response as Readonly<Record<string, unknown>>;
    if (!exactKeys(envelopeRecord, ENVELOPE_KEYS)
      || descriptor === null || typeof descriptor !== "object" || Array.isArray(descriptor)
      || !exactKeys(descriptor, DESCRIPTOR_KEYS)
      || !exactKeys(templateRecord, TEMPLATE_KEYS)
      || !exactKeys(requestRecord, REQUEST_KEYS)
      || responseRecord === null || typeof responseRecord !== "object" || Array.isArray(responseRecord)
      || !exactKeys(responseRecord, RESPONSE_KEYS)) return null;
    return captured;
  } catch {
    return null;
  }
}

function validTemplate(template: ControlInviteTemplate): boolean {
  return boundedString(template.persona) && boundedString(template.audience)
    && validHex(template.client_key, HEX_32)
    && (template.client_class === "human-light" || template.client_class === "automated")
    && captureStringList(template.methods) !== null
    && captureKindList(template.event_kinds) !== null
    && validLimits(template.limits)
    && validHex(template.signer, HEX_32)
    && Number.isSafeInteger(template.expires_at) && template.expires_at > 0;
}

function validResponse(response: InviteResponseInput): boolean {
  return Number.isSafeInteger(response.now) && response.now >= 0
    && Number.isSafeInteger(response.expires_at) && response.expires_at > 0
    && (response.expected_purpose === "dm" || response.expected_purpose === "control-enrollment"
      || response.expected_purpose === "device-enrollment")
    && (response.response_purpose === "dm" || response.response_purpose === "control-enrollment"
      || response.response_purpose === "device-enrollment")
    && typeof response.descriptor_valid === "boolean"
    && typeof response.secret_commitment_valid === "boolean"
    && typeof response.seal_valid === "boolean"
    && validHex(response.seal_pubkey, HEX_32)
    && validHex(response.rumor_pubkey, HEX_32)
    && typeof response.proof_valid === "boolean"
    && typeof response.keypackage_valid === "boolean"
    && typeof response.capabilities_compatible === "boolean"
    && validHex(response.response_digest, HEX_32)
    && typeof response.group_established === "boolean";
}

function validEnvelope(envelope: Readonly<InviteEnvelope>, template: ControlInviteTemplate): boolean {
  const descriptor = envelope.descriptor;
  if (descriptor.version !== 1 || descriptor.purpose !== "control-enrollment"
    || descriptor.approval_mode !== "preauthorized"
    || !validHex(descriptor.inviter_account, HEX_32)
    || !validHex(descriptor.invite_id, HEX_32)
    || !validHex(descriptor.rendezvous_pubkey, HEX_32)
    || !Array.isArray(descriptor.relay_hints) || descriptor.relay_hints.length === 0
    || descriptor.relay_hints.length > 16 || !descriptor.relay_hints.every(validRelayHint)
    || new Set(descriptor.relay_hints).size !== descriptor.relay_hints.length
    || !Number.isSafeInteger(descriptor.issued_at) || descriptor.issued_at < 0
    || !Number.isSafeInteger(descriptor.expires_at) || descriptor.expires_at <= descriptor.issued_at
    || descriptor.expires_at - descriptor.issued_at > 3_600
    || !validHex(descriptor.secret_sha256, HEX_32)
    || !validHex(descriptor.expected_client_pubkey, HEX_32)
    || descriptor.preauthorization === undefined
    || !validHex(envelope.signature, HEX_64) || !validHex(envelope.secret, HEX_32)) return false;
  return descriptor.inviter_account === template.signer
    && descriptor.expected_client_pubkey === template.client_key
    && descriptor.expires_at === template.expires_at
    && jcsCanonicalize(descriptor.preauthorization) === jcsCanonicalize(template)
    && verifyInviteSignature(descriptor as InviteDescriptor, envelope.signature)
    && equalHex(secretCommitment(envelope.secret), descriptor.secret_sha256);
}

function transcript(
  envelope: Readonly<InviteEnvelope>,
  template: ControlInviteTemplate,
  request: ControlInviteRequest,
): Readonly<Record<string, unknown>> {
  const response = request.response;
  return Object.freeze({
    invite_id: envelope.descriptor.invite_id,
    descriptor_digest: Buffer.from(descriptorDigest(envelope.descriptor)).toString("hex"),
    template_digest: createHash("sha256").update(jcsCanonicalize(template)).digest("hex"),
    purpose: request.purpose,
    persona: request.persona,
    audience: request.audience,
    client_key: request.client_key,
    client_class: request.client_class,
    response_now: response.now,
    response_expires_at: response.expires_at,
    response_expected_purpose: response.expected_purpose,
    response_purpose: response.response_purpose,
    response_seal_pubkey: response.seal_pubkey,
    response_rumor_pubkey: response.rumor_pubkey,
    response_digest: response.response_digest,
  });
}

function validRequest(
  envelope: Readonly<InviteEnvelope>,
  template: ControlInviteTemplate,
  request: ControlInviteRequest,
): boolean {
  if (request.purpose !== "control-enrollment" || !validResponse(request.response)
    || !validHex(request.secret_proof, HEX_32)
    || request.persona !== template.persona || request.audience !== template.audience
    || request.client_key !== template.client_key || request.client_class !== template.client_class
    || request.response.expires_at !== template.expires_at
    || request.response.expected_purpose !== "control-enrollment"
    || request.response.response_purpose !== "control-enrollment"
    || request.response.seal_pubkey !== template.client_key
    || request.response.rumor_pubkey !== template.client_key) return false;
  try {
    return equalHex(request.secret_proof, responseProof(envelope.secret, transcript(
      envelope, template, request,
    ) as Record<string, unknown>));
  } catch {
    return false;
  }
}

function ownDataProperty(object: object, name: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(object, name);
  if (descriptor === undefined || !("value" in descriptor) || descriptor.enumerable !== true) {
    throw new TypeError(`Control invite config requires data property ${name}`);
  }
  return descriptor.value;
}

function captureConfig(config: ControlInvitePreauthorizationAuthorityConfig): AuthorityRecord {
  if (config === null || typeof config !== "object" || utilTypes.isProxy(config)
    || Object.getPrototypeOf(config) !== Object.prototype) {
    throw new TypeError("Control invite config must be an ordinary object");
  }
  const descriptors = Object.getOwnPropertyDescriptors(config);
  const keys = Reflect.ownKeys(descriptors);
  const required = ["authority_id", "load_revocation", "trusted_now"] as const;
  if (keys.some((key) => typeof key !== "string") || keys.length !== required.length
    || !required.every((key) => Object.hasOwn(descriptors, key))) {
    throw new TypeError("Control invite config must be closed");
  }
  const authorityId = ownDataProperty(config, "authority_id");
  const trustedNow = ownDataProperty(config, "trusted_now");
  const loadRevocation = ownDataProperty(config, "load_revocation");
  if (!boundedString(authorityId)
    || typeof trustedNow !== "function" || utilTypes.isProxy(trustedNow)
    || typeof loadRevocation !== "function" || utilTypes.isProxy(loadRevocation)) {
    throw new TypeError("Control invite config is invalid");
  }
  return Object.freeze({
    authority_id: authorityId,
    trusted_now: trustedNow as AuthorityRecord["trusted_now"],
    load_revocation: loadRevocation as AuthorityRecord["load_revocation"],
  });
}

export function createControlInvitePreauthorizationAuthority(
  config: ControlInvitePreauthorizationAuthorityConfig,
): ControlInvitePreauthorizationAuthority {
  const authority = Object.freeze({});
  AUTHORITIES.set(authority, captureConfig(config));
  return authority;
}

function validTime(authority: AuthorityRecord, descriptor: Readonly<InviteDescriptor>): boolean {
  try {
    const now = authority.trusted_now();
    return Number.isSafeInteger(now) && now >= descriptor.issued_at && now < descriptor.expires_at;
  } catch {
    return false;
  }
}

async function loadRevocation(
  authority: AuthorityRecord,
  inviteId: string,
): Promise<RevocationState | null> {
  try {
    const value = await authority.load_revocation(inviteId);
    if (!boundedClosedPreflight(value)) return null;
    const captured = captureAuthorityInput(value) as unknown as Readonly<Record<string, unknown>>;
    if (!exactKeys(captured, ["revision", "state"])
      || !Number.isSafeInteger(captured.revision) || (captured.revision as number) < 0
      || (captured.state !== "active" && captured.state !== "revoked")) return null;
    return captured as unknown as RevocationState;
  } catch {
    return null;
  }
}

export async function verifyControlInvitePreauthorization(
  authority: ControlInvitePreauthorizationAuthority,
  envelope: InviteEnvelope,
  template: ControlInviteTemplate,
  request: ControlInviteRequest,
): Promise<AuthorityDecision<
  "invite-preauthorization-invalid", VerifiedControlInvitePreauthorization
>> {
  const authorityRecord = AUTHORITIES.get(authority);
  if (authorityRecord === undefined) return REJECT;
  try {
    const input = captureInputs(envelope, template, request);
    if (input === null || !validTemplate(input.template)
      || !validEnvelope(input.envelope, input.template)
      || !validRequest(input.envelope, input.template, input.request)
      || !validTime(authorityRecord, input.envelope.descriptor)) return REJECT;

    const initial = await loadRevocation(authorityRecord, input.envelope.descriptor.invite_id);
    if (initial === null || initial.state !== "active"
      || !validTime(authorityRecord, input.envelope.descriptor)) return REJECT;
    const current = await loadRevocation(authorityRecord, input.envelope.descriptor.invite_id);
    if (current === null || current.state !== "active" || current.revision !== initial.revision
      || !validTime(authorityRecord, input.envelope.descriptor)) return REJECT;

    const envelopeBytes = jcsCanonicalize(input.envelope);
    const descriptorDigestHex = Buffer.from(descriptorDigest(input.envelope.descriptor)).toString("hex");
    const templateDigest = createHash("sha256").update(jcsCanonicalize(input.template)).digest("hex");
    const requestDigest = createHash("sha256").update(jcsCanonicalize(input.request)).digest("hex");
    const bindingDigest = authorityBindingDigest("heterodyne.control-invite-preauthorization/v1", {
      authority_id: authorityRecord.authority_id,
      envelope_bytes: envelopeBytes,
      descriptor_digest: descriptorDigestHex,
      template_digest: templateDigest,
      request_digest: requestDigest,
      revocation_revision: current.revision,
    });
    const output = Object.freeze({});
    VERIFIED.set(output, Object.freeze({
      authority: authorityRecord,
      envelope_bytes: envelopeBytes,
      descriptor_digest: descriptorDigestHex,
      template_digest: templateDigest,
      request_digest: requestDigest,
      invite_id: input.envelope.descriptor.invite_id,
      purpose: "control-enrollment",
      persona: input.template.persona,
      audience: input.template.audience,
      client_key: input.template.client_key,
      client_class: input.template.client_class,
      signer: input.template.signer,
      methods: input.template.methods,
      event_kinds: input.template.event_kinds,
      limits: input.template.limits,
      expires_at: input.template.expires_at,
      revocation_revision: current.revision,
      binding_digest: bindingDigest,
    }));
    return Object.freeze({ verdict: "accept", output });
  } catch {
    return REJECT;
  }
}
