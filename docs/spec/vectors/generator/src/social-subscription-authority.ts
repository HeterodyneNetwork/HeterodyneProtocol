import { types as utilTypes } from "node:util";
import type { AgentAssociation } from "./agent-authorship.js";
import {
  snapshotAgentPolicyEvent,
  snapshotAgentPolicyTarget,
  validateAgentPolicyCorrection,
  validateAgentPolicyList,
  validateAgentPolicyReceipt,
  type AgentPolicyDecision,
  type AgentPolicyList,
  type AgentPolicyNostrSignedEvent as NostrSignedEvent,
  type AgentPolicyReceipt,
  type VerifiedAgentPolicyEvent as VerifiedNostrEvent,
  type VerifiedAgentPolicyTarget,
} from "./agent-moderation.js";
import { captureExactDataObject } from "./closed-data.js";
import {
  selectCurrentReplaceableEvent,
  type ReplaceableSelectionAuthority,
} from "./replaceable-selection.js";

declare const socialSubscriptionAuthorityBrand: unique symbol;

export type SocialSubscriptionAuthority = Readonly<{
  readonly [socialSubscriptionAuthorityBrand]: true;
}>;

export type SocialSubscriptionAuthorityConfig = Readonly<{
  authority_id: string;
  trusted_now: () => number;
  replaceable_selection: ReplaceableSelectionAuthority;
  load_subscription: (policy_persona: string) => Promise<Readonly<{
    revision: number;
    subscribed: boolean;
    default_visible: boolean;
  }>>;
}>;

export type SocialSubscriptionInput = Readonly<{
  policy_persona: string;
  list_candidates: readonly NostrSignedEvent[];
  receipt_events: readonly NostrSignedEvent[];
  target_events: readonly NostrSignedEvent[];
  correction_events: readonly NostrSignedEvent[];
}>;

export type SubscribedAgentPolicyView = Readonly<Record<never, never>>;

type LocalSubscription = Readonly<{
  revision: number;
  subscribed: boolean;
  default_visible: boolean;
}>;

type MutedBinding = Readonly<{
  event_id: string;
  event_author: string;
  receipt_id: string;
  reason: string;
  agent_association: AgentAssociation | null;
  receipt_event: VerifiedNostrEvent;
  target_event: VerifiedNostrEvent;
}>;

type PolicyState = {
  list_id: string;
  list_created_at: number;
  list_event: VerifiedNostrEvent;
  muted: readonly MutedBinding[];
  current_view: SubscribedAgentPolicyView | null;
};

type CapturedAuthority = Readonly<{
  authority_id: string;
  trusted_now: () => number;
  replaceable_selection: ReplaceableSelectionAuthority;
  load_subscription: SocialSubscriptionAuthorityConfig["load_subscription"];
  subscriptions: Map<string, LocalSubscription>;
  policies: Map<string, PolicyState>;
}>;

type ReceiptRecord = Readonly<{
  receipt: AgentPolicyReceipt;
  event: VerifiedNostrEvent;
  target: VerifiedNostrEvent;
}>;

type ViewRecord = Readonly<{
  authority: SocialSubscriptionAuthority;
  policy_persona: string;
  subscription_revision: number;
  list_id: string;
  list_event: VerifiedNostrEvent;
  muted: readonly MutedBinding[];
}>;

const AUTHORITIES = new WeakMap<object, CapturedAuthority>();
const VIEWS = new WeakMap<object, ViewRecord>();
const UTF8_ENCODER = new TextEncoder();
const HEX_32 = /^[0-9a-f]{64}$/u;
const MAX_EVENTS_PER_COLLECTION = 64;
const MAX_TOTAL_EVENTS = 128;
const MAX_EVENT_CONTENT_BYTES = 65_536;
const MAX_EVENT_TAGS = 256;
const MAX_TAG_WIDTH = 8;
const MAX_TAG_MEMBER_BYTES = 1_024;
const MAX_EVENT_BYTES = 131_072;
const MAX_TOTAL_INPUT_BYTES = 2_097_152;
const FUTURE_BOUND_SECONDS = 900;
const INPUT_KEYS = [
  "policy_persona",
  "list_candidates",
  "receipt_events",
  "target_events",
  "correction_events",
] as const;

export function createSocialSubscriptionAuthority(
  config: SocialSubscriptionAuthorityConfig,
): SocialSubscriptionAuthority {
  try {
    const captured = captureExactDataObject(config, [[
      "authority_id",
      "trusted_now",
      "replaceable_selection",
      "load_subscription",
    ]], "Social subscription authority config");
    if (
      typeof captured.authority_id !== "string"
      || captured.authority_id.length === 0
      || captured.authority_id.length > 256
      || typeof captured.trusted_now !== "function"
      || utilTypes.isProxy(captured.trusted_now)
      || typeof captured.load_subscription !== "function"
      || utilTypes.isProxy(captured.load_subscription)
      || captured.replaceable_selection === null
      || typeof captured.replaceable_selection !== "object"
      || utilTypes.isProxy(captured.replaceable_selection)
    ) throw invalid();

    const authority = Object.freeze({}) as SocialSubscriptionAuthority;
    AUTHORITIES.set(authority, Object.freeze({
      authority_id: captured.authority_id,
      trusted_now: captured.trusted_now as () => number,
      replaceable_selection: captured.replaceable_selection as ReplaceableSelectionAuthority,
      load_subscription: captured.load_subscription as CapturedAuthority["load_subscription"],
      subscriptions: new Map(),
      policies: new Map(),
    }));
    return authority;
  } catch {
    throw invalid();
  }
}

export async function resolveSubscribedAgentPolicy(
  authorityValue: SocialSubscriptionAuthority,
  inputValue: SocialSubscriptionInput,
): Promise<SubscribedAgentPolicyView | null> {
  const authority = opaqueAuthority(authorityValue);
  if (authority === null) return null;

  try {
    const input = captureInput(inputValue);
    if (input === null) return invalidate(authority, null);
    const now = authority.trusted_now();
    if (!Number.isSafeInteger(now) || now < 0) return invalidate(authority, null);

    const targets = new Map<string, VerifiedAgentPolicyTarget>();
    for (const target of input.target_events) {
      const verified = snapshotAgentPolicyTarget(target);
      if (
        verified === null
        || verified.event.created_at > now + FUTURE_BOUND_SECONDS
        || targets.has(verified.event.id)
      ) return invalidate(authority, input.policy_persona);
      targets.set(verified.event.id, verified);
    }

    const receipts = resolveReceipts(
      input.policy_persona,
      input.receipt_events,
      targets,
      now,
    );
    if (receipts === null) return invalidate(authority, input.policy_persona);
    const lists = resolveLists(
      input.policy_persona,
      input.list_candidates,
      receipts,
      now,
    );
    if (lists === null) return invalidate(authority, input.policy_persona);
    const selected = selectCurrentReplaceableEvent(
      authority.replaceable_selection,
      lists.map(({ event }) => event),
    ).selected;
    if (selected === null) return invalidate(authority, input.policy_persona);
    const selectedList = lists.find(({ event }) => event.id === selected.id);
    if (selectedList === undefined) return invalidate(authority, input.policy_persona);

    const corrections = resolveCorrections(
      input.policy_persona,
      input.correction_events,
      receipts,
      now,
    );
    if (corrections === null) return invalidate(authority, input.policy_persona);
    const selectedReceipts = new Set(
      selectedList.list.entries.map(({ receipt_id }) => receipt_id),
    );
    for (const [receiptId, correction] of corrections) {
      if (
        !selectedReceipts.has(receiptId)
        && correction.created_at > selectedList.event.created_at
      ) return invalidate(authority, input.policy_persona);
    }

    const pending = authority.load_subscription(input.policy_persona);
    if (
      pending === null
      || typeof pending !== "object"
      || utilTypes.isProxy(pending)
      || Object.getPrototypeOf(pending) !== Promise.prototype
    ) return invalidate(authority, input.policy_persona);
    const local = captureSubscription(await pending);
    if (local === null || !acceptLocalRevision(authority, input.policy_persona, local)) {
      return invalidate(authority, input.policy_persona);
    }
    if (!local.subscribed || !local.default_visible) {
      invalidate(authority, input.policy_persona);
      authority.policies.delete(input.policy_persona);
      return null;
    }

    const prior = authority.policies.get(input.policy_persona);
    const relation = prior === undefined
      ? "newer"
      : compareReplaceable(selected, prior);
    let listId = selected.id;
    let listCreatedAt = selected.created_at;
    let listEvent = selected;
    let muted: readonly MutedBinding[];
    if (relation === "older") {
      listId = prior?.list_id ?? selected.id;
      listCreatedAt = prior?.list_created_at ?? selected.created_at;
      listEvent = prior?.list_event ?? selected;
      muted = prior?.muted ?? [];
    } else {
      muted = composeMutedBindings(
        selectedList.list,
        receipts,
        prior?.muted ?? [],
        corrections,
      );
    }

    const view = Object.freeze({}) as SubscribedAgentPolicyView;
    const state: PolicyState = {
      list_id: listId,
      list_created_at: listCreatedAt,
      list_event: listEvent,
      muted,
      current_view: view,
    };
    authority.policies.set(input.policy_persona, state);
    VIEWS.set(view, Object.freeze({
      authority: authorityValue,
      policy_persona: input.policy_persona,
      subscription_revision: local.revision,
      list_id: listId,
      list_event: listEvent,
      muted,
    }));
    return view;
  } catch {
    return invalidate(authority, null);
  }
}

export function applySubscribedAgentPolicy(
  viewValue: SubscribedAgentPolicyView | null,
  eventValue: NostrSignedEvent,
): AgentPolicyDecision {
  if (viewValue === null || typeof viewValue !== "object") {
    return visible();
  }
  const view = VIEWS.get(viewValue);
  if (view === undefined) return visible();
  const authority = AUTHORITIES.get(view.authority);
  const current = authority?.policies.get(view.policy_persona);
  const subscription = authority?.subscriptions.get(view.policy_persona);
  if (
    authority === undefined
    || current?.current_view !== viewValue
    || current.list_id !== view.list_id
    || current.list_event !== view.list_event
    || subscription?.revision !== view.subscription_revision
    || !subscription.subscribed
    || !subscription.default_visible
  ) return visible();

  const event = snapshotBoundedEvent(eventValue);
  if (event === null) return visible();
  const muted = view.muted.some((binding) => binding.event_author === event.pubkey);
  return muted
    ? {
        visible: false,
        muted: true,
        source: view.policy_persona,
        reason: "subscribed-event-author-policy",
      }
    : visible();
}

function captureInput(value: unknown): Readonly<{
  policy_persona: string;
  list_candidates: readonly VerifiedNostrEvent[];
  receipt_events: readonly VerifiedNostrEvent[];
  target_events: readonly VerifiedNostrEvent[];
  correction_events: readonly VerifiedNostrEvent[];
}> | null {
  try {
    const captured = captureExactDataObject(
      value,
      [[...INPUT_KEYS]],
      "Social subscription input",
    );
    const policyPersona = captured.policy_persona;
    const rawCollections = [
      captureRawEventArray(captured.list_candidates),
      captureRawEventArray(captured.receipt_events),
      captureRawEventArray(captured.target_events),
      captureRawEventArray(captured.correction_events),
    ] as const;
    if (
      typeof policyPersona !== "string"
      || !HEX_32.test(policyPersona)
      || rawCollections.some((collection) => collection === null)
    ) return null;
    const collections = rawCollections as readonly (readonly unknown[])[];
    const totalEvents = collections.reduce((total, collection) => total + collection.length, 0);
    if (totalEvents > MAX_TOTAL_EVENTS) return null;

    const budget = { bytes: 0 };
    const capturedCollections: NostrSignedEvent[][] = [];
    for (const collection of collections) {
      const events: NostrSignedEvent[] = [];
      for (const event of collection) {
        const snapshot = captureBoundedEvent(event, budget);
        if (snapshot === null) return null;
        events.push(snapshot);
      }
      capturedCollections.push(events);
    }

    const verifiedCollections: VerifiedNostrEvent[][] = [];
    for (const collection of capturedCollections) {
      const events: VerifiedNostrEvent[] = [];
      for (const event of collection) {
        const verified = snapshotAgentPolicyEvent(event);
        if (verified === null) return null;
        events.push(verified);
      }
      verifiedCollections.push(events);
    }
    const [listCandidates, receiptEvents, targetEvents, correctionEvents] =
      verifiedCollections.map((collection) => Object.freeze(collection));
    return Object.freeze({
      policy_persona: policyPersona,
      list_candidates: listCandidates,
      receipt_events: receiptEvents,
      target_events: targetEvents,
      correction_events: correctionEvents,
    });
  } catch {
    return null;
  }
}

function captureRawEventArray(value: unknown): readonly unknown[] | null {
  if (
    value === null
    || typeof value !== "object"
    || utilTypes.isProxy(value)
    || !Array.isArray(value)
  ) return null;
  try {
    if (Object.getPrototypeOf(value) !== Array.prototype) return null;
    const lengthDescriptor = Object.getOwnPropertyDescriptor(value, "length");
    if (
      lengthDescriptor === undefined
      || !("value" in lengthDescriptor)
      || !Number.isSafeInteger(lengthDescriptor.value)
      || lengthDescriptor.value < 0
      || lengthDescriptor.value > MAX_EVENTS_PER_COLLECTION
    ) return null;
    const descriptors = Object.getOwnPropertyDescriptors(value) as unknown as PropertyDescriptorMap;
    const keys = Reflect.ownKeys(descriptors);
    if (
      keys.some((key) => typeof key !== "string")
      || keys.length !== lengthDescriptor.value + 1
    ) return null;
    const events: unknown[] = [];
    for (let index = 0; index < lengthDescriptor.value; index += 1) {
      const descriptor = descriptors[String(index)];
      if (
        descriptor === undefined
        || !("value" in descriptor)
        || descriptor.enumerable !== true
      ) return null;
      events.push(descriptor.value);
    }
    return Object.freeze(events);
  } catch {
    return null;
  }
}

function captureBoundedEvent(
  value: unknown,
  budget: { bytes: number },
): NostrSignedEvent | null {
  if (
    value === null
    || typeof value !== "object"
    || utilTypes.isProxy(value)
    || Array.isArray(value)
  ) return null;
  try {
    if (Object.getPrototypeOf(value) !== Object.prototype) return null;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    const eventKeys = ["content", "created_at", "id", "kind", "pubkey", "sig", "tags"] as const;
    if (
      keys.some((key) => typeof key !== "string")
      || keys.length !== eventKeys.length
      || !eventKeys.every((key) => Object.hasOwn(descriptors, key))
    ) return null;
    const read = (key: typeof eventKeys[number]): unknown => {
      const descriptor = descriptors[key];
      return descriptor !== undefined
        && "value" in descriptor
        && descriptor.enumerable === true
        ? descriptor.value
        : undefined;
    };
    const content = read("content");
    const createdAt = read("created_at");
    const id = read("id");
    const kind = read("kind");
    const pubkey = read("pubkey");
    const sig = read("sig");
    const tags = captureBoundedTags(read("tags"));
    if (
      typeof content !== "string"
      || content.length > MAX_EVENT_CONTENT_BYTES
      || !Number.isSafeInteger(createdAt)
      || (createdAt as number) < 0
      || typeof id !== "string"
      || !HEX_32.test(id)
      || !Number.isSafeInteger(kind)
      || (kind as number) < 0
      || (kind as number) > 65_535
      || typeof pubkey !== "string"
      || !HEX_32.test(pubkey)
      || typeof sig !== "string"
      || !/^[0-9a-f]{128}$/u.test(sig)
      || tags === null
    ) return null;
    const contentBytes = utf8Length(content);
    if (contentBytes > MAX_EVENT_CONTENT_BYTES) return null;
    let eventBytes = contentBytes + utf8Length(id) + utf8Length(pubkey) + utf8Length(sig);
    for (const tag of tags) {
      for (const member of tag) eventBytes += utf8Length(member);
    }
    if (
      eventBytes > MAX_EVENT_BYTES
      || budget.bytes + eventBytes > MAX_TOTAL_INPUT_BYTES
    ) return null;
    budget.bytes += eventBytes;
    return Object.freeze({
      content,
      created_at: createdAt as number,
      id,
      kind: kind as number,
      pubkey,
      sig,
      tags,
    });
  } catch {
    return null;
  }
}

function snapshotBoundedEvent(value: unknown): VerifiedNostrEvent | null {
  const captured = captureBoundedEvent(value, { bytes: 0 });
  return captured === null ? null : snapshotAgentPolicyEvent(captured);
}

function captureBoundedTags(value: unknown): string[][] | null {
  if (
    value === null
    || typeof value !== "object"
    || utilTypes.isProxy(value)
    || !Array.isArray(value)
    || Object.getPrototypeOf(value) !== Array.prototype
  ) return null;
  const tags = captureDenseArray(value, MAX_EVENT_TAGS);
  if (tags === null) return null;
  const captured: string[][] = [];
  for (const tagValue of tags) {
    if (
      tagValue === null
      || typeof tagValue !== "object"
      || utilTypes.isProxy(tagValue)
      || !Array.isArray(tagValue)
      || Object.getPrototypeOf(tagValue) !== Array.prototype
    ) return null;
    const members = captureDenseArray(tagValue, MAX_TAG_WIDTH);
    if (
      members === null
      || members.length === 0
      || members.some((member) =>
        typeof member !== "string"
        || member.length > MAX_TAG_MEMBER_BYTES
        || utf8Length(member) > MAX_TAG_MEMBER_BYTES)
    ) return null;
    captured.push(Object.freeze(members as string[]) as string[]);
  }
  return Object.freeze(captured) as string[][];
}

function captureDenseArray(value: unknown[], maximum: number): readonly unknown[] | null {
  const lengthDescriptor = Object.getOwnPropertyDescriptor(value, "length");
  if (
    lengthDescriptor === undefined
    || !("value" in lengthDescriptor)
    || !Number.isSafeInteger(lengthDescriptor.value)
    || lengthDescriptor.value < 0
    || lengthDescriptor.value > maximum
  ) return null;
  const descriptors = Object.getOwnPropertyDescriptors(value) as unknown as PropertyDescriptorMap;
  const keys = Reflect.ownKeys(descriptors);
  if (
    keys.some((key) => typeof key !== "string")
    || keys.length !== lengthDescriptor.value + 1
  ) return null;
  const result: unknown[] = [];
  for (let index = 0; index < lengthDescriptor.value; index += 1) {
    const descriptor = descriptors[String(index)];
    if (
      descriptor === undefined
      || !("value" in descriptor)
      || descriptor.enumerable !== true
    ) return null;
    result.push(descriptor.value);
  }
  return Object.freeze(result);
}

function utf8Length(value: string): number {
  return UTF8_ENCODER.encode(value).byteLength;
}

function resolveReceipts(
  policyPersona: string,
  events: readonly VerifiedNostrEvent[],
  targets: ReadonlyMap<string, VerifiedAgentPolicyTarget>,
  now: number,
): ReadonlyMap<string, ReceiptRecord> | null {
  const receipts = new Map<string, ReceiptRecord>();
  for (const event of events) {
    if (event.pubkey !== policyPersona || event.created_at > now + FUTURE_BOUND_SECONDS) return null;
    const targetId = exactTagValue(event, "e");
    if (targetId === null) return null;
    const target = targets.get(targetId);
    if (target === undefined || target.event.created_at > event.created_at) return null;
    try {
      const receipt = validateAgentPolicyReceipt(event, target);
      if (receipt.observed_at !== event.created_at || receipts.has(event.id)) return null;
      receipts.set(event.id, Object.freeze({ receipt, event, target: target.event }));
    } catch {
      return null;
    }
  }
  return receipts;
}

function resolveLists(
  policyPersona: string,
  events: readonly VerifiedNostrEvent[],
  receipts: ReadonlyMap<string, ReceiptRecord>,
  now: number,
): readonly Readonly<{ event: VerifiedNostrEvent; list: AgentPolicyList }>[] | null {
  const parsed = new Map<string, Readonly<{ event: VerifiedNostrEvent; list: AgentPolicyList }>>();
  const receiptValues = new Map(
    [...receipts].map(([id, value]) => [id, value.receipt] as const),
  );
  for (const event of events) {
    if (
      event.pubkey !== policyPersona
      || event.kind !== 10_000
      || event.created_at > now + FUTURE_BOUND_SECONDS
      || parsed.has(event.id)
    ) return null;
    try {
      const list = validateAgentPolicyList(event, receiptValues);
      if (list.entries.some(({ receipt_id }) => {
        const receipt = receipts.get(receipt_id);
        return receipt === undefined || receipt.event.created_at > event.created_at;
      })) return null;
      parsed.set(event.id, Object.freeze({ event, list }));
    } catch {
      return null;
    }
  }
  return Object.freeze([...parsed.values()]);
}

function resolveCorrections(
  policyPersona: string,
  events: readonly VerifiedNostrEvent[],
  receipts: ReadonlyMap<string, ReceiptRecord>,
  now: number,
): ReadonlyMap<string, VerifiedNostrEvent> | null {
  const corrected = new Map<string, VerifiedNostrEvent>();
  for (const event of events) {
    if (event.pubkey !== policyPersona || event.created_at > now + FUTURE_BOUND_SECONDS) return null;
    const receiptId = exactTagValue(event, "e");
    if (receiptId === null) return null;
    const record = receipts.get(receiptId);
    if (
      record === undefined
      || event.created_at < record.event.created_at
      || corrected.has(receiptId)
    ) return null;
    try {
      validateAgentPolicyCorrection(event, record.receipt);
      corrected.set(receiptId, event);
    } catch {
      return null;
    }
  }
  return corrected;
}

function composeMutedBindings(
  selected: AgentPolicyList,
  receipts: ReadonlyMap<string, ReceiptRecord>,
  prior: readonly MutedBinding[],
  corrections: ReadonlyMap<string, VerifiedNostrEvent>,
): readonly MutedBinding[] {
  const muted = new Map<string, MutedBinding>();
  for (const entry of selected.entries) {
    const record = receipts.get(entry.receipt_id);
    if (record === undefined) continue;
    muted.set(entry.receipt_id, Object.freeze({
      event_id: record.receipt.event_id,
      event_author: record.receipt.event_author,
      receipt_id: record.receipt.receipt_id,
      reason: record.receipt.reason,
      agent_association: record.receipt.agent_association === null
        ? null
        : Object.freeze({ ...record.receipt.agent_association }),
      receipt_event: record.event,
      target_event: record.target,
    }));
  }
  for (const binding of prior) {
    if (!muted.has(binding.receipt_id) && !corrections.has(binding.receipt_id)) {
      muted.set(binding.receipt_id, binding);
    }
  }
  return Object.freeze([...muted.values()]);
}

function exactTagValue(event: VerifiedNostrEvent, name: string): string | null {
  const tags = event.tags.filter((tag) => tag[0] === name);
  return tags.length === 1 && (tags[0].length === 2 || tags[0].length === 3)
    ? tags[0][1]
    : null;
}

function captureSubscription(value: unknown): LocalSubscription | null {
  try {
    const captured = captureExactDataObject(value, [[
      "revision",
      "subscribed",
      "default_visible",
    ]], "Social local subscription");
    if (
      !Number.isSafeInteger(captured.revision)
      || (captured.revision as number) < 0
      || typeof captured.subscribed !== "boolean"
      || typeof captured.default_visible !== "boolean"
    ) return null;
    return Object.freeze({
      revision: captured.revision as number,
      subscribed: captured.subscribed,
      default_visible: captured.default_visible,
    });
  } catch {
    return null;
  }
}

function acceptLocalRevision(
  authority: CapturedAuthority,
  persona: string,
  current: LocalSubscription,
): boolean {
  const prior = authority.subscriptions.get(persona);
  if (
    prior !== undefined
    && (current.revision < prior.revision
      || current.revision === prior.revision
        && (current.subscribed !== prior.subscribed
          || current.default_visible !== prior.default_visible))
  ) return false;
  authority.subscriptions.set(persona, current);
  return true;
}

function compareReplaceable(
  selected: VerifiedNostrEvent,
  prior: PolicyState,
): "older" | "same-or-newer" {
  if (selected.created_at < prior.list_created_at) return "older";
  if (selected.created_at > prior.list_created_at) return "same-or-newer";
  return selected.id > prior.list_id ? "older" : "same-or-newer";
}

function opaqueAuthority(value: unknown): CapturedAuthority | null {
  return value !== null && typeof value === "object"
    ? AUTHORITIES.get(value) ?? null
    : null;
}

function invalidate(
  authority: CapturedAuthority,
  persona: string | null,
): null {
  if (persona === null) {
    for (const policy of authority.policies.values()) policy.current_view = null;
  } else {
    const policy = authority.policies.get(persona);
    if (policy !== undefined) policy.current_view = null;
  }
  return null;
}

function visible(): AgentPolicyDecision {
  return { visible: true, muted: false };
}

function invalid(): Error {
  return new Error("social-subscription-authority-invalid");
}
