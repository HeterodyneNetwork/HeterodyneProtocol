import { types as utilTypes } from "node:util";
import {
  matchesAgentAttributionProfile,
  createCommsSocialSignedPublicationConsumer,
  type AgentAssociation,
  type CommsSocialPublicationAuthority,
  type CommsSocialSignedPublicationConsumer,
  type CommsSocialSignedPublication,
} from "./agent-authorship.js";
import {
  snapshotAndVerifyNostrEvent,
  type NostrSignedEvent,
  type VerifiedNostrEvent,
} from "./nostr.js";
import {
  createReplaceableSelectionAuthority,
  selectCurrentReplaceableEvent,
  type ReplaceableSelectionAuthority,
} from "./replaceable-selection.js";

export type SocialAuthorshipInput = {
  event: NostrSignedEvent;
  persona_active_key?: string;
  comms_authorization?: CommsSocialSignedPublication;
  requested_feed?: string;
  requested_resource?: string;
};

export type SocialAuthorshipDecision =
  | {
      verdict: "accept";
      event_author: string;
      represented_persona: string;
      agent_association?: AgentAssociation;
    }
  | {
      verdict: "reject";
      reason_code: "social-event-invalid" | "social-author-binding-invalid";
    };

export type SocialEventCandidate = {
  carrier: "relay" | "repository";
  event: NostrSignedEvent;
};

export type SocialReplaceableCoordinate = {
  pubkey: string;
  kind: number;
  d?: string;
};

const SEVEN_DAYS_SECONDS = 7 * 24 * 60 * 60;
const HEX_32 = /^[0-9a-f]{64}$/;
const SOCIAL_SELECTION_AUTHORITY = createReplaceableSelectionAuthority({
  trusted_now: () => Math.floor(Date.now() / 1_000),
});

export function validateSocialAuthorship(
  input: SocialAuthorshipInput,
): SocialAuthorshipDecision {
  return validateSocialAuthorshipWithConsumer(input, null);
}

export function createSocialAuthorshipValidator(input: {
  publication_authority: CommsSocialPublicationAuthority;
}): (publication: SocialAuthorshipInput) => SocialAuthorshipDecision {
  const consumePublication = createCommsSocialSignedPublicationConsumer({
    authority: input.publication_authority,
  });
  return (publication) => validateSocialAuthorshipWithConsumer(
    publication,
    consumePublication,
  );
}

function validateSocialAuthorshipWithConsumer(
  input: SocialAuthorshipInput,
  consumePublication: CommsSocialSignedPublicationConsumer | null,
): SocialAuthorshipDecision {
  const event = snapshotAndVerifyNostrEvent(input.event);
  if (event === null) {
    return { verdict: "reject", reason_code: "social-event-invalid" };
  }
  const representedPersona = input.persona_active_key ?? event.pubkey;
  if (!HEX_32.test(representedPersona)) {
    return { verdict: "reject", reason_code: "social-author-binding-invalid" };
  }
  if (event.pubkey === representedPersona) {
    return {
      verdict: "accept",
      event_author: event.pubkey,
      represented_persona: representedPersona,
    };
  }

  const attribution = signedAgentAssociation(event);
  if (
    !attribution.valid
    || input.requested_feed === undefined
    || input.requested_resource === undefined
    || consumePublication === null
    || !consumePublication({
      publication: input.comms_authorization,
      represented_persona: representedPersona,
      event,
      agent_association: attribution.association,
      requested_feed: input.requested_feed,
      requested_resource: input.requested_resource,
    })
    || attribution.association?.kind === "key"
      && attribution.association.value !== event.pubkey
  ) {
    return { verdict: "reject", reason_code: "social-author-binding-invalid" };
  }
  return {
    verdict: "accept",
    event_author: event.pubkey,
    represented_persona: representedPersona,
    ...(attribution.association === null
      ? {}
      : { agent_association: attribution.association }),
  };
}

export function selectCurrentSocialEvent(input: {
  selection_authority?: ReplaceableSelectionAuthority;
  coordinate: SocialReplaceableCoordinate;
  candidates: readonly SocialEventCandidate[];
}): NostrSignedEvent | null {
  if (!validCoordinate(input.coordinate)) return null;
  const capturedCandidates = captureSocialCandidateEvents(input.candidates);
  if (capturedCandidates === null) return null;
  const candidates: VerifiedNostrEvent[] = [];
  for (const event of capturedCandidates) {
    if (event !== null && validateSocialReplaceableCandidate({
      coordinate: input.coordinate,
      event,
    }).verdict === "accept") {
      candidates.push(event);
    }
  }
  return selectCurrentReplaceableEvent(
    input.selection_authority ?? SOCIAL_SELECTION_AUTHORITY,
    candidates,
  ).selected;
}

function captureSocialCandidateEvents(
  value: unknown,
): readonly (VerifiedNostrEvent | null)[] | null {
  if (
    value === null
    || typeof value !== "object"
    || utilTypes.isProxy(value)
    || !Array.isArray(value)
  ) return null;
  let prototype: object | null;
  let descriptors: PropertyDescriptorMap;
  try {
    prototype = Object.getPrototypeOf(value) as object | null;
    descriptors = Object.getOwnPropertyDescriptors(value) as unknown as PropertyDescriptorMap;
  } catch {
    return null;
  }
  const keys = Reflect.ownKeys(descriptors);
  const lengthDescriptor = descriptors.length;
  if (
    prototype !== Array.prototype
    || keys.some((key) => typeof key !== "string")
    || lengthDescriptor === undefined
    || !("value" in lengthDescriptor)
    || !Number.isSafeInteger(lengthDescriptor.value)
    || lengthDescriptor.value < 0
    || keys.length !== lengthDescriptor.value + 1
  ) return null;

  const captured: Array<VerifiedNostrEvent | null> = [];
  for (let index = 0; index < lengthDescriptor.value; index += 1) {
    const candidateDescriptor = descriptors[String(index)];
    if (
      candidateDescriptor === undefined
      || !("value" in candidateDescriptor)
      || candidateDescriptor.enumerable !== true
    ) return null;
    const candidate = candidateDescriptor.value;
    if (
      candidate === null
      || typeof candidate !== "object"
      || utilTypes.isProxy(candidate)
      || Array.isArray(candidate)
    ) return null;
    let candidatePrototype: object | null;
    let candidateDescriptors: PropertyDescriptorMap;
    try {
      candidatePrototype = Object.getPrototypeOf(candidate) as object | null;
      candidateDescriptors = Object.getOwnPropertyDescriptors(candidate);
    } catch {
      return null;
    }
    const candidateKeys = Reflect.ownKeys(candidateDescriptors);
    const carrierDescriptor = candidateDescriptors.carrier;
    const eventDescriptor = candidateDescriptors.event;
    if (
      candidatePrototype !== Object.prototype
      || candidateKeys.length !== 2
      || candidateKeys.some((key) => typeof key !== "string")
      || carrierDescriptor === undefined
      || !("value" in carrierDescriptor)
      || carrierDescriptor.enumerable !== true
      || carrierDescriptor.value !== "relay" && carrierDescriptor.value !== "repository"
      || eventDescriptor === undefined
      || !("value" in eventDescriptor)
      || eventDescriptor.enumerable !== true
    ) return null;
    captured.push(snapshotAndVerifyNostrEvent(eventDescriptor.value));
  }
  return Object.freeze(captured);
}

export function validateSocialReplaceableCandidate(input: {
  coordinate: SocialReplaceableCoordinate;
  event: NostrSignedEvent;
}): { verdict: "accept" } | {
  verdict: "reject";
  reason_code: "social-event-invalid" | "social-replaceable-coordinate-mismatch";
} {
  const event = snapshotAndVerifyNostrEvent(input.event);
  if (event === null) {
    return { verdict: "reject", reason_code: "social-event-invalid" };
  }
  if (
    !validCoordinate(input.coordinate)
    || event.pubkey !== input.coordinate.pubkey
    || event.kind !== input.coordinate.kind
    || coordinateD(event) !== input.coordinate.d
  ) {
    return {
      verdict: "reject",
      reason_code: "social-replaceable-coordinate-mismatch",
    };
  }
  return { verdict: "accept" };
}

export function assessSocialStateFreshness(
  event: NostrSignedEvent,
  now: number,
): { valid: boolean; warning: "stale" | null } {
  const verified = snapshotAndVerifyNostrEvent(event);
  if (verified === null || ![0, 10002].includes(verified.kind)) {
    return { valid: false, warning: null };
  }
  return {
    valid: true,
    warning: now - verified.created_at > SEVEN_DAYS_SECONDS ? "stale" : null,
  };
}

function validCoordinate(coordinate: SocialReplaceableCoordinate): boolean {
  if (!HEX_32.test(coordinate.pubkey)) return false;
  if (coordinate.kind === 0 || coordinate.kind === 3
    || coordinate.kind >= 10_000 && coordinate.kind < 20_000) {
    return coordinate.d === undefined;
  }
  return coordinate.kind >= 30_000
    && coordinate.kind < 40_000
    && typeof coordinate.d === "string";
}

function coordinateD(event: NostrSignedEvent): string | undefined | null {
  if (event.kind === 0 || event.kind === 3
    || event.kind >= 10_000 && event.kind < 20_000) {
    return undefined;
  }
  const dTags = event.tags.filter((tag) => tag[0] === "d");
  return dTags.length === 1 && dTags[0].length >= 2 ? dTags[0][1] : null;
}

function signedAgentAssociation(event: VerifiedNostrEvent): {
  valid: boolean;
  association: AgentAssociation | null;
} {
  if (!matchesAgentAttributionProfile(event.tags)) {
    return { valid: false, association: null };
  }
  const tags = event.tags.filter((tag) => tag[0] === "heterodyne_agent");
  if (tags.length === 0) return { valid: true, association: null };
  if (tags.length !== 1 || tags[0].length !== 4 || tags[0][1] !== "v1") {
    return { valid: false, association: null };
  }
  const association = { kind: tags[0][2], value: tags[0][3] };
  if (association.kind === "key" && HEX_32.test(association.value)) {
    return { valid: true, association: association as AgentAssociation };
  }
  if (
    association.kind === "role"
    && association.value.length >= 1
    && association.value.length <= 128
  ) {
    return { valid: true, association: association as AgentAssociation };
  }
  return { valid: false, association: null };
}
