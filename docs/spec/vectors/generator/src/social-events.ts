import {
  matchesAgentAttributionProfile,
  createCommsSocialSignedPublicationConsumer,
  type AgentAssociation,
  type CommsSocialPublicationAuthority,
  type CommsSocialSignedPublicationConsumer,
  type CommsSocialSignedPublication,
} from "./agent-authorship.js";
import { isStrictNostrSignedEvent, type NostrSignedEvent } from "./nostr.js";

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
  if (!validSignedEvent(input.event)) {
    return { verdict: "reject", reason_code: "social-event-invalid" };
  }
  const representedPersona = input.persona_active_key ?? input.event.pubkey;
  if (!HEX_32.test(representedPersona)) {
    return { verdict: "reject", reason_code: "social-author-binding-invalid" };
  }
  if (input.event.pubkey === representedPersona) {
    return {
      verdict: "accept",
      event_author: input.event.pubkey,
      represented_persona: representedPersona,
    };
  }

  const attribution = signedAgentAssociation(input.event);
  if (
    !attribution.valid
    || input.requested_feed === undefined
    || input.requested_resource === undefined
    || consumePublication === null
    || !consumePublication({
      publication: input.comms_authorization,
      represented_persona: representedPersona,
      event: input.event,
      agent_association: attribution.association,
      requested_feed: input.requested_feed,
      requested_resource: input.requested_resource,
    })
    || attribution.association?.kind === "key"
      && attribution.association.value !== input.event.pubkey
  ) {
    return { verdict: "reject", reason_code: "social-author-binding-invalid" };
  }
  return {
    verdict: "accept",
    event_author: input.event.pubkey,
    represented_persona: representedPersona,
    ...(attribution.association === null
      ? {}
      : { agent_association: attribution.association }),
  };
}

export function selectCurrentSocialEvent(input: {
  coordinate: SocialReplaceableCoordinate;
  candidates: readonly SocialEventCandidate[];
}): NostrSignedEvent | null {
  if (!validCoordinate(input.coordinate)) return null;
  const unique = new Map<string, NostrSignedEvent>();
  for (const { event } of input.candidates) {
    if (validateSocialReplaceableCandidate({
      coordinate: input.coordinate,
      event,
    }).verdict === "accept") {
      unique.set(event.id, event);
    }
  }
  return [...unique.values()].sort((left, right) =>
    right.created_at - left.created_at || left.id.localeCompare(right.id))[0] ?? null;
}

export function validateSocialReplaceableCandidate(input: {
  coordinate: SocialReplaceableCoordinate;
  event: NostrSignedEvent;
}): { verdict: "accept" } | {
  verdict: "reject";
  reason_code: "social-event-invalid" | "social-replaceable-coordinate-mismatch";
} {
  if (!validSignedEvent(input.event)) {
    return { verdict: "reject", reason_code: "social-event-invalid" };
  }
  if (
    !validCoordinate(input.coordinate)
    || input.event.pubkey !== input.coordinate.pubkey
    || input.event.kind !== input.coordinate.kind
    || coordinateD(input.event) !== input.coordinate.d
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
  if (!validSignedEvent(event) || ![0, 10002].includes(event.kind)) {
    return { valid: false, warning: null };
  }
  return {
    valid: true,
    warning: now - event.created_at > SEVEN_DAYS_SECONDS ? "stale" : null,
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

function signedAgentAssociation(event: NostrSignedEvent): {
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

function validSignedEvent(event: NostrSignedEvent): boolean {
  return isStrictNostrSignedEvent(event);
}
