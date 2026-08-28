import {
  snapshotAndVerifyNostrEvent,
  type NostrSignedEvent,
  type VerifiedNostrEvent,
} from "./nostr.js";

declare const replaceableSelectionAuthorityBrand: unique symbol;
export type ReplaceableSelectionAuthority = {
  readonly [replaceableSelectionAuthorityBrand]: true;
};

export type ReplaceableSelectionResult = {
  selected: VerifiedNostrEvent | null;
  quarantined: Array<{
    event_id: string;
    reason_code: "core-created-at-premature";
  }>;
};

type StoredAuthority = {
  trusted_now: (() => number) | null;
};

const AUTHORITIES = new WeakMap<object, StoredAuthority>();
const FUTURE_BOUND_SECONDS = 900;

export function createReplaceableSelectionAuthority(input: {
  trusted_now: () => number;
}): ReplaceableSelectionAuthority {
  let trustedNow: unknown = null;
  try {
    trustedNow = input.trusted_now;
  } catch {
    // An unreadable clock configuration produces a fail-closed authority.
  }
  const authority = Object.freeze({}) as ReplaceableSelectionAuthority;
  AUTHORITIES.set(authority, {
    trusted_now: typeof trustedNow === "function"
      ? trustedNow as () => number
      : null,
  });
  return authority;
}

export function selectCurrentReplaceableEvent(
  authorityValue: ReplaceableSelectionAuthority,
  candidates: readonly NostrSignedEvent[],
): ReplaceableSelectionResult {
  const authority = authorityValue !== null && typeof authorityValue === "object"
    ? AUTHORITIES.get(authorityValue)
    : undefined;
  const now = callTrustedClock(authority?.trusted_now ?? null);
  if (now === null) return { selected: null, quarantined: [] };

  const unique = new Map<string, VerifiedNostrEvent>();
  try {
    for (const sourceEvent of candidates) {
      const event = snapshotAndVerifyNostrEvent(sourceEvent);
      if (event !== null && isReplaceableKind(event.kind)) {
        unique.set(event.id, event);
      }
    }
  } catch {
    return { selected: null, quarantined: [] };
  }

  const admitted: VerifiedNostrEvent[] = [];
  const quarantined: ReplaceableSelectionResult["quarantined"] = [];
  for (const event of unique.values()) {
    if (event.created_at > now + FUTURE_BOUND_SECONDS) {
      quarantined.push({
        event_id: event.id,
        reason_code: "core-created-at-premature",
      });
    } else {
      admitted.push(event);
    }
  }
  admitted.sort((left, right) =>
    right.created_at - left.created_at || left.id.localeCompare(right.id));
  return { selected: admitted[0] ?? null, quarantined };
}

function callTrustedClock(trustedNow: (() => number) | null): number | null {
  if (trustedNow === null) return null;
  try {
    const now = trustedNow();
    return Number.isSafeInteger(now) && now >= 0 ? now : null;
  } catch {
    return null;
  }
}

function isReplaceableKind(kind: number): boolean {
  return kind === 0
    || kind === 3
    || kind >= 10_000 && kind < 20_000
    || kind >= 30_000 && kind < 40_000;
}
