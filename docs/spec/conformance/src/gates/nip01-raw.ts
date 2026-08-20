import { createHash } from "node:crypto";
import { resolveJsonPointer } from "../json-pointer.js";
import type { ArtifactCorpus, VectorDocument } from "../types.js";

const EVENT_MEMBERS = ["id", "pubkey", "created_at", "kind", "tags", "content", "sig"] as const;

type EventShape = Record<(typeof EVENT_MEMBERS)[number], unknown>;
type DiscoveredEvent = {
  event: EventShape;
  parent: unknown;
  pointer: string;
};

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isEventShape(value: unknown): value is EventShape {
  return isRecord(value) && EVENT_MEMBERS.every((member) => Object.hasOwn(value, member));
}

function pointerToken(value: string): string {
  return value.replaceAll("~", "~0").replaceAll("/", "~1");
}

function discoverEvents(
  value: unknown,
  pointer: string,
  parent: unknown,
  events: DiscoveredEvent[],
): void {
  if (isEventShape(value)) {
    events.push({ event: value, parent, pointer });
  }

  if (Array.isArray(value)) {
    value.forEach((item, index) => {
      discoverEvents(item, `${pointer}/${index}`, value, events);
    });
    return;
  }
  if (isRecord(value)) {
    for (const [key, item] of Object.entries(value)) {
      discoverEvents(item, `${pointer}/${pointerToken(key)}`, value, events);
    }
  }
}

function rawMatches(event: EventShape, raw: unknown): boolean {
  if (typeof raw !== "string") {
    return false;
  }
  try {
    return raw === JSON.stringify([
      0,
      event.pubkey,
      event.created_at,
      event.kind,
      event.tags,
      event.content,
    ]);
  } catch {
    return false;
  }
}

function eventFingerprint(event: EventShape): string {
  const semanticTuple = [
    event.id,
    event.pubkey,
    event.created_at,
    event.kind,
    event.tags,
    event.content,
    event.sig,
  ];
  return createHash("sha256")
    .update(JSON.stringify(semanticTuple), "utf8")
    .digest("hex");
}

function failureKey(path: string, event: EventShape): string {
  return `${path} :: event-sha256:${eventFingerprint(event)}`;
}

function declaredRawResult(
  vector: VectorDocument,
  eventPointer: string,
  rawPointer: string,
): { event: EventShape; matches: boolean } | undefined {
  try {
    const event = resolveJsonPointer(vector, eventPointer);
    if (!event.found || !isEventShape(event.value)) {
      return undefined;
    }
    const raw = resolveJsonPointer(vector, rawPointer);
    return {
      event: event.value,
      matches: rawMatches(event.value, raw.found ? raw.value : undefined),
    };
  } catch {
    return undefined;
  }
}

export function findNip01RawFailures(corpus: ArtifactCorpus): string[] {
  const failures = new Set<string>();

  for (const { path, value: vector } of corpus.vectors) {
    const events: DiscoveredEvent[] = [];
    discoverEvents(vector, "", undefined, events);
    for (const { event, parent } of events) {
      const siblingRaw = isRecord(parent) && Object.hasOwn(parent, "nip01_raw")
        ? parent.nip01_raw
        : undefined;
      if (!rawMatches(event, siblingRaw)) {
        failures.add(failureKey(path, event));
      }
    }

    for (const check of vector.conformance_checks ?? []) {
      const result = declaredRawResult(vector, check.event_pointer, check.nip01_raw_pointer);
      if (result !== undefined && !result.matches) {
        failures.add(failureKey(path, result.event));
      }
    }
  }

  return [...failures].sort(compareText);
}
