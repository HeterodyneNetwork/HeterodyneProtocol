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

function declaredRawMatches(
  vector: VectorDocument,
  eventPointer: string,
  rawPointer: string,
): boolean | undefined {
  try {
    const event = resolveJsonPointer(vector, eventPointer);
    if (!event.found || !isEventShape(event.value)) {
      return undefined;
    }
    const raw = resolveJsonPointer(vector, rawPointer);
    return rawMatches(event.value, raw.found ? raw.value : undefined);
  } catch {
    return false;
  }
}

export function findNip01RawFailures(corpus: ArtifactCorpus): string[] {
  const failures = new Set<string>();

  for (const { path, value: vector } of corpus.vectors) {
    const events: DiscoveredEvent[] = [];
    discoverEvents(vector, "", undefined, events);
    for (const { event, parent, pointer } of events) {
      const siblingRaw = isRecord(parent) && Object.hasOwn(parent, "nip01_raw")
        ? parent.nip01_raw
        : undefined;
      if (!rawMatches(event, siblingRaw)) {
        failures.add(`${path} :: ${pointer}`);
      }
    }

    for (const check of vector.conformance_checks ?? []) {
      if (declaredRawMatches(vector, check.event_pointer, check.nip01_raw_pointer) === false) {
        failures.add(`${path} :: ${check.event_pointer}`);
      }
    }
  }

  return [...failures].sort(compareText);
}
