import { createHash } from "node:crypto";
import { types as utilTypes } from "node:util";

export type IndeterminateDecision<I extends string = never> = Readonly<
  [I] extends [never]
    ? { verdict: "indeterminate"; reconciliation_digest: string }
    : { verdict: "indeterminate"; reason_code: I; reconciliation_digest: string }
>;

export type AuthorityDecision<R extends string, O, I extends string = never> = Readonly<
  | { verdict: "accept"; output: O }
  | { verdict: "reject"; reason_code: R }
  | IndeterminateDecision<I>
>;

export type DurableAuthorityRecord<O> = Readonly<
  | { state: "available"; revision: number; binding_digest: string; output: O }
  | { state: "executing"; revision: number; binding_digest: string; execution_token: string }
  | { state: "committed"; revision: number; binding_digest: string; execution_token: string;
      output_digest: string; output: O }
  | { state: "indeterminate"; revision: number; binding_digest: string; execution_token: string;
      reconciliation_digest: string }
>;

export interface DurableAuthorityStore<O> {
  load(key: string): Promise<DurableAuthorityRecord<O> | null>;
  acquire(input: Readonly<{
    key: string; expected_revision: number | null;
    binding_digest: string; execution_token: string;
  }>): Promise<"acquired" | "replay" | "conflict" | "unavailable">;
  compareAndSwap(input: Readonly<{
    key: string; expected_revision: number | null; next: DurableAuthorityRecord<O>;
  }>): Promise<"committed" | "conflict" | "unknown">;
  commit(input: Readonly<{
    key: string; binding_digest: string; execution_token: string;
    output_digest: string; output: O;
  }>): Promise<"committed" | "conflict" | "unknown">;
  markIndeterminate(input: Readonly<{
    key: string; binding_digest: string; execution_token: string;
    reconciliation_digest: string;
  }>): Promise<"indeterminate" | "conflict" | "unknown">;
}

interface ClosedObject {
  readonly [key: string]: ClosedValue;
}

type ClosedValue = null | boolean | number | string | Uint8Array
  | readonly ClosedValue[] | ClosedObject;

function invalidInput(): never {
  throw new TypeError("closed authority input required");
}

function snapshotClosed(value: unknown, active: Set<object>): ClosedValue {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) return invalidInput();
    return value;
  }
  if (typeof value !== "object" || utilTypes.isProxy(value)) return invalidInput();

  if (value instanceof Uint8Array) {
    if (Object.getPrototypeOf(value) !== Uint8Array.prototype) return invalidInput();
    const descriptors = Object.getOwnPropertyDescriptors(value);
    if (Reflect.ownKeys(descriptors).some((key) =>
      typeof key !== "string" || !/^(0|[1-9][0-9]*)$/.test(key)
    )) return invalidInput();
    return new Uint8Array(value);
  }

  if (active.has(value)) return invalidInput();
  active.add(value);
  try {
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    if (keys.some((key) => typeof key !== "string")) return invalidInput();

    if (Array.isArray(value)) {
      if (Object.getPrototypeOf(value) !== Array.prototype) return invalidInput();
      const lengthDescriptor = descriptors.length;
      if (lengthDescriptor === undefined || !("value" in lengthDescriptor)) return invalidInput();
      const length = lengthDescriptor.value;
      if (!Number.isSafeInteger(length) || length < 0) return invalidInput();
      if (keys.length !== length + 1) return invalidInput();
      const result: ClosedValue[] = [];
      for (let index = 0; index < length; index += 1) {
        const descriptor = descriptors[String(index)];
        if (
          descriptor === undefined
          || !("value" in descriptor)
          || descriptor.enumerable !== true
        ) return invalidInput();
        result.push(snapshotClosed(descriptor.value, active));
      }
      return Object.freeze(result);
    }

    if (Object.getPrototypeOf(value) !== Object.prototype) return invalidInput();
    const result: Record<string, ClosedValue> = {};
    for (const key of keys as string[]) {
      const descriptor = descriptors[key];
      if (
        descriptor === undefined
        || !("value" in descriptor)
        || descriptor.enumerable !== true
      ) return invalidInput();
      Object.defineProperty(result, key, {
        value: snapshotClosed(descriptor.value, active),
        enumerable: true,
        writable: false,
        configurable: false,
      });
    }
    return Object.freeze(result);
  } finally {
    active.delete(value);
  }
}

export function captureAuthorityInput<T>(value: T): Readonly<T> {
  return snapshotClosed(value, new Set()) as Readonly<T>;
}

function canonicalClosed(value: ClosedValue): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") return `number:${Object.is(value, -0) ? "-0" : String(value)}`;
  if (typeof value === "string") return `string:${JSON.stringify(value)}`;
  if (value instanceof Uint8Array) return `bytes:${Buffer.from(value).toString("hex")}`;
  if (Array.isArray(value)) return `array:[${value.map(canonicalClosed).join(",")}]`;
  const objectValue = value as ClosedObject;
  return `object:{${Object.keys(objectValue).sort().map((key) =>
    `${JSON.stringify(key)}:${canonicalClosed(objectValue[key])}`
  ).join(",")}}`;
}

export function authorityBindingDigest(
  domain: string,
  value: Readonly<Record<string, unknown>>,
): string {
  if (typeof domain !== "string" || domain.length === 0) return invalidInput();
  const captured = captureAuthorityInput(value) as Readonly<Record<string, ClosedValue>>;
  return createHash("sha256")
    .update("Heterodyne authority binding\0", "utf8")
    .update(domain, "utf8")
    .update("\0", "utf8")
    .update(canonicalClosed(captured), "utf8")
    .digest("hex");
}
