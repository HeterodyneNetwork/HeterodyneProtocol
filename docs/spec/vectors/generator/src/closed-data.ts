import { isProxy } from "node:util/types";

export function captureExactDataObject(
  value: unknown,
  allowedKeySets: readonly (readonly string[])[],
  label: string,
): Readonly<Record<string, unknown>> {
  if (value === null || typeof value !== "object" || Array.isArray(value) || isProxy(value) ||
      Object.getPrototypeOf(value) !== Object.prototype) {
    throw new Error(`${label} must be an exact ordinary data object`);
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const descriptorKeys = Reflect.ownKeys(descriptors);
  if (descriptorKeys.some((key) => typeof key === "symbol")) {
    throw new Error(`${label} must be an exact ordinary data object`);
  }
  const keys = descriptorKeys.map(String).sort();
  const allowed = allowedKeySets.some((candidate) =>
    [...candidate].sort().join("\0") === keys.join("\0"));
  if (!allowed) throw new Error(`${label} must be an exact ordinary data object`);

  const captured: Record<string, unknown> = {};
  for (const key of keys) {
    const descriptor = descriptors[key];
    if (descriptor === undefined || descriptor.enumerable !== true || !("value" in descriptor)) {
      throw new Error(`${label} members must use enumerable data descriptors`);
    }
    captured[key] = descriptor.value;
  }
  return Object.freeze(captured);
}

export function snapshotClosedDataTree<T>(value: T, label: string): T {
  return snapshotValue(value, label, new WeakSet<object>()) as T;
}

function snapshotValue(value: unknown, label: string, ancestors: WeakSet<object>): unknown {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error(`${label} contains a non-finite number`);
    return value;
  }
  if (typeof value !== "object" || isProxy(value)) {
    throw new Error(`${label} must be a closed ordinary data tree`);
  }
  if (ancestors.has(value)) throw new Error(`${label} must not contain cycles`);
  ancestors.add(value);
  try {
    if (Array.isArray(value)) return snapshotArray(value, label, ancestors);
    if (Object.getPrototypeOf(value) !== Object.prototype) {
      throw new Error(`${label} must be a closed ordinary data tree`);
    }
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    if (keys.some((key) => typeof key === "symbol")) {
      throw new Error(`${label} must not contain symbol members`);
    }
    const captured: Record<string, unknown> = {};
    for (const propertyKey of keys) {
      const key = String(propertyKey);
      const descriptor = descriptors[key];
      if (descriptor === undefined || descriptor.enumerable !== true || !("value" in descriptor)) {
        throw new Error(`${label} members must use enumerable data descriptors`);
      }
      captured[key] = snapshotValue(descriptor.value, `${label}.${key}`, ancestors);
    }
    return Object.freeze(captured);
  } finally {
    ancestors.delete(value);
  }
}

function snapshotArray(value: unknown[], label: string, ancestors: WeakSet<object>): readonly unknown[] {
  if (Object.getPrototypeOf(value) !== Array.prototype) {
    throw new Error(`${label} must contain ordinary arrays`);
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(descriptors);
  if (keys.some((key) => typeof key === "symbol")) {
    throw new Error(`${label} must not contain symbol members`);
  }
  const lengthDescriptor = Reflect.get(descriptors, "length") as PropertyDescriptor | undefined;
  if (lengthDescriptor === undefined || !("value" in lengthDescriptor) ||
      !Number.isSafeInteger(lengthDescriptor.value) || lengthDescriptor.value < 0) {
    throw new Error(`${label} must contain a closed array`);
  }
  const length = lengthDescriptor.value as number;
  const expectedKeys = ["length", ...Array.from({ length }, (_, index) => String(index))].sort();
  if (keys.map(String).sort().join("\0") !== expectedKeys.join("\0")) {
    throw new Error(`${label} must contain a dense closed array`);
  }
  const captured: unknown[] = [];
  for (let index = 0; index < length; index += 1) {
    const descriptor = descriptors[String(index)];
    if (descriptor === undefined || descriptor.enumerable !== true || !("value" in descriptor)) {
      throw new Error(`${label} members must use enumerable data descriptors`);
    }
    captured.push(snapshotValue(descriptor.value, `${label}[${index}]`, ancestors));
  }
  return Object.freeze(captured);
}
