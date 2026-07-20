/** RFC 8785 JSON Canonicalization Scheme for valid I-JSON values. */
export function jcsCanonicalize(value: unknown): string {
  return serialize(value, new Set<object>());
}

function serialize(value: unknown, ancestors: Set<object>): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "string") return serializeString(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new Error("JCS numbers must be finite IEEE 754 values");
    }
    return JSON.stringify(value);
  }
  if (typeof value !== "object") {
    throw new Error(`unsupported JCS value type: ${typeof value}`);
  }
  if (ancestors.has(value)) {
    throw new Error("unsupported cyclic JCS value");
  }

  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      const entries: string[] = [];
      for (let index = 0; index < value.length; index += 1) {
        if (!Object.prototype.hasOwnProperty.call(value, index)) {
          throw new Error("sparse arrays are not valid JCS input");
        }
        const entry = value[index];
        if (entry === undefined) throw new Error("undefined is not a valid JCS array value");
        entries.push(serialize(entry, ancestors));
      }
      return `[${entries.join(",")}]`;
    }

    if (Object.prototype.toString.call(value) !== "[object Object]") {
      throw new Error("unsupported non-JSON object in JCS input");
    }
    const object = value as Record<string, unknown>;
    const entries = Object.keys(object)
      .sort(compareUtf16)
      .map((key) => {
        const member = object[key];
        if (member === undefined) {
          throw new Error(`undefined is not a valid JCS member value: ${key}`);
        }
        return `${serializeString(key)}:${serialize(member, ancestors)}`;
      });
    return `{${entries.join(",")}}`;
  } finally {
    ancestors.delete(value);
  }
}

function serializeString(value: string): string {
  assertUnicodeScalarSequence(value);
  return JSON.stringify(value);
}

function assertUnicodeScalarSequence(value: string): void {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        throw new Error("JCS string contains a lone surrogate and is not valid Unicode");
      }
      index += 1;
    } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
      throw new Error("JCS string contains a lone surrogate and is not valid Unicode");
    }
  }
}

function compareUtf16(left: string, right: string): number {
  const length = Math.min(left.length, right.length);
  for (let index = 0; index < length; index += 1) {
    const difference = left.charCodeAt(index) - right.charCodeAt(index);
    if (difference !== 0) return difference;
  }
  return left.length - right.length;
}
