const forbiddenTokens = new Set(["__proto__", "constructor", "prototype"]);

export type JsonPointerResult =
  | { found: true; value: unknown }
  | { found: false };

export function parseJsonPointer(pointer: string): string[] {
  if (pointer.length === 0 || !pointer.startsWith("/")) {
    throw new Error("JSON Pointer must be a non-root absolute pointer");
  }

  return pointer.slice(1).split("/").map((encoded) => {
    if (/~(?:[^01]|$)/u.test(encoded)) {
      throw new Error(`JSON Pointer contains an invalid escape: ${pointer}`);
    }
    const token = encoded.replaceAll("~1", "/").replaceAll("~0", "~");
    if (forbiddenTokens.has(token)) {
      throw new Error(`JSON Pointer contains a forbidden token: ${pointer}`);
    }
    return token;
  });
}

export function resolveJsonPointer(document: unknown, pointer: string): JsonPointerResult {
  let value = document;
  for (const token of parseJsonPointer(pointer)) {
    if (Array.isArray(value)) {
      if (!/^(?:0|[1-9][0-9]*)$/u.test(token)) {
        return { found: false };
      }
    } else if (value === null || typeof value !== "object") {
      return { found: false };
    }

    if (!Object.hasOwn(value, token)) {
      return { found: false };
    }
    value = (value as Record<string, unknown>)[token];
  }
  return { found: true, value };
}
