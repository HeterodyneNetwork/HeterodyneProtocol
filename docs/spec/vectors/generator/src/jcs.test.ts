import { describe, expect, it } from "vitest";
import { jcsCanonicalize } from "./jcs.js";

describe("RFC 8785 JSON Canonicalization Scheme", () => {
  it("sorts object member names by UTF-16 code units", () => {
    expect(jcsCanonicalize({ "\u{10000}": 1, "\ue000": 2, a: 3 })).toBe(
      '{"a":3,"𐀀":1,"":2}',
    );
  });

  it("uses ECMAScript escaping and number serialization", () => {
    expect(jcsCanonicalize({ text: "\b\t\n\f\r\"\\\u0001", values: [1e30, 4.5, 2e-3, -0] })).toBe(
      '{"text":"\\b\\t\\n\\f\\r\\\"\\\\\\u0001","values":[1e+30,4.5,0.002,0]}',
    );
  });

  it("preserves array order and recursively canonicalizes members", () => {
    expect(jcsCanonicalize([true, null, { z: 1, a: ["x", 2] }])).toBe(
      '[true,null,{"a":["x",2],"z":1}]',
    );
  });

  it.each([Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY])(
    "rejects non-finite JSON number %s",
    (value) => expect(() => jcsCanonicalize(value)).toThrow(/finite/),
  );

  it("rejects undefined and unsupported values, including nested ones", () => {
    expect(() => jcsCanonicalize(undefined)).toThrow(/unsupported|undefined/);
    expect(() => jcsCanonicalize({ present: 1, omitted: undefined })).toThrow(/undefined/);
    expect(() => jcsCanonicalize([1, undefined])).toThrow(/undefined/);
    expect(() => jcsCanonicalize(Array(1))).toThrow(/sparse/);
    expect(() => jcsCanonicalize(1n)).toThrow(/unsupported/);
    expect(() => jcsCanonicalize(() => undefined)).toThrow(/unsupported/);
  });

  it("serializes only enumerable own string-keyed members", () => {
    const value = Object.create({ inherited: true }) as Record<string, unknown>;
    Object.defineProperty(value, "hidden", { value: true, enumerable: false });
    value.visible = true;
    (value as Record<PropertyKey, unknown>)[Symbol.for("omitted")] = true;
    expect(jcsCanonicalize(value)).toBe('{"visible":true}');
  });

  it("rejects lone surrogate code units", () => {
    expect(() => jcsCanonicalize("\ud800")).toThrow(/Unicode|surrogate/);
    expect(() => jcsCanonicalize({ "\udfff": true })).toThrow(/Unicode|surrogate/);
  });

  it("rejects cycles and non-JSON objects", () => {
    const cycle: Record<string, unknown> = {};
    cycle.self = cycle;
    expect(() => jcsCanonicalize(cycle)).toThrow(/cyclic/);
    expect(() => jcsCanonicalize(new Date(0))).toThrow(/non-JSON/);
  });
});
