import { describe, expect, it } from "vitest";
import {
  authorityBindingDigest,
  captureAuthorityInput,
  type IndeterminateDecision,
} from "./security-authority-support.js";

describe("security authority support", () => {
  it("BLUE TEAM VALIDATION: synthetic/local captures without retaining caller-owned bytes", () => {
    const bytes = new Uint8Array([1, 2, 3]);
    const source = { bytes, nested: [{ value: "bound" }], nil: null };
    const captured = captureAuthorityInput(source);

    bytes[0] = 9;
    source.nested[0].value = "changed";

    expect([...captured.bytes]).toEqual([1, 2, 3]);
    expect(captured.nested[0].value).toBe("bound");
    expect(Object.isFrozen(captured)).toBe(true);
    expect(Object.isFrozen(captured.nested)).toBe(true);
    expect(Object.isFrozen(captured.nested[0])).toBe(true);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects accessors without invoking them", () => {
    let reads = 0;
    const hostile = Object.create(Object.prototype, {
      value: {
        enumerable: true,
        get() {
          reads += 1;
          return "attacker-controlled";
        },
      },
    });

    expect(() => captureAuthorityInput(hostile)).toThrow(/closed authority input/);
    expect(reads).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects proxies without invoking traps", () => {
    let traps = 0;
    const hostile = new Proxy({ value: "attacker-controlled" }, {
      get() {
        traps += 1;
        return "attacker-controlled";
      },
      getOwnPropertyDescriptor() {
        traps += 1;
        return undefined;
      },
      ownKeys() {
        traps += 1;
        return [];
      },
    });

    expect(() => captureAuthorityInput(hostile)).toThrow(/closed authority input/);
    expect(traps).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects cycles, symbols, and non-finite numbers", () => {
    const cyclic: { self?: unknown } = {};
    cyclic.self = cyclic;
    expect(() => captureAuthorityInput(cyclic)).toThrow(/closed authority input/);
    expect(() => captureAuthorityInput({ [Symbol("hidden")]: true })).toThrow(/closed authority input/);
    expect(() => captureAuthorityInput({ value: Number.POSITIVE_INFINITY }))
      .toThrow(/closed authority input/);
  });

  it("derives a domain-separated, insertion-order-independent binding digest", () => {
    const left = authorityBindingDigest("example-authority/v1", {
      beta: new Uint8Array([0, 255]),
      alpha: "bound",
    });
    const right = authorityBindingDigest("example-authority/v1", {
      alpha: "bound",
      beta: new Uint8Array([0, 255]),
    });

    expect(left).toMatch(/^[0-9a-f]{64}$/);
    expect(right).toBe(left);
    expect(authorityBindingDigest("other-authority/v1", {
      alpha: "bound",
      beta: new Uint8Array([0, 255]),
    })).not.toBe(left);
  });

  it("BLUE TEAM VALIDATION: synthetic/local preserves an own __proto__ data property without digest collapse", () => {
    const source = Object.defineProperty({ safe: "value" }, "__proto__", {
      value: "bound-prototype-data",
      enumerable: true,
      writable: true,
      configurable: true,
    });
    const captured = captureAuthorityInput(source) as Readonly<Record<string, unknown>>;

    expect(Object.getPrototypeOf(captured)).toBe(Object.prototype);
    expect(Object.hasOwn(captured, "__proto__")).toBe(true);
    expect(Object.getOwnPropertyDescriptor(captured, "__proto__")?.value)
      .toBe("bound-prototype-data");
    expect(authorityBindingDigest("proto-collapse/v1", source))
      .not.toBe(authorityBindingDigest("proto-collapse/v1", { safe: "value" }));
  });

  it("requires a reconciliation digest on a reasonless indeterminate decision", () => {
    const decision: IndeterminateDecision = Object.freeze({
      verdict: "indeterminate",
      reconciliation_digest: "11".repeat(32),
    });
    expect(decision).toEqual({
      verdict: "indeterminate",
      reconciliation_digest: "11".repeat(32),
    });
  });
});
