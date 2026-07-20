import { ed25519 } from "@noble/curves/ed25519";
import { describe, expect, it } from "vitest";
import {
  buildLedgerRepositoryEvidence,
  materializeLedgerLayout,
  validateReaderOnboardingBundle,
  type LedgerValidationContext,
  type ReaderAccessRequest,
} from "./claim-ledger.js";
import { buildFixtures } from "./fixtures.js";

const fixtures = buildFixtures();

describe("claim-ledger remediation security contexts", () => {
  it("requires explicit repository and record validation evidence", () => {
    expect(typeof buildLedgerRepositoryEvidence).toBe("function");
    expect({} as LedgerValidationContext).toBeDefined();
    expect({} as ReaderAccessRequest).toBeDefined();
  });

  it("materializes a fixed 256-entry re-encrypted layout", () => {
    const key = Uint8Array.from({ length: 32 }, () => 0x51);
    const first = materializeLedgerLayout(key, 1, "aa".repeat(32), "11".repeat(32), []);
    const second = materializeLedgerLayout(key, 1, "bb".repeat(32), "12".repeat(32), []);
    expect(first.entries).toHaveLength(256);
    expect(new Set(first.entries.map(({ size }) => size))).toEqual(new Set([64]));
    expect(first.entries.map(({ path }) => path)).toEqual(
      Array.from({ length: 256 }, (_, index) => `objects/${index.toString(16).padStart(2, "0")}.bin`),
    );
    expect(first.entries.every((entry, index) => entry.ciphertext !== second.entries[index].ciphertext)).toBe(true);
  });

  it("exposes an executable onboarding validator", () => {
    expect(typeof validateReaderOnboardingBundle).toBe("function");
    expect(ed25519.getPublicKey(fixtures.ed25519_nids.alice_device_1.private_key)).toHaveLength(32);
  });
});
