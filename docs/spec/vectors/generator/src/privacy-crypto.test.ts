import { nip44 } from "nostr-tools";
import { describe, expect, it } from "vitest";
import { bytesToHex, hexToBytes } from "./hex.js";
import { deriveConfigPostKey, deriveTier3IndexKey } from "./privacy-crypto.js";

describe("current Tier 3 labeled HKDF semantics", () => {
  it("derives the current index key used directly as the NIP-44 conversation key", () => {
    const derived = deriveTier3IndexKey(
      "40".repeat(32),
      "aud-2026-05-25-a",
    );
    const plaintext = JSON.stringify({ page_id: "opaque-page-01" });
    const encrypted = nip44.v2.encrypt(plaintext, derived, hexToBytes("51".repeat(32)));

    expect(bytesToHex(derived)).toBe(
      "8af8dbc5e089ab6857e01895e8aeba6520564f01ed5e22f6eb0f147b9cee75ab",
    );
    expect(nip44.v2.decrypt(encrypted, derived)).toBe(plaintext);
  });

  it("derives the config post key used directly as the NIP-44 conversation key", () => {
    const derived = deriveConfigPostKey(
      "42".repeat(32),
      "c5120a3891ce2129a423416f405d8d49",
    );
    const plaintext = JSON.stringify({ blob: "persona_config" });
    const encrypted = nip44.v2.encrypt(plaintext, derived, hexToBytes("60".repeat(32)));

    expect(bytesToHex(derived)).toBe(
      "1716e262bf6f31fbf4736347947ce142c71fbb9c3f55f0d4c71d130a8a8be3fc",
    );
    expect(nip44.v2.decrypt(encrypted, derived)).toBe(plaintext);
  });
});
