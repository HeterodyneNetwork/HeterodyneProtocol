export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function hexToBytes(hex: string): Uint8Array {
  if (!/^(?:[0-9a-f]{2})+$/iu.test(hex)) {
    throw new Error(`invalid hex string length/content: ${hex}`);
  }
  return Uint8Array.from(hex.match(/../g)?.map((byte) => Number.parseInt(byte, 16)) ?? []);
}

export function utf8Bytes(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}
