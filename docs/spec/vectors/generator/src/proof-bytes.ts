import { jcsCanonicalize } from "./jcs.js";
import { utf8Bytes } from "./hex.js";

/**
 * The family's only proof-byte construction, pinned by Core 3.5.1:
 * `<domain> || 0x00 || JCS(<claim>)`.
 */
export function proofBytes(domain: string, claim: unknown): Uint8Array {
  const prefix = utf8Bytes(domain);
  const payload = utf8Bytes(jcsCanonicalize(claim));
  const bytes = new Uint8Array(prefix.length + 1 + payload.length);
  bytes.set(prefix, 0);
  bytes[prefix.length] = 0;
  bytes.set(payload, prefix.length + 1);
  return bytes;
}
