import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { ReasonCodeEntry } from "./registry.js";

export type ReasonCode = ReasonCodeEntry;

const here = dirname(fileURLToPath(import.meta.url));
const registryPath = resolve(here, "../../../registry/reason-codes.json");
const registryReasonCodes = (
  JSON.parse(readFileSync(registryPath, "utf8")) as {
    reason_codes: ReasonCodeEntry[];
  }
).reason_codes;

/** Generated compatibility copy; docs/spec/registry/reason-codes.json is authoritative. */
export const REASON_CODES: ReasonCode[] = registryReasonCodes;

export function reasonCodeValues(): string[] {
  return registryReasonCodes.map((reason) => reason.code);
}
