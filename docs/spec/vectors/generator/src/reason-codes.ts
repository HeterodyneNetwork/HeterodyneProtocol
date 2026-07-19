import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { ReasonCodeEntry } from "./registry.js";

export type ReasonCode = Pick<
  ReasonCodeEntry,
  "code" | "spec_refs" | "description"
>;

const here = dirname(fileURLToPath(import.meta.url));
const registryPath = resolve(here, "../../../registry/reason-codes.json");
const registryReasonCodes = (
  JSON.parse(readFileSync(registryPath, "utf8")) as {
    reason_codes: ReasonCodeEntry[];
  }
).reason_codes;

/** Compatibility projection for the vector authoring outputs until Task 8. */
export const REASON_CODES: ReasonCode[] = registryReasonCodes.map(
  ({ code, spec_refs, description }) => ({ code, spec_refs, description }),
);

export function reasonCodeValues(): string[] {
  return registryReasonCodes.map((reason) => reason.code);
}
