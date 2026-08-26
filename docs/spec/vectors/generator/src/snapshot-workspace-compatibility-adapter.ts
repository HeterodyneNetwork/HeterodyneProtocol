export * from "./snapshot-workspace-adapter.js";
import { evaluateKeyRequest as evaluateHistoricalKeyRequest } from "./snapshot-workspace-adapter.js";

type HistoricalKeyRequest = Parameters<typeof evaluateHistoricalKeyRequest>[0];

export function evaluateKeyRequest(
  input: HistoricalKeyRequest & { recipient?: { type: string; value: string } },
): ReturnType<typeof evaluateHistoricalKeyRequest> {
  if (Object.hasOwn(input, "recipient")) {
    return { verdict: "reject", reason_code: "workspace_schema_invalid" };
  }
  return evaluateHistoricalKeyRequest(input);
}
