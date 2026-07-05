import type { Fixtures } from "./fixtures.js";
import type { AuthoredVector, Vector } from "./types.js";

export const SCHEMA_VERSION = "1.0.0";
export const SPEC_VERSION = "0.4.0";
export const AUX_RAND = "00".repeat(32);

export type VectorFactory = (fixtures: Fixtures) => Promise<AuthoredVector> | AuthoredVector;

type VectorBody = Omit<Vector, "vector_schema_version" | "spec_version" | "direction">;

export function baseVector(vector: Omit<Vector, "vector_schema_version" | "spec_version">): Vector {
  return {
    vector_schema_version: SCHEMA_VERSION,
    spec_version: SPEC_VERSION,
    ...vector,
  };
}

export function produceVector(vector: VectorBody): Vector {
  return baseVector({ ...vector, direction: "produce" });
}

export function consume(relativePath: string, vector: VectorBody): VectorFactory {
  return () => ({
    relativePath,
    vector: baseVector({ ...vector, direction: "consume" }),
  });
}

export function consumeVector(relativePath: string, vector: VectorBody): AuthoredVector {
  return { relativePath, vector: baseVector({ ...vector, direction: "consume" }) };
}

export function produceAuthored(relativePath: string, vector: VectorBody): AuthoredVector {
  return { relativePath, vector: produceVector(vector) };
}

export function withoutSig(event: {
  pubkey: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
}) {
  return {
    pubkey: event.pubkey,
    created_at: event.created_at,
    kind: event.kind,
    tags: event.tags,
    content: event.content,
  };
}
