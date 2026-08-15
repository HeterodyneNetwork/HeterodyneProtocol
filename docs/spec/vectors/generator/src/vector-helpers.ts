import type { Fixtures } from "./fixtures.js";
import type { AuthoredVector, Vector } from "./types.js";
import { vectorMetadata } from "./vector-metadata.js";

export const SCHEMA_VERSION = "1.0.0";
export const AUX_RAND = "00".repeat(32);

export type VectorFactory = (fixtures: Fixtures) => Promise<AuthoredVector> | AuthoredVector;

type VectorContextMetadata = {
  fixtures?: Record<string, unknown>;
  simulated_clock?: number;
  decision_trace?: string[];
  notes?: string;
};

export type VectorBody = Pick<
  Vector,
  "vector_id" | "spec_refs" | "description" | "input" | "expected_output"
> & VectorContextMetadata;

type DirectionalVectorBody = VectorBody & { direction: Vector["direction"] };

export function baseVector(vector: DirectionalVectorBody): Vector {
  const {
    fixtures,
    simulated_clock,
    decision_trace,
    notes,
    spec_refs: _legacySpecRefs,
    ...body
  } = vector;
  const metadata = vectorMetadata(vector.vector_id);
  const vectorContext = {
    ...(fixtures === undefined ? {} : { fixtures }),
    ...(simulated_clock === undefined ? {} : { simulated_clock }),
    ...(decision_trace === undefined ? {} : { decision_trace }),
    ...(notes === undefined ? {} : { notes }),
  };
  const normalizedInput = {
    ...body.input,
    ...(Object.keys(vectorContext).length === 0 ? {} : { vector_context: vectorContext }),
  };
  return {
    vector_schema_version: SCHEMA_VERSION,
    ...metadata,
    ...body,
    input: normalizedInput,
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
