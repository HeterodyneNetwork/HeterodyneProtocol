export type CorpusIssue = { code: string; path: string; message: string };

export type ExpectedTerminalStage =
  | "event_structure" | "nip01_raw" | "identifier" | "signature"
  | "persona_resolution" | "version_stamp" | "kel_head"
  | "epoch_authority" | "subtype_nid" | "accept";

export type ConformanceCheckDocument = {
  profile: "core-signed-event-v1";
  event_pointer: string;
  nip01_raw_pointer: string;
  context_pointer?: string;
  expected_terminal_stage: ExpectedTerminalStage;
};

type VectorDocumentBase = {
  vector_id: string;
  owner_document: "core" | "assurance" | "comms" | "control" | "social" | "workspace";
  profile?: string;
  spec_refs: string[];
  direction: "consume" | "produce" | "round-trip";
  input: Record<string, unknown>;
  expected_output: Record<string, unknown>;
  conformance_checks?: ConformanceCheckDocument[];
};

export type HistoricalVectorDocument = VectorDocumentBase & {
  vector_schema_version: "2.0.0";
};

export type CurrentVectorDocument = VectorDocumentBase & {
  vector_schema_version: "3.0.0";
  invariants: string[];
  reason_codes: string[];
};

export type VectorDocument = HistoricalVectorDocument | CurrentVectorDocument;

export type RegistryDocument = {
  manifest: { revision: number; schema_version: string; entry_set_sha256: string };
  reason_codes: readonly { code: string }[];
  security_invariants: readonly { id: string; owner: string; feature?: string }[];
};

export type ArtifactCorpus = {
  sourceRoot: string;
  snapshotRoot: string;
  sourceCommit: string;
  snapshotCommit: string;
  vectorSchemaVersion: string;
  specifications: ReadonlyMap<string, string>;
  schemas: ReadonlyMap<string, unknown>;
  vectorSchema: Record<string, unknown>;
  vectors: readonly { path: string; value: VectorDocument }[];
  fixtures: Record<string, unknown>;
  registry: RegistryDocument;
};
