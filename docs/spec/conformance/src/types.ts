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

export type VectorDocument = {
  vector_id: string;
  vector_schema_version: "1.1.0";
  owner_document: "core" | "comms" | "control" | "social" | "workspace";
  spec_version: "heterodyne/0.5.0";
  spec_refs: string[];
  direction: "consume" | "produce" | "round-trip";
  input: Record<string, unknown>;
  expected_output: Record<string, unknown>;
  conformance_checks?: ConformanceCheckDocument[];
};

export type RegistryDocument = {
  manifest: { revision: 13; schema_version: "3.0.0"; entry_set_sha256: string };
  reason_codes: readonly { code: string }[];
  security_invariants: readonly { id: string; owner: string; feature?: string }[];
};

export type ArtifactCorpus = {
  repositoryRoot: string;
  familyVersion: "heterodyne/0.5.0";
  registryRevision: 13;
  registryDigest: string;
  specifications: ReadonlyMap<string, string>;
  schemas: ReadonlyMap<string, unknown>;
  vectors: readonly { path: string; value: VectorDocument }[];
  fixtures: Record<string, unknown>;
  registry: RegistryDocument;
};
