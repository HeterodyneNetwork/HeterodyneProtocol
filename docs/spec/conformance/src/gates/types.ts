import type { ArtifactCorpus } from "../types.js";

export type GateId =
  | "G1" | "G2" | "G3" | "G4" | "G5" | "G6"
  | "G7" | "G8" | "G9" | "G10" | "G11";

export type GateResult = { id: GateId; name: string; failures: string[] };

export type Gate = {
  id: GateId;
  name: string;
  evaluate(corpus: ArtifactCorpus): string[];
};
