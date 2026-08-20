import { findAnchorResolutionFailures } from "./anchor-resolution.js";
import { findInvariantCompletenessFailures } from "./invariant-completeness.js";
import { findReasonCodeClosureFailures } from "./reason-code-closure.js";
import type { Gate } from "./types.js";

export const G1: Gate = {
  id: "G1",
  name: "anchor-resolution",
  evaluate: findAnchorResolutionFailures,
};

export const G2: Gate = {
  id: "G2",
  name: "reason-code-closure",
  evaluate: findReasonCodeClosureFailures,
};

export const G3: Gate = {
  id: "G3",
  name: "invariant-completeness",
  evaluate: findInvariantCompletenessFailures,
};

export const STATIC_GATES: readonly Gate[] = [G1, G2, G3];

export type { Gate, GateId, GateResult } from "./types.js";
