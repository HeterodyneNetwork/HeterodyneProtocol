import { buildSemanticCoverage } from "./coverage.js";
import { buildCurrentCases } from "./current-vectors/index.js";
import { authorCurrentCase } from "./current-vectors/types.js";

const cases = await buildCurrentCases();
const vectors = cases.map(authorCurrentCase).sort((left, right) =>
  left.relativePath.localeCompare(right.relativePath, "en")
);

process.stdout.write(JSON.stringify({
  format: "heterodyne-current-authoring-1",
  vectors,
  semantic_coverage: buildSemanticCoverage(cases),
}));
