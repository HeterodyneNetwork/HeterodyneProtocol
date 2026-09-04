# SARA Vector Traceability and Maintenance Design

**Status:** Original design approved; implementation revised for 0.6 main on 2026-09-04

**Date:** 2026-08-28

## 0. Current implementation direction (2026-09-04)

The [revised implementation plan](../plans/2026-09-04-sara-spec-workflow.md)
supersedes the August 28 plan and the obsolete implementation prescriptions
below. It is based on main `adda8b522f9cb558b31cb27ac0f7e4f1150d5fac`.
The original sections remain as historical design rationale; where they
conflict with this revision, follow this section and the revised plan.

Main now contains a 267-vector schema-3 snapshot. Read mutable snapshot facts
from its manifest and history instead of encoding them in the adapter.
Current authoring uses explicit `current-vectors/case-contracts.ts` allocations
and boundary execution certificates. Preserve that separation. The old proposal
to move traceability authority into lazy fixture builders and delete the global
legacy mapper is superseded. Resolve profile and boundary overrides, and report
computations a static projection cannot resolve. Declared metadata is not proof
of executed conformance.

The first deliverable is a current-draft change packet with requirement,
case declaration, boundary, source, schema, registry, and candidate-test links,
plus explicit gaps and shared-file collisions. Historical reverse lookup alone
does not meet the efficiency objective. Draft references are version-qualified;
snapshot references are owner-qualified. Normalize only with validated owner,
version, and anchor evidence, preserving raw references.

The skill remains a recipe for fresh queries and normative citations. Return
the receipt with every query to avoid duplicate builds. Core indexing and
change packets work without SARA; SARA-specific operations require a tested
compatible CLI. Generated graph items remain disposable.

Measure cold indexing, warm lookup, investigation time, and time to relevant
test feedback. Proposed targets are 10 seconds cold, 2 seconds warm p95, and
50% lower median investigation time; no such gains have yet been measured.
Profile before introducing caches or parallelism. Current test workers are
explicitly serialized, and boundary execution carries private state. Preserve
these constraints and the independent full gate.

The merged snapshot establishes a new baseline for planning. Further generator
restructuring still follows the previously agreed maintainer-confirmation gate;
this documentation update neither performs reconciliation nor changes vectors.

**Scope:** Add a derived, provenance-bearing SARA query layer and a small
repository-local agent skill without changing current vector definitions or
the frozen rolling snapshot. Defer vector-authoring restructuring until the
separate reconciliation of drifted vectors is complete.

## 1. Purpose

Vector searches and reconciliation currently require repeated manual searches
across specification anchors, a large central metadata mapper, topic builders,
registries, schemas, generated vectors, and coverage reports. The repository
already contains stable qualified specification references, but it does not
offer one fast interface for answering which vectors cover an anchor, which
anchors changed, or how reconciliation work can be divided.

[SARA](https://github.com/cledouarec/sara) can provide that interface if
Heterodyne generates a disposable graph from repository artifacts. The graph
is an index and query projection. It does not replace the documents from which
it is derived.

The implementation has two phases:

1. add the safe derived graph, commands, tests, agent skill, and AGENTS routing;
2. after current vectors are reconciled, restructure vector authoring metadata
   so indexing and parallel maintenance no longer depend on a global inferred
   metadata table or execution of the complete generator.

## 2. Authority model

The workflow distinguishes four forms of truth:

1. **Normative protocol authority:** the six specifications, registry entries,
   and protocol schemas identified by `AGENTS.md`.
2. **Current-draft authoring inputs:** non-normative generator-owned semantic
   evaluators, vector definitions, and fixtures kept synchronized with the
   normative artifacts.
3. **Frozen validation history:** the rolling vector snapshot and its pinned
   source and snapshot commits.
4. **Derived traceability view:** a reproducible SARA graph generated from one
   explicitly selected lane and exact input identities.

SARA is the preferred query interface for traceability when its freshness
receipt is valid. It is not protocol authority and cannot amend, activate, or
override a requirement. A generated graph cannot become the source of the
facts from which it was generated; it can become the authoritative interface
for querying those facts only when every result carries and verifies its input
provenance.

An agent must refuse a definitive answer from a stale graph, a graph with
unresolved required inputs, or a graph that mixes current draft documents with
historical snapshot evidence without labeling that operation as reconciliation
analysis.

## 3. Phase-one architecture

### 3.1 Repository-owned files

Phase one adds:

- `scripts/vector-trace.mjs`: deterministic adapter and command wrapper;
- `scripts/vector-trace.test.mjs`: behavior tests using synthetic repositories;
- `scripts/sara/model.yaml`: Heterodyne's custom SARA graph model;
- `.agents/skills/using-sara/SKILL.md`: concise agent-facing workflow; and
- an `AGENTS.md` section that requires the skill for vector impact, coverage,
  reconciliation, and reverse-lookup work.

Generated graph items live in an operating-system temporary directory by
default. A caller may request an explicit output directory for inspection, but
generated item files are never committed and never enter
`docs/spec/vectors/`.

SARA remains an external developer CLI pinned by the workflow to the tested
major/minor release. The wrapper performs a prerequisite and version check and
returns an actionable installation command when the CLI is unavailable. SARA
is not added to the ordinary conformance gate in phase one.

### 3.2 Graph model

The initial graph contains these item types:

- `spec_anchor`: a qualified permanent anchor, owning document, heading, and
  anchor-bounded content digest;
- `vector`: vector ID, owner, optional profile, vector path, and coverage
  relations;
- `registry_artifact`: a registry file or entry that can be attached to a
  specification anchor when an exact repository reference exists;
- `schema_artifact`: a protocol schema and its stable identifier; and
- `source_module`: a generator source module identified through deterministic
  repository metadata where available.

Relations include `covers`, `defined_by`, `uses_schema`, `uses_registry`, and
their inverses. Phase one does not guess an edge with semantic search. An edge
must come from a qualified repository reference, an exact manifest entry, an
explicit command input, or another deterministic parser rule covered by a
test. Semble may help an agent investigate missing edges, but semantic search
results never become graph truth automatically.

SARA requires generated identifiers to match its model format. The adapter
therefore derives stable UUID-shaped SARA identifiers from semantic keys and
writes an index mapping them back to values such as
`heterodyne:comms#comms-privacy-tiers` and
`privacy-tiers/tier3-kind31011-audience-key-wrap`. Users and agents interact
with semantic keys through the wrapper rather than copying SARA UUIDs.

### 3.3 Explicit lanes

Every command selects one of three lanes:

- `snapshot`: materialize the source commit pinned by the history-bound rolling
  snapshot and combine it only with that snapshot's coverage manifest;
- `draft`: index current normative and current-draft authoring artifacts without
  treating the frozen snapshot as current evidence; and
- `reconciliation`: intentionally compare current specification anchors with a
  named historical or candidate vector manifest, prominently labeling the
  resulting unresolved references and coverage as maintenance information.

The default for historical vector queries is `snapshot`. No command silently
combines the draft and snapshot lanes.

While the separate reconciliation agent is working, phase-one verification
uses synthetic fixtures and the frozen snapshot lane. Known current vector
drift is reported if encountered but is not repaired, baselined, or added to
acceptance criteria for this change.

### 3.4 Commands and output contracts

The wrapper exposes the following stable operations:

- `check`: build the selected graph and validate its relationships;
- `query <semantic-id>`: traverse upstream or downstream from an anchor,
  vector, schema, registry artifact, or source module;
- `coverage`: report covered and uncovered specification anchors by document;
- `matrix`: emit a machine-readable or CSV traceability matrix;
- `impact --base <git-ref> --head <git-ref>`: compare anchor-bounded content
  digests and report directly related graph items;
- `worklist --base <git-ref> --head <git-ref>`: group impacted work by owner and
  topic prefix, listing shared-file collision risks instead of claiming unsafe
  independence; and
- `receipt`: print the lane, Git identities, input paths, digests, SARA version,
  graph schema version, unresolved references, and generation time.

Machine output is pure JSON. The wrapper normalizes SARA commands that emit a
human preamble before JSON, preserves SARA's diagnostic text separately, and
propagates a nonzero status for validation failures. Stable sorting makes
repeated generation byte-identical for the same inputs.

For Git-ref comparisons, the adapter reads blobs from the named refs without
checking them out over the working tree. Where `sara diff` requires branch
references, the wrapper constructs a disposable Git repository containing the
two generated projections and runs the comparison there.

### 3.5 Agent skill and AGENTS routing

No maintained SARA-specific skill was found in SARA, the curated Codex skill
catalog, or the relevant public skill search. Heterodyne therefore owns a small
reference skill under the cross-runtime `.agents/skills/` location.

The skill applies when an agent must find vectors for a specification section,
assess vector impact, inspect coverage, prepare a reconciliation, or divide
vector work. It instructs the agent to:

1. read `AGENTS.md` for the protocol authority and lane rules;
2. run the wrapper rather than searching generated vector files manually;
3. inspect the receipt before trusting query results;
4. use Semble only to investigate implementation details or missing explicit
   links after the graph query; and
5. cite normative specification anchors, not SARA item files, in protocol work.

`AGENTS.md` links directly to the skill and makes it required for those tasks.
SARA's generated YAML frontmatter is confined to disposable graph items; the
normative specification Markdown is not split or decorated with SARA
frontmatter.

## 4. Phase-one failure behavior

The wrapper fails closed when:

- SARA is missing or outside the supported version range;
- a requested Git object is unavailable;
- the snapshot history binding cannot be established;
- an input changes between hashing and graph completion;
- duplicate semantic or SARA identifiers are generated;
- required machine-readable input is malformed;
- output escapes the owned temporary or explicit destination root; or
- a caller asks for a definitive mixed-lane result.

Broken graph references remain visible to SARA and to the receipt. The adapter
does not silently discard them. Reconciliation mode may finish with a report
describing broken links, while `check` remains nonzero.

Temporary repositories and projections contain only public repository data.
The workflow does not contact relays, deployments, accounts, identity
providers, or other external targets.

## 5. Phase-one testing

Implementation follows test-driven development. Tests exercise the real Node
wrapper and, when SARA is installed, the real SARA CLI. Synthetic fixtures
cover:

1. stable semantic-to-SARA identifier generation;
2. anchor-bounded hashing and heading extraction;
3. reverse anchor-to-vector lookup;
4. broken-link preservation and nonzero validation;
5. strict separation of draft, snapshot, and reconciliation lanes;
6. pure JSON normalization;
7. byte-stable graph and receipt generation;
8. Git-ref impact comparison without working-tree mutation;
9. collision-aware worklist grouping; and
10. stale-receipt refusal.

Skill validation begins with an agent scenario that lacks the new skill and
demonstrates the baseline failure: manually searching generated vectors,
mixing current and snapshot evidence, or citing the derived graph as protocol
authority. The same scenario is then run with the skill and must select the
correct lane, inspect freshness, and cite the normative anchor. The skill is
also checked with the standard skill frontmatter validator.

Repository verification includes the focused tests, a frozen-snapshot query
whose known anchor coverage matches the existing historical result, the two
normal read-only validation lanes, and `scripts/conformance-ci.sh`. Existing
untracked `.DS_Store` files remain untouched.

## 6. Phase-two vector-maintenance architecture

Phase two begins only after the maintainer confirms that the separate vector
reconciliation has completed. It must start from the reconciled source rather
than resolve conflicts against work in progress.

The primary maintenance defect to remove is the global inferred metadata path:

- vector behavior is defined across more than eleven thousand lines of topic
  modules;
- calls commonly carry placeholder or obsolete `spec_refs` values; and
- `vector-metadata.ts` separately assigns owners, profiles, and final anchors
  through exhaustive ID sets, prefix tests, and regular-expression branches.

That makes a vector's behavior and traceability two independently maintained
surfaces. It also requires broad execution or global search to discover the
complete definition.

Phase two migrates to co-located, declarative vector definitions. Each
definition carries its semantic metadata beside a lazy behavior builder:

```text
vector ID + relative path + owner + qualified spec refs + optional profile
    -> lazy deterministic input/expected-output builder
```

A metadata-only catalog is then available without evaluating cryptography,
building fixtures, or writing vector JSON. The same definition feeds vector
generation, SARA projection, coverage, schema validation, and topic selection.
There is no second ownership/reference mapper.

The migration is incremental by topic but has an atomic compatibility rule:
every migrated topic must prove that its generated vector bytes are unchanged
unless the reconciliation itself intentionally changed them. The central
mapper remains only for unmigrated topics and is deleted when the last topic
moves.

## 7. Phase-two efficiency improvements

Once definitions are declarative and lazy, the generator can add:

- metadata-only indexing that completes without full vector execution;
- `author --topic` and `verify --topic` commands;
- impacted-topic selection from changed anchors, schemas, registry entries,
  evaluators, fixtures, and source modules;
- parallel topic execution with deterministic final ordering;
- content-addressed caches keyed by definition, dependency, fixture, and tool
  digests;
- isolated output shards that can be reviewed and combined without concurrent
  writes to one directory; and
- worklists whose collision analysis is based on actual owned files rather
  than topic-name heuristics.

Parallelism is applied only after dependency declarations make independence
provable. Shared fixtures, registries, schemas, reason-code projections, and
snapshot packaging remain explicit convergence points.

## 8. Alternatives considered

### Make generated SARA Markdown normative

Rejected. It would create hundreds of duplicate files, confuse generated
traceability with protocol authority, and force ordinary specification edits
to maintain SARA formatting.

### Put SARA frontmatter directly into the six specifications

Rejected. SARA models one item per Markdown file, while Heterodyne's permanent
anchors intentionally identify many requirements inside each normative
document. Splitting the specifications or duplicating their sections would
weaken the existing authority model.

### Adopt Doorstop or OpenFastTrace instead

[Doorstop](https://github.com/doorstop-dev/doorstop) and
[OpenFastTrace](https://github.com/itsallcode/openfasttrace) provide useful
Git-native traceability. Doorstop expects separately stored requirement items,
and OpenFastTrace expects trace tags embedded across source artifacts. Neither
removes Heterodyne's need for an adapter around permanent anchors and its
distinct draft/snapshot lifecycle. SARA's custom graph model and reverse
queries fit the approved first phase with less authority churn.

### Adopt agent-spec as the repository requirements system

[Agent-spec](https://github.com/ZhangHanDong/agent-spec) includes AI skills,
requirements graphs, impact analysis, and work-unit generation. Adopting its
complete contract and knowledge model would add a second specification and
conformance framework beside Heterodyne's existing normative family and
independent harness. Its provenance, freshness, and work-unit concepts inform
this design, but it is not a phase-one dependency.

### Use Semble as the traceability database

Rejected as the only traceability layer. Semble is valuable for discovering
implementation by intent, but semantic retrieval is not a deterministic
machine-verifiable relation. The workflow uses Semble after exact graph queries,
not in place of explicit references.

## 9. Acceptance criteria

Phase one is complete when:

1. `AGENTS.md` requires and links the repository-local SARA skill for applicable
   work;
2. the skill has valid frontmatter and passes its baseline/forward behavior
   scenario;
3. the wrapper produces byte-stable graph items and provenance receipts;
4. semantic anchor queries return their related frozen vectors without exposing
   SARA UUIDs as the user interface;
5. snapshot, draft, and reconciliation inputs cannot be mixed silently;
6. impact and worklist commands do not mutate the working tree;
7. known current vector drift is neither changed nor accepted as a new
   baseline;
8. the repository's normal verification lanes remain unchanged and pass in a
   clean dependency installation; and
9. no generated SARA item is committed under the normative or snapshot trees.

Phase two is eligible to start only after the user or maintainer confirms that
the separate vector reconciliation is complete. Its detailed implementation
plan is written against that reconciled state.
