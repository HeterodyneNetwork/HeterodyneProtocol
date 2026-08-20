import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import type {
  ArtifactCorpus,
  ConformanceCheckDocument,
  ExpectedTerminalStage,
  VectorDocument,
} from "../types.js";
import { checkCoreSignedEvent } from "../subjects/reference-checker.js";
import { findIdentifierIntegrityFailures } from "./identifier-integrity.js";
import { ALL_GATES } from "./index.js";
import { findNegativeHygieneFailures } from "./negative-hygiene.js";
import { findNip01RawFailures } from "./nip01-raw.js";
import { findSignatureIntegrityFailures } from "./signature-integrity.js";

const DIGEST = "aa".repeat(32);
const VALID_RAW =
  '[0,"f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",100,1,[["spec_version","heterodyne/0.5.0"],["kel_head","b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0","0"]],"fixture"]';
const VALID_ID = "74fed57cc8f0d83a0e01c12cb0a1cae66acfc6326b254c4783226e1a17121c83";
const VALID_SIGNATURE =
  "6044a1b015173a9e853867e61b2545554406c1c78e6944802fc0bd1e1484e998dfdb5e228e4d2b6adc5cb1066ef29ae3232d915d97975af48a88d68d3c6ab858";

type CorpusVector = { path: string; value: VectorDocument };
const REPOSITORY_ROOT = resolve(import.meta.dirname, "../../../../../");

function signedEvent(): Record<string, unknown> {
  return {
    id: VALID_ID,
    pubkey: "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
    created_at: 100,
    kind: 1,
    tags: [
      ["spec_version", "heterodyne/0.5.0"],
      ["kel_head", "b0".repeat(32), "0"],
    ],
    content: "fixture",
    sig: VALID_SIGNATURE,
  };
}

function eventLocator(event: Record<string, unknown>): string {
  const semanticTuple = [
    event.id,
    event.pubkey,
    event.created_at,
    event.kind,
    event.tags,
    event.content,
    event.sig,
  ];
  return `event-sha256:${createHash("sha256")
    .update(JSON.stringify(semanticTuple), "utf8").digest("hex")}`;
}

function vector(
  vectorId: string,
  input: Record<string, unknown>,
  check?: ConformanceCheckDocument,
): VectorDocument {
  return {
    vector_id: vectorId,
    vector_schema_version: "1.1.0",
    owner_document: "core",
    spec_version: "heterodyne/0.5.0",
    spec_refs: ["heterodyne:0.5.0#core-verification"],
    direction: "consume",
    input,
    expected_output: {
      verdict: check?.expected_terminal_stage === "accept" ? "accept" : "reject",
      ...(check !== undefined && check.expected_terminal_stage !== "accept"
        ? { reason_code: "bad_signature" }
        : {}),
    },
    ...(check === undefined ? {} : { conformance_checks: [check] }),
  };
}

function check(
  expectedTerminalStage: ExpectedTerminalStage,
  eventPointer = "/input/event",
  nip01RawPointer = "/input/nip01_raw",
): ConformanceCheckDocument {
  return {
    profile: "core-signed-event-v1",
    event_pointer: eventPointer,
    nip01_raw_pointer: nip01RawPointer,
    expected_terminal_stage: expectedTerminalStage,
  };
}

function corpus(vectors: CorpusVector[]): ArtifactCorpus {
  return {
    repositoryRoot: "/synthetic",
    familyVersion: "heterodyne/0.5.0",
    registryRevision: 13,
    registryDigest: DIGEST,
    specifications: new Map(),
    schemas: new Map(),
    vectors,
    fixtures: {},
    registry: {
      manifest: { revision: 13, schema_version: "3.0.0", entry_set_sha256: DIGEST },
      reason_codes: [],
      security_invariants: [],
    },
  };
}

function corpusVector(value: VectorDocument, path = `docs/spec/vectors/${value.vector_id}.json`): CorpusVector {
  return { path, value };
}

describe("declared Core signed-event gates", () => {
  it("waives only an explicitly declared identifier-terminal case in G8", () => {
    const event = signedEvent();
    event.id = "00".repeat(32);
    const identifierNegativeCorpus = corpus([
      corpusVector(vector(
        "verification/bad-identifier-rejects",
        { event, nip01_raw: VALID_RAW },
        check("identifier"),
      )),
    ]);

    expect(findIdentifierIntegrityFailures(identifierNegativeCorpus)).toEqual([]);
  });

  it("reports a bad identifier when a declared case claims a later terminal stage", () => {
    const event = signedEvent();
    event.id = "00".repeat(32);
    const input = corpus([
      corpusVector(vector(
        "verification/bad-signature-rejects",
        { event, nip01_raw: VALID_RAW },
        check("signature"),
      )),
    ]);

    expect(findIdentifierIntegrityFailures(input)).toEqual([
      "verification/bad-signature-rejects :: /input/event",
    ]);
  });

  it("waives only an explicitly declared signature-terminal case in G9", () => {
    const event = signedEvent();
    event.sig = "00".repeat(64);
    const signatureNegativeCorpus = corpus([
      corpusVector(vector(
        "verification/bad-signature-rejects",
        { event, nip01_raw: VALID_RAW },
        check("signature"),
      )),
    ]);

    expect(findSignatureIntegrityFailures(signatureNegativeCorpus)).toEqual([]);
  });

  it("reports a bad signature when a declared case claims a later terminal stage", () => {
    const event = signedEvent();
    event.sig = "00".repeat(64);
    const input = corpus([
      corpusVector(vector(
        "verification/signed-event-accepts",
        { event, nip01_raw: VALID_RAW },
        check("accept"),
      )),
    ]);

    expect(findSignatureIntegrityFailures(input)).toEqual([
      "verification/signed-event-accepts :: /input/event",
    ]);
  });

  it("does not infer G8, G9, or G11 applicability from an undeclared event shape", () => {
    const event = signedEvent();
    event.id = "00".repeat(32);
    event.sig = "00".repeat(64);
    const undeclared = corpus([
      corpusVector(vector(
        "verification/undeclared-shape",
        { event, nip01_raw: VALID_RAW },
      )),
    ]);

    expect(findIdentifierIntegrityFailures(undeclared)).toEqual([]);
    expect(findSignatureIntegrityFailures(undeclared)).toEqual([]);
    expect(findNegativeHygieneFailures(undeclared)).toEqual([]);
  });

  it("reports a declared negative that fails before its claimed terminal stage", () => {
    const event = signedEvent();
    event.id = "00".repeat(32);
    event.sig = "00".repeat(64);
    const doubleBrokenCorpus = corpus([
      corpusVector(vector(
        "verification/bad-signature-rejects",
        { event, nip01_raw: VALID_RAW },
        check("signature"),
      )),
    ]);

    expect(findNegativeHygieneFailures(doubleBrokenCorpus)).toEqual([
      "verification/bad-signature-rejects :: /input/event",
    ]);
  });

  it("accepts a declared negative only when the checker reaches its exact terminal stage", () => {
    const event = signedEvent();
    event.sig = "00".repeat(64);
    const signatureNegativeCorpus = corpus([
      corpusVector(vector(
        "verification/bad-signature-rejects",
        { event, nip01_raw: VALID_RAW },
        check("signature"),
      )),
    ]);

    expect(findNegativeHygieneFailures(signatureNegativeCorpus)).toEqual([]);
  });

  it("reports an accepted declaration that does not complete all checker stages", () => {
    const incompleteAcceptedCorpus = corpus([
      corpusVector(vector(
        "verification/incomplete-accept",
        { event: signedEvent(), nip01_raw: VALID_RAW },
        check("accept"),
      )),
    ]);

    expect(findNegativeHygieneFailures(incompleteAcceptedCorpus)).toEqual([
      "verification/incomplete-accept :: /input/event",
    ]);
  });
});

describe("G10 NIP-01 raw discovery and binding", () => {
  it("recursively discovers an undeclared signed event with no sibling raw value", () => {
    const missingRawCorpus = corpus([
      corpusVector(
        vector("sample", { event: signedEvent() }),
        "docs/spec/vectors/sample.json",
      ),
    ]);

    expect(findNip01RawFailures(missingRawCorpus)).toEqual([
      `docs/spec/vectors/sample.json :: ${eventLocator(signedEvent())}`,
    ]);
  });

  it("accepts an exact sibling raw value for an undeclared nested event", () => {
    const input = corpus([
      corpusVector(vector("sample", {
        envelope: { event: signedEvent(), nip01_raw: VALID_RAW },
      }), "docs/spec/vectors/sample.json"),
    ]);

    expect(findNip01RawFailures(input)).toEqual([]);
  });

  it("uses semantic event fingerprints and sorts stable file keys", () => {
    const input = corpus([
      corpusVector(vector("z-sample", {
        "nested/key~part": { event: signedEvent() },
      }), "docs/spec/vectors/z-sample.json"),
      corpusVector(vector("a-sample", {
        event: signedEvent(),
      }), "docs/spec/vectors/a-sample.json"),
    ]);

    expect(findNip01RawFailures(input)).toEqual([
      `docs/spec/vectors/a-sample.json :: ${eventLocator(signedEvent())}`,
      `docs/spec/vectors/z-sample.json :: ${eventLocator(signedEvent())}`,
    ]);
  });

  it("cross-checks a declared raw pointer even when the sibling raw is exact", () => {
    const input = corpus([
      corpusVector(vector(
        "sample/declared-raw-mismatch",
        {
          event: signedEvent(),
          nip01_raw: VALID_RAW,
          declared_raw: `${VALID_RAW} `,
        },
        check("signature", "/input/event", "/input/declared_raw"),
      ), "docs/spec/vectors/sample.json"),
    ]);

    expect(findNip01RawFailures(input)).toEqual([
      `docs/spec/vectors/sample.json :: ${eventLocator(signedEvent())}`,
    ]);
  });

  it("keeps a failure key stable when an unrelated array item is inserted", () => {
    const event = signedEvent();
    const before = corpus([
      corpusVector(vector("sample", { records: [{ event }] }), "docs/spec/vectors/sample.json"),
    ]);
    const after = corpus([
      corpusVector(vector("sample", {
        records: [{ unrelated: true }, { event }],
      }), "docs/spec/vectors/sample.json"),
    ]);

    expect(findNip01RawFailures(before)).toEqual(findNip01RawFailures(after));
    expect(findNip01RawFailures(after)[0]).not.toMatch(/\/records\/\d/u);
  });

  it("collapses duplicate semantic signed events in one vector", () => {
    const event = signedEvent();
    const input = corpus([
      corpusVector(vector("sample", { records: [{ event }, { event }] }),
        "docs/spec/vectors/sample.json"),
    ]);

    expect(findNip01RawFailures(input)).toEqual([
      `docs/spec/vectors/sample.json :: ${eventLocator(event)}`,
    ]);
  });
});

describe("ALL_GATES", () => {
  it("registers G1 through G11 in normative order", () => {
    expect(ALL_GATES.map(({ id, name }) => `${id}:${name}`)).toEqual([
      "G1:anchor-resolution",
      "G2:reason-code-closure",
      "G3:invariant-completeness",
      "G4:anchor-coverage",
      "G5:fixtures-consistency",
      "G6:dead-vocabulary",
      "G7:orphan-schemas",
      "G8:identifier-integrity",
      "G9:signature-integrity",
      "G10:nip01-raw",
      "G11:negative-hygiene",
    ]);
  });
});

describe("declared normative Core signed-event cases", () => {
  it("isolates both signature negatives and executes the accepted ten-stage trace", () => {
    const relativePaths = [
      "docs/spec/vectors/node-advert/002-outer-sig-invalid-rejected.json",
      "docs/spec/vectors/verification/001-bad-signature-rejects.json",
      "docs/spec/vectors/verification/005-valid-core-signed-event-accepts.json",
    ];
    const vectors = relativePaths.map((path) => {
      const absolutePath = resolve(REPOSITORY_ROOT, path);
      expect(existsSync(absolutePath), `missing ${path}`).toBe(true);
      return {
        path,
        value: JSON.parse(readFileSync(absolutePath, "utf8")) as VectorDocument,
      };
    });
    const declaredCorpus = corpus(vectors);

    const signatureTrace = [
      { stage: "event_structure", verdict: "pass" },
      { stage: "nip01_raw", verdict: "pass" },
      { stage: "identifier", verdict: "pass" },
      { stage: "signature", verdict: "reject", reasonCode: "bad_signature" },
    ];
    for (const { value } of vectors.slice(0, 2)) {
      expect(value.conformance_checks).toHaveLength(1);
      expect(checkCoreSignedEvent(value, value.conformance_checks![0]!)).toEqual({
        terminalStage: "signature",
        verdict: "reject",
        reasonCode: "bad_signature",
        stages: signatureTrace,
      });
    }

    const accepted = vectors[2]!.value;
    expect(accepted.expected_output).toEqual({ verdict: "accept" });
    expect(accepted.conformance_checks).toHaveLength(1);
    expect(checkCoreSignedEvent(accepted, accepted.conformance_checks![0]!)).toEqual({
      terminalStage: "accept",
      verdict: "accept",
      stages: [
        { stage: "event_structure", verdict: "pass" },
        { stage: "nip01_raw", verdict: "pass" },
        { stage: "identifier", verdict: "pass" },
        { stage: "signature", verdict: "pass" },
        { stage: "persona_resolution", verdict: "pass" },
        { stage: "version_stamp", verdict: "pass" },
        { stage: "kel_head", verdict: "pass" },
        { stage: "epoch_authority", verdict: "pass" },
        { stage: "subtype_nid", verdict: "pass" },
        { stage: "accept", verdict: "pass" },
      ],
    });

    expect(findIdentifierIntegrityFailures(declaredCorpus)).toEqual([]);
    expect(findSignatureIntegrityFailures(declaredCorpus)).toEqual([]);
    expect(findNip01RawFailures(declaredCorpus)).toEqual([]);
    expect(findNegativeHygieneFailures(declaredCorpus)).toEqual([]);
  });
});
