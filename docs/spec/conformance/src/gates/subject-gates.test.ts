import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import type {
  ArtifactCorpus,
  ConformanceCheckDocument,
  ExpectedTerminalStage,
  VectorDocument,
} from "../types.js";
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
const ALTERNATE_ESCAPE_RAW =
  '[0,"f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",100,31008,[["spec_version","heterodyne/0.5.0"],["kel_head","b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0","0"]],"fi\\u0078ture"]';
const ALTERNATE_ESCAPE_ID = "49ee55f141662471402e659860126cd908ccbfcc52560567715a3c75fb86d2f8";
const ALTERNATE_ESCAPE_SIGNATURE =
  "564b09765b0de0fb660d9fafc5b5ab55bed535082ce8b45016bc8c230be46af2518fe3e59385a5e6de75df324e335e828d46e6c5f168b94495640422a8708015";

type CorpusVector = { path: string; value: VectorDocument };

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

function alternateEscapeEvent(): Record<string, unknown> {
  return {
    id: ALTERNATE_ESCAPE_ID,
    pubkey: "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
    created_at: 100,
    kind: 31_008,
    tags: [
      ["spec_version", "heterodyne/0.5.0"],
      ["kel_head", "b0".repeat(32), "0"],
    ],
    content: "fixture",
    sig: ALTERNATE_ESCAPE_SIGNATURE,
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
    vector_schema_version: "2.0.0",
    owner_document: "core",
    spec_refs: ["heterodyne:core#core-verification"],
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
    sourceRoot: "/synthetic/source",
    snapshotRoot: "/synthetic/snapshot",
    sourceCommit: "1".repeat(40),
    snapshotCommit: "2".repeat(40),
    vectorSchemaVersion: "2.0.0",
    specifications: new Map(),
    schemas: new Map(),
    vectorSchema: {},
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
  it("accepts a sibling raw value with an RFC 8259 alternate escape spelling", () => {
    const input = corpus([
      corpusVector(vector("sample", {
        event: alternateEscapeEvent(),
        nip01_raw: ALTERNATE_ESCAPE_RAW,
      }), "docs/spec/vectors/sample.json"),
    ]);

    expect(findNip01RawFailures(input)).toEqual([]);
  });

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
