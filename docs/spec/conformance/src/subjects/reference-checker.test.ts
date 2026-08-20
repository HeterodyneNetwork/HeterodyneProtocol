import { ed25519 } from "@noble/curves/ed25519";
import { schnorr } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha2";
import { describe, expect, it } from "vitest";
import type { ArtifactCorpus, ConformanceCheckDocument, VectorDocument } from "../types.js";
import { findNegativeHygieneFailures } from "../gates/negative-hygiene.js";
import { checkCoreSignedEvent } from "./reference-checker.js";
import type { CheckerStage } from "./types.js";

const EVENT_SECRET = "0000000000000000000000000000000000000000000000000000000000000003";
const EVENT_PUBKEY = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";
const KEL_EVENT_ID = "b0".repeat(32);
const PERSONA = "a0".repeat(32);
const ZERO_AUX = new Uint8Array(32);
const SECOND_EVENT_SECRET = "0000000000000000000000000000000000000000000000000000000000000004";
const SECOND_EVENT_PUBKEY = hex(schnorr.getPublicKey(SECOND_EVENT_SECRET));
const SECOND_KEL_EVENT_ID = "c0".repeat(32);
const NID_SECRET = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const NID_PUBKEY = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const NID = "did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw";
const SMALL_ORDER_NID_PUBKEY = `01${"00".repeat(31)}`;
const SMALL_ORDER_NID = "did:key:z6MkeXATEjyXENzBXBxgC5EHk2JE5aqd7qMGGtDpLUH1e2Sj";
const SMALL_ORDER_SIGNATURE = `01${"00".repeat(63)}`;

const BIP340_VECTOR_0_PUBLIC_KEY =
  "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9";
const BIP340_VECTOR_0_MESSAGE =
  "0000000000000000000000000000000000000000000000000000000000000000";
const BIP340_VECTOR_0_SIGNATURE =
  "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0";
const LOCAL_FIXTURE_RAW =
  '[0,"f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",100,1,[["spec_version","heterodyne/0.5.0"],["kel_head","b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0","0"]],"fixture"]';
const LOCAL_FIXTURE_ID = "74fed57cc8f0d83a0e01c12cb0a1cae66acfc6326b254c4783226e1a17121c83";
const LOCAL_FIXTURE_SIGNATURE =
  "6044a1b015173a9e853867e61b2545554406c1c78e6944802fc0bd1e1484e998dfdb5e228e4d2b6adc5cb1066ef29ae3232d915d97975af48a88d68d3c6ab858";

type Fixture = {
  vector: VectorDocument;
  check: ConformanceCheckDocument;
};

function hex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

function signedEvent(
  fields: {
    created_at?: number;
    kind?: number;
    tags?: string[][];
    content?: string;
    secretKey?: string;
  } = {},
): { event: Record<string, unknown>; nip01_raw: string } {
  const secretKey = fields.secretKey ?? EVENT_SECRET;
  const pubkey = hex(schnorr.getPublicKey(secretKey));
  const createdAt = fields.created_at ?? 100;
  const kind = fields.kind ?? 1;
  const tags = fields.tags ?? [
    ["spec_version", "heterodyne/0.5.0"],
    ["kel_head", KEL_EVENT_ID, "0"],
  ];
  const content = fields.content ?? "fixture";
  const nip01Raw = JSON.stringify([0, pubkey, createdAt, kind, tags, content]);
  const digest = sha256(new TextEncoder().encode(nip01Raw));
  return {
    event: {
      id: hex(digest),
      pubkey,
      created_at: createdAt,
      kind,
      tags,
      content,
      sig: hex(schnorr.sign(digest, secretKey, ZERO_AUX)),
    },
    nip01_raw: nip01Raw,
  };
}

function validFixture(): Fixture {
  const { event, nip01_raw } = signedEvent();
  const vector: VectorDocument = {
    vector_id: "test/reference-checker",
    vector_schema_version: "1.1.0",
    owner_document: "core",
    spec_version: "heterodyne/0.5.0",
    spec_refs: ["heterodyne:0.5.0#core-verification"],
    direction: "consume",
    input: {
      event,
      nip01_raw,
      vector_context: {
        core_verification: {
          persona: PERSONA,
          evaluation_time: 100,
          nid_clock_skew_allowance: 0,
          clock_uncertainty: 0,
          pointer: {
            persona: PERSONA,
            kel_head: { event_id: KEL_EVENT_ID, sequence: 0 },
          },
          kel: [{
            event_id: KEL_EVENT_ID,
            sequence: 0,
            prior_event_id: null,
            epoch_pubkey: EVENT_PUBKEY,
            effective_from: 0,
            effective_until: null,
            compromise_since: null,
          }],
          kel_refresh: { status: "not-needed" },
          signer: { type: "epoch", pubkey: EVENT_PUBKEY, delegation: null },
          version_policy: { mode: "required", value: "heterodyne/0.5.0" },
          kel_head_policy: { mode: "required" },
          subtype_policy: { mode: "generic", nid_pubkey: null },
        },
      },
    },
    expected_output: { verdict: "accept" },
  };
  const check: ConformanceCheckDocument = {
    profile: "core-signed-event-v1",
    event_pointer: "/input/event",
    nip01_raw_pointer: "/input/nip01_raw",
    context_pointer: "/input/vector_context/core_verification",
    expected_terminal_stage: "accept",
  };
  vector.conformance_checks = [check];
  return { vector, check };
}

function replaceSignedInput(
  fixture: Fixture,
  fields: Parameters<typeof signedEvent>[0],
): void {
  const { event, nip01_raw } = signedEvent(fields);
  fixture.vector.input.event = event;
  fixture.vector.input.nip01_raw = nip01_raw;
}

function contextOf(fixture: Fixture): Record<string, unknown> {
  return ((fixture.vector.input.vector_context as Record<string, unknown>)
    .core_verification as Record<string, unknown>);
}

function signEd25519Proof(domain: string, canonicalClaim: string): string {
  const message = new TextEncoder().encode(`${domain}\0${canonicalClaim}`);
  return hex(ed25519.sign(message, NID_SECRET));
}

function configureNidDelegation(
  fixture: Fixture,
  fields: { createdAt?: number; secretKey?: string; validUntil?: string } = {},
): void {
  const publishingKey = "d0".repeat(32);
  const canonicalClaim = `{"cold_root":"${PERSONA}","nid":"${NID}"}`;
  const nidProof = signEd25519Proof("heterodyne-nid-binding-v1", canonicalClaim);
  replaceSignedInput(fixture, {
    created_at: fields.createdAt,
    secretKey: fields.secretKey,
    kind: 31_001,
    content: "",
    tags: [
      ["d", `nid:${NID}`],
      ["heterodyne", "delegation"],
      ["radicle_nid", NID],
      ["publishing_key", publishingKey],
      ["cold_root", PERSONA],
      ["nid_proof", nidProof],
      ["kel_head", KEL_EVENT_ID, "0"],
      ["valid_until", fields.validUntil ?? ""],
      ["spec_version", "heterodyne/0.5.0"],
    ],
  });
  contextOf(fixture).subtype_policy = { mode: "nid-delegation", nid_pubkey: NID_PUBKEY };
}

function configureNodeAdvertisement(
  fixture: Fixture,
  fields: { createdAt?: number; endpoint?: string; expiry?: string; rid?: string } = {},
): void {
  const rid = fields.rid ?? "rad:z2TJoDAhK5pTmLzqmK9W4FMdtjyy1";
  const endpoint = fields.endpoint ?? "wss://node.example/relay";
  const expiry = fields.expiry ?? "200";
  const repoHead = "4a19af7f069f3c32d4235c726f666fc8cd0175fa";
  const canonicalClaim = JSON.stringify({
    endpoint,
    expiry,
    nid: NID,
    repo_head: repoHead,
    rid,
  });
  const nidProof = signEd25519Proof("heterodyne-node-advert-v1", canonicalClaim);
  replaceSignedInput(fixture, {
    created_at: fields.createdAt,
    kind: 31_010,
    content: "",
    tags: [
      ["d", rid],
      ["heterodyne", "node_advert"],
      ["rid", rid],
      ["nid", NID],
      ["endpoint", endpoint],
      ["repo_head", repoHead],
      ["expiry", expiry],
      ["nid_proof", nidProof],
      ["kel_head", KEL_EVENT_ID, "0"],
      ["spec_version", "heterodyne/0.5.0"],
    ],
  });
  contextOf(fixture).subtype_policy = { mode: "node-advertisement", nid_pubkey: NID_PUBKEY };
}

function configureTwoEpochKel(fixture: Fixture, signerSecret: string): void {
  const signerPubkey = hex(schnorr.getPublicKey(signerSecret));
  replaceSignedInput(fixture, {
    secretKey: signerSecret,
    tags: [
      ["spec_version", "heterodyne/0.5.0"],
      ["kel_head", SECOND_KEL_EVENT_ID, "1"],
    ],
  });
  const context = contextOf(fixture);
  context.pointer = {
    persona: PERSONA,
    kel_head: { event_id: SECOND_KEL_EVENT_ID, sequence: 1 },
  };
  context.kel = [
    {
      event_id: KEL_EVENT_ID,
      sequence: 0,
      prior_event_id: null,
      epoch_pubkey: EVENT_PUBKEY,
      effective_from: 0,
      effective_until: 100,
      compromise_since: null,
    },
    {
      event_id: SECOND_KEL_EVENT_ID,
      sequence: 1,
      prior_event_id: KEL_EVENT_ID,
      epoch_pubkey: SECOND_EVENT_PUBKEY,
      effective_from: 100,
      effective_until: null,
      compromise_since: null,
    },
  ];
  context.signer = { type: "epoch", pubkey: signerPubkey, delegation: null };
}

function configureHistoricalTwoEpochKel(
  fixture: Fixture,
  fields: { createdAt: number; pointer: "historical" | "current"; transition: number },
): void {
  replaceSignedInput(fixture, {
    created_at: fields.createdAt,
    tags: [
      ["spec_version", "heterodyne/0.5.0"],
      ["kel_head", KEL_EVENT_ID, "0"],
    ],
  });
  configureHistoricalTwoEpochKelContext(fixture, fields.transition, fields.pointer);
}

function configureHistoricalTwoEpochKelContext(
  fixture: Fixture,
  transition: number,
  pointer: "historical" | "current" = "current",
): void {
  const context = contextOf(fixture);
  context.pointer = {
    persona: PERSONA,
    kel_head: pointer === "historical"
      ? { event_id: KEL_EVENT_ID, sequence: 0 }
      : { event_id: SECOND_KEL_EVENT_ID, sequence: 1 },
  };
  context.kel = [
    {
      event_id: KEL_EVENT_ID,
      sequence: 0,
      prior_event_id: null,
      epoch_pubkey: EVENT_PUBKEY,
      effective_from: 0,
      effective_until: transition,
      compromise_since: null,
    },
    {
      event_id: SECOND_KEL_EVENT_ID,
      sequence: 1,
      prior_event_id: KEL_EVENT_ID,
      epoch_pubkey: SECOND_EVENT_PUBKEY,
      effective_from: transition,
      effective_until: null,
      compromise_since: null,
    },
  ];
}

function configureDelegatedSigner(fixture: Fixture): void {
  replaceSignedInput(fixture, { secretKey: SECOND_EVENT_SECRET });
  contextOf(fixture).signer = {
    type: "delegated",
    pubkey: SECOND_EVENT_PUBKEY,
    delegation: {
      persona: PERSONA,
      publisher_pubkey: SECOND_EVENT_PUBKEY,
      valid_from: 100,
      valid_until: 101,
      revoked_at: null,
    },
  };
}

function expectTerminal(fixture: Fixture, stage: CheckerStage): void {
  const result = checkCoreSignedEvent(fixture.vector, fixture.check);
  expect(result.terminalStage).toBe(stage);
  expect(result.verdict).toBe(stage === "accept" ? "accept" : "reject");
  expect(result.stages.at(-1)).toMatchObject({
    stage,
    verdict: stage === "accept" ? "pass" : "reject",
  });
}

function base58(bytes: Uint8Array): string {
  const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  let value = 0n;
  for (const byte of bytes) value = value * 256n + BigInt(byte);
  let encoded = "";
  while (value > 0n) {
    encoded = alphabet[Number(value % 58n)]! + encoded;
    value /= 58n;
  }
  let zeroes = 0;
  while (bytes[zeroes] === 0) zeroes += 1;
  return "1".repeat(zeroes) + encoded;
}

describe("independent Core signed-event checker", () => {
  it("verifies official BIP-340 vector 0 exactly", () => {
    expect(schnorr.verify(
      BIP340_VECTOR_0_SIGNATURE,
      BIP340_VECTOR_0_MESSAGE,
      BIP340_VECTOR_0_PUBLIC_KEY,
    )).toBe(true);
  });

  it("pins the local fixture's raw bytes, identifier, and real signature as literals", () => {
    const fixture = validFixture();
    const event = fixture.vector.input.event as Record<string, unknown>;

    expect(fixture.vector.input.nip01_raw).toBe(LOCAL_FIXTURE_RAW);
    expect(event.id).toBe(LOCAL_FIXTURE_ID);
    expect(event.sig).toBe(LOCAL_FIXTURE_SIGNATURE);
  });

  it("rejects a malformed signed event at event_structure", () => {
    const fixture = validFixture();
    delete (fixture.vector.input.event as Record<string, unknown>).sig;

    expectTerminal(fixture, "event_structure");
  });

  it("rejects a noncanonical raw serialization at nip01_raw", () => {
    const fixture = validFixture();
    fixture.vector.input.nip01_raw = ` ${fixture.vector.input.nip01_raw as string}`;

    expectTerminal(fixture, "nip01_raw");
  });

  it("rejects a wrong identifier at identifier without relabeling it as signature", () => {
    const fixture = validFixture();
    (fixture.vector.input.event as Record<string, unknown>).id = "00".repeat(32);

    expectTerminal(fixture, "identifier");
  });

  it("rejects an invalid signature at signature while retaining a valid identifier", () => {
    const fixture = validFixture();
    (fixture.vector.input.event as Record<string, unknown>).sig = "00".repeat(64);

    expectTerminal(fixture, "signature");
  });

  it("rejects mismatched pointer and persona evidence at persona_resolution", () => {
    const fixture = validFixture();
    const context = ((fixture.vector.input.vector_context as Record<string, unknown>)
      .core_verification as Record<string, unknown>);
    (context.pointer as Record<string, unknown>).persona = "c0".repeat(32);

    expectTerminal(fixture, "persona_resolution");
  });

  it("rejects an incompatible future major at version_stamp with its registered reason", () => {
    const fixture = validFixture();
    replaceSignedInput(fixture, {
      tags: [
        ["spec_version", "heterodyne/1.0.0"],
        ["kel_head", KEL_EVENT_ID, "0"],
      ],
    });

    expectTerminal(fixture, "version_stamp");
    expect(checkCoreSignedEvent(fixture.vector, fixture.check).reasonCode)
      .toBe("unknown_major_version");
  });

  it("rejects a head that does not exactly bind the supplied pointer at kel_head", () => {
    const fixture = validFixture();
    replaceSignedInput(fixture, {
      tags: [
        ["spec_version", "heterodyne/0.5.0"],
        ["kel_head", KEL_EVENT_ID, "1"],
      ],
    });

    expectTerminal(fixture, "kel_head");
  });

  it("rejects an event before the epoch's inclusive lower bound at epoch_authority", () => {
    const fixture = validFixture();
    const context = ((fixture.vector.input.vector_context as Record<string, unknown>)
      .core_verification as Record<string, unknown>);
    ((context.kel as Record<string, unknown>[])[0]!).effective_from = 101;

    expectTerminal(fixture, "epoch_authority");
  });

  it("rejects missing Ed25519 NID-delegation proof material at subtype_nid", () => {
    const fixture = validFixture();
    const context = ((fixture.vector.input.vector_context as Record<string, unknown>)
      .core_verification as Record<string, unknown>);
    context.subtype_policy = {
      mode: "nid-delegation",
      nid_pubkey: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    };

    expectTerminal(fixture, "subtype_nid");
  });

  it("accepts the valid locally signed Core fixture", () => {
    expectTerminal(validFixture(), "accept");
  });

  it("accepts an empty NIP-01 tag array as structurally valid", () => {
    const fixture = validFixture();
    replaceSignedInput(fixture, {
      tags: [
        [],
        ["spec_version", "heterodyne/0.5.0"],
        ["kel_head", KEL_EVENT_ID, "0"],
      ],
    });

    expectTerminal(fixture, "accept");
  });

  it("proves all ten terminal stages in their required order", () => {
    const orderedStages: CheckerStage[] = [
      "event_structure",
      "nip01_raw",
      "identifier",
      "signature",
      "persona_resolution",
      "version_stamp",
      "kel_head",
      "epoch_authority",
      "subtype_nid",
      "accept",
    ];
    const fixtures = orderedStages.map(() => validFixture());
    delete (fixtures[0]!.vector.input.event as Record<string, unknown>).sig;
    fixtures[1]!.vector.input.nip01_raw = ` ${fixtures[1]!.vector.input.nip01_raw as string}`;
    (fixtures[2]!.vector.input.event as Record<string, unknown>).id = "00".repeat(32);
    (fixtures[3]!.vector.input.event as Record<string, unknown>).sig = "00".repeat(64);
    const personaContext = ((fixtures[4]!.vector.input.vector_context as Record<string, unknown>)
      .core_verification as Record<string, unknown>);
    (personaContext.pointer as Record<string, unknown>).persona = "c0".repeat(32);
    replaceSignedInput(fixtures[5]!, {
      tags: [
        ["spec_version", "heterodyne/1.0.0"],
        ["kel_head", KEL_EVENT_ID, "0"],
      ],
    });
    replaceSignedInput(fixtures[6]!, {
      tags: [
        ["spec_version", "heterodyne/0.5.0"],
        ["kel_head", KEL_EVENT_ID, "1"],
      ],
    });
    const authorityContext = ((fixtures[7]!.vector.input.vector_context as Record<string, unknown>)
      .core_verification as Record<string, unknown>);
    ((authorityContext.kel as Record<string, unknown>[])[0]!).effective_from = 101;
    const subtypeContext = ((fixtures[8]!.vector.input.vector_context as Record<string, unknown>)
      .core_verification as Record<string, unknown>);
    subtypeContext.subtype_policy = {
      mode: "nid-delegation",
      nid_pubkey: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    };

    const results = fixtures.map((fixture) => checkCoreSignedEvent(fixture.vector, fixture.check));
    expect(results.map((result) => result.terminalStage)).toEqual(orderedStages);
    results.forEach((result, index) => {
      expect(result.stages.map((stage) => stage.stage)).toEqual(orderedStages.slice(0, index + 1));
      expect(result.stages.slice(0, -1).every((stage) => stage.verdict === "pass")).toBe(true);
      expect(result.stages.at(-1)!.verdict).toBe(index === 9 ? "pass" : "reject");
    });
    const expectedReasons = [
      "bad_signature",
      "nip01_raw_mismatch",
      "bad_signature",
      "bad_signature",
      "delegation_mismatch",
      "unknown_major_version",
      "kel_head_mismatch",
      "retired-key-authority-window-invalid",
      "nid_binding_missing_signature",
    ];
    expect(results.slice(0, -1).map((result) => result.reasonCode)).toEqual(expectedReasons);

    fixtures.forEach((fixture, index) => {
      fixture.check.expected_terminal_stage = orderedStages[index]!;
      fixture.vector.expected_output = index === orderedStages.length - 1
        ? { verdict: "accept" }
        : { verdict: "reject", reason_code: expectedReasons[index] };
    });
    const corpus: ArtifactCorpus = {
      repositoryRoot: "/synthetic",
      familyVersion: "heterodyne/0.5.0",
      registryRevision: 13,
      registryDigest: "00".repeat(32),
      specifications: new Map(),
      schemas: new Map(),
      vectors: fixtures.map((fixture, index) => ({
        path: `docs/spec/vectors/test/${index}.json`,
        value: fixture.vector,
      })),
      fixtures: {},
      registry: {
        manifest: {
          revision: 13,
          schema_version: "3.0.0",
          entry_set_sha256: "00".repeat(32),
        },
        reason_codes: [],
        security_invariants: [],
      },
    };
    expect(findNegativeHygieneFailures(corpus)).toEqual([]);
  });
});

describe("raw binding and context consumption", () => {
  it("binds every exposed field to the parsed raw tuple", () => {
    const fixture = validFixture();
    (fixture.vector.input.event as Record<string, unknown>).content = "substituted";

    expectTerminal(fixture, "nip01_raw");
  });

  it("does not require or consume context before persona_resolution", () => {
    const fixture = validFixture();
    delete fixture.check.context_pointer;
    delete fixture.vector.input.vector_context;
    (fixture.vector.input.event as Record<string, unknown>).sig = "00".repeat(64);

    expectTerminal(fixture, "signature");
  });

  it("requires context once execution reaches persona_resolution", () => {
    const fixture = validFixture();
    delete fixture.check.context_pointer;
    delete fixture.vector.input.vector_context;

    expectTerminal(fixture, "persona_resolution");
  });

  it("rejects an unknown context member through the closed AJV schema", () => {
    const topLevelFixture = validFixture();
    contextOf(topLevelFixture).inferred_persona = PERSONA;

    const nestedFixture = validFixture();
    (contextOf(nestedFixture).signer as Record<string, unknown>).inferred_authority = true;

    expectTerminal(topLevelFixture, "persona_resolution");
    expectTerminal(nestedFixture, "persona_resolution");
  });

  it("requires explicit evaluation time, NID skew allowance, and clock uncertainty", () => {
    for (const field of [
      "evaluation_time",
      "nid_clock_skew_allowance",
      "clock_uncertainty",
    ]) {
      const fixture = validFixture();
      delete contextOf(fixture)[field];
      expectTerminal(fixture, "persona_resolution");
    }
  });

  it("accepts only closed safe-integer clock evidence and a bounded NID allowance", () => {
    const validClockFixture = validFixture();
    Object.assign(contextOf(validClockFixture), {
      evaluation_time: 100,
      nid_clock_skew_allowance: 0,
      clock_uncertainty: 0,
    });

    const unsafeTimeFixture = validFixture();
    Object.assign(contextOf(unsafeTimeFixture), {
      evaluation_time: Number.MAX_SAFE_INTEGER + 1,
      nid_clock_skew_allowance: 0,
      clock_uncertainty: 0,
    });

    const unboundedAllowanceFixture = validFixture();
    Object.assign(contextOf(unboundedAllowanceFixture), {
      evaluation_time: 100,
      nid_clock_skew_allowance: 301,
      clock_uncertainty: 0,
    });

    const negativeUncertaintyFixture = validFixture();
    Object.assign(contextOf(negativeUncertaintyFixture), {
      evaluation_time: 100,
      nid_clock_skew_allowance: 0,
      clock_uncertainty: -1,
    });

    const unknownClockFixture = validFixture();
    Object.assign(contextOf(unknownClockFixture), {
      evaluation_time: 100,
      nid_clock_skew_allowance: 0,
      clock_uncertainty: 0,
      inferred_clock_source: "wall",
    });

    expectTerminal(validClockFixture, "accept");
    for (const fixture of [
      unsafeTimeFixture,
      unboundedAllowanceFixture,
      negativeUncertaintyFixture,
      unknownClockFixture,
    ]) {
      expectTerminal(fixture, "persona_resolution");
    }
  });

  it("maps structure and future-major failures to existing Core reasons", () => {
    const structureFixture = validFixture();
    delete (structureFixture.vector.input.event as Record<string, unknown>).sig;

    const versionFixture = validFixture();
    replaceSignedInput(versionFixture, {
      tags: [
        ["spec_version", "heterodyne/1.0.0"],
        ["kel_head", KEL_EVENT_ID, "0"],
      ],
    });

    const malformedVersionFixture = validFixture();
    replaceSignedInput(malformedVersionFixture, {
      tags: [
        ["spec_version", "heterodyne/1.invalid"],
        ["kel_head", KEL_EVENT_ID, "0"],
      ],
    });

    expect(checkCoreSignedEvent(structureFixture.vector, structureFixture.check).reasonCode)
      .toBe("bad_signature");
    expect(checkCoreSignedEvent(versionFixture.vector, versionFixture.check).reasonCode)
      .toBe("unknown_major_version");
    expect(checkCoreSignedEvent(
      malformedVersionFixture.vector,
      malformedVersionFixture.check,
    ).reasonCode).toBeUndefined();
  });

  it("rejects noncontiguous KEL sequence, prior links, and pointer heads", () => {
    const sequenceFixture = validFixture();
    ((contextOf(sequenceFixture).kel as Record<string, unknown>[])[0]!).sequence = 1;

    const priorFixture = validFixture();
    ((contextOf(priorFixture).kel as Record<string, unknown>[])[0]!).prior_event_id = "d0".repeat(32);

    const headFixture = validFixture();
    ((contextOf(headFixture).pointer as Record<string, unknown>).kel_head as Record<string, unknown>)
      .event_id = SECOND_KEL_EVENT_ID;

    for (const fixture of [sequenceFixture, priorFixture, headFixture]) {
      expectTerminal(fixture, "persona_resolution");
    }
  });
});

describe("explicit version and KEL-head policies", () => {
  it("accepts required content stamps and optional or forbidden absent stamps", () => {
    const contentFixture = validFixture();
    replaceSignedInput(contentFixture, {
      content: '{"spec_version":"heterodyne/0.5.0","value":1}',
      tags: [["kel_head", KEL_EVENT_ID, "0"]],
    });

    const optionalFixture = validFixture();
    contextOf(optionalFixture).version_policy = {
      mode: "optional",
      value: "heterodyne/0.5.0",
    };
    replaceSignedInput(optionalFixture, { tags: [["kel_head", KEL_EVENT_ID, "0"]] });

    const forbiddenFixture = validFixture();
    contextOf(forbiddenFixture).version_policy = {
      mode: "forbidden",
      value: "heterodyne/0.5.0",
    };
    replaceSignedInput(forbiddenFixture, { tags: [["kel_head", KEL_EVENT_ID, "0"]] });

    for (const fixture of [contentFixture, optionalFixture, forbiddenFixture]) {
      expectTerminal(fixture, "accept");
    }
  });

  it("rejects duplicate stamps and a stamp forbidden by policy", () => {
    const duplicateFixture = validFixture();
    replaceSignedInput(duplicateFixture, {
      content: '{"spec_version":"heterodyne/0.5.0"}',
      tags: [
        ["spec_version", "heterodyne/0.5.0"],
        ["kel_head", KEL_EVENT_ID, "0"],
      ],
    });

    const forbiddenFixture = validFixture();
    contextOf(forbiddenFixture).version_policy = {
      mode: "forbidden",
      value: "heterodyne/0.5.0",
    };

    expectTerminal(duplicateFixture, "version_stamp");
    expectTerminal(forbiddenFixture, "version_stamp");
  });

  it("rejects duplicate spec_version members in JSON content", () => {
    const fixture = validFixture();
    replaceSignedInput(fixture, {
      content:
        '{"spec_\\u0076ersion":"heterodyne/0.5.0","spec_version":"heterodyne/0.5.0"}',
      tags: [["kel_head", KEL_EVENT_ID, "0"]],
    });

    expectTerminal(fixture, "version_stamp");
  });

  it("accepts optional and forbidden absent heads", () => {
    const optionalFixture = validFixture();
    contextOf(optionalFixture).kel_head_policy = { mode: "optional" };
    replaceSignedInput(optionalFixture, { tags: [["spec_version", "heterodyne/0.5.0"]] });

    const forbiddenFixture = validFixture();
    contextOf(forbiddenFixture).kel_head_policy = { mode: "forbidden" };
    replaceSignedInput(forbiddenFixture, { tags: [["spec_version", "heterodyne/0.5.0"]] });

    expectTerminal(optionalFixture, "accept");
    expectTerminal(forbiddenFixture, "accept");
  });

  it("rejects required missing, duplicate, malformed, and forbidden heads", () => {
    const missingFixture = validFixture();
    replaceSignedInput(missingFixture, { tags: [["spec_version", "heterodyne/0.5.0"]] });

    const duplicateFixture = validFixture();
    replaceSignedInput(duplicateFixture, {
      tags: [
        ["spec_version", "heterodyne/0.5.0"],
        ["kel_head", KEL_EVENT_ID, "0"],
        ["kel_head", KEL_EVENT_ID, "0"],
      ],
    });

    const malformedFixture = validFixture();
    replaceSignedInput(malformedFixture, {
      tags: [
        ["spec_version", "heterodyne/0.5.0"],
        ["kel_head", KEL_EVENT_ID, "00"],
      ],
    });

    const forbiddenFixture = validFixture();
    contextOf(forbiddenFixture).kel_head_policy = { mode: "forbidden" };

    for (const fixture of [missingFixture, duplicateFixture, malformedFixture, forbiddenFixture]) {
      expectTerminal(fixture, "kel_head");
    }
  });

  it("accepts a pointer head that exactly identifies a non-final KEL entry", () => {
    const fixture = validFixture();
    configureHistoricalTwoEpochKel(fixture, {
      createdAt: 100,
      pointer: "historical",
      transition: 200,
    });

    expectTerminal(fixture, "accept");
  });

  it("accepts a historical event head that is stale but on the accepted KEL", () => {
    const fixture = validFixture();
    configureHistoricalTwoEpochKel(fixture, {
      createdAt: 99,
      pointer: "current",
      transition: 100,
    });

    expectTerminal(fixture, "accept");
  });

  it("classifies a well-formed off-KEL head as equivocation rather than permanent reject", () => {
    const fixture = validFixture();
    contextOf(fixture).kel_refresh = { status: "not-needed" };
    replaceSignedInput(fixture, {
      tags: [
        ["spec_version", "heterodyne/0.5.0"],
        ["kel_head", "d0".repeat(32), "0"],
      ],
    });

    const result = checkCoreSignedEvent(fixture.vector, fixture.check);
    expect(result).toMatchObject({
      terminalStage: "kel_head",
      verdict: "equivocation_flagged",
    });
    expect(result.stages.at(-1)).toEqual({
      stage: "kel_head",
      verdict: "equivocation_flagged",
    });
  });

  it.each(["pending", "failed"] as const)(
    "classifies a sequence-ahead head with %s refresh as provisional before off-KEL",
    (status) => {
      const fixture = validFixture();
      contextOf(fixture).kel_refresh = { status };
      replaceSignedInput(fixture, {
        tags: [
          ["spec_version", "heterodyne/0.5.0"],
          ["kel_head", "d0".repeat(32), "1"],
        ],
      });

      const result = checkCoreSignedEvent(fixture.vector, fixture.check);
      expect(result).toMatchObject({ terminalStage: "accept", verdict: "accept_provisional" });
      expect(result.stages).toContainEqual({ stage: "kel_head", verdict: "provisional" });
      expect(result.stages.at(-1)).toEqual({ stage: "accept", verdict: "provisional" });
    },
  );

  it("flags a still-off-chain ahead head after a completed refresh", () => {
    const fixture = validFixture();
    contextOf(fixture).kel_refresh = { status: "succeeded" };
    replaceSignedInput(fixture, {
      tags: [
        ["spec_version", "heterodyne/0.5.0"],
        ["kel_head", "d0".repeat(32), "1"],
      ],
    });

    expect(checkCoreSignedEvent(fixture.vector, fixture.check)).toMatchObject({
      terminalStage: "kel_head",
      verdict: "equivocation_flagged",
    });
  });

  it("uses the final accepted KEL entry rather than the supplied pointer as accepted head", () => {
    const fixture = validFixture();
    configureTwoEpochKel(fixture, SECOND_EVENT_SECRET);
    contextOf(fixture).pointer = {
      persona: PERSONA,
      kel_head: { event_id: KEL_EVENT_ID, sequence: 0 },
    };
    contextOf(fixture).kel_refresh = { status: "succeeded" };

    expectTerminal(fixture, "accept");
  });
});

describe("epoch and delegated authority", () => {
  it("accepts the inclusive lower bound and selects the successor at the exclusive upper bound", () => {
    const successorFixture = validFixture();
    configureTwoEpochKel(successorFixture, SECOND_EVENT_SECRET);

    const retiredFixture = validFixture();
    configureTwoEpochKel(retiredFixture, EVENT_SECRET);

    expectTerminal(successorFixture, "accept");
    expectTerminal(retiredFixture, "epoch_authority");
  });

  it("applies effective_compromise_since minus 300 at the exact boundary", () => {
    const beforeFixture = validFixture();
    replaceSignedInput(beforeFixture, { created_at: 99 });
    ((contextOf(beforeFixture).kel as Record<string, unknown>[])[0]!).compromise_since = 400;

    const cutoffFixture = validFixture();
    ((contextOf(cutoffFixture).kel as Record<string, unknown>[])[0]!).compromise_since = 400;

    expectTerminal(beforeFixture, "accept");
    expectTerminal(cutoffFixture, "epoch_authority");
  });

  it("binds an epoch signer to the authoritative entry's exact key", () => {
    const fixture = validFixture();
    ((contextOf(fixture).kel as Record<string, unknown>[])[0]!).epoch_pubkey = SECOND_EVENT_PUBKEY;

    expectTerminal(fixture, "epoch_authority");
  });

  it("requires a kind 31001 epoch signer to remain authoritative at evaluation time", () => {
    const beforeRotation = validFixture();
    configureNidDelegation(beforeRotation, { createdAt: 99 });
    configureHistoricalTwoEpochKelContext(beforeRotation, 100);
    contextOf(beforeRotation).evaluation_time = 99;

    const atRotation = validFixture();
    configureNidDelegation(atRotation, { createdAt: 99 });
    configureHistoricalTwoEpochKelContext(atRotation, 100);
    contextOf(atRotation).evaluation_time = 100;

    expectTerminal(beforeRotation, "accept");
    expectTerminal(atRotation, "epoch_authority");
  });

  it("accepts a delegated signer at valid_from and enforces exclusive expiry and revocation", () => {
    const validFixtureAtLowerBound = validFixture();
    configureDelegatedSigner(validFixtureAtLowerBound);

    const expiredFixture = validFixture();
    configureDelegatedSigner(expiredFixture);
    const expiredDelegation = (contextOf(expiredFixture).signer as Record<string, unknown>)
      .delegation as Record<string, unknown>;
    expiredDelegation.valid_until = 100;

    const revokedFixture = validFixture();
    configureDelegatedSigner(revokedFixture);
    const revokedDelegation = (contextOf(revokedFixture).signer as Record<string, unknown>)
      .delegation as Record<string, unknown>;
    revokedDelegation.revoked_at = 100;

    expectTerminal(validFixtureAtLowerBound, "accept");
    expectTerminal(expiredFixture, "epoch_authority");
    expectTerminal(revokedFixture, "epoch_authority");
  });

  it("rejects a delegated publisher or persona mismatch during resolution", () => {
    const publisherFixture = validFixture();
    configureDelegatedSigner(publisherFixture);
    const publisherDelegation = (contextOf(publisherFixture).signer as Record<string, unknown>)
      .delegation as Record<string, unknown>;
    publisherDelegation.publisher_pubkey = EVENT_PUBKEY;

    const personaFixture = validFixture();
    configureDelegatedSigner(personaFixture);
    const personaDelegation = (contextOf(personaFixture).signer as Record<string, unknown>)
      .delegation as Record<string, unknown>;
    personaDelegation.persona = "d0".repeat(32);

    expectTerminal(publisherFixture, "persona_resolution");
    expectTerminal(personaFixture, "persona_resolution");
  });
});

describe("Ed25519 NID subtype proofs", () => {
  it("accepts an exact NID-delegation proof over domain-zero-JCS bytes", () => {
    const fixture = validFixture();
    configureNidDelegation(fixture);

    expectTerminal(fixture, "accept");
  });

  it("rejects a kind 31001 outer-signed by a delegated publisher", () => {
    const fixture = validFixture();
    configureNidDelegation(fixture, { secretKey: SECOND_EVENT_SECRET });
    contextOf(fixture).signer = {
      type: "delegated",
      pubkey: SECOND_EVENT_PUBKEY,
      delegation: {
        persona: PERSONA,
        publisher_pubkey: SECOND_EVENT_PUBKEY,
        valid_from: 0,
        valid_until: null,
        revoked_at: null,
      },
    };

    expectTerminal(fixture, "subtype_nid");
    expect(checkCoreSignedEvent(fixture.vector, fixture.check).reasonCode)
      .toBe("delegation_mismatch");
  });

  it("evaluates NID expiry against evaluation time minus the explicit allowance", () => {
    const expiredFixture = validFixture();
    Object.assign(contextOf(expiredFixture), {
      evaluation_time: 200,
      nid_clock_skew_allowance: 5,
    });
    configureNidDelegation(expiredFixture, { validUntil: "195" });

    const futureFixture = validFixture();
    Object.assign(contextOf(futureFixture), {
      evaluation_time: 200,
      nid_clock_skew_allowance: 5,
    });
    configureNidDelegation(futureFixture, { validUntil: "196" });

    expectTerminal(expiredFixture, "subtype_nid");
    expect(checkCoreSignedEvent(expiredFixture.vector, expiredFixture.check).reasonCode)
      .toBe("expired_delegation");
    expectTerminal(futureFixture, "accept");
  });

  it("rejects an invalid NID-delegation proof or mismatched NID key", () => {
    const proofFixture = validFixture();
    configureNidDelegation(proofFixture);
    const proofEvent = proofFixture.vector.input.event as Record<string, unknown>;
    const proofTags = structuredClone(proofEvent.tags as string[][]);
    proofTags.find((tag) => tag[0] === "nid_proof")![1] = "00".repeat(64);
    replaceSignedInput(proofFixture, { kind: 31_001, content: "", tags: proofTags });

    const keyFixture = validFixture();
    configureNidDelegation(keyFixture);
    contextOf(keyFixture).subtype_policy = {
      mode: "nid-delegation",
      nid_pubkey: "e0".repeat(32),
    };

    expectTerminal(proofFixture, "subtype_nid");
    expectTerminal(keyFixture, "subtype_nid");
  });

  it("uses strict RFC 8032 verification rather than permissive ZIP-215 semantics", () => {
    const fixture = validFixture();
    replaceSignedInput(fixture, {
      kind: 31_001,
      content: "",
      tags: [
        ["d", `nid:${SMALL_ORDER_NID}`],
        ["heterodyne", "delegation"],
        ["radicle_nid", SMALL_ORDER_NID],
        ["publishing_key", "d0".repeat(32)],
        ["cold_root", PERSONA],
        ["nid_proof", SMALL_ORDER_SIGNATURE],
        ["kel_head", KEL_EVENT_ID, "0"],
        ["valid_until", ""],
        ["spec_version", "heterodyne/0.5.0"],
      ],
    });
    contextOf(fixture).subtype_policy = {
      mode: "nid-delegation",
      nid_pubkey: SMALL_ORDER_NID_PUBKEY,
    };

    expectTerminal(fixture, "subtype_nid");
  });

  it("rejects nonempty delegation content and expiry at the evaluation cutoff", () => {
    const contentFixture = validFixture();
    configureNidDelegation(contentFixture);
    const contentTags = structuredClone(
      (contentFixture.vector.input.event as Record<string, unknown>).tags as string[][],
    );
    replaceSignedInput(contentFixture, { kind: 31_001, content: "unexpected", tags: contentTags });

    const expiryFixture = validFixture();
    configureNidDelegation(expiryFixture);
    const expiryTags = structuredClone(
      (expiryFixture.vector.input.event as Record<string, unknown>).tags as string[][],
    );
    expiryTags.find((tag) => tag[0] === "valid_until")![1] = "100";
    replaceSignedInput(expiryFixture, { kind: 31_001, content: "", tags: expiryTags });

    expectTerminal(contentFixture, "subtype_nid");
    expectTerminal(expiryFixture, "subtype_nid");
  });

  it("accepts an exact node-advertisement proof over all five bound fields", () => {
    const fixture = validFixture();
    configureNodeAdvertisement(fixture);

    expectTerminal(fixture, "accept");
  });

  it("accepts exactly canonical rad:z Base58BTC encodings of 20 raw RID bytes", () => {
    const validLeadingZero = new Uint8Array(20);
    validLeadingZero[19] = 1;
    const validFixtureWithZero = validFixture();
    configureNodeAdvertisement(validFixtureWithZero, {
      rid: `rad:z${base58(validLeadingZero)}`,
    });
    expectTerminal(validFixtureWithZero, "accept");

    const validRid = "rad:z2TJoDAhK5pTmLzqmK9W4FMdtjyy1";
    const invalidRids = [
      validRid.replace("rad:z", "repo:z"),
      "rad:z0malformed",
      `rad:z1${validRid.slice("rad:z".length)}`,
      `rad:z${base58(new Uint8Array(19).fill(1))}`,
      `rad:z${NID.slice("did:key:z".length)}`,
    ];
    for (const rid of invalidRids) {
      const fixture = validFixture();
      configureNodeAdvertisement(fixture, { rid });
      expectTerminal(fixture, "subtype_nid");
    }
  });

  it("enforces the inclusive plus-or-minus 300-second first-acceptance window", () => {
    const lowerBoundaryFixture = validFixture();
    contextOf(lowerBoundaryFixture).evaluation_time = 400;
    configureNodeAdvertisement(lowerBoundaryFixture, { expiry: "500" });

    const tooOldFixture = validFixture();
    contextOf(tooOldFixture).evaluation_time = 401;
    configureNodeAdvertisement(tooOldFixture, { expiry: "500" });

    const upperBoundaryFixture = validFixture();
    configureNodeAdvertisement(upperBoundaryFixture, { createdAt: 400, expiry: "500" });

    const tooFutureFixture = validFixture();
    configureNodeAdvertisement(tooFutureFixture, { createdAt: 401, expiry: "500" });

    expectTerminal(lowerBoundaryFixture, "accept");
    expectTerminal(tooOldFixture, "subtype_nid");
    expect(checkCoreSignedEvent(tooOldFixture.vector, tooOldFixture.check).reasonCode)
      .toBe("node-advert-clock-skew");
    expectTerminal(upperBoundaryFixture, "accept");
    expectTerminal(tooFutureFixture, "subtype_nid");
  });

  it("requires evaluation time to be strictly before node-advert expiry", () => {
    const beforeExpiryFixture = validFixture();
    contextOf(beforeExpiryFixture).evaluation_time = 199;
    configureNodeAdvertisement(beforeExpiryFixture);

    const atExpiryFixture = validFixture();
    contextOf(atExpiryFixture).evaluation_time = 200;
    configureNodeAdvertisement(atExpiryFixture);

    expectTerminal(beforeExpiryFixture, "accept");
    expectTerminal(atExpiryFixture, "subtype_nid");
    expect(checkCoreSignedEvent(atExpiryFixture.vector, atExpiryFixture.check).reasonCode)
      .toBe("node_advert_expired");
  });

  it("fails closed when node-advert clock uncertainty exceeds 300 seconds", () => {
    const boundaryFixture = validFixture();
    contextOf(boundaryFixture).clock_uncertainty = 300;
    configureNodeAdvertisement(boundaryFixture);

    const uncertainFixture = validFixture();
    contextOf(uncertainFixture).clock_uncertainty = 301;
    configureNodeAdvertisement(uncertainFixture);

    expectTerminal(boundaryFixture, "accept");
    expectTerminal(uncertainFixture, "subtype_nid");
    expect(checkCoreSignedEvent(uncertainFixture.vector, uncertainFixture.check).reasonCode)
      .toBe("node-advert-clock-uncertain");
  });

  it("rejects a node advertisement with nonempty content or an excessive lifetime", () => {
    const contentFixture = validFixture();
    configureNodeAdvertisement(contentFixture);
    const contentTags = structuredClone(
      (contentFixture.vector.input.event as Record<string, unknown>).tags as string[][],
    );
    replaceSignedInput(contentFixture, { kind: 31_010, content: "unexpected", tags: contentTags });

    const lifetimeFixture = validFixture();
    configureNodeAdvertisement(lifetimeFixture);
    const lifetimeTags = structuredClone(
      (lifetimeFixture.vector.input.event as Record<string, unknown>).tags as string[][],
    );
    lifetimeTags.find((tag) => tag[0] === "expiry")![1] = "86501";
    replaceSignedInput(lifetimeFixture, { kind: 31_010, content: "", tags: lifetimeTags });

    expectTerminal(contentFixture, "subtype_nid");
    expectTerminal(lifetimeFixture, "subtype_nid");
  });

  it("rejects proof claims containing an unpaired Unicode surrogate as non-JCS", () => {
    const fixture = validFixture();
    configureNodeAdvertisement(fixture, { endpoint: "\ud800" });

    expectTerminal(fixture, "subtype_nid");
  });
});
