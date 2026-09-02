import { schnorr } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha2";
import { describe, expect, it } from "vitest";
import type { ConformanceCheckDocument, VectorDocument } from "../types.js";
import { checkCoreSignedEvent } from "./reference-checker.js";

const EVENT_SECRET = "0000000000000000000000000000000000000000000000000000000000000003";
const EVENT_PUBKEY = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";
const SECOND_EVENT_SECRET = "0000000000000000000000000000000000000000000000000000000000000004";
const SECOND_EVENT_PUBKEY = hex(schnorr.getPublicKey(SECOND_EVENT_SECRET));
const ZERO_AUX = new Uint8Array(32);

const BIP340_VECTOR_0_PUBLIC_KEY =
  "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9";
const BIP340_VECTOR_0_MESSAGE =
  "0000000000000000000000000000000000000000000000000000000000000000";
const BIP340_VECTOR_0_SIGNATURE =
  "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0";
const LOCAL_FIXTURE_RAW =
  '[0,"f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",100,1,[],"plain Nostr note"]';
const LOCAL_FIXTURE_ID = "0ca4d11b4c9a066c9d72929c8048f360f23da62346b33e125f0b011b5eb6bc5a";
const LOCAL_FIXTURE_SIGNATURE =
  "95002c9025721f3d93be71c6e78ea5792ddcf338aa2658846f270b7fbb07447548fb809ca72f0e08ef50ae416c1f3ac626480b648aebc49cb1c496bda0df1a05";
const ALTERNATE_ESCAPE_RAW =
  '[0,"f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",100,31008,[["spec_version","heterodyne/0.6.0"],["kel_head","b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0","0"]],"fi\\u0078ture"]';
const ALTERNATE_ESCAPE_ID = "d692c7c0d06430c9a6e3a554eac6cd02c9342056aa9575eb5c8afb5c0c8147d0";
const ALTERNATE_ESCAPE_SIGNATURE =
  "283cad197c3675df637c7fcc7b63e3042a4752dd75ddd0ec71ce3ffa029d8a03f902bf7dc00a2d7ee2b53188cfcebb2e09c1fa6efc6727154852a743d603236d";
const CANONICAL_RID = "rad:z2TJoDAhK5pTmLzqmK9W4FMdtjyy1";
const REGEX_VALID_WRONG_LENGTH_RID = "rad:z111111111111111111111";
const REGEX_VALID_BAD_CHECKSUM_NADDR =
  "naddr1qvzqqqr4gupzqyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3qyw8wumn8ghj7ctyv3ex2umn94ex2mrp0yhx27rpd4cxcef0qqrkzun5d93kceguqvdyq";

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
  const tags = fields.tags ?? [];
  const content = fields.content ?? "plain Nostr note";
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

function activeKeyFixture(activePersonaKey = EVENT_PUBKEY): Fixture {
  const { event, nip01_raw } = signedEvent();
  const vector: VectorDocument = {
    vector_id: "test/active-key-reference-checker",
    vector_schema_version: "2.0.0",
    owner_document: "core",
    spec_refs: ["heterodyne:core#core-verification"],
    direction: "consume",
    input: {
      event,
      nip01_raw,
      vector_context: {
        core_verification: { active_persona_key: activePersonaKey },
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
  return { vector, check };
}

function contextOf(fixture: Fixture): Record<string, unknown> {
  return ((fixture.vector.input.vector_context as Record<string, unknown>)
    .core_verification as Record<string, unknown>);
}

function replaceSignedEvent(fixture: Fixture, fields: Parameters<typeof signedEvent>[0]): void {
  const replacement = signedEvent(fields);
  fixture.vector.input.event = replacement.event;
  fixture.vector.input.nip01_raw = replacement.nip01_raw;
}

describe("active-key Core signed-event checker", () => {
  it("verifies official BIP-340 vector 0 exactly", () => {
    expect(schnorr.verify(
      BIP340_VECTOR_0_SIGNATURE,
      BIP340_VECTOR_0_MESSAGE,
      BIP340_VECTOR_0_PUBLIC_KEY,
    )).toBe(true);
  });

  it("pins the baseline fixture's raw bytes, identifier, and signature as literals", () => {
    const fixture = activeKeyFixture();
    const event = fixture.vector.input.event as Record<string, unknown>;

    expect(fixture.vector.input.nip01_raw).toBe(LOCAL_FIXTURE_RAW);
    expect(event.id).toBe(LOCAL_FIXTURE_ID);
    expect(event.sig).toBe(LOCAL_FIXTURE_SIGNATURE);
  });

  it("accepts a correctly signed event authored by the active persona key without pointer or KEL evidence", () => {
    const fixture = activeKeyFixture();

    expect(checkCoreSignedEvent(fixture.vector, fixture.check)).toEqual({
      terminalStage: "accept",
      verdict: "accept",
      stages: [
        { stage: "event_structure", verdict: "pass" },
        { stage: "nip01_raw", verdict: "pass" },
        { stage: "identifier", verdict: "pass" },
        { stage: "signature", verdict: "pass" },
        { stage: "persona_resolution", verdict: "pass" },
        { stage: "accept", verdict: "pass" },
      ],
    });
  });

  it.each([
    ["RID whose Base58 body decodes to 21 bytes", {
      name: "Ada",
      heterodyne: { profile: REGEX_VALID_WRONG_LENGTH_RID },
    }],
    ["naddr with a corrupted Bech32 checksum", {
      name: "Ada",
      heterodyne: {
        profile: CANONICAL_RID,
        identity_chain: REGEX_VALID_BAD_CHECKSUM_NADDR,
      },
    }],
  ])("keeps the surrounding signed kind-0 event valid while ignoring a noncanonical %s", (_name, content) => {
    const fixture = activeKeyFixture();
    replaceSignedEvent(fixture, { kind: 0, content: JSON.stringify(content) });

    expect(checkCoreSignedEvent(fixture.vector, fixture.check).verdict).toBe("accept");
  });

  it("rejects a malformed event before consuming raw bytes or context", () => {
    const fixture = activeKeyFixture();
    delete (fixture.vector.input.event as Record<string, unknown>).sig;

    expect(checkCoreSignedEvent(fixture.vector, fixture.check)).toMatchObject({
      terminalStage: "event_structure",
      reasonCode: "bad_signature",
    });
  });

  it("rejects a noncanonical or mismatched raw serialization", () => {
    const fixture = activeKeyFixture();
    fixture.vector.input.nip01_raw = ` ${fixture.vector.input.nip01_raw as string}`;

    expect(checkCoreSignedEvent(fixture.vector, fixture.check)).toMatchObject({
      terminalStage: "nip01_raw",
      reasonCode: "nip01_raw_mismatch",
    });
  });

  it("binds every exposed event field to the supplied raw tuple", () => {
    const fixture = activeKeyFixture();
    (fixture.vector.input.event as Record<string, unknown>).content = "substituted";

    expect(checkCoreSignedEvent(fixture.vector, fixture.check).terminalStage).toBe("nip01_raw");
  });

  it("hashes the supplied compact RFC 8259 bytes without normalizing escape spelling", () => {
    const fixture = activeKeyFixture();
    fixture.vector.input.event = {
      id: ALTERNATE_ESCAPE_ID,
      pubkey: EVENT_PUBKEY,
      created_at: 100,
      kind: 31_008,
      tags: [
        ["spec_version", "heterodyne/0.6.0"],
        ["kel_head", "b0".repeat(32), "0"],
      ],
      content: "fixture",
      sig: ALTERNATE_ESCAPE_SIGNATURE,
    };
    fixture.vector.input.nip01_raw = ALTERNATE_ESCAPE_RAW;

    expect(checkCoreSignedEvent(fixture.vector, fixture.check).verdict).toBe("accept");
  });

  it("rejects a wrong event identifier before active-key resolution", () => {
    const fixture = activeKeyFixture();
    (fixture.vector.input.event as Record<string, unknown>).id = "00".repeat(32);

    expect(checkCoreSignedEvent(fixture.vector, fixture.check)).toMatchObject({
      terminalStage: "identifier",
      reasonCode: "bad_signature",
    });
  });

  it("rejects an invalid BIP-340 signature before active-key resolution", () => {
    const fixture = activeKeyFixture();
    (fixture.vector.input.event as Record<string, unknown>).sig = "00".repeat(64);

    expect(checkCoreSignedEvent(fixture.vector, fixture.check)).toMatchObject({
      terminalStage: "signature",
      reasonCode: "bad_signature",
    });
  });

  it("rejects a valid signature when the event author is not the active persona key", () => {
    const fixture = activeKeyFixture(SECOND_EVENT_PUBKEY);

    expect(checkCoreSignedEvent(fixture.vector, fixture.check)).toMatchObject({
      terminalStage: "persona_resolution",
      verdict: "reject",
      reasonCode: "delegation_mismatch",
    });
  });

  it("requires a closed canonical active-key context only after signature verification", () => {
    for (const context of [
      {},
      { active_persona_key: EVENT_PUBKEY.toUpperCase() },
      { active_persona_key: EVENT_PUBKEY, extra_authority: true },
    ]) {
      const fixture = activeKeyFixture();
      (fixture.vector.input.vector_context as Record<string, unknown>).core_verification = context;
      expect(checkCoreSignedEvent(fixture.vector, fixture.check).terminalStage)
        .toBe("persona_resolution");
    }

    const invalidSignature = activeKeyFixture();
    delete invalidSignature.check.context_pointer;
    delete invalidSignature.vector.input.vector_context;
    (invalidSignature.vector.input.event as Record<string, unknown>).sig = "00".repeat(64);
    expect(checkCoreSignedEvent(invalidSignature.vector, invalidSignature.check).terminalStage)
      .toBe("signature");
  });

  it.each([
    "malformed",
    { requested: false, verified: "not-a-boolean" },
    { requested: false, verified: false, unknown: "ignored with the optional evidence" },
  ])("ignores invalid optional Assurance evidence when no claim is requested: %j", (assurance) => {
    const fixture = activeKeyFixture();
    contextOf(fixture).assurance = assurance;

    expect(checkCoreSignedEvent(fixture.vector, fixture.check).verdict).toBe("accept");
  });

  it("accepts an explicitly requested and verified Assurance claim after baseline identity", () => {
    const fixture = activeKeyFixture();
    contextOf(fixture).assurance = { requested: true, verified: true };

    expect(checkCoreSignedEvent(fixture.vector, fixture.check).verdict).toBe("accept");
  });

  it.each([
    { requested: true, verified: false },
    { requested: true },
    { requested: true, verified: true, unknown: "closed" },
  ])("rejects invalid Assurance evidence when its claim is explicitly requested: %j", (assurance) => {
    const fixture = activeKeyFixture();
    contextOf(fixture).assurance = assurance;

    expect(checkCoreSignedEvent(fixture.vector, fixture.check)).toMatchObject({
      terminalStage: "persona_resolution",
      verdict: "reject",
    });
  });
});
