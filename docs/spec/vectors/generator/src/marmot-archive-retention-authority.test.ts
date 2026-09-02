import { describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import {
  acknowledgeMarmotArchive,
  appendExactMarmotArchive,
  createMarmotArchiveRetentionAuthority,
  expireMarmotPresentation,
  type MarmotArchiveAppendReceipt,
  type MarmotArchiveInput,
  type MarmotArchiveReceiptData,
  type MarmotArchiveRetentionAuthorityConfig,
} from "./marmot-archive-retention-authority.js";
import type { CurrentRepositoryWriterBinding } from "./core-writer-binding.js";
import {
  signEvent,
  type NostrSignedEvent,
} from "./nostr.js";
import type {
  DurableAuthorityRecord,
  DurableAuthorityStore,
} from "./security-authority-support.js";
import { AUX_RAND } from "./vector-helpers.js";

const AUTHORITY_ID = "synthetic-local-marmot-archive";
const RID = "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5";
const REF = "refs/xyz.heterodyne.marmot/writers/synthetic-local";
const COMMIT = "ab".repeat(20);
const SECRET = "31".repeat(32);
const MARMOT_GROUP_ID = "44".repeat(32);
const MARMOT_EVENT_CONTENT = Buffer.from(
  Uint8Array.from({ length: 28 }, (_, index) => index),
).toString("base64");

function sha256(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

async function signedEvent(
  overrides: Partial<NostrSignedEvent> = {},
): Promise<NostrSignedEvent> {
  const event = await signEvent({
    secretKey: SECRET,
    auxRand: AUX_RAND,
    created_at: 1_800_000_000,
    kind: 445,
    tags: [["h", MARMOT_GROUP_ID]],
    content: MARMOT_EVENT_CONTENT,
  });
  return { ...event, ...overrides };
}

async function eventInput(): Promise<MarmotArchiveInput> {
  const event = await signedEvent();
  return eventInputFrom(event);
}

function eventInputFrom(event: NostrSignedEvent): MarmotArchiveInput {
  return {
    repository_rid: RID,
    ref: REF,
    source: {
      kind: "signed-event",
      event,
      event_bytes: new TextEncoder().encode(JSON.stringify(event)),
    },
  };
}

async function mediaInput(
  ciphertext = new Uint8Array([0x00, 0x45, 0x91, 0xfe, 0x10]),
): Promise<MarmotArchiveInput> {
  const digest = sha256(ciphertext);
  const authorizationEvent = await signEvent({
    secretKey: SECRET,
    auxRand: AUX_RAND,
    created_at: 1_800_000_001,
    kind: 9,
    tags: [[
      "imeta",
      "v encrypted-media-v2",
      "locator blossom-v1 https://invalid.example/synthetic",
      `ciphertext_sha256 ${digest}`,
      `plaintext_sha256 ${"77".repeat(32)}`,
      "nonce 00112233445566778899aabb",
      "m image/png",
      "filename synthetic.png",
    ]],
    content: "synthetic-local-media",
  });
  return {
    repository_rid: RID,
    ref: REF,
    source: {
      kind: "encrypted-media",
      ciphertext,
      authorization_event: authorizationEvent,
    },
  };
}

function opaqueWriter(): CurrentRepositoryWriterBinding {
  return Object.freeze({}) as CurrentRepositoryWriterBinding;
}

class ArchiveStore implements DurableAuthorityStore<MarmotArchiveReceiptData> {
  readonly records = new Map<string, DurableAuthorityRecord<MarmotArchiveReceiptData>>();
  acquireResult: "acquired" | "replay" | "conflict" | "unavailable" = "acquired";
  commitResult: "committed" | "conflict" | "unknown" = "committed";
  casResult: "committed" | "conflict" | "unknown" = "committed";
  markResult: "indeterminate" | "conflict" | "unknown" = "indeterminate";
  availableAfterFailedAcquire: MarmotArchiveReceiptData | null = null;
  commitConflictWritesExact = false;
  casConflictWritesExact = false;
  loadCalls = 0;
  acquireCalls = 0;
  commitCalls = 0;
  casCalls = 0;
  markCalls = 0;

  async load(key: string): Promise<DurableAuthorityRecord<MarmotArchiveReceiptData> | null> {
    this.loadCalls += 1;
    return this.records.get(key) ?? null;
  }

  async acquire(input: Readonly<{
    key: string;
    expected_revision: number | null;
    binding_digest: string;
    execution_token: string;
  }>): Promise<"acquired" | "replay" | "conflict" | "unavailable"> {
    this.acquireCalls += 1;
    if (this.acquireResult === "acquired") {
      this.records.set(input.key, {
        state: "executing",
        revision: (input.expected_revision ?? -1) + 1,
        binding_digest: input.binding_digest,
        execution_token: input.execution_token,
      });
    } else if (this.availableAfterFailedAcquire !== null) {
      this.records.set(input.key, {
        state: "available",
        revision: 0,
        binding_digest: input.binding_digest,
        output: this.availableAfterFailedAcquire,
      });
    }
    return this.acquireResult;
  }

  async compareAndSwap(input: Readonly<{
    key: string;
    expected_revision: number | null;
    next: DurableAuthorityRecord<MarmotArchiveReceiptData>;
  }>): Promise<"committed" | "conflict" | "unknown"> {
    this.casCalls += 1;
    if (this.casResult === "committed" || this.casConflictWritesExact) {
      this.records.set(input.key, input.next);
    }
    return this.casResult;
  }

  async commit(input: Readonly<{
    key: string;
    binding_digest: string;
    execution_token: string;
    output_digest: string;
    output: MarmotArchiveReceiptData;
  }>): Promise<"committed" | "conflict" | "unknown"> {
    this.commitCalls += 1;
    if (this.commitResult === "committed" || this.commitConflictWritesExact) {
      const current = this.records.get(input.key);
      this.records.set(input.key, {
        state: "committed",
        revision: (current?.revision ?? 0) + 1,
        binding_digest: input.binding_digest,
        execution_token: input.execution_token,
        output_digest: input.output_digest,
        output: input.output,
      });
    }
    return this.commitResult;
  }

  async markIndeterminate(input: Readonly<{
    key: string;
    binding_digest: string;
    execution_token: string;
    reconciliation_digest: string;
  }>): Promise<"indeterminate" | "conflict" | "unknown"> {
    this.markCalls += 1;
    if (this.markResult === "indeterminate") {
      const current = this.records.get(input.key);
      this.records.set(input.key, {
        state: "indeterminate",
        revision: (current?.revision ?? 0) + 1,
        binding_digest: input.binding_digest,
        execution_token: input.execution_token,
        reconciliation_digest: input.reconciliation_digest,
      });
    }
    return this.markResult;
  }
}

type ArchiveHarness = Readonly<{
  store: ArchiveStore;
  config: MarmotArchiveRetentionAuthorityConfig;
  appended: Uint8Array[];
  resolved: Array<Readonly<{ rid: string; ref: string }>>;
  appendCalls: () => number;
}>;

function harness(options: Readonly<{
  reachable?: boolean;
  appendDigest?: string;
  appendThrows?: boolean;
  resolveThrows?: boolean;
  store?: ArchiveStore;
}> = {}): ArchiveHarness {
  const store = options.store ?? new ArchiveStore();
  const appended: Uint8Array[] = [];
  const resolved: Array<Readonly<{ rid: string; ref: string }>> = [];
  let appendCalls = 0;
  return {
    store,
    appended,
    resolved,
    appendCalls: () => appendCalls,
    config: {
      authority_id: AUTHORITY_ID,
      store,
      resolve_writer: async (rid, ref) => {
        resolved.push({ rid, ref });
        if (options.resolveThrows) throw new Error("synthetic writer denied");
        return opaqueWriter();
      },
      append_and_resolve: async ({ bytes }) => {
        appendCalls += 1;
        appended.push(new Uint8Array(bytes));
        if (options.appendThrows) throw new Error("synthetic unknown append result");
        return {
          object_digest: options.appendDigest ?? sha256(bytes),
          commit: COMMIT,
          reachable: options.reachable ?? true,
        };
      },
    },
  };
}

describe("Marmot archive retention authority", () => {
  it("appends and acknowledges exact signed-event bytes only after durable readback", async () => {
    const fixture = harness();
    const authority = createMarmotArchiveRetentionAuthority(fixture.config);
    const input = await eventInput();
    const exactBytes = new Uint8Array(input.source.kind === "signed-event"
      ? input.source.event_bytes
      : new Uint8Array());

    const appended = await appendExactMarmotArchive(authority, input);

    expect(appended.verdict).toBe("accept");
    if (appended.verdict !== "accept") return;
    expect(appended.output).toEqual({});
    expect(Object.isFrozen(appended.output)).toBe(true);
    expect(fixture.appended).toHaveLength(1);
    expect(fixture.appended[0]).toEqual(exactBytes);
    await expect(acknowledgeMarmotArchive(authority, appended.output)).resolves.toEqual({
      verdict: "accept",
      output: {
        repository_rid: RID,
        ref: REF,
        object_digest: sha256(exactBytes),
        source_digest: input.source.kind === "signed-event"
          ? input.source.event.id
          : "",
        commit: COMMIT,
      },
    });
  });

  it("preserves a valid signed event's original serialized whitespace", async () => {
    const fixture = harness();
    const authority = createMarmotArchiveRetentionAuthority(fixture.config);
    const input = await eventInput();
    if (input.source.kind !== "signed-event") throw new Error("synthetic fixture error");
    const original = new TextEncoder().encode(` \n${JSON.stringify(input.source.event)}\n`);

    const appended = await appendExactMarmotArchive(authority, {
      ...input,
      source: { ...input.source, event_bytes: original },
    });

    expect(appended.verdict).toBe("accept");
    expect(fixture.appended).toEqual([original]);
  });

  it("appends ciphertext only when a signed Marmot media event binds its exact digest", async () => {
    const fixture = harness();
    const authority = createMarmotArchiveRetentionAuthority(fixture.config);
    const input = await mediaInput();
    const ciphertext = new Uint8Array(input.source.kind === "encrypted-media"
      ? input.source.ciphertext
      : new Uint8Array());

    const appended = await appendExactMarmotArchive(authority, input);

    expect(appended.verdict).toBe("accept");
    expect(fixture.appended).toEqual([ciphertext]);
    if (appended.verdict !== "accept") return;
    await expect(acknowledgeMarmotArchive(authority, appended.output)).resolves.toMatchObject({
      verdict: "accept",
      output: { object_digest: sha256(ciphertext), source_digest: sha256(ciphertext) },
    });
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects invalid event IDs, signatures, and mismatched event bytes", async () => {
    for (const mutate of [
      async (input: MarmotArchiveInput): Promise<MarmotArchiveInput> => {
        if (input.source.kind !== "signed-event") return input;
        return { ...input, source: { ...input.source, event: { ...input.source.event, id: "00".repeat(32) } } };
      },
      async (input: MarmotArchiveInput): Promise<MarmotArchiveInput> => {
        if (input.source.kind !== "signed-event") return input;
        return { ...input, source: { ...input.source, event: { ...input.source.event, sig: "00".repeat(64) } } };
      },
      async (input: MarmotArchiveInput): Promise<MarmotArchiveInput> => {
        if (input.source.kind !== "signed-event") return input;
        return {
          ...input,
          source: {
            ...input.source,
            event_bytes: new TextEncoder().encode(JSON.stringify({
              ...input.source.event,
              content: "synthetic changed bytes",
            })),
          },
        };
      },
    ]) {
      const fixture = harness();
      const authority = createMarmotArchiveRetentionAuthority(fixture.config);
      const result = await appendExactMarmotArchive(authority, await mutate(await eventInput()));
      expect(result).toEqual({ verdict: "reject", reason_code: "marmot-premature-ack" });
      expect(fixture.appendCalls()).toBe(0);
      expect(fixture.store.acquireCalls).toBe(0);
    }
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects a generic signed kind-1 source", async () => {
    const event = await signEvent({
      secretKey: SECRET,
      auxRand: AUX_RAND,
      created_at: 1_800_000_004,
      kind: 1,
      tags: [],
      content: "synthetic local generic note",
    });
    const fixture = harness();
    const authority = createMarmotArchiveRetentionAuthority(fixture.config);

    await expect(appendExactMarmotArchive(authority, {
      repository_rid: RID,
      ref: REF,
      source: {
        kind: "signed-event",
        event,
        event_bytes: new TextEncoder().encode(JSON.stringify(event)),
      },
    })).resolves.toEqual({ verdict: "reject", reason_code: "marmot-premature-ack" });
    expect(fixture.store.acquireCalls).toBe(0);
    expect(fixture.appendCalls()).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects duplicate-key outer signed-event JSON", async () => {
    const input = await eventInput();
    if (input.source.kind !== "signed-event") throw new Error("synthetic fixture error");
    const encoded = JSON.stringify(input.source.event);
    const duplicateId = encoded.replace(
      `"id":"${input.source.event.id}"`,
      `"id":"${input.source.event.id}","id":"${input.source.event.id}"`,
    );
    if (duplicateId === encoded) throw new Error("synthetic duplicate fixture error");
    const fixture = harness();
    const authority = createMarmotArchiveRetentionAuthority(fixture.config);

    await expect(appendExactMarmotArchive(authority, {
      ...input,
      source: {
        ...input.source,
        event_bytes: new TextEncoder().encode(duplicateId),
      },
    })).resolves.toEqual({ verdict: "reject", reason_code: "marmot-premature-ack" });
    expect(fixture.store.acquireCalls).toBe(0);
    expect(fixture.appendCalls()).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects an unauthorized repository writer before append", async () => {
    const fixture = harness({ resolveThrows: true });
    const authority = createMarmotArchiveRetentionAuthority(fixture.config);
    await expect(appendExactMarmotArchive(authority, await eventInput())).resolves.toEqual({
      verdict: "reject",
      reason_code: "marmot-premature-ack",
    });
    expect(fixture.appendCalls()).toBe(0);
    expect(fixture.store.acquireCalls).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local captures bytes, RID, and ref before asynchronous writer resolution", async () => {
    const fixture = harness();
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const originalResolve = fixture.config.resolve_writer;
    const config = {
      ...fixture.config,
      resolve_writer: async (rid: string, ref: string) => {
        await gate;
        return originalResolve(rid, ref);
      },
    };
    const authority = createMarmotArchiveRetentionAuthority(config);
    const input = await eventInput() as {
      repository_rid: string;
      ref: string;
      source: { kind: "signed-event"; event: NostrSignedEvent; event_bytes: Uint8Array };
    };
    const originalBytes = new Uint8Array(input.source.event_bytes);
    const pending = appendExactMarmotArchive(authority, input);
    input.repository_rid = "rad:zChangedSyntheticRid";
    input.ref = "refs/xyz.heterodyne.marmot/writers/changed";
    input.source.event_bytes.fill(0xff);
    input.source.event.content = "changed";
    release();

    const result = await pending;
    expect(result.verdict).toBe("accept");
    expect(fixture.resolved).toEqual([{ rid: RID, ref: REF }]);
    expect(fixture.appended).toEqual([originalBytes]);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects ciphertext without exact authenticated media authorization", async () => {
    const valid = await mediaInput();
    if (valid.source.kind !== "encrypted-media") throw new Error("synthetic fixture error");
    const cases: MarmotArchiveInput[] = [
      {
        ...valid,
        source: {
          ...valid.source,
          authorization_event: { ...valid.source.authorization_event, sig: "00".repeat(64) },
        },
      },
      {
        ...valid,
        source: {
          ...valid.source,
          authorization_event: await signEvent({
            secretKey: SECRET,
            auxRand: AUX_RAND,
            created_at: 1_800_000_002,
            kind: 9,
            tags: [["imeta", "v encrypted-media-v2", `ciphertext_sha256 ${"00".repeat(32)}`]],
            content: "synthetic wrong media binding",
          }),
        },
      },
      {
        ...valid,
        source: {
          ...valid.source,
          authorization_event: await signedEvent(),
        },
      },
    ];
    for (const input of cases) {
      const fixture = harness();
      const authority = createMarmotArchiveRetentionAuthority(fixture.config);
      await expect(appendExactMarmotArchive(authority, input)).resolves.toEqual({
        verdict: "reject",
        reason_code: "marmot-premature-ack",
      });
      expect(fixture.appendCalls()).toBe(0);
    }
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects every missing encrypted-media-v2 required field", async () => {
    const valid = await mediaInput();
    if (valid.source.kind !== "encrypted-media") throw new Error("synthetic fixture error");
    const imeta = valid.source.authorization_event.tags[0];
    if (imeta === undefined) throw new Error("synthetic fixture error");
    const requiredPrefixes = [
      "v ",
      "locator ",
      "ciphertext_sha256 ",
      "plaintext_sha256 ",
      "nonce ",
      "m ",
      "filename ",
    ];

    for (const missingPrefix of requiredPrefixes) {
      const authorizationEvent = await signEvent({
        secretKey: SECRET,
        auxRand: AUX_RAND,
        created_at: 1_800_000_005,
        kind: 9,
        tags: [[
          "imeta",
          ...imeta.slice(1).filter((field) => !field.startsWith(missingPrefix)),
        ]],
        content: `synthetic local missing ${missingPrefix.trim()}`,
      });
      const fixture = harness();
      const authority = createMarmotArchiveRetentionAuthority(fixture.config);

      await expect(appendExactMarmotArchive(authority, {
        ...valid,
        source: { ...valid.source, authorization_event: authorizationEvent },
      })).resolves.toEqual({ verdict: "reject", reason_code: "marmot-premature-ack" });
      expect(fixture.store.acquireCalls).toBe(0);
      expect(fixture.appendCalls()).toBe(0);
    }
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects a U+D800 encrypted-media filename", async () => {
    const valid = await mediaInput();
    if (valid.source.kind !== "encrypted-media") throw new Error("synthetic fixture error");
    const imeta = valid.source.authorization_event.tags[0];
    if (imeta === undefined) throw new Error("synthetic fixture error");
    const authorizationEvent = await signEvent({
      secretKey: SECRET,
      auxRand: AUX_RAND,
      created_at: 1_800_000_006,
      kind: 9,
      tags: [[
        "imeta",
        ...imeta.slice(1).map((field) =>
          field.startsWith("filename ") ? "filename \ud800" : field),
      ]],
      content: "synthetic local surrogate filename",
    });
    const fixture = harness();
    const authority = createMarmotArchiveRetentionAuthority(fixture.config);

    await expect(appendExactMarmotArchive(authority, {
      ...valid,
      source: { ...valid.source, authorization_event: authorizationEvent },
    })).resolves.toEqual({ verdict: "reject", reason_code: "marmot-premature-ack" });
    expect(fixture.store.acquireCalls).toBe(0);
    expect(fixture.appendCalls()).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects U+D800 elsewhere in a signed media event", async () => {
    const valid = await mediaInput();
    if (valid.source.kind !== "encrypted-media") throw new Error("synthetic fixture error");
    const cases = [
      {
        tags: valid.source.authorization_event.tags,
        content: "\ud800",
      },
      {
        tags: [...valid.source.authorization_event.tags, ["synthetic", "\ud800"]],
        content: "synthetic local surrogate tag",
      },
    ];

    for (const invalid of cases) {
      const authorizationEvent = await signEvent({
        secretKey: SECRET,
        auxRand: AUX_RAND,
        created_at: 1_800_000_007,
        kind: 9,
        tags: invalid.tags,
        content: invalid.content,
      });
      const fixture = harness();
      const authority = createMarmotArchiveRetentionAuthority(fixture.config);

      await expect(appendExactMarmotArchive(authority, {
        ...valid,
        source: { ...valid.source, authorization_event: authorizationEvent },
      })).resolves.toEqual({ verdict: "reject", reason_code: "marmot-premature-ack" });
      expect(fixture.store.acquireCalls).toBe(0);
      expect(fixture.appendCalls()).toBe(0);
    }
  });

  it("accepts canonical uint64 maximum and near-maximum Marmot expirations", async () => {
    for (const expiration of ["18446744073709551614", "18446744073709551615"]) {
      const event = await signEvent({
        secretKey: SECRET,
        auxRand: AUX_RAND,
        created_at: 1_800_000_008,
        kind: 445,
        tags: [["h", MARMOT_GROUP_ID], ["expiration", expiration]],
        content: MARMOT_EVENT_CONTENT,
      });
      const fixture = harness();
      const authority = createMarmotArchiveRetentionAuthority(fixture.config);

      await expect(appendExactMarmotArchive(authority, eventInputFrom(event))).resolves.toMatchObject({
        verdict: "accept",
      });
      expect(fixture.appendCalls()).toBe(1);
    }
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects out-of-range or noncanonical Marmot expirations", async () => {
    for (const expiration of [
      "18446744073709551616",
      "-1",
      "+1",
      "01",
      "1.0",
    ]) {
      const event = await signEvent({
        secretKey: SECRET,
        auxRand: AUX_RAND,
        created_at: 1_800_000_009,
        kind: 445,
        tags: [["h", MARMOT_GROUP_ID], ["expiration", expiration]],
        content: MARMOT_EVENT_CONTENT,
      });
      const fixture = harness();
      const authority = createMarmotArchiveRetentionAuthority(fixture.config);

      await expect(appendExactMarmotArchive(authority, eventInputFrom(event))).resolves.toEqual({
        verdict: "reject",
        reason_code: "marmot-premature-ack",
      });
      expect(fixture.store.acquireCalls).toBe(0);
      expect(fixture.appendCalls()).toBe(0);
    }
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects numeric unsafe, fractional, or negative expirations", async () => {
    for (const expiration of [Number.MAX_SAFE_INTEGER + 1, 1.5, -1]) {
      const event = await signEvent({
        secretKey: SECRET,
        auxRand: AUX_RAND,
        created_at: 1_800_000_010,
        kind: 445,
        tags: [["h", MARMOT_GROUP_ID], [
          "expiration",
          expiration as unknown as string,
        ]],
        content: MARMOT_EVENT_CONTENT,
      });
      const fixture = harness();
      const authority = createMarmotArchiveRetentionAuthority(fixture.config);

      await expect(appendExactMarmotArchive(authority, eventInputFrom(event))).resolves.toEqual({
        verdict: "reject",
        reason_code: "marmot-premature-ack",
      });
      expect(fixture.store.acquireCalls).toBe(0);
      expect(fixture.appendCalls()).toBe(0);
    }
  });

  it("BLUE TEAM VALIDATION: synthetic/local prevents another signed media event from inheriting a ciphertext receipt", async () => {
    const fixture = harness();
    const authority = createMarmotArchiveRetentionAuthority(fixture.config);
    const firstInput = await mediaInput();
    const first = await appendExactMarmotArchive(authority, firstInput);
    expect(first.verdict).toBe("accept");
    if (firstInput.source.kind !== "encrypted-media") throw new Error("synthetic fixture error");
    const digest = sha256(firstInput.source.ciphertext);
    const secondAuthorization = await signEvent({
      secretKey: SECRET,
      auxRand: AUX_RAND,
      created_at: 1_800_000_003,
      kind: 9,
      tags: [[
        "imeta",
        "v encrypted-media-v2",
        `ciphertext_sha256 ${digest}`,
      ]],
      content: "synthetic alternate authorization",
    });

    const second = await appendExactMarmotArchive(authority, {
      ...firstInput,
      source: {
        ...firstInput.source,
        authorization_event: secondAuthorization,
      },
    });

    expect(second).toEqual({ verdict: "reject", reason_code: "marmot-premature-ack" });
    expect(fixture.appendCalls()).toBe(1);
  });

  it("BLUE TEAM VALIDATION: synthetic/local forbids acknowledgement before durable reachability", async () => {
    const fixture = harness({ reachable: false });
    const authority = createMarmotArchiveRetentionAuthority(fixture.config);
    const appended = await appendExactMarmotArchive(authority, await eventInput());
    expect(appended).toMatchObject({ verdict: "indeterminate" });
    if (appended.verdict === "indeterminate") {
      expect(appended.reconciliation_digest).toMatch(/^[0-9a-f]{64}$/);
    }
    const loadsBeforeAck = fixture.store.loadCalls;
    await expect(acknowledgeMarmotArchive(
      authority,
      Object.freeze({}) as MarmotArchiveAppendReceipt,
    )).resolves.toEqual({ verdict: "reject", reason_code: "marmot-premature-ack" });
    expect(fixture.store.loadCalls).toBe(loadsBeforeAck);
  });

  it("expires presentation while preserving the retained object and commit history", async () => {
    const fixture = harness();
    const authority = createMarmotArchiveRetentionAuthority(fixture.config);
    const appended = await appendExactMarmotArchive(authority, await mediaInput());
    expect(appended.verdict).toBe("accept");
    if (appended.verdict !== "accept") return;
    const acknowledged = await acknowledgeMarmotArchive(authority, appended.output);
    expect(acknowledged.verdict).toBe("accept");

    const expired = await expireMarmotPresentation(authority, appended.output);

    expect(expired).toEqual(acknowledged);
    expect(fixture.store.casCalls).toBe(1);
    expect(fixture.appendCalls()).toBe(1);
    expect([...fixture.store.records.values()]).toEqual([
      expect.objectContaining({
        state: "available",
        output: acknowledged.verdict === "accept" ? acknowledged.output : undefined,
      }),
    ]);
    await expect(acknowledgeMarmotArchive(authority, appended.output)).resolves.toEqual(acknowledged);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects a durable binding conflict without repeating append", async () => {
    const fixture = harness();
    fixture.store.acquireResult = "conflict";
    const authority = createMarmotArchiveRetentionAuthority(fixture.config);
    await expect(appendExactMarmotArchive(authority, await eventInput())).resolves.toEqual({
      verdict: "indeterminate",
      reconciliation_digest: expect.stringMatching(/^[0-9a-f]{64}$/),
    });
    expect(fixture.appendCalls()).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local refuses available state after null-load and not-acquired replay", async () => {
    const store = new ArchiveStore();
    store.acquireResult = "replay";
    const input = await eventInput();
    if (input.source.kind !== "signed-event") throw new Error("synthetic fixture error");
    store.availableAfterFailedAcquire = {
      repository_rid: RID,
      ref: REF,
      object_digest: sha256(input.source.event_bytes),
      source_digest: input.source.event.id,
      commit: COMMIT,
    };
    const fixture = harness({ store });
    const authority = createMarmotArchiveRetentionAuthority(fixture.config);

    await expect(appendExactMarmotArchive(authority, input)).resolves.toEqual({
      verdict: "indeterminate",
      reconciliation_digest: expect.stringMatching(/^[0-9a-f]{64}$/),
    });
    expect(fixture.store.loadCalls).toBe(2);
    expect(fixture.store.acquireCalls).toBe(1);
    expect(fixture.store.commitCalls).toBe(0);
    expect(fixture.appendCalls()).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local makes an unknown terminal append absorbing and never repeats it", async () => {
    const fixture = harness();
    fixture.store.commitResult = "unknown";
    const authority = createMarmotArchiveRetentionAuthority(fixture.config);
    const input = await eventInput();

    const first = await appendExactMarmotArchive(authority, input);
    const second = await appendExactMarmotArchive(authority, input);

    expect(first).toEqual(second);
    expect(first).toEqual({
      verdict: "indeterminate",
      reconciliation_digest: expect.stringMatching(/^[0-9a-f]{64}$/),
    });
    expect(fixture.appendCalls()).toBe(1);
    expect(fixture.store.markCalls).toBe(1);
  });

  it("replays an exact committed append after reconstruction without repeating the repository effect", async () => {
    const fixture = harness();
    const input = await eventInput();
    const firstAuthority = createMarmotArchiveRetentionAuthority(fixture.config);
    const first = await appendExactMarmotArchive(firstAuthority, input);
    expect(first.verdict).toBe("accept");
    expect(fixture.appendCalls()).toBe(1);

    const secondAuthority = createMarmotArchiveRetentionAuthority(fixture.config);
    const replay = await appendExactMarmotArchive(secondAuthority, input);

    expect(replay.verdict).toBe("accept");
    expect(fixture.appendCalls()).toBe(1);
    if (replay.verdict === "accept") {
      await expect(acknowledgeMarmotArchive(secondAuthority, replay.output)).resolves.toMatchObject({
        verdict: "accept",
        output: { repository_rid: RID, ref: REF, commit: COMMIT },
      });
    }
  });

  it("accepts an exact committed terminal that wins a terminal-write conflict", async () => {
    const fixture = harness();
    fixture.store.commitResult = "conflict";
    fixture.store.commitConflictWritesExact = true;
    const authority = createMarmotArchiveRetentionAuthority(fixture.config);

    const appended = await appendExactMarmotArchive(authority, await eventInput());

    expect(appended.verdict).toBe("accept");
    expect(fixture.appendCalls()).toBe(1);
    expect(fixture.store.markCalls).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local refuses a token-substituted committed terminal without repeating append", async () => {
    const fixture = harness();
    const authority = createMarmotArchiveRetentionAuthority(fixture.config);
    const input = await eventInput();
    const first = await appendExactMarmotArchive(authority, input);
    expect(first.verdict).toBe("accept");
    const entry = [...fixture.store.records.entries()][0];
    if (entry === undefined || entry[1].state !== "committed") {
      throw new Error("synthetic committed record missing");
    }
    fixture.store.records.set(entry[0], {
      ...entry[1],
      execution_token: "ff".repeat(32),
    });

    const replay = await appendExactMarmotArchive(authority, input);

    expect(replay).toEqual({
      verdict: "indeterminate",
      reconciliation_digest: expect.stringMatching(/^[0-9a-f]{64}$/),
    });
    expect(fixture.appendCalls()).toBe(1);
    expect(fixture.store.acquireCalls).toBe(1);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects cloned and cross-authority receipts", async () => {
    const fixture = harness();
    const firstAuthority = createMarmotArchiveRetentionAuthority(fixture.config);
    const secondAuthority = createMarmotArchiveRetentionAuthority({
      ...fixture.config,
      authority_id: "synthetic-local-other-archive",
    });
    const appended = await appendExactMarmotArchive(firstAuthority, await eventInput());
    expect(appended.verdict).toBe("accept");
    if (appended.verdict !== "accept") return;

    await expect(acknowledgeMarmotArchive(
      firstAuthority,
      { ...appended.output },
    )).resolves.toEqual({ verdict: "reject", reason_code: "marmot-premature-ack" });
    await expect(acknowledgeMarmotArchive(
      secondAuthority,
      appended.output,
    )).resolves.toEqual({ verdict: "reject", reason_code: "marmot-premature-ack" });
    await expect(expireMarmotPresentation(
      secondAuthority,
      appended.output,
    )).resolves.toEqual({ verdict: "reject", reason_code: "marmot-premature-ack" });
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects callback accessors and proxies with zero trap invocation", () => {
    let traps = 0;
    const fixture = harness();
    const accessorConfig = Object.defineProperty({
      authority_id: AUTHORITY_ID,
      store: fixture.store,
      append_and_resolve: fixture.config.append_and_resolve,
    }, "resolve_writer", {
      enumerable: true,
      get() {
        traps += 1;
        return fixture.config.resolve_writer;
      },
    }) as unknown as MarmotArchiveRetentionAuthorityConfig;
    expect(() => createMarmotArchiveRetentionAuthority(accessorConfig)).toThrow(TypeError);
    expect(traps).toBe(0);

    const proxy = new Proxy(fixture.config, {
      get() {
        traps += 1;
        throw new Error("synthetic proxy trap");
      },
      ownKeys() {
        traps += 1;
        throw new Error("synthetic proxy trap");
      },
    });
    expect(() => createMarmotArchiveRetentionAuthority(proxy)).toThrow(TypeError);
    expect(traps).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects input accessors and proxies with zero trap invocation", async () => {
    let traps = 0;
    const fixture = harness();
    const authority = createMarmotArchiveRetentionAuthority(fixture.config);
    const base = await eventInput();
    const accessor = Object.defineProperty({
      repository_rid: RID,
      ref: REF,
    }, "source", {
      enumerable: true,
      get() {
        traps += 1;
        return base.source;
      },
    }) as MarmotArchiveInput;
    await expect(appendExactMarmotArchive(authority, accessor)).resolves.toEqual({
      verdict: "reject",
      reason_code: "marmot-premature-ack",
    });
    expect(traps).toBe(0);

    const proxy = new Proxy(base, {
      get() {
        traps += 1;
        throw new Error("synthetic proxy trap");
      },
      ownKeys() {
        traps += 1;
        throw new Error("synthetic proxy trap");
      },
    });
    await expect(appendExactMarmotArchive(authority, proxy)).resolves.toEqual({
      verdict: "reject",
      reason_code: "marmot-premature-ack",
    });
    expect(traps).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects non-exact append results and marks the terminal indeterminate", async () => {
    for (const fixture of [
      harness({ appendDigest: "00".repeat(32) }),
      harness({ appendThrows: true }),
    ]) {
      const authority = createMarmotArchiveRetentionAuthority(fixture.config);
      const result = await appendExactMarmotArchive(authority, await eventInput());
      expect(result).toEqual({
        verdict: "indeterminate",
        reconciliation_digest: expect.stringMatching(/^[0-9a-f]{64}$/),
      });
      expect(fixture.store.markCalls).toBe(1);
      expect(fixture.appendCalls()).toBe(1);
    }
  });

  it("BLUE TEAM VALIDATION: synthetic/local keeps an expiration CAS conflict non-authoritative", async () => {
    const fixture = harness();
    const authority = createMarmotArchiveRetentionAuthority(fixture.config);
    const appended = await appendExactMarmotArchive(authority, await eventInput());
    expect(appended.verdict).toBe("accept");
    if (appended.verdict !== "accept") return;
    fixture.store.casResult = "unknown";

    const result = await expireMarmotPresentation(authority, appended.output);

    expect(result).toEqual({
      verdict: "indeterminate",
      reconciliation_digest: expect.stringMatching(/^[0-9a-f]{64}$/),
    });
    expect(fixture.appendCalls()).toBe(1);
  });

  it("accepts an exact expired-but-retained terminal that wins an expiration CAS conflict", async () => {
    const fixture = harness();
    const authority = createMarmotArchiveRetentionAuthority(fixture.config);
    const appended = await appendExactMarmotArchive(authority, await eventInput());
    expect(appended.verdict).toBe("accept");
    if (appended.verdict !== "accept") return;
    fixture.store.casResult = "conflict";
    fixture.store.casConflictWritesExact = true;

    const expired = await expireMarmotPresentation(authority, appended.output);

    expect(expired.verdict).toBe("accept");
    expect(fixture.appendCalls()).toBe(1);
  });

  it("BLUE TEAM VALIDATION: synthetic/local does not remint presentation authority from an expired durable record", async () => {
    const fixture = harness();
    const input = await eventInput();
    const firstAuthority = createMarmotArchiveRetentionAuthority(fixture.config);
    const appended = await appendExactMarmotArchive(firstAuthority, input);
    expect(appended.verdict).toBe("accept");
    if (appended.verdict !== "accept") return;
    await expect(expireMarmotPresentation(firstAuthority, appended.output)).resolves.toMatchObject({
      verdict: "accept",
    });

    const reconstructed = createMarmotArchiveRetentionAuthority(fixture.config);
    const replay = await appendExactMarmotArchive(reconstructed, input);

    expect(replay).toEqual({
      verdict: "indeterminate",
      reconciliation_digest: expect.stringMatching(/^[0-9a-f]{64}$/),
    });
    expect(fixture.appendCalls()).toBe(1);
  });
});
