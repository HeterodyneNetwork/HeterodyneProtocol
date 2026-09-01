import { ed25519 } from "@noble/curves/ed25519";
import { schnorr } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha2";
import { describe, expect, it } from "vitest";
import type { CanonicalProfileSelectionAuthority } from "./canonical-profile-selection-authority.js";
import {
  createCoreRepositoryWriterAuthority,
  resolveCurrentRepositoryWriterBinding,
  type CoreRepositoryWriterAuthority,
  type CurrentRepositoryWriterBinding,
  type RepositoryWriterBindingV1,
} from "./core-writer-binding.js";
import type { CurrentRepositoryPolicy } from "./core-policy.js";
import { bytesToHex, hexToBytes, utf8Bytes } from "./hex.js";
import { jcsCanonicalize } from "./jcs.js";
import { getPublicKey, signEvent, type NostrSignedEvent } from "./nostr.js";
import { proofBytes } from "./proof-bytes.js";
import {
  createReplaceableSelectionAuthority,
  type ReplaceableSelectionAuthority,
} from "./replaceable-selection.js";
import {
  didKeyFromEd25519,
  ed25519PublicKey,
  fixtureRid,
} from "./radicle.js";
import { AUX_RAND } from "./vector-helpers.js";

type CanonicalProfileView = Readonly<Record<never, never>>;
type AuthorityDecision<Reason extends string, View> = Readonly<
  | { verdict: "accept"; view: View }
  | { verdict: "reject"; reason_code: Reason }
>;
type CanonicalProfileSelectionAuthorityConfig = Readonly<{
  authority_id: string;
  trusted_now: () => number;
  replaceable_selection: ReplaceableSelectionAuthority;
  repository_writer_authority: CoreRepositoryWriterAuthority;
  authenticate_repository_candidate: (
    event: NostrSignedEvent,
    rid: string,
    ref: string,
  ) => Promise<CurrentRepositoryWriterBinding | null>;
  inspect_repository_candidate: (
    binding: CurrentRepositoryWriterBinding,
    event: NostrSignedEvent,
    rid: string,
    ref: string,
  ) => RepositoryCandidateBindingInspection | null;
}>;
type RepositoryBindingTuple = Readonly<{
  profile: "heterodyne.core.repository-writer-binding.v1";
  spec_version: "heterodyne/0.6.0";
  owner_active_key: string;
  repository_rid: string;
  writer_nid: string;
  ref_namespace: string;
  operations: readonly string[];
  issued_at: number;
  expires_at: number;
  owner_signature: string;
  nid_signature: string;
  writer_ref: string;
  operation: "claim-ledger-write";
  source_identity: string;
  proof_identity: string;
  policy_revision: number;
  policy_checkpoint: string;
  policy_predecessor: string | null;
}>;
type RepositoryCandidateBindingInspection = Readonly<{
  candidate_event_id: string;
  expected: RepositoryBindingTuple;
  binding: RepositoryBindingTuple;
}>;
type CanonicalProfileSelectionInput = Readonly<{
  relay_candidates: readonly NostrSignedEvent[];
  repository_candidates: readonly Readonly<{
    event: NostrSignedEvent;
    repository_rid: string;
    ref: string;
  }>[];
}>;
type CanonicalModule = {
  createCanonicalProfileSelectionAuthority?: (
    config: CanonicalProfileSelectionAuthorityConfig,
  ) => CanonicalProfileSelectionAuthority;
  selectCanonicalProfile?: (
    authority: CanonicalProfileSelectionAuthority,
    input: CanonicalProfileSelectionInput,
  ) => Promise<AuthorityDecision<"profile-repository-selection-required", CanonicalProfileView>>;
};

const SECRET = "41".repeat(32);
const OTHER_SECRET = "42".repeat(32);
const WRITER_NID_SECRET = "43".repeat(32);
const NOW = 1_800_000_000;
const PROFILE_RID = fixtureRid("task-13-canonical-profile");
const OTHER_RID = fixtureRid("task-13-other-profile");
const REF = "refs/heads/persona-profile";
const REF_NAMESPACE = "refs/heads/";
const WRITER_NID = didKeyFromEd25519(ed25519PublicKey(WRITER_NID_SECRET));
const MISSING_AUTHORITY = Object.freeze({}) as CanonicalProfileSelectionAuthority;

async function loadCanonical(): Promise<CanonicalModule> {
  return await import("./canonical-profile-selection-authority.js").catch(() => ({}));
}

async function profileEvent(input: Readonly<{
  created_at?: number;
  repository_rid?: string | null;
  content?: string;
  secret_key?: string;
}> = {}): Promise<NostrSignedEvent> {
  const content = input.content ?? JSON.stringify({
    name: "synthetic local persona",
    ...(input.repository_rid === undefined
      ? { heterodyne: { profile: PROFILE_RID } }
      : input.repository_rid === null
        ? {}
        : { heterodyne: { profile: input.repository_rid } }),
  });
  return await signEvent({
    secretKey: input.secret_key ?? SECRET,
    created_at: input.created_at ?? NOW,
    kind: 0,
    tags: [],
    content,
    auxRand: AUX_RAND,
  });
}

type WriterEvidence = Readonly<{
  authority: CoreRepositoryWriterAuthority;
  binding: CurrentRepositoryWriterBinding;
  source: RepositoryWriterBindingV1;
  request: Readonly<{
    owner_active_key: string;
    repository_rid: string;
    writer_nid: string;
    writer_ref: string;
    operation: "claim-ledger-write";
  }>;
  tuple: RepositoryBindingTuple;
  authenticate: CanonicalProfileSelectionAuthorityConfig[
    "authenticate_repository_candidate"
  ];
  inspect: CanonicalProfileSelectionAuthorityConfig[
    "inspect_repository_candidate"
  ];
  replace_policy: (policy: CurrentRepositoryPolicy) => void;
  active_policy: () => CurrentRepositoryPolicy;
}>;

function writerEvidence(input: Readonly<{
  owner_secret?: string;
  repository_rid?: string;
}> = {}): WriterEvidence {
  const ownerSecret = input.owner_secret ?? SECRET;
  const ownerKey = getPublicKey(ownerSecret);
  const repositoryRid = input.repository_rid ?? PROFILE_RID;
  const unsigned = {
    profile: "heterodyne.core.repository-writer-binding.v1" as const,
    spec_version: "heterodyne/0.6.0" as const,
    owner_active_key: ownerKey,
    repository_rid: repositoryRid,
    writer_nid: WRITER_NID,
    ref_namespace: REF_NAMESPACE,
    operations: ["claim-ledger-write"],
    issued_at: NOW - 10,
    expires_at: NOW + 100,
  };
  const payload = proofBytes(
    "heterodyne-core-repository-writer-binding-v1",
    unsigned,
  );
  const source: RepositoryWriterBindingV1 = {
    ...unsigned,
    owner_signature: bytesToHex(schnorr.sign(
      sha256(payload),
      hexToBytes(ownerSecret),
      hexToBytes(AUX_RAND),
    )),
    nid_signature: bytesToHex(ed25519.sign(
      payload,
      hexToBytes(WRITER_NID_SECRET),
    )),
  };
  const activePolicy = (): CurrentRepositoryPolicy => ({
    repository_rid: repositoryRid,
    owner_active_key: ownerKey,
    revision: 1,
    checkpoint: "a1".repeat(20),
    predecessor: null,
    state: "active",
    writers: [{
      writer_nid: WRITER_NID,
      ref_namespace: REF_NAMESPACE,
      operations: ["claim-ledger-write"],
      state: "active",
    }],
  });
  let policy = activePolicy();
  const writerAuthority = createCoreRepositoryWriterAuthority({
    authority_id: `synthetic-local-profile-writer-${repositoryRid}`,
    trusted_now: () => NOW,
    load_current_policy: () => policy,
  });
  const request = {
    owner_active_key: ownerKey,
    repository_rid: repositoryRid,
    writer_nid: WRITER_NID,
    writer_ref: REF,
    operation: "claim-ledger-write" as const,
  };
  const binding = resolveCurrentRepositoryWriterBinding(
    writerAuthority,
    source,
    request,
  );
  const tuple = Object.freeze({
    ...source,
    writer_ref: request.writer_ref,
    operation: request.operation,
    source_identity: bytesToHex(sha256(utf8Bytes(jcsCanonicalize(source)))),
    proof_identity: bytesToHex(sha256(payload)),
    policy_revision: policy.revision,
    policy_checkpoint: policy.checkpoint,
    policy_predecessor: policy.predecessor,
  });
  return Object.freeze({
    authority: writerAuthority,
    binding,
    source,
    request: Object.freeze(request),
    tuple,
    authenticate: async (event, rid, ref) =>
      event.pubkey === ownerKey && rid === repositoryRid && ref === REF
        ? binding
        : null,
    inspect: (candidateBinding, event, rid, ref) =>
      candidateBinding === binding
        && event.id.length === 64
        && rid === repositoryRid
        && ref === REF
        ? Object.freeze({
            candidate_event_id: event.id,
            expected: tuple,
            binding: tuple,
          })
        : null,
    replace_policy: (replacement) => {
      policy = replacement;
    },
    active_policy: activePolicy,
  });
}

function config(input: Readonly<{
  writer?: WriterEvidence;
  trusted_now?: () => number;
  replaceable_selection?: ReplaceableSelectionAuthority;
  repository_writer_authority?: CoreRepositoryWriterAuthority;
  authenticate_repository_candidate?: CanonicalProfileSelectionAuthorityConfig[
    "authenticate_repository_candidate"
  ];
  inspect_repository_candidate?: CanonicalProfileSelectionAuthorityConfig[
    "inspect_repository_candidate"
  ];
}> = {}): CanonicalProfileSelectionAuthorityConfig {
  const writer = input.writer ?? writerEvidence();
  return {
    authority_id: "synthetic-local-canonical-profile",
    trusted_now: input.trusted_now ?? (() => NOW),
    replaceable_selection: input.replaceable_selection
      ?? createReplaceableSelectionAuthority({ trusted_now: () => NOW }),
    repository_writer_authority:
      input.repository_writer_authority ?? writer.authority,
    authenticate_repository_candidate:
      input.authenticate_repository_candidate ?? writer.authenticate,
    inspect_repository_candidate:
      input.inspect_repository_candidate ?? writer.inspect,
  };
}

describe("canonical Core profile selection authority", () => {
  it("selects signed kind-0 state source-neutrally and returns an opaque view", async () => {
    const canonical = await loadCanonical();
    const olderRepository = await profileEvent({
      created_at: NOW - 1,
      repository_rid: PROFILE_RID,
    });
    const newerRelay = await profileEvent({
      created_at: NOW,
      repository_rid: null,
    });
    const authority = canonical.createCanonicalProfileSelectionAuthority?.(config())
      ?? MISSING_AUTHORITY;

    const decision = await canonical.selectCanonicalProfile?.(authority, {
      relay_candidates: [newerRelay],
      repository_candidates: [{
        event: olderRepository,
        repository_rid: PROFILE_RID,
        ref: REF,
      }],
    });

    expect(decision?.verdict).toBe("accept");
    if (decision?.verdict === "accept") {
      expect(decision.view).toEqual({});
      expect(Object.isFrozen(decision.view)).toBe(true);
    }
  });

  it("BLUE TEAM VALIDATION: synthetic/local derives required repository state from signed profile content", async () => {
    const canonical = await loadCanonical();
    const selected = await profileEvent();
    const authority = canonical.createCanonicalProfileSelectionAuthority?.(config())
      ?? MISSING_AUTHORITY;

    expect(await canonical.selectCanonicalProfile?.(authority, {
      relay_candidates: [selected],
      repository_candidates: [],
    })).toEqual({
      verdict: "reject",
      reason_code: "profile-repository-selection-required",
    });
  });

  it("BLUE TEAM VALIDATION: synthetic/local ignores a closed extension with a non-canonical NIP-19 hint", async () => {
    const canonical = await loadCanonical();
    const selected = await profileEvent({
      content: JSON.stringify({
        name: "synthetic local invalid extension",
        heterodyne: {
          profile: PROFILE_RID,
          identity_chain: "naddr1invalid",
        },
      }),
    });
    const authority = canonical.createCanonicalProfileSelectionAuthority?.(config())
      ?? MISSING_AUTHORITY;

    expect((await canonical.selectCanonicalProfile?.(authority, {
      relay_candidates: [selected],
      repository_candidates: [],
    }))?.verdict).toBe("accept");
  });

  it("accepts repository-bound state only when the exact selected event and RID authenticate", async () => {
    const canonical = await loadCanonical();
    const selected = await profileEvent();
    const writer = writerEvidence();
    const authority = canonical.createCanonicalProfileSelectionAuthority?.(config({
      writer,
      authenticate_repository_candidate: async (event, rid, ref) =>
        event.id === selected.id && rid === PROFILE_RID && ref === REF
          ? writer.binding
          : null,
    })) ?? MISSING_AUTHORITY;

    expect((await canonical.selectCanonicalProfile?.(authority, {
      relay_candidates: [selected],
      repository_candidates: [{ event: selected, repository_rid: PROFILE_RID, ref: REF }],
    }))?.verdict).toBe("accept");
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects a selected profile carried only by an unauthorized repository writer", async () => {
    const canonical = await loadCanonical();
    const selected = await profileEvent();
    const authority = canonical.createCanonicalProfileSelectionAuthority?.(
      config({ authenticate_repository_candidate: async () => null }),
    ) ?? MISSING_AUTHORITY;

    expect(await canonical.selectCanonicalProfile?.(authority, {
      relay_candidates: [],
      repository_candidates: [{ event: selected, repository_rid: PROFILE_RID, ref: REF }],
    })).toEqual({
      verdict: "reject",
      reason_code: "profile-repository-selection-required",
    });
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects cloned repository-writer evidence", async () => {
    const canonical = await loadCanonical();
    const selected = await profileEvent();
    const lookalike = Object.freeze({}) as CurrentRepositoryWriterBinding;
    const authority = canonical.createCanonicalProfileSelectionAuthority?.(
      config({ authenticate_repository_candidate: async () => lookalike }),
    ) ?? MISSING_AUTHORITY;

    expect(await canonical.selectCanonicalProfile?.(authority, {
      relay_candidates: [selected],
      repository_candidates: [{ event: selected, repository_rid: PROFILE_RID, ref: REF }],
    })).toEqual({
      verdict: "reject",
      reason_code: "profile-repository-selection-required",
    });
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects cross-authority repository-writer evidence", async () => {
    const canonical = await loadCanonical();
    const selected = await profileEvent();
    const expectedWriter = writerEvidence();
    const foreignWriter = writerEvidence();
    const authority = canonical.createCanonicalProfileSelectionAuthority?.(config({
      writer: expectedWriter,
      authenticate_repository_candidate: async () => foreignWriter.binding,
    })) ?? MISSING_AUTHORITY;

    expect(await canonical.selectCanonicalProfile?.(authority, {
      relay_candidates: [selected],
      repository_candidates: [{ event: selected, repository_rid: PROFILE_RID, ref: REF }],
    })).toEqual({
      verdict: "reject",
      reason_code: "profile-repository-selection-required",
    });
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects a genuine current binding for a different repository ref", async () => {
    const canonical = await loadCanonical();
    const selected = await profileEvent();
    const writer = writerEvidence();
    const wrongRef = "refs/heads/different-profile-location";
    const wrongBinding = resolveCurrentRepositoryWriterBinding(
      writer.authority,
      writer.source,
      { ...writer.request, writer_ref: wrongRef },
    );
    const wrongTuple = Object.freeze({ ...writer.tuple, writer_ref: wrongRef });
    const authority = canonical.createCanonicalProfileSelectionAuthority?.(config({
      writer,
      authenticate_repository_candidate: async () => wrongBinding,
      inspect_repository_candidate: (binding, event) => binding === wrongBinding
        ? Object.freeze({
            candidate_event_id: event.id,
            expected: writer.tuple,
            binding: wrongTuple,
          })
        : null,
    })) ?? MISSING_AUTHORITY;

    expect(await canonical.selectCanonicalProfile?.(authority, {
      relay_candidates: [selected],
      repository_candidates: [{ event: selected, repository_rid: PROFILE_RID, ref: REF }],
    })).toEqual({
      verdict: "reject",
      reason_code: "profile-repository-selection-required",
    });
  });

  it.each([
    ["owner", (tuple: RepositoryBindingTuple) => ({
      ...tuple,
      owner_active_key: getPublicKey(OTHER_SECRET),
    })],
    ["RID", (tuple: RepositoryBindingTuple) => ({
      ...tuple,
      repository_rid: OTHER_RID,
    })],
    ["ref namespace", (tuple: RepositoryBindingTuple) => ({
      ...tuple,
      ref_namespace: "refs/tags/",
    })],
    ["writer", (tuple: RepositoryBindingTuple) => ({
      ...tuple,
      writer_nid: didKeyFromEd25519(ed25519PublicKey("44".repeat(32))),
    })],
    ["profile", (tuple: RepositoryBindingTuple) => ({
      ...tuple,
      profile: "heterodyne.core.repository-writer-binding.v2",
    })],
    ["operations", (tuple: RepositoryBindingTuple) => ({
      ...tuple,
      operations: ["profile-write"],
    })],
    ["source identity", (tuple: RepositoryBindingTuple) => ({
      ...tuple,
      source_identity: "77".repeat(32),
    })],
    ["proof identity", (tuple: RepositoryBindingTuple) => ({
      ...tuple,
      proof_identity: "77".repeat(32),
    })],
    ["current checkpoint", (tuple: RepositoryBindingTuple) => ({
      ...tuple,
      policy_checkpoint: "77".repeat(20),
    })],
  ] as const)(
    "BLUE TEAM VALIDATION: synthetic/local rejects inspected binding with cross-%s tuple",
    async (_name, mutate) => {
      const canonical = await loadCanonical();
      const selected = await profileEvent();
      const writer = writerEvidence();
      const authority = canonical.createCanonicalProfileSelectionAuthority?.(config({
        writer,
        inspect_repository_candidate: (binding, event) => binding === writer.binding
          ? Object.freeze({
              candidate_event_id: event.id,
              expected: writer.tuple,
              binding: mutate(writer.tuple) as RepositoryBindingTuple,
            })
          : null,
      })) ?? MISSING_AUTHORITY;

      expect(await canonical.selectCanonicalProfile?.(authority, {
        relay_candidates: [selected],
        repository_candidates: [{ event: selected, repository_rid: PROFILE_RID, ref: REF }],
      })).toEqual({
        verdict: "reject",
        reason_code: "profile-repository-selection-required",
      });
    },
  );

  it("BLUE TEAM VALIDATION: synthetic/local revalidates repository-writer evidence against current policy", async () => {
    const canonical = await loadCanonical();
    const selected = await profileEvent();
    const writer = writerEvidence();
    const authority = canonical.createCanonicalProfileSelectionAuthority?.(config({
      writer,
      authenticate_repository_candidate: async () => {
        writer.replace_policy({ ...writer.active_policy(), state: "revoked" });
        return writer.binding;
      },
    })) ?? MISSING_AUTHORITY;

    expect(await canonical.selectCanonicalProfile?.(authority, {
      relay_candidates: [selected],
      repository_candidates: [{ event: selected, repository_rid: PROFILE_RID, ref: REF }],
    })).toEqual({
      verdict: "reject",
      reason_code: "profile-repository-selection-required",
    });
  });

  it("BLUE TEAM VALIDATION: synthetic/local revalidates the complete callback-output batch immediately before selection", async () => {
    const canonical = await loadCanonical();
    const selected = await profileEvent({ created_at: NOW });
    const laterCallback = await profileEvent({ created_at: NOW - 1 });
    const writer = writerEvidence();
    let calls = 0;
    const authority = canonical.createCanonicalProfileSelectionAuthority?.(config({
      writer,
      authenticate_repository_candidate: async () => {
        calls += 1;
        if (calls === 2) {
          writer.replace_policy({ ...writer.active_policy(), revision: 2 });
          return null;
        }
        return writer.binding;
      },
    })) ?? MISSING_AUTHORITY;

    expect(await canonical.selectCanonicalProfile?.(authority, {
      relay_candidates: [],
      repository_candidates: [
        { event: selected, repository_rid: PROFILE_RID, ref: REF },
        { event: laterCallback, repository_rid: PROFILE_RID, ref: REF },
      ],
    })).toEqual({
      verdict: "reject",
      reason_code: "profile-repository-selection-required",
    });
  });

  it("BLUE TEAM VALIDATION: synthetic/local gives no repository carrier priority over a newer relay event", async () => {
    const canonical = await loadCanonical();
    const olderRepository = await profileEvent({ created_at: NOW - 1 });
    const newerRelay = await profileEvent({ created_at: NOW });
    const authority = canonical.createCanonicalProfileSelectionAuthority?.(config())
      ?? MISSING_AUTHORITY;

    expect(await canonical.selectCanonicalProfile?.(authority, {
      relay_candidates: [newerRelay],
      repository_candidates: [{
        event: olderRepository,
        repository_rid: PROFILE_RID,
        ref: REF,
      }],
    })).toEqual({
      verdict: "reject",
      reason_code: "profile-repository-selection-required",
    });
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects a repository RID substituted for the signed profile RID", async () => {
    const canonical = await loadCanonical();
    const selected = await profileEvent();
    const authority = canonical.createCanonicalProfileSelectionAuthority?.(config())
      ?? MISSING_AUTHORITY;

    expect(await canonical.selectCanonicalProfile?.(authority, {
      relay_candidates: [selected],
      repository_candidates: [{ event: selected, repository_rid: OTHER_RID, ref: REF }],
    })).toEqual({
      verdict: "reject",
      reason_code: "profile-repository-selection-required",
    });
  });

  it("BLUE TEAM VALIDATION: synthetic/local snapshots candidate bytes before awaiting repository authentication", async () => {
    const canonical = await loadCanonical();
    const source = await profileEvent();
    const writer = writerEvidence();
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const authority = canonical.createCanonicalProfileSelectionAuthority?.(config({
      writer,
      authenticate_repository_candidate: async () => {
        await gate;
        return writer.binding;
      },
    })) ?? MISSING_AUTHORITY;
    const pending = canonical.selectCanonicalProfile?.(authority, {
      relay_candidates: [source],
      repository_candidates: [{ event: source, repository_rid: PROFILE_RID, ref: REF }],
    });
    source.content = "mutated after capture";
    source.tags.push(["mutated"]);
    release();

    expect((await pending)?.verdict).toBe("accept");
  });

  it("BLUE TEAM VALIDATION: synthetic/local snapshots the complete candidate batch before the first await", async () => {
    const canonical = await loadCanonical();
    const first = await profileEvent({ created_at: NOW - 1 });
    const second = await profileEvent({
      created_at: NOW,
      repository_rid: OTHER_RID,
      secret_key: OTHER_SECRET,
    });
    const firstWriter = writerEvidence();
    const secondWriter = writerEvidence({
      owner_secret: OTHER_SECRET,
      repository_rid: OTHER_RID,
    });
    const authority = canonical.createCanonicalProfileSelectionAuthority?.(config({
      writer: firstWriter,
      authenticate_repository_candidate: async (event, rid) => {
        if (event.id === first.id && rid === PROFILE_RID) {
          second.content = "mutated during the first async callback";
          return firstWriter.binding;
        }
        return event.id === second.id && rid === OTHER_RID
          ? secondWriter.binding
          : null;
      },
    })) ?? MISSING_AUTHORITY;

    expect(await canonical.selectCanonicalProfile?.(authority, {
      relay_candidates: [],
      repository_candidates: [
        { event: first, repository_rid: PROFILE_RID, ref: REF },
        { event: second, repository_rid: OTHER_RID, ref: REF },
      ],
    })).toEqual({
      verdict: "reject",
      reason_code: "profile-repository-selection-required",
    });
  });

  it("BLUE TEAM VALIDATION: synthetic/local binds selection to one constructor-captured trusted-time snapshot", async () => {
    const canonical = await loadCanonical();
    const premature = await profileEvent({
      created_at: NOW + 901,
      repository_rid: null,
    });
    let clockReads = 0;
    const authority = canonical.createCanonicalProfileSelectionAuthority?.(config({
      trusted_now: () => {
        clockReads += 1;
        return clockReads === 1 ? NOW : NOW + 10_000;
      },
      replaceable_selection: createReplaceableSelectionAuthority({
        trusted_now: () => NOW + 10_000,
      }),
    })) ?? MISSING_AUTHORITY;

    expect(await canonical.selectCanonicalProfile?.(authority, {
      relay_candidates: [premature],
      repository_candidates: [],
    })).toEqual({
      verdict: "reject",
      reason_code: "profile-repository-selection-required",
    });
    expect(clockReads).toBe(1);
  });

  it("BLUE TEAM VALIDATION: synthetic/local captures the repository authenticator against callback substitution", async () => {
    const canonical = await loadCanonical();
    const selected = await profileEvent();
    const foreignWriter = writerEvidence();
    const mutableConfig = config() as {
      authority_id: string;
      trusted_now: () => number;
      replaceable_selection: ReplaceableSelectionAuthority;
      repository_writer_authority: CoreRepositoryWriterAuthority;
      authenticate_repository_candidate:
        CanonicalProfileSelectionAuthorityConfig["authenticate_repository_candidate"];
      inspect_repository_candidate:
        CanonicalProfileSelectionAuthorityConfig["inspect_repository_candidate"];
    };
    const authority = canonical.createCanonicalProfileSelectionAuthority?.(mutableConfig)
      ?? MISSING_AUTHORITY;
    mutableConfig.authenticate_repository_candidate = async () => null;
    mutableConfig.repository_writer_authority = foreignWriter.authority;
    mutableConfig.inspect_repository_candidate = () => null;

    expect((await canonical.selectCanonicalProfile?.(authority, {
      relay_candidates: [selected],
      repository_candidates: [{ event: selected, repository_rid: PROFILE_RID, ref: REF }],
    }))?.verdict).toBe("accept");
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects cloned and cross-authority handles", async () => {
    const canonical = await loadCanonical();
    const selected = await profileEvent({ repository_rid: null });
    const authority = canonical.createCanonicalProfileSelectionAuthority?.(config())
      ?? MISSING_AUTHORITY;
    const cloned = Object.freeze({ ...authority }) as CanonicalProfileSelectionAuthority;
    const crossAuthority = createReplaceableSelectionAuthority({ trusted_now: () => NOW }) as
      unknown as CanonicalProfileSelectionAuthority;

    for (const hostile of [cloned, crossAuthority]) {
      expect(await canonical.selectCanonicalProfile?.(hostile, {
        relay_candidates: [selected],
        repository_candidates: [],
      })).toEqual({
        verdict: "reject",
        reason_code: "profile-repository-selection-required",
      });
    }
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects proxy and accessor-bearing input without invoking accessors", async () => {
    const canonical = await loadCanonical();
    const authority = canonical.createCanonicalProfileSelectionAuthority?.(config())
      ?? MISSING_AUTHORITY;
    let reads = 0;
    const accessor = {} as CanonicalProfileSelectionInput;
    Object.defineProperty(accessor, "relay_candidates", {
      enumerable: true,
      get: () => {
        reads += 1;
        return [];
      },
    });
    Object.defineProperty(accessor, "repository_candidates", {
      enumerable: true,
      value: [],
    });
    const proxy = new Proxy({ relay_candidates: [], repository_candidates: [] }, {});

    for (const hostile of [accessor, proxy]) {
      expect(await canonical.selectCanonicalProfile?.(
        authority,
        hostile as CanonicalProfileSelectionInput,
      )).toEqual({
        verdict: "reject",
        reason_code: "profile-repository-selection-required",
      });
    }
    expect(reads).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects oversized candidate collections with bounded work", async () => {
    const canonical = await loadCanonical();
    const selected = await profileEvent({ repository_rid: null });
    const authority = canonical.createCanonicalProfileSelectionAuthority?.(config())
      ?? MISSING_AUTHORITY;

    expect(await canonical.selectCanonicalProfile?.(authority, {
      relay_candidates: Array.from({ length: 65 }, () => selected),
      repository_candidates: [],
    })).toEqual({
      verdict: "reject",
      reason_code: "profile-repository-selection-required",
    });
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects an aggregate oversized signed event before selection", async () => {
    const canonical = await loadCanonical();
    const oversized = await signEvent({
      secretKey: SECRET,
      created_at: NOW,
      kind: 0,
      tags: Array.from({ length: 130 }, () => ["x", "a".repeat(1_024)]),
      content: JSON.stringify({ name: "synthetic local bounded-work fixture" }),
      auxRand: AUX_RAND,
    });
    const authority = canonical.createCanonicalProfileSelectionAuthority?.(config())
      ?? MISSING_AUTHORITY;

    expect(await canonical.selectCanonicalProfile?.(authority, {
      relay_candidates: [oversized],
      repository_candidates: [],
    })).toEqual({
      verdict: "reject",
      reason_code: "profile-repository-selection-required",
    });
  });
});
