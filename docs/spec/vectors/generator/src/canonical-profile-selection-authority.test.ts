import { describe, expect, it } from "vitest";
import type { CanonicalProfileSelectionAuthority } from "./canonical-profile-selection-authority.js";
import type { CurrentRepositoryWriterBinding } from "./core-writer-binding.js";
import { signEvent, type NostrSignedEvent } from "./nostr.js";
import {
  createReplaceableSelectionAuthority,
  type ReplaceableSelectionAuthority,
} from "./replaceable-selection.js";
import { fixtureRid } from "./radicle.js";
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
  authenticate_repository_candidate: (
    event: NostrSignedEvent,
    rid: string,
    ref: string,
  ) => Promise<CurrentRepositoryWriterBinding | null>;
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
const NOW = 1_800_000_000;
const PROFILE_RID = fixtureRid("task-13-canonical-profile");
const OTHER_RID = fixtureRid("task-13-other-profile");
const REF = "refs/heads/persona-profile";
const WRITER_BINDING = Object.freeze({}) as CurrentRepositoryWriterBinding;
const MISSING_AUTHORITY = Object.freeze({}) as CanonicalProfileSelectionAuthority;

async function loadCanonical(): Promise<CanonicalModule> {
  return await import("./canonical-profile-selection-authority.js").catch(() => ({}));
}

async function profileEvent(input: Readonly<{
  created_at?: number;
  repository_rid?: string | null;
  content?: string;
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
    secretKey: SECRET,
    created_at: input.created_at ?? NOW,
    kind: 0,
    tags: [],
    content,
    auxRand: AUX_RAND,
  });
}

function config(
  authenticateRepositoryCandidate: CanonicalProfileSelectionAuthorityConfig[
    "authenticate_repository_candidate"
  ] = async () => WRITER_BINDING,
): CanonicalProfileSelectionAuthorityConfig {
  return {
    authority_id: "synthetic-local-canonical-profile",
    trusted_now: () => NOW,
    replaceable_selection: createReplaceableSelectionAuthority({ trusted_now: () => NOW }),
    authenticate_repository_candidate: authenticateRepositoryCandidate,
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
    const authority = canonical.createCanonicalProfileSelectionAuthority?.(config(
      async (event, rid, ref) =>
        event.id === selected.id && rid === PROFILE_RID && ref === REF
          ? WRITER_BINDING
          : null,
    )) ?? MISSING_AUTHORITY;

    expect((await canonical.selectCanonicalProfile?.(authority, {
      relay_candidates: [selected],
      repository_candidates: [{ event: selected, repository_rid: PROFILE_RID, ref: REF }],
    }))?.verdict).toBe("accept");
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects a selected profile carried only by an unauthorized repository writer", async () => {
    const canonical = await loadCanonical();
    const selected = await profileEvent();
    const authority = canonical.createCanonicalProfileSelectionAuthority?.(
      config(async () => null),
    ) ?? MISSING_AUTHORITY;

    expect(await canonical.selectCanonicalProfile?.(authority, {
      relay_candidates: [],
      repository_candidates: [{ event: selected, repository_rid: PROFILE_RID, ref: REF }],
    })).toEqual({
      verdict: "reject",
      reason_code: "profile-repository-selection-required",
    });
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects malformed repository authenticator output", async () => {
    const canonical = await loadCanonical();
    const selected = await profileEvent();
    const authority = canonical.createCanonicalProfileSelectionAuthority?.(
      config(async () => undefined as unknown as CurrentRepositoryWriterBinding),
    ) ?? MISSING_AUTHORITY;

    expect(await canonical.selectCanonicalProfile?.(authority, {
      relay_candidates: [selected],
      repository_candidates: [{ event: selected, repository_rid: PROFILE_RID, ref: REF }],
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
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const authority = canonical.createCanonicalProfileSelectionAuthority?.(config(
      async () => {
        await gate;
        return WRITER_BINDING;
      },
    )) ?? MISSING_AUTHORITY;
    const pending = canonical.selectCanonicalProfile?.(authority, {
      relay_candidates: [source],
      repository_candidates: [{ event: source, repository_rid: PROFILE_RID, ref: REF }],
    });
    source.content = "mutated after capture";
    source.tags.push(["mutated"]);
    release();

    expect((await pending)?.verdict).toBe("accept");
  });

  it("BLUE TEAM VALIDATION: synthetic/local captures the repository authenticator against callback substitution", async () => {
    const canonical = await loadCanonical();
    const selected = await profileEvent();
    const mutableConfig = config(async () => WRITER_BINDING) as {
      authority_id: string;
      trusted_now: () => number;
      replaceable_selection: ReplaceableSelectionAuthority;
      authenticate_repository_candidate:
        CanonicalProfileSelectionAuthorityConfig["authenticate_repository_candidate"];
    };
    const authority = canonical.createCanonicalProfileSelectionAuthority?.(mutableConfig)
      ?? MISSING_AUTHORITY;
    mutableConfig.authenticate_repository_candidate = async () => null;

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
