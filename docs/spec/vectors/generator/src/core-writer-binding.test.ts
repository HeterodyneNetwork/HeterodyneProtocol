import { ed25519 } from "@noble/curves/ed25519";
import { schnorr } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha2";
import { base58 } from "@scure/base";
import { describe, expect, it } from "vitest";
import {
  createCoreRepositoryWriterAuthority,
  inspectRepositoryWriterBinding,
  repositoryWriterBindingProofBytes,
  resolveCurrentRepositoryWriterBinding,
  revalidateCurrentRepositoryWriterBinding,
  type RepositoryWriterBindingV1,
  type RepositoryWriterRequest,
} from "./core-writer-binding.js";
import type { CurrentRepositoryPolicy } from "./core-policy.js";
import { bytesToHex, hexToBytes } from "./hex.js";
import { proofBytes } from "./proof-bytes.js";
import {
  didKeyFromEd25519,
  ed25519PublicKey,
  fixtureRid,
} from "./radicle.js";

// BLUE TEAM VALIDATION: synthetic/local deterministic, non-deployable fixtures only;
// no live targets, production deployments, real credentials/accounts, external systems,
// reusable payloads, scanning, persistence, evasion, destructive actions, or weakened controls.
const OWNER_SECRET = "11".repeat(32);
const OTHER_OWNER_SECRET = "33".repeat(32);
const NID_SECRET = "22".repeat(32);
const OTHER_NID_SECRET = "44".repeat(32);
const AUX_RAND = "00".repeat(32);
const NOW = 1_800_000_000;
const OWNER_KEY = bytesToHex(schnorr.getPublicKey(hexToBytes(OWNER_SECRET)));
const OTHER_OWNER_KEY = bytesToHex(
  schnorr.getPublicKey(hexToBytes(OTHER_OWNER_SECRET)),
);
const WRITER_NID = didKeyFromEd25519(ed25519PublicKey(NID_SECRET));
const OTHER_WRITER_NID = didKeyFromEd25519(
  ed25519PublicKey(OTHER_NID_SECRET),
);
const RID = fixtureRid("core-writer-binding");
const OTHER_RID = fixtureRid("core-writer-binding-other");
const SHORT_RID = `rad:z${base58.encode(new Uint8Array(19).fill(7))}`;
const LONG_RID = `rad:z${base58.encode(new Uint8Array(21).fill(7))}`;
const LEADING_ZERO_LONG_RID = `rad:z${base58.encode(Uint8Array.from([
  0,
  ...new Uint8Array(20).fill(7),
]))}`;
const REF_NAMESPACE = "refs/xyz.heterodyne.claim-ledger/writers/";
const WRITER_REF = `${REF_NAMESPACE}writer-one`;

const unsignedBody = (overrides: Partial<RepositoryWriterBindingV1> = {}) => ({
  profile: "heterodyne.core.repository-writer-binding.v1" as const,
  spec_version: "heterodyne/0.6.0" as const,
  owner_active_key: OWNER_KEY,
  repository_rid: RID,
  writer_nid: WRITER_NID,
  ref_namespace: REF_NAMESPACE,
  operations: ["claim-ledger-write"],
  issued_at: NOW - 10,
  expires_at: NOW + 100,
  ...overrides,
});

function signedBinding(
  overrides: Partial<RepositoryWriterBindingV1> = {},
  ownerSecret = OWNER_SECRET,
  nidSecret = NID_SECRET,
): RepositoryWriterBindingV1 {
  const body = unsignedBody(overrides);
  const payload = proofBytes(
    "heterodyne-core-repository-writer-binding-v1",
    body,
  );
  return {
    ...body,
    owner_signature: bytesToHex(schnorr.sign(
      sha256(payload),
      hexToBytes(ownerSecret),
      hexToBytes(AUX_RAND),
    )),
    nid_signature: bytesToHex(ed25519.sign(
      payload,
      hexToBytes(nidSecret),
    )),
  };
}

function activePolicy(
  overrides: Partial<CurrentRepositoryPolicy> = {},
): CurrentRepositoryPolicy {
  return {
    repository_rid: RID,
    owner_active_key: OWNER_KEY,
    revision: 7,
    checkpoint: "aa".repeat(20),
    predecessor: "99".repeat(20),
    state: "active",
    writers: [{
      writer_nid: WRITER_NID,
      ref_namespace: REF_NAMESPACE,
      operations: ["claim-ledger-write"],
      state: "active",
    }],
    ...overrides,
  };
}

const request = () => ({
  owner_active_key: OWNER_KEY,
  repository_rid: RID,
  writer_nid: WRITER_NID,
  writer_ref: WRITER_REF,
  operation: "claim-ledger-write" as const,
});

function authorityFor(
  load: () => CurrentRepositoryPolicy,
  authorityId = "synthetic-local-core-writer-authority",
  trustedNow: () => number = () => NOW,
) {
  return createCoreRepositoryWriterAuthority({
    authority_id: authorityId,
    trusted_now: trustedNow,
    load_current_policy: () => load(),
  });
}

describe("current Core repository-writer binding", () => {
  it("verifies both signatures over the identical exact proof bytes and mints an opaque binding", () => {
    const source = signedBinding();
    const expected = proofBytes(
      "heterodyne-core-repository-writer-binding-v1",
      unsignedBody(),
    );
    expect(bytesToHex(repositoryWriterBindingProofBytes(source)))
      .toBe(bytesToHex(expected));

    const authority = authorityFor(() => activePolicy());
    const binding = resolveCurrentRepositoryWriterBinding(
      authority,
      source,
      request(),
    );
    expect(binding).toEqual({});
    expect(Object.isFrozen(binding)).toBe(true);
    expect(revalidateCurrentRepositoryWriterBinding(authority, binding))
      .toBe(binding);
    expect(inspectRepositoryWriterBinding(authority, binding)).toMatchObject({
      profile: "heterodyne.core.repository-writer-binding.v1",
      owner_active_key: OWNER_KEY,
      repository_rid: RID,
      writer_nid: WRITER_NID,
      ref_namespace: REF_NAMESPACE,
      operations: ["claim-ledger-write"],
      writer_ref: WRITER_REF,
      operation: "claim-ledger-write",
      policy_revision: 7,
      policy_checkpoint: "aa".repeat(20),
      policy_predecessor: "99".repeat(20),
    });
  });

  it("accepts exact 20-byte canonical RIDs and vanilla Git-compatible ref descendants", () => {
    expect(base58.decode(RID.slice("rad:z".length))).toHaveLength(20);
    const namespace = "refs/heads/équipe/";
    const source = signedBinding({ ref_namespace: namespace });
    const authority = authorityFor(() => activePolicy({
      writers: [{
        writer_nid: WRITER_NID,
        ref_namespace: namespace,
        operations: ["claim-ledger-write"],
        state: "active",
      }],
    }));
    expect(() => resolveCurrentRepositoryWriterBinding(
      authority,
      source,
      { ...request(), writer_ref: `${namespace}writer-one` },
    )).not.toThrow();
  });
});

describe("BLUE TEAM VALIDATION: synthetic/local repository-writer boundary", () => {
  it.each([
    ["19-byte RID", SHORT_RID],
    ["21-byte RID", LONG_RID],
    ["leading-zero 21-byte RID", LEADING_ZERO_LONG_RID],
  ] as const)(
    "BLUE TEAM VALIDATION: synthetic/local rejects %s with valid matching proofs and policy",
    (_name, repositoryRid) => {
      const source = signedBinding({ repository_rid: repositoryRid });
      const policy = activePolicy({ repository_rid: repositoryRid });
      expect(() => resolveCurrentRepositoryWriterBinding(
        authorityFor(() => policy),
        source,
        { ...request(), repository_rid: repositoryRid },
      )).toThrow(/^repository-writer-binding-invalid:/);
    },
  );

  it.each([
    ["leading-dot component", "refs/.bad/"],
    ["leading-dot ancestor component", "refs/.bad/descendants/"],
    ["lock-suffix component", "refs/good.lock/"],
    ["lock-suffix ancestor component", "refs/good.lock/descendants/"],
    ["empty component", "refs/heads//writers/"],
    ["dot component", "refs/heads/./writers/"],
    ["dotdot component", "refs/heads/../writers/"],
    ["trailing-dot component", "refs/heads/writers./"],
    ["at-brace sequence", "refs/heads/@{/"],
    ["backslash", "refs/heads/back\\slash/"],
    ["space", "refs/heads/space name/"],
    ["tilde", "refs/heads/tilde~/"],
    ["caret", "refs/heads/caret^/"],
    ["colon", "refs/heads/colon:/"],
    ["question mark", "refs/heads/question?/"],
    ["asterisk", "refs/heads/star*/"],
    ["open bracket", "refs/heads/bracket[/"],
    ["control character", "refs/heads/control\u001f/"],
    ["missing namespace terminator", "refs/heads/writers"],
  ] as const)(
    "BLUE TEAM VALIDATION: synthetic/local rejects Git-invalid namespace %s",
    (_name, namespace) => {
      const source = signedBinding({ ref_namespace: namespace });
      const policy = activePolicy({
        writers: [{
          writer_nid: WRITER_NID,
          ref_namespace: namespace,
          operations: ["claim-ledger-write"],
          state: "active",
        }],
      });
      expect(() => resolveCurrentRepositoryWriterBinding(
        authorityFor(() => policy),
        source,
        { ...request(), writer_ref: `${namespace}/writer-one` },
      )).toThrow(/^repository-writer-binding-invalid:/);
    },
  );

  it("BLUE TEAM VALIDATION: synthetic/local rejects a non-UTF-8 lone-surrogate namespace", () => {
    const source = {
      ...signedBinding(),
      ref_namespace: "refs/heads/\ud800/",
    };
    expect(() => resolveCurrentRepositoryWriterBinding(
      authorityFor(() => activePolicy()),
      source,
      request(),
    )).toThrow(/^repository-writer-binding-invalid:/);
  });

  it.each([
    ["namespace itself", REF_NAMESPACE],
    ["trailing slash", `${WRITER_REF}/`],
    ["leading-dot descendant", `${REF_NAMESPACE}.bad`],
    ["lock-suffix descendant", `${REF_NAMESPACE}writer.lock`],
    ["lock-suffix ancestor descendant", `${REF_NAMESPACE}writer.lock/child`],
    ["trailing-dot descendant", `${REF_NAMESPACE}writer.`],
    ["dotdot descendant", `${REF_NAMESPACE}../writer`],
    ["duplicate-slash descendant", `${REF_NAMESPACE}/writer`],
  ] as const)(
    "BLUE TEAM VALIDATION: synthetic/local rejects Git-invalid writer ref %s",
    (_name, writerRef) => {
      expect(() => resolveCurrentRepositoryWriterBinding(
        authorityFor(() => activePolicy()),
        signedBinding(),
        { ...request(), writer_ref: writerRef },
      )).toThrow(/^repository-writer-binding-invalid:/);
    },
  );

  it.each([
    ["missing owner proof", (value: RepositoryWriterBindingV1) => {
      const { owner_signature: _signature, ...missing } = value;
      return missing;
    }],
    ["missing NID proof", (value: RepositoryWriterBindingV1) => {
      const { nid_signature: _signature, ...missing } = value;
      return missing;
    }],
    ["wrong owner proof", (value: RepositoryWriterBindingV1) => ({
      ...value,
      owner_signature: signedBinding({}, OTHER_OWNER_SECRET).owner_signature,
    })],
    ["wrong NID proof", (value: RepositoryWriterBindingV1) => ({
      ...value,
      nid_signature: signedBinding({}, OWNER_SECRET, OTHER_NID_SECRET)
        .nid_signature,
    })],
    ["NID key derivation substitution", () => signedBinding({
      writer_nid: OTHER_WRITER_NID,
    })],
  ] as const)(
    "BLUE TEAM VALIDATION: synthetic/local rejects %s",
    (_name, mutate) => {
      expect(() => resolveCurrentRepositoryWriterBinding(
        authorityFor(() => activePolicy()),
        mutate(signedBinding()),
        request(),
      )).toThrow(/^repository-writer-binding-invalid:/);
    },
  );

  it.each([
    ["non-safe issued time", { issued_at: Number.MAX_SAFE_INTEGER + 1 }],
    ["equal expiry", { issued_at: NOW, expires_at: NOW }],
    ["descending operations", {
      operations: ["status-list-write", "claim-ledger-write"],
    }],
    ["duplicate operations", {
      operations: ["claim-ledger-write", "claim-ledger-write"],
    }],
  ] as const)(
    "BLUE TEAM VALIDATION: synthetic/local rejects %s",
    (_name, overrides) => {
      expect(() => resolveCurrentRepositoryWriterBinding(
        authorityFor(() => activePolicy()),
        signedBinding(overrides),
        request(),
      )).toThrow(/^repository-writer-binding-invalid:/);
    },
  );

  it.each([
    ["before issuance", NOW - 11],
    ["at expiry", NOW + 100],
    ["non-safe trusted time", Number.MAX_SAFE_INTEGER + 1],
  ] as const)(
    "BLUE TEAM VALIDATION: synthetic/local rejects trusted time %s",
    (_name, trustedNow) => {
      expect(() => resolveCurrentRepositoryWriterBinding(
        authorityFor(() => activePolicy(), "synthetic-time", () => trustedNow),
        signedBinding(),
        request(),
      )).toThrow(/^repository-writer-binding-invalid:/);
    },
  );

  it.each([
    ["wrong request owner", { owner_active_key: OTHER_OWNER_KEY }],
    ["cross-persona repository", { repository_rid: OTHER_RID }],
    ["wrong writer", { writer_nid: OTHER_WRITER_NID }],
    ["wrong ref namespace", { writer_ref: "refs/heads/main" }],
    ["wrong operation", { operation: "status-list-write" }],
  ] as const)(
    "BLUE TEAM VALIDATION: synthetic/local rejects %s",
    (_name, overrides) => {
      expect(() => resolveCurrentRepositoryWriterBinding(
        authorityFor(() => activePolicy()),
        signedBinding(),
        { ...request(), ...overrides } as unknown as RepositoryWriterRequest,
      )).toThrow(/^repository-writer-binding-invalid:/);
    },
  );

  it.each([
    ["cross-persona owner policy", { owner_active_key: OTHER_OWNER_KEY }],
    ["wrong repository policy", { repository_rid: OTHER_RID }],
    ["revoked policy", { state: "revoked" }],
    ["conflicted policy", { state: "conflicted" }],
    ["revoked writer", { writers: [{
      writer_nid: WRITER_NID,
      ref_namespace: REF_NAMESPACE,
      operations: ["claim-ledger-write"],
      state: "revoked",
    }] }],
    ["conflicted writer", { writers: [{
      writer_nid: WRITER_NID,
      ref_namespace: REF_NAMESPACE,
      operations: ["claim-ledger-write"],
      state: "conflicted",
    }] }],
    ["missing current writer", { writers: [] }],
  ] as const)(
    "BLUE TEAM VALIDATION: synthetic/local rejects %s",
    (_name, overrides) => {
      expect(() => resolveCurrentRepositoryWriterBinding(
        authorityFor(() => activePolicy(overrides as Partial<CurrentRepositoryPolicy>)),
        signedBinding(),
        request(),
      )).toThrow(/^repository-writer-binding-invalid:/);
    },
  );

  it("BLUE TEAM VALIDATION: synthetic/local rejects caller policy assertions", () => {
    expect(() => resolveCurrentRepositoryWriterBinding(
      authorityFor(() => activePolicy()),
      signedBinding(),
      { ...request(), revision: 7 } as unknown as RepositoryWriterRequest,
    )).toThrow(/^repository-writer-binding-invalid:/);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects accessor and proxy inputs without invoking them", () => {
    let reads = 0;
    const source = signedBinding() as RepositoryWriterBindingV1 & {
      injected?: boolean;
    };
    Object.defineProperty(source, "owner_active_key", {
      enumerable: true,
      get() {
        reads += 1;
        return OWNER_KEY;
      },
    });
    expect(() => resolveCurrentRepositoryWriterBinding(
      authorityFor(() => activePolicy()),
      source,
      request(),
    )).toThrow(/^repository-writer-binding-invalid:/);
    expect(reads).toBe(0);

    const proxied = new Proxy(signedBinding(), {
      get() {
        reads += 1;
        return undefined;
      },
    });
    expect(() => resolveCurrentRepositoryWriterBinding(
      authorityFor(() => activePolicy()),
      proxied,
      request(),
    )).toThrow(/^repository-writer-binding-invalid:/);
    expect(reads).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local snapshots loader results and detects revision/checkpoint substitution", () => {
    const mutable = activePolicy() as {
      revision: number;
      checkpoint: string;
    } & CurrentRepositoryPolicy;
    const authority = authorityFor(() => mutable);
    const source = signedBinding();
    const binding = resolveCurrentRepositoryWriterBinding(
      authority,
      source,
      request(),
    );

    mutable.revision += 1;
    expect(() => revalidateCurrentRepositoryWriterBinding(authority, binding))
      .toThrow(/^repository-writer-binding-invalid:/);

    const mutableCheckpoint = activePolicy() as {
      checkpoint: string;
    } & CurrentRepositoryPolicy;
    const secondAuthority = authorityFor(
      () => mutableCheckpoint,
      "synthetic-checkpoint-authority",
    );
    const second = resolveCurrentRepositoryWriterBinding(
      secondAuthority,
      signedBinding(),
      request(),
    );
    mutableCheckpoint.checkpoint = "bb".repeat(20);
    expect(() => revalidateCurrentRepositoryWriterBinding(secondAuthority, second))
      .toThrow(/^repository-writer-binding-invalid:/);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects source mutation, clones, and foreign authorities", () => {
    const source = signedBinding() as { expires_at: number } & RepositoryWriterBindingV1;
    const firstAuthority = authorityFor(() => activePolicy(), "synthetic-first");
    const secondAuthority = authorityFor(() => activePolicy(), "synthetic-second");
    const binding = resolveCurrentRepositoryWriterBinding(
      firstAuthority,
      source,
      request(),
    );

    expect(() => revalidateCurrentRepositoryWriterBinding(
      firstAuthority,
      { ...binding },
    )).toThrow(/^repository-writer-binding-invalid:/);
    expect(() => revalidateCurrentRepositoryWriterBinding(
      secondAuthority,
      binding,
    )).toThrow(/^repository-writer-binding-invalid:/);
    source.expires_at += 1;
    expect(() => revalidateCurrentRepositoryWriterBinding(firstAuthority, binding))
      .toThrow(/^repository-writer-binding-invalid:/);
  });

  it("BLUE TEAM VALIDATION: synthetic/local captures authority callback descriptors exactly once", () => {
    let reads = 0;
    const config = {
      authority_id: "synthetic-accessor-authority",
      trusted_now: () => NOW,
      load_current_policy: () => activePolicy(),
    };
    Object.defineProperty(config, "trusted_now", {
      enumerable: true,
      get() {
        reads += 1;
        return () => NOW;
      },
    });
    expect(() => createCoreRepositoryWriterAuthority(config))
      .toThrow(/^repository-writer-binding-invalid:/);
    expect(reads).toBe(0);
  });

  it.each([
    ["revoked policy", activePolicy({ state: "revoked" })],
    ["conflicted policy", activePolicy({ state: "conflicted" })],
    ["removed writer", activePolicy({ writers: [] })],
    ["replaced writer", activePolicy({ writers: [{
      writer_nid: OTHER_WRITER_NID,
      ref_namespace: REF_NAMESPACE,
      operations: ["claim-ledger-write"],
      state: "active",
    }] })],
    ["changed predecessor", activePolicy({ predecessor: "88".repeat(20) })],
    ["changed ref inclusion", activePolicy({ writers: [{
      writer_nid: WRITER_NID,
      ref_namespace: "refs/xyz.heterodyne.claim-ledger/replaced/",
      operations: ["claim-ledger-write"],
      state: "active",
    }] })],
    ["changed operation inclusion", activePolicy({ writers: [{
      writer_nid: WRITER_NID,
      ref_namespace: REF_NAMESPACE,
      operations: ["status-list-write"],
      state: "active",
    }] })],
  ] as const)(
    "BLUE TEAM VALIDATION: synthetic/local effect-time revalidation rejects %s",
    (_name, replacement) => {
      let current = activePolicy();
      const authority = authorityFor(() => current);
      const binding = resolveCurrentRepositoryWriterBinding(
        authority,
        signedBinding(),
        request(),
      );
      current = replacement;
      expect(() => revalidateCurrentRepositoryWriterBinding(authority, binding))
        .toThrow(/^repository-writer-binding-invalid:/);
    },
  );

  it("BLUE TEAM VALIDATION: synthetic/local effect-time revalidation rejects expired and throwing clocks", () => {
    let now = NOW;
    let clockThrows = false;
    const authority = authorityFor(
      () => activePolicy(),
      "synthetic-effect-clock",
      () => {
        if (clockThrows) throw new Error("synthetic local clock failure");
        return now;
      },
    );
    const binding = resolveCurrentRepositoryWriterBinding(
      authority,
      signedBinding(),
      request(),
    );
    now = NOW + 100;
    expect(() => revalidateCurrentRepositoryWriterBinding(authority, binding))
      .toThrow(/^repository-writer-binding-invalid:/);
    now = NOW;
    clockThrows = true;
    expect(() => revalidateCurrentRepositoryWriterBinding(authority, binding))
      .toThrow(/^repository-writer-binding-invalid:/);
  });

  it("BLUE TEAM VALIDATION: synthetic/local effect-time revalidation rejects throwing and proxy loader results", () => {
    let mode: "valid" | "throw" | "proxy" = "valid";
    let proxyReads = 0;
    const authority = authorityFor(() => {
      if (mode === "throw") throw new Error("synthetic local loader failure");
      if (mode === "proxy") {
        return new Proxy(activePolicy(), {
          get() {
            proxyReads += 1;
            return undefined;
          },
        });
      }
      return activePolicy();
    });
    const binding = resolveCurrentRepositoryWriterBinding(
      authority,
      signedBinding(),
      request(),
    );
    mode = "throw";
    expect(() => revalidateCurrentRepositoryWriterBinding(authority, binding))
      .toThrow(/^repository-writer-binding-invalid:/);
    mode = "proxy";
    expect(() => revalidateCurrentRepositoryWriterBinding(authority, binding))
      .toThrow(/^repository-writer-binding-invalid:/);
    expect(proxyReads).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local effect-time revalidation rejects accessor loader results without reads", () => {
    let accessorResult = false;
    let reads = 0;
    const authority = authorityFor(() => {
      const policy = activePolicy() as CurrentRepositoryPolicy & {
        repository_rid: string;
      };
      if (accessorResult) {
        Object.defineProperty(policy, "repository_rid", {
          enumerable: true,
          get() {
            reads += 1;
            return RID;
          },
        });
      }
      return policy;
    });
    const binding = resolveCurrentRepositoryWriterBinding(
      authority,
      signedBinding(),
      request(),
    );
    accessorResult = true;
    expect(() => revalidateCurrentRepositoryWriterBinding(authority, binding))
      .toThrow(/^repository-writer-binding-invalid:/);
    expect(reads).toBe(0);
  });
});
