import { describe, expect, it } from "vitest";
import {
  createAuthorizationFreshnessAuthority,
  evaluateAuthorizationFreshness,
  type AuthorizationViewBinding,
  type AuthoritativeAuthorizationView,
} from "./authorization-freshness.js";
import type { LedgerMergeResult } from "./claim-ledger.js";
import {
  continuityManifestDigest,
  type ContinuityManifest,
} from "./token-status.js";

const manifest: ContinuityManifest = {
  profile: "heterodyne-oidc-continuity-v1",
  repository_rid: `rad:z${"1".repeat(48)}`,
  branch: "main",
  persona_npub: `npub1${"q".repeat(58)}`,
  persona_key: "11".repeat(32),
  issuer: "https://node.example/oidc/test",
  sequence: 0,
  predecessor_digest: null,
  max_checkpoint_age_seconds: 300,
  authorization_view_max_age: 300,
  current_jwks_sha256: "22".repeat(32),
  current_signing_key_id: "A".repeat(43),
  current_signing_jwk_sha256: "33".repeat(32),
  retiring_signing_key_ids: [],
  retiring_jwks_sha256: [],
  status_lists: [],
  successor: null,
  authority: {
    writer_nid: `did:key:z${"1".repeat(48)}`,
    issued_at: 1,
    checkpoint: {
      repository_rid: `rad:z${"1".repeat(48)}`,
      branch: "main",
      commit_oid: "44".repeat(32),
      observed_at: 1,
    },
  },
  authority_proof: { type: "nostr-bip340", signature: "55".repeat(64) },
};

const binding: AuthorizationViewBinding = {
  repository_rid: manifest.repository_rid,
  persona_key: manifest.persona_key,
  manifest_digest: continuityManifestDigest(manifest),
};

const inertLedgerState: LedgerMergeResult = {
  credential_ledger: {
    credential_ledger_persona: manifest.persona_key,
    credential_ledger_generation: 1,
  },
  records: [],
  conflicted_claim_ids: [],
  checkpoint: manifest.authority.checkpoint,
};

const source = {
  trusted_now: () => 1,
  load_current_view: (): AuthoritativeAuthorizationView => ({
    manifest,
    ledger_state: inertLedgerState,
  }),
};

describe("BLUE TEAM VALIDATION: synthetic/local — authorization freshness hostile-object boundary", () => {
  it("rejects binding and source accessors without invoking them", () => {
    let bindingReads = 0;
    const accessorBinding = {
      get repository_rid() {
        bindingReads += 1;
        return binding.repository_rid;
      },
      persona_key: binding.persona_key,
      manifest_digest: binding.manifest_digest,
    };
    expect(() => createAuthorizationFreshnessAuthority(accessorBinding, source)).toThrow(/data descriptor/i);
    expect(bindingReads).toBe(0);

    let sourceReads = 0;
    const accessorSource = {
      get trusted_now() {
        sourceReads += 1;
        return source.trusted_now;
      },
      load_current_view: source.load_current_view,
    };
    expect(() => createAuthorizationFreshnessAuthority(binding, accessorSource)).toThrow(/data descriptor/i);
    expect(sourceReads).toBe(0);
  });

  it.each([
    {
      name: "symbol member",
      value: Object.assign({ ...source }, { [Symbol("extra")]: true }),
    },
    {
      name: "non-enumerable member",
      value: Object.defineProperty({ ...source }, "extra", { value: true }),
    },
    {
      name: "custom prototype",
      value: Object.setPrototypeOf({ ...source }, { hostile: true }),
    },
    {
      name: "proxy",
      value: new Proxy({ ...source }, {}),
    },
  ])("BLUE TEAM VALIDATION: synthetic/local rejects a hostile source with a $name", ({ value }) => {
    expect(() => createAuthorizationFreshnessAuthority(binding, value)).toThrow(/exact ordinary data object/i);
  });

  it("rejects loader accessors before reading substitutable values", () => {
    let reads = 0;
    const loaded = {
      get manifest() {
        reads += 1;
        return manifest;
      },
      ledger_state: inertLedgerState,
    };
    const authority = createAuthorizationFreshnessAuthority(binding, {
      trusted_now: () => 1,
      load_current_view: () => loaded,
    });
    expect(evaluateAuthorizationFreshness(authority, manifest)).toEqual({
      verdict: "reject",
      reason: "control-authorization-view-stale",
    });
    expect(reads).toBe(0);
  });

  it("rejects a proxied loader result without triggering proxy traps", () => {
    let traps = 0;
    const loaded = new Proxy({ manifest, ledger_state: inertLedgerState }, {
      ownKeys(target) {
        traps += 1;
        return Reflect.ownKeys(target);
      },
      get(target, key, receiver) {
        traps += 1;
        return Reflect.get(target, key, receiver);
      },
    });
    const authority = createAuthorizationFreshnessAuthority(binding, {
      trusted_now: () => 1,
      load_current_view: () => loaded,
    });
    expect(evaluateAuthorizationFreshness(authority, manifest)).toEqual({
      verdict: "reject",
      reason: "control-authorization-view-stale",
    });
    expect(traps).toBe(0);
  });

  it("rejects loader substitution accessors without observing either value", () => {
    let manifestReads = 0;
    const substituted = { ...manifest, authorization_view_max_age: 301 };
    const loaded = Object.defineProperties({ manifest, ledger_state: inertLedgerState }, {
      manifest: {
        enumerable: true,
        get: () => {
          manifestReads += 1;
          return manifestReads === 1 ? manifest : substituted;
        },
      },
      ledger_state: { enumerable: true, value: inertLedgerState },
    });
    const authority = createAuthorizationFreshnessAuthority(binding, {
      trusted_now: () => 1,
      load_current_view: () => loaded,
    });
    expect(evaluateAuthorizationFreshness(authority, manifest)).toEqual({
      verdict: "reject",
      reason: "control-authorization-view-stale",
    });
    expect(manifestReads).toBe(0);
  });
});
