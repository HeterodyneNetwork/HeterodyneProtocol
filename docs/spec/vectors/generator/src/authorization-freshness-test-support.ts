import { createHash } from "node:crypto";
import { nip19 } from "nostr-tools";
import {
  createAuthorizationFreshnessAuthority,
  evaluateAuthorizationFreshness,
  type AuthorizationFreshnessAuthority,
  type AuthoritativeAuthorizationView,
  type CurrentAuthorizationView,
} from "./authorization-freshness.js";
import type { LedgerMergeResult } from "./claim-ledger.js";
import { buildClaimLedgerScenario } from "./claim-ledger-test-support.js";
import { buildFixtures } from "./fixtures.js";
import { utf8Bytes } from "./hex.js";
import { jcsCanonicalize } from "./jcs.js";
import { OIDC_RSA_ONE } from "./oidc-rsa-fixtures.js";
import {
  continuityManifestDigest,
  createContinuityAuthorityProof,
  type ContinuityManifest,
  type ContinuityManifestBody,
} from "./token-status.js";

export type AuthorizationFreshnessClock = { now: number };

export async function buildAuthorizationFreshnessTestSupport() {
  const fixtures = buildFixtures();
  const scenario = await buildClaimLedgerScenario(fixtures);
  const sha256 = (value: Uint8Array): string => createHash("sha256").update(value).digest("hex");

  function signedManifest(
    state: LedgerMergeResult = scenario.issuerKeyEpochOneState,
    options: {
      checkpoint_age?: number;
      authorization_view_max_age?: number;
    } = {},
  ): ContinuityManifest {
    const personaKey = scenario.persona;
    const personaNpub = nip19.npubEncode(personaKey);
    const body: ContinuityManifestBody = {
      profile: "heterodyne-oidc-continuity-v1",
      repository_rid: scenario.rid,
      branch: "main",
      persona_npub: personaNpub,
      persona_key: personaKey,
      issuer: `https://node.example/oidc/${personaNpub}`,
      sequence: 0,
      predecessor_digest: null,
      max_checkpoint_age_seconds: 300,
      authorization_view_max_age: options.authorization_view_max_age ?? 300,
      current_jwks_sha256: sha256(utf8Bytes(jcsCanonicalize({ keys: [OIDC_RSA_ONE.public_jwk] }))),
      current_signing_key_id: OIDC_RSA_ONE.key_id,
      current_signing_jwk_sha256: sha256(utf8Bytes(jcsCanonicalize(OIDC_RSA_ONE.public_jwk))),
      retiring_signing_key_ids: [],
      retiring_jwks_sha256: [],
      status_lists: [],
      successor: null,
      authority: {
        writer_nid: scenario.writerOne.did_key,
        issued_at: state.checkpoint.observed_at + (options.checkpoint_age ?? 0),
        checkpoint: state.checkpoint,
      },
    };
    return {
      ...body,
      authority_proof: createContinuityAuthorityProof(body, scenario.writerOne.private_key),
    };
  }

  function authorityFor(
    manifest: ContinuityManifest,
    state: LedgerMergeResult,
    clock: AuthorizationFreshnessClock,
    load = (): AuthoritativeAuthorizationView => ({ manifest, ledger_state: state }),
  ): AuthorizationFreshnessAuthority {
    const manifestDigest = continuityManifestDigest(manifest);
    return createAuthorizationFreshnessAuthority({
      repository_rid: manifest.repository_rid,
      persona_key: manifest.persona_key,
      manifest_digest: manifestDigest,
    }, {
      trusted_now: () => clock.now,
      load_current_view: (binding) => {
        if (binding.repository_rid !== manifest.repository_rid
          || binding.persona_key !== manifest.persona_key
          || binding.manifest_digest !== manifestDigest) {
          throw new Error("freshness loader received an unbound request");
        }
        return load();
      },
    });
  }

  function currentView(
    clock: AuthorizationFreshnessClock,
    state: LedgerMergeResult = scenario.issuerKeyEpochOneState,
    manifest: ContinuityManifest = signedManifest(state),
    load?: () => AuthoritativeAuthorizationView,
  ): CurrentAuthorizationView {
    const result = evaluateAuthorizationFreshness(
      authorityFor(manifest, state, clock, load),
      manifest,
    );
    if (result.verdict !== "accept") {
      throw new Error(`freshness fixture rejected: ${result.reason}`);
    }
    return result.view;
  }

  return {
    fixtures,
    scenario,
    signedManifest,
    authorityFor,
    currentView,
  };
}
