import { ed25519 } from "@noble/curves/ed25519";
import { schnorr } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex, hexToBytes } from "../hex.js";
import type { CurrentProfileWireProbe } from "../profile-negotiation.js";
import type { RegisteredKindProfile } from "../registry.js";
import type { DocumentId } from "../types.js";
import { createSocialSubscriptionAuthority } from "../social-subscription-authority.js";
import { createReplaceableSelectionAuthority } from "../replaceable-selection.js";
import type { NostrSignedEvent } from "../nostr.js";
import type { CurrentCaseFixture } from "./types.js";
import { registerPrivateCurrentFixture } from "./boundary-runners.js";
import { definePrivateCurrentFixtureSpecification } from "./private-fixture-specification.js";

export type CurrentProfileOracle = Readonly<{
  vector_id: string;
  tuple: Readonly<RegisteredKindProfile>;
  wire_probe: CurrentProfileWireProbe;
  semantic_boundary: string;
  exercised_invariants: readonly string[];
  semantic_input: Readonly<Record<string, unknown>>;
  claim_proof_expectation?: Readonly<{
    suite: "nostr-bip340" | "radicle-ed25519" | "jwk-jws";
    purpose: "claim-subject-pop" | "claim-revoker";
  }>;
}>;

const PROFILE_VERSION = "heterodyne/0.5.0";
const CURRENT_PROFILE_VERSION = "heterodyne/0.6.0";
const KEY = "11".repeat(32);
const OTHER_KEY = "22".repeat(32);
const CORE_BREADCRUMB_SECRET = "33".repeat(32);
const TIER3_PRIVATE_REPOSITORY_RID = "rad:z3CurrentPrivateRepository";
const TIER3_PRIVATE_INTERFACE_ID = "radicle-native-private";
const TIER3_PRIVATE_ROUTE = TIER3_PRIVATE_REPOSITORY_RID;
export const CURRENT_SOCIAL_PROFILE_PRIVATE_CASE_IDS = Object.freeze([
  "social/profile-heterodyne-social-agent-policy-list-v1",
  "social/profile-heterodyne-social-agent-policy-receipt-v1",
]);
const SOCIAL_PROFILE_PRIVATE_FIXTURES = definePrivateCurrentFixtureSpecification(
  CURRENT_SOCIAL_PROFILE_PRIVATE_CASE_IDS,
);

function socialSignedEvent(secretHex: string, createdAt: number, kind: number, tags: string[][], content: string): NostrSignedEvent {
  const secret = hexToBytes(secretHex);
  const pubkey = bytesToHex(schnorr.getPublicKey(secret));
  const serialized = JSON.stringify([0, pubkey, createdAt, kind, tags, content]);
  const id = bytesToHex(sha256(new TextEncoder().encode(serialized)));
  return Object.freeze({ pubkey, created_at: createdAt, kind, tags: Object.freeze(tags.map((tag) => Object.freeze([...tag]))) as string[][], content, id, sig: bytesToHex(schnorr.sign(hexToBytes(id), secret, hexToBytes("00".repeat(32)))) });
}

function currentSocialProfilePrivateArgs(
  vectorId: string,
): readonly unknown[] | undefined {
  if (!CURRENT_SOCIAL_PROFILE_PRIVATE_CASE_IDS.includes(vectorId)) {
    return undefined;
  }
  const policySecret = "0d".repeat(32), deviceSecret = "0e".repeat(32);
  const policyPersona = bytesToHex(schnorr.getPublicKey(hexToBytes(policySecret)));
  const device = bytesToHex(schnorr.getPublicKey(hexToBytes(deviceSecret)));
  const target = socialSignedEvent(deviceSecret, 1_000, 1, [["L", "network.heterodyne.agent"], ["l", "ai", "network.heterodyne.agent"], ["heterodyne_agent", "v1", "key", device], ["agent_action", "publish"]], "Synthetic local current profile publication.");
  const receiptContent = JSON.stringify({ profile: "heterodyne.social.agent-policy-receipt.v1", spec_version: CURRENT_PROFILE_VERSION, event_id: target.id, event_author: device, agent_association: { kind: "key", value: device }, policy: { id: "network.heterodyne.agent-policy", version: "1.0.0" }, decision: "advisory-violation", reason: "agent-attribution-missing", observed_at: 1_100, evidence: ["sha256:synthetic-local-current-profile"], explanation: "Synthetic local current profile boundary evidence.", remediation: "replace-signing-key" });
  const receipt = socialSignedEvent(policySecret, 1_100, 1_985, [["L", "network.heterodyne.agent-policy"], ["l", "agent-attribution-missing", "network.heterodyne.agent-policy"], ["e", target.id], ["p", device]], receiptContent);
  const list = socialSignedEvent(policySecret, 1_200, 10_000, [["heterodyne", "social-agent-policy-list-v1"], ["spec_version", CURRENT_PROFILE_VERSION], ["p", device], ["e", receipt.id], ["agent_violation", device, receipt.id, "agent-attribution-missing"]], "");
  const authority = createSocialSubscriptionAuthority({ authority_id: `synthetic-local-current-${vectorId}`, trusted_now: () => 2_000, replaceable_selection: createReplaceableSelectionAuthority({ trusted_now: () => 2_000 }), load_subscription: async () => ({ revision: 1, subscribed: true, default_visible: true }) });
  const input = Object.freeze({ policy_persona: policyPersona, list_candidates: Object.freeze([list]), receipt_events: Object.freeze([receipt]), target_events: Object.freeze([target]), correction_events: Object.freeze([]) });
  return Object.freeze([authority, input, target]);
}

function fixedTuple(
  kind: number,
  profile_id: string,
  owner: DocumentId,
  discriminator: string,
  stamping: boolean,
  first_version = PROFILE_VERSION,
): RegisteredKindProfile {
  return {
    kind,
    profile_id,
    owner,
    discriminator,
    stamping,
    first_version,
    status: "draft",
  };
}

function fixedWireProbe(discriminator: string): CurrentProfileWireProbe {
  if (discriminator.startsWith("content.profile=")) {
    return {
      content_is_heterodyne_json: true,
      is_dr_outer: false,
      content_profile: discriminator.slice("content.profile=".length),
    };
  }
  if (discriminator === "tag:heterodyne_wrap=room_key.v2") {
    return {
      content_is_heterodyne_json: false,
      is_dr_outer: false,
      tags: [["heterodyne_wrap", "room_key.v2"]],
    };
  }
  if (discriminator === "tag:heterodyne=social-mute-list-v1") {
    return {
      content_is_heterodyne_json: false,
      is_dr_outer: false,
      tags: [["heterodyne", "social-mute-list-v1"]],
    };
  }
  if (discriminator === "tag:heterodyne=social-agent-policy-list-v1") {
    return {
      content_is_heterodyne_json: false,
      is_dr_outer: false,
      tags: [["heterodyne", "social-agent-policy-list-v1"]],
    };
  }
  if (discriminator.startsWith("tags:L=")) {
    return {
      content_is_heterodyne_json: false,
      is_dr_outer: false,
      tags: [
        ["L", "network.heterodyne.agent-policy"],
        ["l", "agent-attribution-missing@network.heterodyne.agent-policy"],
      ],
    };
  }
  if (discriminator.startsWith("production-rule:")) {
    return {
      content_is_heterodyne_json: false,
      is_dr_outer: false,
      production_rule: discriminator.slice("production-rule:".length),
    };
  }
  if (discriminator === "marmot-inner-only;content=control-frame-v1") {
    return {
      content_is_heterodyne_json: true,
      is_dr_outer: false,
      transport: "marmot-inner",
      content_profile_id: "control-frame-v1",
    };
  }
  throw new Error(`unsupported fixed profile discriminator: ${discriminator}`);
}

function oracle(
  tuple: RegisteredKindProfile,
  semantic_boundary: string,
  exercised_invariants: readonly string[],
  semantic_input: Readonly<Record<string, unknown>>,
  claimProofExpectation?: CurrentProfileOracle["claim_proof_expectation"],
): CurrentProfileOracle {
  return {
    vector_id: `${tuple.owner}/profile-${tuple.profile_id}`,
    tuple,
    wire_probe: fixedWireProbe(tuple.discriminator),
    semantic_boundary,
    exercised_invariants,
    semantic_input,
    ...(claimProofExpectation === undefined
      ? {}
      : { claim_proof_expectation: claimProofExpectation }),
  };
}

function attributionInput(kind: number): Readonly<Record<string, unknown>> {
  return {
    kind,
    tags: [["client", "heterodyne-current-profile"]],
    agent_class: "ai",
    persona: KEY,
    issuer: "https://issuer.example/current-profile",
    subject: "current-profile-agent",
    client_id: "current-profile-client",
    signer: OTHER_KEY,
    expected_signer: OTHER_KEY,
    signer_key_class: "agent",
    oidc_scopes: ["heterodyne:agent:publish"],
    agent_association: { kind: "key", value: OTHER_KEY },
    expected_agent_association: { kind: "key", value: OTHER_KEY },
    tier: 1,
  };
}

function coreBreadcrumbInput(kind: 0 | 1): Readonly<Record<string, unknown>> {
  const secret = hexToBytes(CORE_BREADCRUMB_SECRET);
  const event = {
    pubkey: bytesToHex(schnorr.getPublicKey(secret)),
    created_at: 1_800_000_000,
    kind,
    tags: [["d", `current-core-breadcrumb-kind-${kind}`]],
    content: kind === 0
      ? JSON.stringify({ name: "Current Core breadcrumb" })
      : "Current Core rotation breadcrumb",
  };
  const nip01Raw = JSON.stringify([
    0,
    event.pubkey,
    event.created_at,
    event.kind,
    event.tags,
    event.content,
  ]);
  const digest = sha256(new TextEncoder().encode(nip01Raw));
  return {
    event: {
      ...event,
      id: bytesToHex(digest),
      sig: bytesToHex(schnorr.sign(
        digest,
        secret,
        hexToBytes("00".repeat(32)),
      )),
    },
    nip01_raw: nip01Raw,
    stamp_policy: "forbidden",
    active_persona_key: event.pubkey,
  };
}

function proofInput(
  suite: "nostr-bip340" | "radicle-ed25519" | "jwk-jws",
  purpose: "claim-subject-pop" | "claim-revoker",
): Readonly<Record<string, unknown>> {
  const message = sha256(new TextEncoder().encode(
    `heterodyne-current-profile-proof-fixture-v1:${purpose}`,
  ));
  const secret = hexToBytes(suite === "nostr-bip340" ? "31".repeat(32) : "32".repeat(32));
  if (suite === "nostr-bip340") {
    return {
      proof_suite: suite,
      proof_purpose: purpose,
      message: bytesToHex(message),
      public_key: bytesToHex(schnorr.getPublicKey(secret)),
      signature: bytesToHex(schnorr.sign(message, secret, hexToBytes("00".repeat(32)))),
    };
  }
  const publicKey = ed25519.getPublicKey(secret);
  const signature = ed25519.sign(message, secret);
  return suite === "radicle-ed25519"
    ? {
        proof_suite: suite,
        proof_purpose: purpose,
        message: bytesToHex(message),
        public_key: bytesToHex(publicKey),
        signature: bytesToHex(signature),
      }
    : (() => {
        const protectedHeader = Buffer.from('{"alg":"EdDSA"}', "utf8")
          .toString("base64url");
        const encodedPayload = Buffer.from(message).toString("base64url");
        const signingInput = new TextEncoder().encode(
          `${protectedHeader}.${encodedPayload}`,
        );
        return {
          proof_suite: suite,
          proof_purpose: purpose,
          message: bytesToHex(message),
          public_jwk: {
            kty: "OKP",
            crv: "Ed25519",
            x: Buffer.from(publicKey).toString("base64url"),
          },
          protected: protectedHeader,
          signature: Buffer.from(ed25519.sign(signingInput, secret)).toString("base64url"),
        };
      })();
}

const rows: CurrentProfileOracle[] = [];

for (const [kind, suffix] of [[0, "profile"], [1, "note"]] as const) {
  rows.push(oracle(
    fixedTuple(
      kind,
      `heterodyne-core-rotation-breadcrumb-${suffix}-v1`,
      "core",
      `production-rule:rotation-breadcrumb-kind${kind}-v1`,
      false,
    ),
    "core-policy.validateCorePersonaSignedEvent",
    ["CORE-I-IDENTITY-INTEGRITY"],
    coreBreadcrumbInput(kind),
  ));
}

for (const kind of [1, 6, 16, 1063, 30023, 30402] as const) {
  rows.push(oracle(
    fixedTuple(
      kind,
      `heterodyne-comms-tier3-wrapped-content-kind-${kind}-v1`,
      "comms",
      "tag:heterodyne_wrap=room_key.v2",
      true,
    ),
    "privacy-crypto.deriveTier3IndexKey+nostr-tools.nip44+follow-up-hardening.resolveTier3Recipients+current-private-route.evaluateCurrentTier3PrivateRoute",
    ["COMMS-I-TIER3-BLIND-CARRIER", "COMMS-I-TIER3-CONFINED"],
    {
      audience_key: "40".repeat(32),
      key_id: `current-profile-tier3-kind-${kind}`,
      plaintext: JSON.stringify({ kind, audience: "fixed-current-profile" }),
      memberPersonas: [KEY],
      devices: [
        { persona: KEY, pubkey: OTHER_KEY, active: true, role: "human-device" },
      ],
      selected: [OTHER_KEY],
      requested_repository_rid: TIER3_PRIVATE_REPOSITORY_RID,
      requested_interface_id: TIER3_PRIVATE_INTERFACE_ID,
      requested_route: TIER3_PRIVATE_ROUTE,
    },
  ));
}

for (const kind of [1, 6, 7, 16, 1063, 1985, 4550, 30023] as const) {
  rows.push(oracle(
    fixedTuple(
      kind,
      `heterodyne-comms-agent-attribution-kind-${kind}-v1`,
      "comms",
      "production-rule:agent-attribution-v1",
      false,
    ),
    "agent-authorship.injectAgentAttribution+matchesAgentAttributionProfile",
    ["COMMS-I-AGENT-ATTRIBUTION", "COMMS-I-AGENT-SIGNER-BINDING"],
    attributionInput(kind),
  ));
}

for (const [kind, profileId, discriminator, invariant, fixture] of [
  [
    31000,
    "heterodyne-assurance-active-key-acceptance-v1",
    "content.profile=heterodyne.assurance.active-key-acceptance.v1",
    "ASSURANCE-I-RECIPROCAL-ENROLLMENT",
    "reciprocal",
  ],
  [
    31001,
    "heterodyne-assurance-associated-key-v1",
    "content.profile=heterodyne.assurance.associated-key.v1",
    "ASSURANCE-I-ASSOCIATED-KEY-BOUNDS",
    "associated",
  ],
  [
    31002,
    "heterodyne-assurance-enrollment-inception-v1",
    "content.profile=heterodyne.assurance.enrollment-inception.v1",
    "ASSURANCE-I-RECIPROCAL-ENROLLMENT",
    "reciprocal",
  ],
  [
    31003,
    "heterodyne-assurance-succession-v1",
    "content.profile=heterodyne.assurance.succession.v1",
    "ASSURANCE-I-TRANSITION-PROOF-BINDING",
    "succession",
  ],
  [
    31006,
    "heterodyne-assurance-enrollment-contest-profile-v1",
    "content.profile=heterodyne.assurance.enrollment-contest.v1",
    "ASSURANCE-I-ENROLLMENT-WINDOWED",
    "contest",
  ],
] as const) {
  const boundary = fixture === "succession"
    ? "assurance.evaluateSuccession"
    : fixture === "associated"
      ? "assurance.evaluateAssociatedKey"
      : fixture === "reciprocal"
        ? "assurance.evaluateEnrollment"
        : "assurance-observation.evaluateEnrollmentEligibility";
  rows.push(oracle(
    fixedTuple(
      kind,
      profileId,
      "assurance",
      discriminator,
      false,
      kind === 31006 ? CURRENT_PROFILE_VERSION : PROFILE_VERSION,
    ),
    boundary,
    [invariant],
    { assurance_profile_fixture: fixture },
  ));
}

for (const [kind, purpose, profileStem, invariant] of [
  [31013, "claim-subject-pop", "heterodyne-comms-key-claim", "COMMS-I-CLAIM-AUTHENTICITY"],
  [31014, "claim-revoker", "heterodyne-comms-claim-revocation", "COMMS-I-CLAIM-REVOCATION"],
] as const) {
  for (const [profileSuffix, suite] of [
    ["nostr-bip340-v1", "nostr-bip340"],
    ["radicle-ed25519-v1", "radicle-ed25519"],
    ["jwk-jws-v1", "jwk-jws"],
  ] as const) {
    rows.push(oracle(
      fixedTuple(
        kind,
        `${profileStem}-${profileSuffix}`,
        "comms",
        `production-rule:${purpose};proof=${profileSuffix}`,
        false,
      ),
      purpose === "claim-revoker"
        ? "current-revocation.evaluateCurrentRevocationProfile"
        : "profile-negotiation.verifyCurrentClaimProofProfile",
      [invariant],
      purpose === "claim-revoker" ? {} : proofInput(suite, purpose),
      { suite, purpose },
    ));
  }
}

rows.push(oracle(
  fixedTuple(
    31017,
    "heterodyne-control-marmot-frame-v1",
    "control",
    "marmot-inner-only;content=control-frame-v1",
    false,
  ),
  "profile-negotiation.validateCurrentControlGrantProfile",
  ["CONTROL-I-MARMOT-GRANT-CONFINEMENT"],
  {
    transport: "marmot-inner",
    frame: {
      version: "heterodyne/0.6.0",
      profile: "human-jsonrpc",
      frame_type: "request",
      request_id: "current-profile-request",
      expires_at: 1800000060,
      access_token: "current-profile-token",
      payload: { method: "status" },
    },
    active_account: KEY,
    authenticated_account: KEY,
    grant_account: KEY,
    requested_device: "device-one",
    grant_device: "device-one",
    requested_leaf: "leaf-one",
    grant_leaf: "leaf-one",
    requested_group: "group-one",
    grant_group: "group-one",
    requested_grant: "grant-one",
    grant_id: "grant-one",
    requested_content_ids: ["content-one"],
    granted_content_ids: ["content-one"],
    requested_secret_classes: [],
  },
));

for (const [kind, profileId, discriminator] of [
  [
    1985,
    "heterodyne-social-agent-policy-receipt-v1",
    "tags:L=network.heterodyne.agent-policy,l=<reason>@network.heterodyne.agent-policy",
  ],
  [
    10000,
    "heterodyne-social-agent-policy-list-v1",
    "tag:heterodyne=social-agent-policy-list-v1",
  ],
] as const) {
  const vectorId = `social/profile-${profileId}`;
  rows.push(oracle(
    fixedTuple(kind, profileId, "social", discriminator, true),
    "social-subscription-authority.resolveSubscribedAgentPolicy+applySubscribedAgentPolicy",
    ["SOCIAL-I-AGENT-AUTHORSHIP-EXACT", "SOCIAL-I-AGENT-POLICY-LOCAL"],
    { evidence: "signed subscribed local agent policy list and receipt resolve before exact application" },
  ));
}

rows.push(oracle(
  fixedTuple(
    10000,
    "heterodyne-social-mute-list-v1",
    "social",
    "tag:heterodyne=social-mute-list-v1",
    true,
  ),
  "privacy-crypto.deriveConfigPostKey+nostr-tools.nip44",
  ["SOCIAL-I-PRIVATE-STATE-AT-REST"],
  {
    config_audience_key: "42".repeat(32),
    key_id: "current-social-mute-state",
    plaintext: JSON.stringify({ muted_pubkeys: [OTHER_KEY] }),
  },
));

function deepFreeze<T>(value: T, seen = new WeakSet<object>()): T {
  if (value === null || typeof value !== "object") return value;
  const object = value as object;
  if (seen.has(object)) return value;
  seen.add(object);
  for (const key of Reflect.ownKeys(object)) {
    deepFreeze((object as Record<PropertyKey, unknown>)[key], seen);
  }
  if (!ArrayBuffer.isView(object)) Object.freeze(object);
  return value;
}

export const CURRENT_PROFILE_ORACLES: readonly CurrentProfileOracle[] = deepFreeze(rows);

if (CURRENT_PROFILE_ORACLES.length !== 31) {
  throw new Error(`fixed current profile oracle count mismatch: ${CURRENT_PROFILE_ORACLES.length}`);
}

const oracleByVectorId = new Map(
  CURRENT_PROFILE_ORACLES.map((entry) => [entry.vector_id, entry]),
);

export function currentProfileOracleForVector(
  vectorId: string,
): CurrentProfileOracle | undefined {
  return oracleByVectorId.get(vectorId);
}

/** Constructs and privately binds one exact oracle-owned fixture without exposing its arguments. */
export function buildCurrentProfileOracleFixture(
  oracle: CurrentProfileOracle,
  input: Readonly<Record<string, unknown>>,
  boundaryArgs?: readonly unknown[],
): CurrentCaseFixture {
  if (oracleByVectorId.get(oracle.vector_id) !== oracle) {
    throw new Error(`unknown current profile oracle identity: ${oracle.vector_id}`);
  }
  const fixture: CurrentCaseFixture = {
    vector_id: oracle.vector_id,
    description:
      `The fixed ${oracle.tuple.profile_id} allocation is checked separately from its live semantic boundary.`,
    direction: "consume",
    input,
    ...(boundaryArgs === undefined ? {} : { boundary_args: boundaryArgs }),
  };
  const privateArgs = currentSocialProfilePrivateArgs(fixture.vector_id);
  if (privateArgs !== undefined) {
    registerPrivateCurrentFixture(SOCIAL_PROFILE_PRIVATE_FIXTURES, fixture, privateArgs);
  }
  return fixture;
}
