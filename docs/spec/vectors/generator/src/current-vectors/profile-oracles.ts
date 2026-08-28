import { ed25519 } from "@noble/curves/ed25519";
import { schnorr } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex, hexToBytes } from "../hex.js";
import type { CurrentProfileWireProbe } from "../profile-negotiation.js";
import type { RegisteredKindProfile } from "../registry.js";
import type { DocumentId } from "../types.js";

export type CurrentProfileOracle = Readonly<{
  vector_id: string;
  tuple: Readonly<RegisteredKindProfile>;
  wire_probe: CurrentProfileWireProbe;
  semantic_boundary: string;
  exercised_invariants: readonly string[];
  semantic_input: Readonly<Record<string, unknown>>;
}>;

const PROFILE_VERSION = "heterodyne/0.5.0";
const CURRENT_PROFILE_VERSION = "heterodyne/0.6.0";
const KEY = "11".repeat(32);
const OTHER_KEY = "22".repeat(32);

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
): CurrentProfileOracle {
  return {
    vector_id: `${tuple.owner}/profile-${tuple.profile_id}`,
    tuple,
    wire_probe: fixedWireProbe(tuple.discriminator),
    semantic_boundary,
    exercised_invariants,
    semantic_input,
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
    "follow-up-hardening.validateCanonicalProfile",
    ["CORE-I-IDENTITY-INTEGRITY"],
    {
      canonicalRepoSelected: true,
      publisher: KEY,
      delegatedPublisher: KEY,
      nip05Present: false,
    },
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
    "privacy-crypto.deriveTier3IndexKey+nostr-tools.nip44",
    ["COMMS-I-TIER3-BLIND-CARRIER", "COMMS-I-TIER3-CONFINED"],
    {
      audience_key: "40".repeat(32),
      key_id: `current-profile-tier3-kind-${kind}`,
      plaintext: JSON.stringify({ kind, audience: "fixed-current-profile" }),
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
        : "assurance.evaluateEnrollmentEligibility";
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
      "profile-negotiation.verifyCurrentClaimProofProfile",
      [invariant],
      proofInput(suite, purpose),
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
  "profile-negotiation.validateCurrentControlFrameProfile",
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
  rows.push(oracle(
    fixedTuple(kind, profileId, "social", discriminator, true),
    "agent-authorship.injectAgentAttribution+agent-moderation.applySubscribedAgentPolicy",
    ["SOCIAL-I-AGENT-AUTHORSHIP-EXACT", "SOCIAL-I-AGENT-POLICY-LOCAL"],
    {
      publication: attributionInput(1),
      policy: {
        subscribed: true,
        policy_persona: KEY,
        policy_event_selected: true,
        event_author: OTHER_KEY,
        muted_event_authors: [OTHER_KEY],
        default_subscription: false,
        default_visible: true,
        can_disable_default: true,
      },
    },
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
