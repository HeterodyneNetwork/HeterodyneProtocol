import { schnorr } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha2";
import {
  agentBindingMessage,
  deriveAgentIdentity,
  injectAgentAttribution,
  validateAgentAccessToken,
  validateAgentDelegation,
  validateWorkloadRegistration,
  type AgentTokenValidationInput,
  type WorkloadRegistration,
} from "./agent-authorship.js";
import { bytesToHex, hexToBytes, utf8Bytes } from "./hex.js";
import { getPublicKey, signEvent, verifyEventSignature } from "./nostr.js";
import { ed25519Sign } from "./radicle.js";
import { AUX_RAND, baseVector } from "./vector-helpers.js";
import type { Fixtures } from "./fixtures.js";
import type { AuthoredVector, VectorDirection } from "./types.js";

const roleId = "ab".repeat(32);
const rolePrivateKey = "0a".repeat(32);
const rolePublicKey = getPublicKey(rolePrivateKey);
const issuer = "https://issuer.example/oidc/npub1persona";
const audience = "https://node.example/control/agent-publication";
const subjectJkt = "A".repeat(43);
const subject = "stable-pairwise-agent-subject";
const clientId = "agent-client";
const agentKinds = [1, 6, 7, 16, 1063, 1985, 4550, 30023] as const;

const profileByKind = new Map<number, string>(agentKinds.map((kind) => [
  kind,
  `heterodyne-comms-agent-attribution-kind-${kind}-v1`,
]));

export async function buildAgentAuthorshipVectors(
  fixtures: Fixtures,
): Promise<AuthoredVector[]> {
  const vectors: AuthoredVector[] = [];
  const persona = fixtures.personas.alice;
  const nid = fixtures.ed25519_nids.alice_device_1;
  const proofBytes = agentBindingMessage(
    persona.cold_root.pubkey,
    nid.did_key,
    roleId,
    rolePublicKey,
  );
  const nidProof = ed25519Sign(proofBytes, nid.private_key);
  const keyProof = bytesToHex(schnorr.sign(
    sha256(utf8Bytes(proofBytes)),
    hexToBytes(rolePrivateKey),
    hexToBytes(AUX_RAND),
  ));
  const delegation = await signEvent({
    secretKey: persona.epoch_keys.epoch_1.private_key,
    created_at: fixtures.test_epoch + 700,
    kind: 31001,
    tags: [
      ["d", `agent:${roleId}`],
      ["heterodyne", "delegation"],
      ["radicle_nid", nid.did_key],
      ["publishing_key", rolePublicKey],
      ["cold_root", persona.cold_root.pubkey],
      ["nid_proof", nidProof],
      ["key_proof", keyProof],
      ["kel_head", fixtures.kel.alice.head.id, "0"],
      ["valid_until", String(fixtures.test_epoch + 3_600)],
      ["spec_version", "core/0.5.0"],
    ],
    content: "",
    auxRand: AUX_RAND,
  });
  const delegationInput = {
    cold_root: persona.cold_root.pubkey,
    credential_ledger_generation: 0,
    expected_credential_ledger_persona: persona.cold_root.pubkey,
    expected_credential_ledger_generation: 0,
    nid: nid.did_key,
    role_id: roleId,
    publishing_key: rolePublicKey,
    address: `agent:${roleId}`,
    proof_bytes: proofBytes,
    outer_epoch_signature_valid: verifyEventSignature(delegation),
    nid_proof_valid: true,
    key_proof_valid: true,
    kel_authority_current: true,
    unexpired: true,
    repo_final: true,
  };
  vectors.push(authored(
    "agent-authorship/001-delegation-valid.json",
    "agent-authorship/delegation-valid",
    "A complete Core-stamped agent role delegation verifies the epoch, NID, and dedicated role-key proofs over one exact binding.",
    { event: delegation, proof_bytes: proofBytes, nid_proof: nidProof, key_proof: keyProof },
    validateAgentDelegation(delegationInput),
    "round-trip",
  ));
  vectors.push(authored(
    "agent-authorship/002-delegation-key-proof-invalid.json",
    "agent-authorship/delegation-key-proof-invalid",
    "A role delegation with a failed agent-key proof is rejected.",
    { ...delegationInput, key_proof_valid: false },
    validateAgentDelegation({ ...delegationInput, key_proof_valid: false }),
  ));
  vectors.push(authored(
    "agent-authorship/003-role-key-replacement.json",
    "agent-authorship/role-key-replacement",
    "Replacing the current key at one stable agent role address deauthorizes only the prior role key.",
    {
      address: `agent:${roleId}`,
      prior_key: rolePublicKey,
      replacement_key: getPublicKey("0b".repeat(32)),
      repository_final: true,
    },
    {
      verdict: "accept",
      normalized: {
        prior_key_authorizes_new_events: false,
        replacement_key_authorizes_new_events: true,
        epoch_key_rotated: false,
      },
    },
  ));
  vectors.push(authored(
    "agent-authorship/004-multiple-roles-one-nid.json",
    "agent-authorship/multiple-roles-one-nid",
    "One hosting NID may hold independently replaceable generic and newsletter agent roles.",
    {
      nid: nid.did_key,
      roles: [roleId, "cd".repeat(32)],
      publishing_keys: [rolePublicKey, getPublicKey("0c".repeat(32))],
    },
    {
      verdict: "accept",
      normalized: {
        role_count: 2,
        independently_replaceable: true,
        epoch_key_rotated: false,
      },
    },
  ));

  const stableIdentity = deriveAgentIdentity(
    persona.cold_root.pubkey,
    "https://sector.example",
    "55".repeat(32),
    issuer,
    clientId,
  );
  vectors.push(authored(
    "agent-authorship/005-stable-identity-renewal.json",
    "agent-authorship/stable-identity-renewal",
    "Temporary token renewal preserves the exact issuer, pairwise subject, and client identity tuple.",
    { renewals: 2, local_subject: persona.cold_root.pubkey },
    { verdict: "accept", normalized: { first: stableIdentity, renewed: stableIdentity } },
  ));
  const otherIdentity = deriveAgentIdentity(
    fixtures.personas.bob.cold_root.pubkey,
    "https://sector.example",
    "66".repeat(32),
    "https://other.example/oidc/npub1other",
    clientId,
  );
  vectors.push(authored(
    "agent-authorship/006-cross-persona-unlinkable.json",
    "agent-authorship/cross-persona-unlinkable",
    "Distinct persona pairwise secrets prevent one workload from receiving a correlatable subject across personas.",
    { first_persona: persona.cold_root.pubkey, second_persona: fixtures.personas.bob.cold_root.pubkey },
    {
      verdict: "accept",
      normalized: {
        first_sub: stableIdentity.sub,
        second_sub: otherIdentity.sub,
        equal: false,
      },
    },
  ));

  const registration: WorkloadRegistration = {
    client_id: clientId,
    subject_jkt: subjectJkt,
    agent_class: "ai",
    role_id: roleId,
    audience,
    scopes: ["heterodyne:agent:publish"],
    allowed_kinds: [1, 30023],
    allowed_feeds: ["main"],
    allowed_resources: ["feed:main"],
    max_content_bytes: 4096,
    rate_limit: { window_seconds: 60, count: 20, burst: 5 },
    not_before: fixtures.test_epoch,
    expires_at: fixtures.test_epoch + 3_600,
  };
  vectors.push(authored(
    "agent-authorship/007-workload-registration-valid.json",
    "agent-authorship/workload-registration-valid",
    "The private workload registration has one role and finite kind, feed, resource, size, rate, and burst authority.",
    { registration },
    { verdict: "accept", normalized: validateWorkloadRegistration(registration) },
  ));
  vectors.push(authored(
    "agent-authorship/008-workload-registration-unbounded-rejected.json",
    "agent-authorship/workload-registration-unbounded-rejected",
    "A zero-size or otherwise unbounded automated publication registration is rejected.",
    { registration: { ...registration, max_content_bytes: 0 } },
    { verdict: "reject", reason_code: "agent-workload-registration-invalid" },
  ));

  const token = tokenInput(fixtures.test_epoch, persona.cold_root.pubkey);
  const tokenCases: Array<[string, string, Partial<AgentTokenValidationInput>]> = [
    ["009", "token-valid", {}],
    ["010", "token-expired", { now: token.exp }],
    ["011", "token-revoked", { status: "INVALID" }],
    ["012", "token-audience-invalid", { aud: [audience, "https://other.example"] }],
    ["013", "token-sender-proof-invalid", { sender_proof_valid: false }],
    ["014", "token-role-mismatch", { agent_role_id: "cd".repeat(32) }],
  ];
  for (const [number, name, patch] of tokenCases) {
    const candidate = { ...token, ...patch };
    vectors.push(authored(
      `agent-authorship/${number}-${name}.json`,
      `agent-authorship/${name}`,
      `The sender-constrained workload-token decision is ${name}.`,
      candidate,
      validateAgentAccessToken(candidate),
    ));
  }

  let counter = 15;
  for (const kind of agentKinds) {
    const attribution = injectAgentAttribution(publicationInput(kind));
    if (attribution.verdict !== "accept") throw new Error("agent attribution fixture rejected");
    const event = await signEvent({
      secretKey: rolePrivateKey,
      created_at: fixtures.test_epoch + 700 + counter,
      kind,
      tags: attribution.tags,
      content: `agent publication kind ${kind}`,
      auxRand: AUX_RAND,
    });
    vectors.push(authored(
      `agent-authorship/${String(counter).padStart(3, "0")}-attribution-kind-${kind}.json`,
      `agent-authorship/attribution-kind-${kind}`,
      `A deterministic kind:${kind} role-key-signed event carries the exact ordered canonical agent attribution profile.`,
      { event },
      {
        verdict: "accept",
        normalized: {
          signature_valid: verifyEventSignature(event),
          signer: event.pubkey,
          role_id: roleId,
          attribution_tags: attribution.tags.slice(-4),
        },
      },
      "round-trip",
    ));
    counter += 1;
  }

  const forged = injectAgentAttribution({
    ...publicationInput(1),
    tags: [
      ["heterodyne_agent", "v1", "forged", "forged", "forged", "cd".repeat(32)],
      ["agent_action", "human"],
    ],
  });
  vectors.push(authored(
    "agent-authorship/023-caller-forgery-replaced.json",
    "agent-authorship/caller-forgery-replaced",
    "Caller-supplied reserved attribution is removed before the full node inserts canonical identity fields.",
    { caller_tags: publicationInput(1).tags },
    forged,
  ));
  vectors.push(authored(
    "agent-authorship/024-human-review-preserves-agent-label.json",
    "agent-authorship/human-review-preserves-agent-label",
    "Verified human review appends evidence without removing or reclassifying the canonical agent block.",
    { review: "approved-by-human" },
    injectAgentAttribution({
      ...publicationInput(1),
      agent_review: "approved-by-human",
      agent_review_verified: true,
    }),
  ));
  vectors.push(authored(
    "agent-authorship/025-tier3-inner-only.json",
    "agent-authorship/tier3-inner-only",
    "Tier 3 places canonical agent attribution only inside the encrypted logical event and adds no clear outer marker.",
    { ...publicationInput(1), tier: 3 },
    injectAgentAttribution({ ...publicationInput(1), tier: 3 }),
  ));
  vectors.push(authored(
    "agent-authorship/026-profile-unavailable-rejected.json",
    "agent-authorship/profile-unavailable-rejected",
    "An automated publication kind without an active attribution profile fails without human or unlabeled fallback.",
    publicationInput(31007),
    injectAgentAttribution(publicationInput(31007)),
  ));
  vectors.push(authored(
    "agent-authorship/027-idempotent-retry-reuses-event.json",
    "agent-authorship/idempotent-retry-reuses-event",
    "An identical retry returns the already signed event and event id without exercising the role key again.",
    { request_id: "request-1", attempts: 2, payload_digest: "ef".repeat(32) },
    {
      verdict: "accept",
      normalized: {
        signing_operations: 1,
        event_ids_equal: true,
        event_bytes_equal: true,
      },
    },
  ));
  return vectors;
}

function tokenInput(now: number, credentialLedgerPersona: string): AgentTokenValidationInput {
  return {
    typ: "at+jwt",
    credential_ledger_persona: credentialLedgerPersona,
    credential_ledger_generation: 0,
    expected_credential_ledger_persona: credentialLedgerPersona,
    expected_credential_ledger_generation: 0,
    iss: issuer,
    sub: subject,
    aud: [audience],
    exp: now + 250,
    iat: now,
    jti: "token-1",
    client_id: clientId,
    scope: "heterodyne:agent:publish",
    cnf_jkt: subjectJkt,
    sender_proof_jkt: subjectJkt,
    sender_proof_valid: true,
    agent_role_id: roleId,
    expected_issuer: issuer,
    expected_subject: subject,
    expected_audience: audience,
    expected_client_id: clientId,
    expected_scope: "heterodyne:agent:publish",
    expected_role_id: roleId,
    now: now + 100,
    status: "VALID",
    ledger_active: true,
    ledger_binding_valid: true,
    status_binding_valid: true,
    session_expires_at: now + 300,
    delegation_expires_at: now + 300,
    registration_expires_at: now + 300,
    consent_expires_at: now + 300,
    source_authorization_expires_at: now + 300,
  };
}

function publicationInput(kind: number) {
  return {
    kind,
    tags: [["client", "heterodyne"]],
    agent_class: "ai" as const,
    issuer,
    subject,
    client_id: clientId,
    role_id: roleId,
    signer: rolePublicKey,
    current_role_key: rolePublicKey,
    tier: 1 as const,
  };
}

function authored(
  relativePath: string,
  vectorId: string,
  description: string,
  input: Record<string, unknown>,
  expectedOutput: Record<string, unknown>,
  direction: VectorDirection = "consume",
): AuthoredVector {
  return {
    relativePath,
    vector: baseVector({
      vector_id: vectorId,
      spec_refs: ["metadata-selects-agent-authorship-anchor"],
      description,
      direction,
      input,
      expected_output: expectedOutput,
    }),
  };
}
