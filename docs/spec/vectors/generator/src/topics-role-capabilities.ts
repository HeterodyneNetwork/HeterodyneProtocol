import {
  evaluateRoleCapabilities,
  validateFullNodeReachability,
  validateRoleDelegationAddress,
  type CoreRole,
  type FullNodeReachabilityInput,
} from "./role-capabilities.js";
import { baseVector } from "./vector-helpers.js";
import type { AuthoredVector } from "./types.js";

const RELAY_READ = "core.nostr-relay-read.v1";
const OUTBOUND_TOR = "core.outbound-tor.v1";
const REPO_RELAY = "core.repo-relay-client.v1";
const ONION_HOST = "core.onion-service-host.v1";
const BROWSER_RELAY = "core.browser-shared-relay.v1";

type RoleCase = {
  path: string;
  id: string;
  description: string;
  role: CoreRole;
  features: string[];
  strict: boolean;
};

const ROLE_CASES: RoleCase[] = [
  {
    path: "role-capabilities/001-public-reader-reduced-assurance.json",
    id: "role-capabilities/public-reader-reduced-assurance",
    description: "A browser public reader with relay read but no outbound Tor is accepted only in explicitly reported reduced-assurance mode.",
    role: "public-reader",
    features: [RELAY_READ],
    strict: false,
  },
  {
    path: "role-capabilities/002-strict-missing-tor-rejected.json",
    id: "role-capabilities/strict-missing-tor-rejected",
    description: "A strict authenticated-light client cannot claim conformance without the exact outbound-Tor feature.",
    role: "authenticated-light",
    features: [RELAY_READ],
    strict: true,
  },
  {
    path: "role-capabilities/003-full-node-feature-set-required.json",
    id: "role-capabilities/full-node-feature-set-required",
    description: "A full node advertises the complete outbound-Tor, repo-relay-client, and onion-service-host feature set.",
    role: "full-node",
    features: [OUTBOUND_TOR, REPO_RELAY, ONION_HOST],
    strict: false,
  },
];

export function buildRoleCapabilityVectors(): AuthoredVector[] {
  const authored = ROLE_CASES.map((testCase) => ({
    relativePath: testCase.path,
    vector: baseVector({
      vector_id: testCase.id,
      spec_refs: ["metadata-selects-core-role-anchor"],
      description: testCase.description,
      direction: "consume",
      input: {
        role: testCase.role,
        features: testCase.features,
        strict: testCase.strict,
      },
      expected_output: withReasonCode(
        evaluateRoleCapabilities(
          testCase.role,
          testCase.features,
          testCase.strict,
        ),
        "strict_mode_tor_disabled",
      ),
    }),
  }));

  const completeReachability: FullNodeReachabilityInput = {
    features: [OUTBOUND_TOR, REPO_RELAY, ONION_HOST, BROWSER_RELAY],
    onion_service: `${"a".repeat(56)}.onion`,
    onion_version: 3,
    onion_persistent: true,
    outbound_backends_via_tor: true,
    browser_compatible: true,
    shared_relays: ["wss://relay.example/"],
  };
  const reachabilityCases = [
    {
      relativePath: "role-capabilities/004-full-node-onion-advertised.json",
      id: "role-capabilities/full-node-onion-advertised",
      description: "A full node is accepted when it has a persistent v3 onion service, Tor-default outbound backends, and the required feature set.",
      input: completeReachability,
    },
    {
      relativePath: "role-capabilities/005-browser-shared-relay-required.json",
      id: "role-capabilities/browser-shared-relay-required",
      description: "A browser-compatible full node advertises at least one normalized clearnet wss shared relay.",
      input: completeReachability,
    },
    {
      relativePath: "role-capabilities/006-full-node-tor-default.json",
      id: "role-capabilities/full-node-tor-default",
      description: "A full node routes every declared outbound backend through Tor by default.",
      input: completeReachability,
    },
  ] as const;
  for (const testCase of reachabilityCases) {
    authored.push({
      relativePath: testCase.relativePath,
      vector: baseVector({
        vector_id: testCase.id,
        spec_refs: ["metadata-selects-core-role-anchor"],
        description: testCase.description,
        direction: "consume",
        input: testCase.input,
        expected_output: validateFullNodeReachability(testCase.input),
      }),
    });
  }

  for (const [suffix, address] of [
    ["valid", `agent:${"ab".repeat(32)}`],
    ["invalid", `agent:${"AB".repeat(32)}`],
  ] as const) {
    authored.push({
      relativePath: `role-capabilities/00${suffix === "valid" ? "7" : "8"}-role-address-${suffix}.json`,
      vector: baseVector({
        vector_id: `role-capabilities/role-address-${suffix}`,
        spec_refs: ["metadata-selects-core-role-anchor"],
        description: suffix === "valid"
          ? "A registered agent role address uses the exact lowercase 64-hex identifier syntax."
          : "An uppercase agent role address is rejected before higher-layer semantics are applied.",
        direction: "consume",
        input: { address },
        expected_output: suffix === "valid"
          ? validateRoleDelegationAddress(address)
          : {
              ...validateRoleDelegationAddress(address),
              reason_code: "role-delegation-address-invalid",
            },
      }),
    });
  }

  return authored;
}

function withReasonCode(
  decision: ReturnType<typeof evaluateRoleCapabilities>,
  reasonCode: string,
): Record<string, unknown> {
  return decision.verdict === "reject"
    ? { ...decision, reason_code: reasonCode }
    : decision;
}
