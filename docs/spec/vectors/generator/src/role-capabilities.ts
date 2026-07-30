export type CoreRole = "public-reader" | "authenticated-light" | "full-node";

export type CapabilityVerdict = {
  verdict: "accept" | "reject";
  reduced_assurance: boolean;
  warnings: string[];
};

export type FullNodeReachabilityInput = {
  features: readonly string[];
  onion_service: string;
  onion_version: number;
  onion_persistent: boolean;
  outbound_backends_via_tor: boolean;
  browser_compatible: boolean;
  shared_relays: readonly string[];
};

const RELAY_READ = "core.nostr-relay-read.v1";
const OUTBOUND_TOR = "core.outbound-tor.v1";
const REPO_RELAY = "core.repo-relay-client.v1";
const ONION_HOST = "core.onion-service-host.v1";
const BROWSER_RELAY = "core.browser-shared-relay.v1";

const KNOWN_FEATURES = new Set([
  RELAY_READ,
  OUTBOUND_TOR,
  REPO_RELAY,
  ONION_HOST,
  BROWSER_RELAY,
]);

function reject(warnings: string[]): CapabilityVerdict {
  return { verdict: "reject", reduced_assurance: false, warnings };
}

export function evaluateRoleCapabilities(
  role: CoreRole,
  features: readonly string[],
  strict: boolean,
): CapabilityVerdict {
  const featureSet = new Set(features);
  const unknown = [...featureSet]
    .filter((feature) => !KNOWN_FEATURES.has(feature))
    .sort((left, right) => left.localeCompare(right, "en"));
  if (unknown.length > 0) {
    return reject(unknown.map((feature) => `unknown-feature:${feature}`));
  }

  if (role !== "full-node" && !featureSet.has(RELAY_READ)) {
    return reject([`missing-feature:${RELAY_READ}`]);
  }

  if (role === "full-node") {
    const missing = [OUTBOUND_TOR, REPO_RELAY, ONION_HOST]
      .filter((feature) => !featureSet.has(feature))
      .map((feature) => `missing-feature:${feature}`);
    return missing.length > 0
      ? reject(missing)
      : { verdict: "accept", reduced_assurance: false, warnings: [] };
  }

  if (!featureSet.has(OUTBOUND_TOR)) {
    return strict
      ? reject([`missing-feature:${OUTBOUND_TOR}`])
      : {
          verdict: "accept",
          reduced_assurance: true,
          warnings: ["tor-unavailable"],
        };
  }

  return { verdict: "accept", reduced_assurance: false, warnings: [] };
}

export function validateRoleDelegationAddress(
  address: string,
): { verdict: "accept" | "reject"; role_id?: string } {
  const match = /^agent:([0-9a-f]{64})$/.exec(address);
  return match === null
    ? { verdict: "reject" }
    : { verdict: "accept", role_id: match[1] };
}

export function validateFullNodeReachability(
  input: FullNodeReachabilityInput,
): CapabilityVerdict {
  const capabilities = evaluateRoleCapabilities("full-node", input.features, false);
  if (capabilities.verdict === "reject") return capabilities;

  const featureSet = new Set(input.features);
  const warnings: string[] = [];
  if (
    input.onion_version !== 3
    || !input.onion_persistent
    || !/^[a-z2-7]{56}\.onion$/.test(input.onion_service)
  ) {
    warnings.push("persistent-v3-onion-required");
  }
  if (!input.outbound_backends_via_tor) {
    warnings.push("tor-default-outbound-required");
  }
  if (input.browser_compatible) {
    if (!featureSet.has(BROWSER_RELAY)) {
      warnings.push(`missing-feature:${BROWSER_RELAY}`);
    } else if (!input.shared_relays.some(isNormalizedClearnetWssRelay)) {
      warnings.push("browser-shared-relay-unavailable");
    }
  } else if (featureSet.has(BROWSER_RELAY)) {
    warnings.push("browser-feature-without-compatibility-claim");
  }

  return warnings.length > 0
    ? reject(warnings)
    : { verdict: "accept", reduced_assurance: false, warnings: [] };
}

function isNormalizedClearnetWssRelay(value: string): boolean {
  try {
    const parsed = new URL(value);
    return parsed.protocol === "wss:"
      && !parsed.hostname.endsWith(".onion")
      && parsed.username === ""
      && parsed.password === ""
      && parsed.hash === ""
      && parsed.toString() === value;
  } catch {
    return false;
  }
}
