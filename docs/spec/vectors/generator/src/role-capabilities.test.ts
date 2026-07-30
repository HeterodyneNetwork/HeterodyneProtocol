import { describe, expect, it } from "vitest";
import {
  evaluateRoleCapabilities,
  validateFullNodeReachability,
  validateRoleDelegationAddress,
} from "./role-capabilities.js";

const RELAY_READ = "core.nostr-relay-read.v1";
const OUTBOUND_TOR = "core.outbound-tor.v1";
const REPO_RELAY = "core.repo-relay-client.v1";
const ONION_HOST = "core.onion-service-host.v1";
const BROWSER_RELAY = "core.browser-shared-relay.v1";

describe("role-scoped Core capabilities", () => {
  it("accepts a browser public reader without Tor in reduced-assurance mode", () => {
    expect(evaluateRoleCapabilities("public-reader", [RELAY_READ], false)).toEqual({
      verdict: "accept",
      reduced_assurance: true,
      warnings: ["tor-unavailable"],
    });
  });

  it("fails closed when a public reader cannot read Nostr relays", () => {
    expect(evaluateRoleCapabilities("public-reader", [], false)).toEqual({
      verdict: "reject",
      reduced_assurance: false,
      warnings: ["missing-feature:core.nostr-relay-read.v1"],
    });
  });

  it("rejects strict public and authenticated-light clients without Tor", () => {
    for (const role of ["public-reader", "authenticated-light"] as const) {
      expect(evaluateRoleCapabilities(role, [RELAY_READ], true)).toEqual({
        verdict: "reject",
        reduced_assurance: false,
        warnings: ["missing-feature:core.outbound-tor.v1"],
      });
    }
  });

  it("requires the full-node Tor, repository-relay, and onion-host feature set", () => {
    expect(evaluateRoleCapabilities("full-node", [RELAY_READ, OUTBOUND_TOR], false)).toEqual({
      verdict: "reject",
      reduced_assurance: false,
      warnings: [
        "missing-feature:core.repo-relay-client.v1",
        "missing-feature:core.onion-service-host.v1",
      ],
    });
    expect(evaluateRoleCapabilities("full-node", [
      RELAY_READ,
      OUTBOUND_TOR,
      REPO_RELAY,
      ONION_HOST,
    ], false)).toEqual({
      verdict: "accept",
      reduced_assurance: false,
      warnings: [],
    });
  });

  it("rejects unknown feature advertisements", () => {
    expect(evaluateRoleCapabilities("public-reader", [RELAY_READ, "core.future.v1"], false))
      .toEqual({
        verdict: "reject",
        reduced_assurance: false,
        warnings: ["unknown-feature:core.future.v1"],
      });
  });
});

describe("full-node reachability", () => {
  const complete = {
    features: [RELAY_READ, OUTBOUND_TOR, REPO_RELAY, ONION_HOST, BROWSER_RELAY],
    onion_service: `${"a".repeat(56)}.onion`,
    onion_version: 3 as const,
    onion_persistent: true,
    outbound_backends_via_tor: true,
    browser_compatible: true,
    shared_relays: ["wss://relay.example/"],
  };

  it("accepts a Tor-default full node with a persistent v3 onion service", () => {
    expect(validateFullNodeReachability(complete)).toEqual({
      verdict: "accept",
      reduced_assurance: false,
      warnings: [],
    });
  });

  it("rejects browser compatibility without a normalized clearnet shared relay", () => {
    expect(validateFullNodeReachability({
      ...complete,
      shared_relays: ["ws://relay.example", "wss://hiddenservice.onion"],
    })).toEqual({
      verdict: "reject",
      reduced_assurance: false,
      warnings: ["browser-shared-relay-unavailable"],
    });
  });

  it("rejects ephemeral, non-v3, or direct-clearnet full-node routing", () => {
    expect(validateFullNodeReachability({
      ...complete,
      onion_version: 2,
      onion_persistent: false,
      outbound_backends_via_tor: false,
    })).toEqual({
      verdict: "reject",
      reduced_assurance: false,
      warnings: [
        "persistent-v3-onion-required",
        "tor-default-outbound-required",
      ],
    });
  });
});

describe("generic role delegation addresses", () => {
  const roleId = "ab".repeat(32);

  it("accepts only agent plus a 64-lowercase-hex role identifier", () => {
    expect(validateRoleDelegationAddress(`agent:${roleId}`)).toEqual({
      verdict: "accept",
      role_id: roleId,
    });
  });

  it("rejects uppercase, short, non-hex, and alternate namespace forms", () => {
    for (const address of [
      `agent:${roleId.toUpperCase()}`,
      `agent:${roleId.slice(2)}`,
      `agent:${"z".repeat(64)}`,
      `bot:${roleId}`,
    ]) {
      expect(validateRoleDelegationAddress(address)).toEqual({ verdict: "reject" });
    }
  });
});
