import { createHash } from "node:crypto";
import { schnorr } from "@noble/curves/secp256k1";
import { describe, expect, it } from "vitest";
import {
  descriptorDigest,
  responseProof,
  secretCommitment,
  type InviteDescriptor,
  type InviteEnvelope,
  type InviteResponseInput,
} from "./one-time-invite.js";
import { jcsCanonicalize } from "./jcs.js";
import {
  createControlInvitePreauthorizationAuthority,
  verifyControlInvitePreauthorization,
  type ControlInvitePreauthorizationAuthorityConfig,
  type ControlInviteRequest,
  type ControlInviteTemplate,
} from "./control-invite-preauthorization.js";

const INVITER_SECRET = "01".padStart(64, "0");
const INVITER = Buffer.from(schnorr.getPublicKey(INVITER_SECRET)).toString("hex");
const CLIENT = "22".repeat(32);
const SECRET = "33".repeat(32);
const NOW = 1_200;

function inviteTemplate(
  overrides: Partial<ControlInviteTemplate> = {},
): ControlInviteTemplate {
  return {
    persona: "persona:alice",
    audience: "nip46://signer.example",
    client_key: CLIENT,
    client_class: "human-light",
    methods: ["sign_event"],
    event_kinds: [1, 7],
    limits: { requests_per_hour: 10, max_content_bytes: 4_096 },
    signer: INVITER,
    expires_at: 1_600,
    ...overrides,
  };
}

function signedInviteEnvelope(
  overrides: Partial<InviteDescriptor> = {},
  template: ControlInviteTemplate = inviteTemplate(),
  secret = SECRET,
): InviteEnvelope {
  const descriptor: InviteDescriptor = {
    version: 1,
    purpose: "control-enrollment",
    inviter_account: INVITER,
    invite_id: "11".repeat(32),
    rendezvous_pubkey: "44".repeat(32),
    relay_hints: ["wss://relay.example"],
    issued_at: 1_000,
    expires_at: template.expires_at,
    secret_sha256: secretCommitment(secret),
    approval_mode: "preauthorized",
    preauthorization: template as unknown as Record<string, unknown>,
    expected_client_pubkey: template.client_key,
    ...overrides,
  };
  return {
    descriptor,
    signature: Buffer.from(
      schnorr.sign(descriptorDigest(descriptor), INVITER_SECRET, new Uint8Array(32)),
    ).toString("hex"),
    secret,
  };
}

function response(
  overrides: Partial<InviteResponseInput> = {},
): InviteResponseInput {
  return {
    now: 0,
    expires_at: 1_600,
    expected_purpose: "control-enrollment",
    response_purpose: "control-enrollment",
    descriptor_valid: false,
    secret_commitment_valid: false,
    seal_valid: false,
    seal_pubkey: CLIENT,
    rumor_pubkey: CLIENT,
    proof_valid: false,
    keypackage_valid: false,
    capabilities_compatible: false,
    response_digest: "55".repeat(32),
    group_established: false,
    ...overrides,
  };
}

function inviteRequest(
  envelope: InviteEnvelope,
  template: ControlInviteTemplate = inviteTemplate(),
  overrides: Partial<ControlInviteRequest> = {},
): ControlInviteRequest {
  const responseInput = response();
  const request: Omit<ControlInviteRequest, "secret_proof"> = {
    purpose: "control-enrollment" as const,
    persona: template.persona,
    audience: template.audience,
    client_key: template.client_key,
    client_class: template.client_class,
    response: responseInput,
    ...overrides,
  };
  return {
    ...request,
    secret_proof: overrides.secret_proof ?? controlSecretProof(
      envelope,
      template,
      request as Omit<ControlInviteRequest, "secret_proof">,
    ),
  };
}

function controlSecretProof(
  envelope: InviteEnvelope,
  template: ControlInviteTemplate,
  request: Omit<ControlInviteRequest, "secret_proof">,
): string {
  return responseProof(envelope.secret, {
    invite_id: envelope.descriptor.invite_id,
    descriptor_digest: Buffer.from(descriptorDigest(envelope.descriptor)).toString("hex"),
    template_digest: createHash("sha256").update(jcsCanonicalize(template)).digest("hex"),
    purpose: request.purpose,
    persona: request.persona,
    audience: request.audience,
    client_key: request.client_key,
    client_class: request.client_class,
    response_now: request.response.now,
    response_expires_at: request.response.expires_at,
    response_expected_purpose: request.response.expected_purpose,
    response_purpose: request.response.response_purpose,
    response_seal_pubkey: request.response.seal_pubkey,
    response_rumor_pubkey: request.response.rumor_pubkey,
    response_digest: request.response.response_digest,
  });
}

function inviteConfig(
  overrides: Partial<ControlInvitePreauthorizationAuthorityConfig> = {},
): ControlInvitePreauthorizationAuthorityConfig {
  return {
    authority_id: "local-control-invite",
    trusted_now: () => NOW,
    load_revocation: async () => ({ revision: 7, state: "active" }),
    ...overrides,
  };
}

const reject = Object.freeze({
  verdict: "reject" as const,
  reason_code: "invite-preauthorization-invalid" as const,
});

describe("Control invite preauthorization authority", () => {
  it("accepts an exact signed, key-bound, currently active Control preauthorization", async () => {
    const template = inviteTemplate();
    const envelope = signedInviteEnvelope({}, template);
    const result = await verifyControlInvitePreauthorization(
      createControlInvitePreauthorizationAuthority(inviteConfig()),
      envelope,
      template,
      inviteRequest(envelope),
    );

    expect(result.verdict).toBe("accept");
    if (result.verdict !== "accept") throw new Error("exact fixture rejected");
    expect(result.output).toEqual({});
    expect(Object.isFrozen(result.output)).toBe(true);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects an invalid signed fragment", async () => {
    const template = inviteTemplate();
    const envelope = signedInviteEnvelope({}, template);
    envelope.signature = "00".repeat(64);
    await expect(verifyControlInvitePreauthorization(
      createControlInvitePreauthorizationAuthority(inviteConfig()),
      envelope, template, inviteRequest(envelope),
    )).resolves.toEqual(reject);
  });

  it("BLUE TEAM VALIDATION: synthetic/local forbids prompt-free KERI device conversion", async () => {
    const template = inviteTemplate();
    const envelope = signedInviteEnvelope({ purpose: "device-enrollment" }, template);
    await expect(verifyControlInvitePreauthorization(
      createControlInvitePreauthorizationAuthority(inviteConfig()),
      envelope, template, inviteRequest(envelope),
    )).resolves.toEqual(reject);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects client-key and response-key substitution", async () => {
    const template = inviteTemplate();
    const envelope = signedInviteEnvelope({}, template);
    for (const request of [
      inviteRequest(envelope, template, { client_key: "66".repeat(32) }),
      inviteRequest(envelope, template, { response: response({ seal_pubkey: "66".repeat(32) }) }),
      inviteRequest(envelope, template, { response: response({ rumor_pubkey: "66".repeat(32) }) }),
    ]) {
      await expect(verifyControlInvitePreauthorization(
        createControlInvitePreauthorizationAuthority(inviteConfig()),
        envelope, template, request,
      )).resolves.toEqual(reject);
    }
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects changed signer persona audience and class", async () => {
    const template = inviteTemplate();
    const envelope = signedInviteEnvelope({}, template);
    const cases: readonly [ControlInviteTemplate, ControlInviteRequest][] = [
      [inviteTemplate({ signer: "77".repeat(32) }), inviteRequest(envelope)],
      [template, inviteRequest(envelope, template, { persona: "persona:bob" })],
      [template, inviteRequest(envelope, template, { audience: "nip46://other.example" })],
      [template, inviteRequest(envelope, template, { client_class: "automated" })],
    ];
    for (const [candidateTemplate, request] of cases) {
      await expect(verifyControlInvitePreauthorization(
        createControlInvitePreauthorizationAuthority(inviteConfig()),
        envelope, candidateTemplate, request,
      )).resolves.toEqual(reject);
    }
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects changed methods kinds and limits", async () => {
    const template = inviteTemplate();
    const envelope = signedInviteEnvelope({}, template);
    for (const candidate of [
      inviteTemplate({ methods: ["get_public_key"] }),
      inviteTemplate({ event_kinds: [1, 42] }),
      inviteTemplate({ limits: { requests_per_hour: 11, max_content_bytes: 4_096 } }),
    ]) {
      await expect(verifyControlInvitePreauthorization(
        createControlInvitePreauthorizationAuthority(inviteConfig()),
        envelope, candidate, inviteRequest(envelope),
      )).resolves.toEqual(reject);
    }
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects invalid secret proof and commitment", async () => {
    const template = inviteTemplate();
    const envelope = signedInviteEnvelope({}, template);
    await expect(verifyControlInvitePreauthorization(
      createControlInvitePreauthorizationAuthority(inviteConfig()),
      envelope, template, inviteRequest(envelope, template, { secret_proof: "00".repeat(32) }),
    )).resolves.toEqual(reject);

    const wrongSecret = signedInviteEnvelope(
      { secret_sha256: secretCommitment(SECRET) }, template, "88".repeat(32),
    );
    await expect(verifyControlInvitePreauthorization(
      createControlInvitePreauthorizationAuthority(inviteConfig()),
      wrongSecret, template, inviteRequest(wrongSecret),
    )).resolves.toEqual(reject);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects expiry and current revocation", async () => {
    const template = inviteTemplate();
    const envelope = signedInviteEnvelope({}, template);
    for (const config of [
      inviteConfig({ trusted_now: () => template.expires_at }),
      inviteConfig({ load_revocation: async () => ({ revision: 8, state: "revoked" }) }),
    ]) {
      await expect(verifyControlInvitePreauthorization(
        createControlInvitePreauthorizationAuthority(config),
        envelope, template, inviteRequest(envelope),
      )).resolves.toEqual(reject);
    }
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects revocation revision change before mint", async () => {
    const template = inviteTemplate();
    const envelope = signedInviteEnvelope({}, template);
    let loads = 0;
    const authority = createControlInvitePreauthorizationAuthority(inviteConfig({
      load_revocation: async () => ({ revision: ++loads === 1 ? 7 : 8, state: "active" }),
    }));
    await expect(verifyControlInvitePreauthorization(
      authority, envelope, template, inviteRequest(envelope),
    )).resolves.toEqual(reject);
    expect(loads).toBe(2);
  });

  it("BLUE TEAM VALIDATION: synthetic/local ignores caller validity booleans as authority", async () => {
    const template = inviteTemplate();
    const envelope = signedInviteEnvelope({}, template);
    const assertedValid = response({
      descriptor_valid: true,
      secret_commitment_valid: true,
      seal_valid: true,
      proof_valid: true,
      keypackage_valid: true,
      capabilities_compatible: true,
      group_established: true,
    });
    await expect(verifyControlInvitePreauthorization(
      createControlInvitePreauthorizationAuthority(inviteConfig()),
      envelope,
      template,
      inviteRequest(envelope, template, {
        response: assertedValid,
        secret_proof: "00".repeat(32),
      }),
    )).resolves.toEqual(reject);

    const inconsistent = response({
      descriptor_valid: true,
      secret_commitment_valid: true,
      seal_valid: true,
      proof_valid: true,
      keypackage_valid: true,
      capabilities_compatible: true,
      group_established: true,
      response_purpose: "device-enrollment",
    });
    await expect(verifyControlInvitePreauthorization(
      createControlInvitePreauthorizationAuthority(inviteConfig()),
      envelope,
      template,
      inviteRequest(envelope, template, { response: inconsistent }),
    )).resolves.toEqual(reject);
  });

  it("BLUE TEAM VALIDATION: synthetic/local captures exact inputs before revocation lookup", async () => {
    let release!: (value: Readonly<{ revision: number; state: "active" }>) => void;
    const pending = new Promise<Readonly<{ revision: number; state: "active" }>>((resolve) => {
      release = resolve;
    });
    const template = inviteTemplate() as ControlInviteTemplate & { methods: string[] };
    const envelope = signedInviteEnvelope({}, template);
    const request = inviteRequest(envelope) as ControlInviteRequest & { response: InviteResponseInput };
    const decision = verifyControlInvitePreauthorization(
      createControlInvitePreauthorizationAuthority(inviteConfig({ load_revocation: () => pending })),
      envelope, template, request,
    );
    envelope.descriptor.purpose = "device-enrollment";
    template.methods[0] = "get_public_key";
    request.response.response_purpose = "device-enrollment";
    release({ revision: 7, state: "active" });

    await expect(decision).resolves.toMatchObject({ verdict: "accept" });
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects cloned and cross-authority handles", async () => {
    const template = inviteTemplate();
    const envelope = signedInviteEnvelope({}, template);
    const authority = createControlInvitePreauthorizationAuthority(inviteConfig());
    await expect(verifyControlInvitePreauthorization(
      { ...authority }, envelope, template, inviteRequest(envelope),
    )).resolves.toEqual(reject);
    await expect(verifyControlInvitePreauthorization(
      Object.freeze({}), envelope, template, inviteRequest(envelope),
    )).resolves.toEqual(reject);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects proxy and accessor inputs without invoking traps", async () => {
    let traps = 0;
    const template = inviteTemplate();
    const envelope = signedInviteEnvelope({}, template);
    const proxiedTemplate = new Proxy(template, {
      getPrototypeOf() { traps += 1; throw new Error("trap"); },
      ownKeys() { traps += 1; throw new Error("trap"); },
    });
    await expect(verifyControlInvitePreauthorization(
      createControlInvitePreauthorizationAuthority(inviteConfig()),
      envelope, proxiedTemplate, inviteRequest(envelope),
    )).resolves.toEqual(reject);

    const accessorRequest = inviteRequest(envelope) as Record<string, unknown>;
    Object.defineProperty(accessorRequest, "purpose", {
      enumerable: true,
      get() { traps += 1; throw new Error("trap"); },
    });
    await expect(verifyControlInvitePreauthorization(
      createControlInvitePreauthorizationAuthority(inviteConfig()),
      envelope, template, accessorRequest as ControlInviteRequest,
    )).resolves.toEqual(reject);
    expect(traps).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects non-scalar strings before revocation lookup", async () => {
    type Fixture = Readonly<{
      envelope: InviteEnvelope;
      template: ControlInviteTemplate;
      request: ControlInviteRequest;
    }>;
    const validFixture = (): Fixture => {
      const template = inviteTemplate();
      const envelope = signedInviteEnvelope({}, template);
      return { envelope, template, request: inviteRequest(envelope, template) };
    };
    const cases: Array<Readonly<{ name: string; fixture: Fixture }>> = [];

    for (const [name, malformed] of [["high", "\ud800"], ["low", "\udfff"]] as const) {
      {
        const fixture = validFixture();
        fixture.envelope.descriptor.relay_hints[0] = `wss://relay.example/${malformed}`;
        cases.push({ name: `envelope ${name} value`, fixture });
      }
      {
        const fixture = validFixture();
        cases.push({
          name: `template ${name} value`,
          fixture: { ...fixture, template: { ...fixture.template, audience: malformed } },
        });
      }
      {
        const fixture = validFixture();
        cases.push({
          name: `request ${name} value`,
          fixture: { ...fixture, request: { ...fixture.request, persona: malformed } },
        });
      }
      {
        const fixture = validFixture();
        cases.push({
          name: `response ${name} value`,
          fixture: {
            ...fixture,
            request: {
              ...fixture.request,
              response: { ...fixture.request.response, seal_pubkey: malformed },
            },
          },
        });
      }
    }

    {
      const fixture = validFixture();
      cases.push({
        name: "template invalid Unicode key",
        fixture: {
          ...fixture,
          template: { ...fixture.template, limits: { "\ud800": 1 } },
        },
      });
    }
    {
      const fixture = validFixture();
      const malformedResponse = { ...fixture.request.response } as Record<string, unknown>;
      malformedResponse["\udfff"] = "value";
      cases.push({
        name: "response invalid Unicode key",
        fixture: {
          ...fixture,
          request: {
            ...fixture.request,
            response: malformedResponse as unknown as InviteResponseInput,
          },
        },
      });
    }

    for (const testCase of cases) {
      let revocationLoads = 0;
      const authority = createControlInvitePreauthorizationAuthority(inviteConfig({
        load_revocation: async () => {
          revocationLoads += 1;
          return { revision: 7, state: "active" };
        },
      }));
      await expect(verifyControlInvitePreauthorization(
        authority,
        testCase.fixture.envelope,
        testCase.fixture.template,
        testCase.fixture.request,
      ), testCase.name).resolves.toEqual(reject);
      expect(revocationLoads, testCase.name).toBe(0);
    }
  });

  it("BLUE TEAM VALIDATION: synthetic/local captures constructor callbacks once", async () => {
    const template = inviteTemplate();
    const envelope = signedInviteEnvelope({}, template);
    const config = inviteConfig() as unknown as {
      authority_id: string;
      trusted_now: ControlInvitePreauthorizationAuthorityConfig["trusted_now"];
      load_revocation: ControlInvitePreauthorizationAuthorityConfig["load_revocation"];
    };
    const authority = createControlInvitePreauthorizationAuthority(config);
    config.trusted_now = () => 9_999;
    config.load_revocation = async () => ({ revision: 8, state: "revoked" });
    await expect(verifyControlInvitePreauthorization(
      authority, envelope, template, inviteRequest(envelope),
    )).resolves.toMatchObject({ verdict: "accept" });
  });
});
