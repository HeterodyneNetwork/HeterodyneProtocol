import { describe, expect, it } from "vitest";
import type { AgentPolicyDecision } from "./agent-moderation.js";
import { getPublicKey, signEvent, type NostrSignedEvent } from "./nostr.js";
import {
  createReplaceableSelectionAuthority,
  type ReplaceableSelectionAuthority,
} from "./replaceable-selection.js";
import { AUX_RAND } from "./vector-helpers.js";

type SubscriptionState = Readonly<{
  revision: number;
  subscribed: boolean;
  default_visible: boolean;
}>;

type SocialSubscriptionAuthority = Readonly<Record<never, never>>;
type SubscribedAgentPolicyView = Readonly<Record<never, never>>;
type SocialSubscriptionAuthorityConfig = Readonly<{
  authority_id: string;
  trusted_now: () => number;
  replaceable_selection: ReplaceableSelectionAuthority;
  load_subscription: (policy_persona: string) => Promise<SubscriptionState>;
}>;
type SocialSubscriptionInput = Readonly<{
  policy_persona: string;
  list_candidates: readonly NostrSignedEvent[];
  receipt_events: readonly NostrSignedEvent[];
  target_events: readonly NostrSignedEvent[];
  correction_events: readonly NostrSignedEvent[];
}>;
type SocialSubscriptionModule = {
  createSocialSubscriptionAuthority?: (
    config: SocialSubscriptionAuthorityConfig,
  ) => SocialSubscriptionAuthority;
  resolveSubscribedAgentPolicy?: (
    authority: SocialSubscriptionAuthority,
    input: SocialSubscriptionInput,
  ) => Promise<SubscribedAgentPolicyView | null>;
  applySubscribedAgentPolicy?: (
    view: SubscribedAgentPolicyView | null,
    event: NostrSignedEvent,
  ) => AgentPolicyDecision;
};

const NOW = 2_000;
const POLICY_SECRET = "0d".repeat(32);
const DEVICE_SECRET = "0e".repeat(32);
const REPLACEMENT_SECRET = "22".repeat(32);
const OTHER_POLICY_SECRET = "23".repeat(32);
const POLICY_PERSONA = getPublicKey(POLICY_SECRET);
const DEVICE_KEY = getPublicKey(DEVICE_SECRET);
const REPLACEMENT_KEY = getPublicKey(REPLACEMENT_SECRET);
const REASON = "agent-attribution-missing" as const;
const ASSOCIATION = { kind: "key", value: DEVICE_KEY } as const;
const MISSING_AUTHORITY = Object.freeze({}) as SocialSubscriptionAuthority;

async function loadModule(): Promise<SocialSubscriptionModule> {
  const loaded: unknown = await import("./social-subscription-authority.js")
    .catch(() => ({}));
  return loaded as SocialSubscriptionModule;
}

function selectionAuthority(): ReplaceableSelectionAuthority {
  return createReplaceableSelectionAuthority({ trusted_now: () => NOW });
}

function config(
  loadSubscription: (policyPersona: string) => Promise<SubscriptionState>,
): SocialSubscriptionAuthorityConfig {
  return {
    authority_id: "synthetic-local-social-policy",
    trusted_now: () => NOW,
    replaceable_selection: selectionAuthority(),
    load_subscription: loadSubscription,
  };
}

async function signedTarget(input: {
  secret?: string;
  created_at?: number;
  content?: string;
  association?: readonly ["key" | "role", string] | null;
} = {}): Promise<NostrSignedEvent> {
  const association = input.association === undefined
    ? ["key", DEVICE_KEY] as const
    : input.association;
  return await signEvent({
    secretKey: input.secret ?? DEVICE_SECRET,
    created_at: input.created_at ?? 1_000,
    kind: 1,
    tags: [
      ["L", "network.heterodyne.agent"],
      ["l", "ai", "network.heterodyne.agent"],
      ...(association === null
        ? []
        : [["heterodyne_agent", "v1", association[0], association[1]]]),
      ["agent_action", "publish"],
    ],
    content: input.content ?? "Synthetic local agent publication.",
    auxRand: AUX_RAND,
  });
}

async function signedReceipt(input: {
  target: NostrSignedEvent;
  secret?: string;
  created_at?: number;
  event_author?: string;
  association?: { kind: "key" | "role"; value: string } | null;
}): Promise<NostrSignedEvent> {
  const author = input.event_author ?? input.target.pubkey;
  return await signEvent({
    secretKey: input.secret ?? POLICY_SECRET,
    created_at: input.created_at ?? 1_100,
    kind: 1_985,
    tags: [
      ["L", "network.heterodyne.agent-policy"],
      ["l", REASON, "network.heterodyne.agent-policy"],
      ["e", input.target.id],
      ["p", author],
    ],
    content: JSON.stringify({
      profile: "heterodyne.social.agent-policy-receipt.v1",
      spec_version: "heterodyne/0.6.0",
      event_id: input.target.id,
      event_author: author,
      agent_association: input.association === undefined ? ASSOCIATION : input.association,
      policy: { id: "network.heterodyne.agent-policy", version: "1.0.0" },
      decision: "advisory-violation",
      reason: REASON,
      observed_at: input.created_at ?? 1_100,
      evidence: ["sha256:synthetic-local-evidence"],
      explanation: "Synthetic local boundary evidence.",
      remediation: "replace-signing-key",
    }),
    auxRand: AUX_RAND,
  });
}

async function signedList(input: {
  created_at: number;
  entries: readonly Readonly<{
    author: string;
    receipt: NostrSignedEvent;
    reason?: typeof REASON;
  }>[];
  secret?: string;
}): Promise<NostrSignedEvent> {
  return await signEvent({
    secretKey: input.secret ?? POLICY_SECRET,
    created_at: input.created_at,
    kind: 10_000,
    tags: [
      ["heterodyne", "social-agent-policy-list-v1"],
      ["spec_version", "heterodyne/0.6.0"],
      ...input.entries.flatMap(({ author, receipt, reason }) => [
        ["p", author],
        ["e", receipt.id],
        ["agent_violation", author, receipt.id, reason ?? REASON],
      ]),
    ],
    content: "",
    auxRand: AUX_RAND,
  });
}

async function signedCorrection(input: {
  receipt: NostrSignedEvent;
  target: NostrSignedEvent;
  secret?: string;
  created_at?: number;
}): Promise<NostrSignedEvent> {
  const createdAt = input.created_at ?? 1_300;
  return await signEvent({
    secretKey: input.secret ?? POLICY_SECRET,
    created_at: createdAt,
    kind: 1_985,
    tags: [
      ["L", "network.heterodyne.agent-policy"],
      ["l", "correction", "network.heterodyne.agent-policy"],
      ["e", input.receipt.id],
      ["p", input.target.pubkey],
    ],
    content: JSON.stringify({
      profile: "heterodyne.social.agent-policy-correction.v1",
      spec_version: "heterodyne/0.6.0",
      corrects_receipt_id: input.receipt.id,
      event_id: input.target.id,
      event_author: input.target.pubkey,
      agent_association: ASSOCIATION,
      policy: { id: "network.heterodyne.agent-policy", version: "1.0.0" },
      decision: "retract",
      corrected_at: createdAt,
      evidence: ["sha256:synthetic-local-correction"],
      explanation: "Synthetic local correction evidence.",
    }),
    auxRand: AUX_RAND,
  });
}

function inputOf(input: {
  list_candidates: readonly NostrSignedEvent[];
  receipt_events?: readonly NostrSignedEvent[];
  target_events?: readonly NostrSignedEvent[];
  correction_events?: readonly NostrSignedEvent[];
  policy_persona?: string;
}): SocialSubscriptionInput {
  return {
    policy_persona: input.policy_persona ?? POLICY_PERSONA,
    list_candidates: input.list_candidates,
    receipt_events: input.receipt_events ?? [],
    target_events: input.target_events ?? [],
    correction_events: input.correction_events ?? [],
  };
}

function subscribed(_policyPersona: string): Promise<SubscriptionState> {
  return Promise.resolve({ revision: 1, subscribed: true, default_visible: true });
}

describe("signed subscriber-local Social policy", () => {
  it("BLUE TEAM VALIDATION: synthetic/local exposes the opaque authority API", async () => {
    const module = await loadModule();
    expect(module.createSocialSubscriptionAuthority).toBeTypeOf("function");
    expect(module.resolveSubscribedAgentPolicy).toBeTypeOf("function");
    expect(module.applySubscribedAgentPolicy).toBeTypeOf("function");
  });

  it("BLUE TEAM VALIDATION: synthetic/local applies a signed current list and receipt to the exact event author", async () => {
    const module = await loadModule();
    const target = await signedTarget();
    const receipt = await signedReceipt({ target });
    const list = await signedList({
      created_at: 1_200,
      entries: [{ author: DEVICE_KEY, receipt }],
    });
    const authority = module.createSocialSubscriptionAuthority?.(config(subscribed))
      ?? MISSING_AUTHORITY;
    const view = await module.resolveSubscribedAgentPolicy?.(authority, inputOf({
      list_candidates: [list],
      receipt_events: [receipt],
      target_events: [target],
    })) ?? null;

    expect(view).not.toBeNull();
    expect(module.applySubscribedAgentPolicy?.(view, target)).toEqual({
      visible: false,
      muted: true,
      source: POLICY_PERSONA,
      reason: "subscribed-event-author-policy",
    });
  });

  it("BLUE TEAM VALIDATION: synthetic/local ignores an unsubscribed relay-selected list", async () => {
    const module = await loadModule();
    const target = await signedTarget();
    const receipt = await signedReceipt({ target });
    const relayList = await signedList({
      created_at: 1_200,
      entries: [{ author: DEVICE_KEY, receipt }],
    });
    const authority = module.createSocialSubscriptionAuthority?.(config(async () => ({
      revision: 1,
      subscribed: false,
      default_visible: true,
    }))) ?? MISSING_AUTHORITY;
    const view = await module.resolveSubscribedAgentPolicy?.(authority, inputOf({
      list_candidates: [relayList],
      receipt_events: [receipt],
      target_events: [target],
    })) ?? null;

    expect(view).toBeNull();
    expect(module.applySubscribedAgentPolicy?.(view, target))
      .toEqual({ visible: true, muted: false });
  });

  it("BLUE TEAM VALIDATION: synthetic/local selects the newer relay candidate without carrier priority", async () => {
    const module = await loadModule();
    const target = await signedTarget();
    const receipt = await signedReceipt({ target });
    const repositoryCandidate = await signedList({ created_at: 1_200, entries: [] });
    const relayCandidate = await signedList({
      created_at: 1_201,
      entries: [{ author: DEVICE_KEY, receipt }],
    });
    const authority = module.createSocialSubscriptionAuthority?.(config(subscribed))
      ?? MISSING_AUTHORITY;
    const view = await module.resolveSubscribedAgentPolicy?.(authority, inputOf({
      list_candidates: [repositoryCandidate, relayCandidate],
      receipt_events: [receipt],
      target_events: [target],
    })) ?? null;

    expect(module.applySubscribedAgentPolicy?.(view, target)?.muted).toBe(true);
  });

  it("BLUE TEAM VALIDATION: synthetic/local gives no authority to a stale replaced list", async () => {
    const module = await loadModule();
    const target = await signedTarget();
    const receipt = await signedReceipt({ target });
    const stale = await signedList({
      created_at: 1_200,
      entries: [{ author: DEVICE_KEY, receipt }],
    });
    const current = await signedList({ created_at: 1_201, entries: [] });
    const authority = module.createSocialSubscriptionAuthority?.(config(subscribed))
      ?? MISSING_AUTHORITY;
    const view = await module.resolveSubscribedAgentPolicy?.(authority, inputOf({
      list_candidates: [stale, current],
      receipt_events: [receipt],
      target_events: [target],
    })) ?? null;

    expect(module.applySubscribedAgentPolicy?.(view, target))
      .toEqual({ visible: true, muted: false });
  });

  it("BLUE TEAM VALIDATION: synthetic/local requires an exact correction and current removal before clearing an existing mute", async () => {
    const module = await loadModule();
    const target = await signedTarget();
    const receipt = await signedReceipt({ target });
    const adopted = await signedList({
      created_at: 1_200,
      entries: [{ author: DEVICE_KEY, receipt }],
    });
    const removed = await signedList({ created_at: 1_400, entries: [] });
    const wrongCorrection = await signedCorrection({
      receipt,
      target,
      secret: OTHER_POLICY_SECRET,
    });
    const correction = await signedCorrection({ receipt, target });
    const authority = module.createSocialSubscriptionAuthority?.(config(subscribed))
      ?? MISSING_AUTHORITY;
    const adoptedView = await module.resolveSubscribedAgentPolicy?.(authority, inputOf({
      list_candidates: [adopted], receipt_events: [receipt], target_events: [target],
    })) ?? null;
    expect(module.applySubscribedAgentPolicy?.(adoptedView, target)?.muted).toBe(true);

    const removalOnly = await module.resolveSubscribedAgentPolicy?.(authority, inputOf({
      list_candidates: [adopted, removed], receipt_events: [receipt], target_events: [target],
    })) ?? null;
    expect(module.applySubscribedAgentPolicy?.(removalOnly, target)?.muted).toBe(true);

    const wrongCorrectionView = await module.resolveSubscribedAgentPolicy?.(
      authority,
      inputOf({
        list_candidates: [adopted, removed],
        receipt_events: [receipt],
        target_events: [target],
        correction_events: [wrongCorrection],
      }),
    ) ?? null;
    expect(wrongCorrectionView).toBeNull();
    expect(module.applySubscribedAgentPolicy?.(adoptedView, target))
      .toEqual({ visible: true, muted: false });

    const corrected = await module.resolveSubscribedAgentPolicy?.(authority, inputOf({
      list_candidates: [adopted, removed],
      receipt_events: [receipt],
      target_events: [target],
      correction_events: [correction],
    })) ?? null;
    expect(module.applySubscribedAgentPolicy?.(corrected, target))
      .toEqual({ visible: true, muted: false });
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects an invalid receipt and a wrong policy author", async () => {
    const module = await loadModule();
    const target = await signedTarget();
    const validReceipt = await signedReceipt({ target });
    const invalidReceipt = { ...validReceipt, sig: "00".repeat(64) };
    const wrongPolicyReceipt = await signedReceipt({ target, secret: OTHER_POLICY_SECRET });
    for (const receipt of [invalidReceipt, wrongPolicyReceipt]) {
      const list = await signedList({
        created_at: 1_200,
        entries: [{ author: DEVICE_KEY, receipt }],
      });
      const authority = module.createSocialSubscriptionAuthority?.(config(subscribed))
        ?? MISSING_AUTHORITY;
      const view = await module.resolveSubscribedAgentPolicy?.(authority, inputOf({
        list_candidates: [list], receipt_events: [receipt], target_events: [target],
      })) ?? null;
      expect(module.applySubscribedAgentPolicy?.(view, target))
        .toEqual({ visible: true, muted: false });
    }
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects a receipt bound to the wrong author or device association", async () => {
    const module = await loadModule();
    const target = await signedTarget();
    const wrongAuthor = await signedReceipt({ target, event_author: REPLACEMENT_KEY });
    const wrongAssociation = await signedReceipt({
      target,
      association: { kind: "key", value: REPLACEMENT_KEY },
    });
    for (const receipt of [wrongAuthor, wrongAssociation]) {
      const list = await signedList({
        created_at: 1_200,
        entries: [{ author: receipt === wrongAuthor ? REPLACEMENT_KEY : DEVICE_KEY, receipt }],
      });
      const authority = module.createSocialSubscriptionAuthority?.(config(subscribed))
        ?? MISSING_AUTHORITY;
      const view = await module.resolveSubscribedAgentPolicy?.(authority, inputOf({
        list_candidates: [list], receipt_events: [receipt], target_events: [target],
      })) ?? null;
      expect(module.applySubscribedAgentPolicy?.(view, target))
        .toEqual({ visible: true, muted: false });
    }
  });

  it("BLUE TEAM VALIDATION: synthetic/local mutes only the exact offending signer and not its replacement", async () => {
    const module = await loadModule();
    const target = await signedTarget();
    const replacement = await signedTarget({
      secret: REPLACEMENT_SECRET,
      association: ["key", REPLACEMENT_KEY],
    });
    const receipt = await signedReceipt({ target });
    const list = await signedList({
      created_at: 1_200,
      entries: [{ author: DEVICE_KEY, receipt }],
    });
    const authority = module.createSocialSubscriptionAuthority?.(config(subscribed))
      ?? MISSING_AUTHORITY;
    const view = await module.resolveSubscribedAgentPolicy?.(authority, inputOf({
      list_candidates: [list], receipt_events: [receipt], target_events: [target],
    })) ?? null;

    expect(module.applySubscribedAgentPolicy?.(view, target)?.muted).toBe(true);
    expect(module.applySubscribedAgentPolicy?.(view, replacement))
      .toEqual({ visible: true, muted: false });
  });

  it("BLUE TEAM VALIDATION: synthetic/local keeps a default subscription visible and removable through current local state", async () => {
    const module = await loadModule();
    const target = await signedTarget();
    const receipt = await signedReceipt({ target });
    const list = await signedList({
      created_at: 1_200,
      entries: [{ author: DEVICE_KEY, receipt }],
    });
    let local: SubscriptionState = {
      revision: 1,
      subscribed: true,
      default_visible: true,
    };
    const authority = module.createSocialSubscriptionAuthority?.(config(async () => local))
      ?? MISSING_AUTHORITY;
    const evidence = inputOf({
      list_candidates: [list], receipt_events: [receipt], target_events: [target],
    });
    const enabled = await module.resolveSubscribedAgentPolicy?.(authority, evidence) ?? null;
    expect(module.applySubscribedAgentPolicy?.(enabled, target)?.muted).toBe(true);

    local = { revision: 2, subscribed: false, default_visible: true };
    expect(await module.resolveSubscribedAgentPolicy?.(authority, evidence)).toBeNull();
    expect(module.applySubscribedAgentPolicy?.(enabled, target))
      .toEqual({ visible: true, muted: false });

    local = { revision: 1, subscribed: true, default_visible: true };
    expect(await module.resolveSubscribedAgentPolicy?.(authority, evidence)).toBeNull();

    local = { revision: 3, subscribed: true, default_visible: true };
    const reenabled = await module.resolveSubscribedAgentPolicy?.(authority, evidence) ?? null;
    expect(module.applySubscribedAgentPolicy?.(reenabled, target)?.muted).toBe(true);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects hidden default state and caller supplied policy booleans", async () => {
    const module = await loadModule();
    const target = await signedTarget();
    const receipt = await signedReceipt({ target });
    const list = await signedList({
      created_at: 1_200,
      entries: [{ author: DEVICE_KEY, receipt }],
    });
    const hidden = module.createSocialSubscriptionAuthority?.(config(async () => ({
      revision: 1,
      subscribed: true,
      default_visible: false,
    }))) ?? MISSING_AUTHORITY;
    expect(await module.resolveSubscribedAgentPolicy?.(hidden, inputOf({
      list_candidates: [list], receipt_events: [receipt], target_events: [target],
    }))).toBeNull();

    let accessorCalls = 0;
    const injected = Object.defineProperty({
      ...inputOf({
        list_candidates: [list], receipt_events: [receipt], target_events: [target],
      }),
    }, "subscribed", {
      enumerable: true,
      get() {
        accessorCalls += 1;
        return true;
      },
    });
    const authority = module.createSocialSubscriptionAuthority?.(config(subscribed))
      ?? MISSING_AUTHORITY;
    expect(await module.resolveSubscribedAgentPolicy?.(
      authority,
      injected as unknown as SocialSubscriptionInput,
    )).toBeNull();
    expect(accessorCalls).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects cloned and cross-authority artifacts while retaining verified snapshots", async () => {
    const module = await loadModule();
    const target = await signedTarget();
    const retainedTarget = structuredClone(target);
    const receipt = await signedReceipt({ target });
    const list = await signedList({
      created_at: 1_200,
      entries: [{ author: DEVICE_KEY, receipt }],
    });
    const authority = module.createSocialSubscriptionAuthority?.(config(subscribed))
      ?? MISSING_AUTHORITY;
    const evidence = inputOf({
      list_candidates: [list], receipt_events: [receipt], target_events: [target],
    });
    const view = await module.resolveSubscribedAgentPolicy?.(authority, evidence) ?? null;

    expect(module.applySubscribedAgentPolicy?.(
      structuredClone(view) as SubscribedAgentPolicyView,
      retainedTarget,
    )).toEqual({ visible: true, muted: false });
    expect(await module.resolveSubscribedAgentPolicy?.(
      structuredClone(authority) as SocialSubscriptionAuthority,
      evidence,
    )).toBeNull();
    expect(await module.resolveSubscribedAgentPolicy?.(
      view as SocialSubscriptionAuthority,
      evidence,
    )).toBeNull();
    expect(Reflect.set(view ?? Object.freeze({}), "subscribed", true)).toBe(false);

    target.content = "mutated after resolution";
    receipt.content = "mutated after resolution";
    list.content = "mutated after resolution";
    expect(module.applySubscribedAgentPolicy?.(view, retainedTarget)?.muted).toBe(true);
    expect(module.applySubscribedAgentPolicy?.(view, target))
      .toEqual({ visible: true, muted: false });
  });

  it("BLUE TEAM VALIDATION: synthetic/local captures constructor callbacks exactly once", async () => {
    const module = await loadModule();
    const target = await signedTarget();
    const receipt = await signedReceipt({ target });
    const list = await signedList({
      created_at: 1_200,
      entries: [{ author: DEVICE_KEY, receipt }],
    });
    let originalCalls = 0;
    let requestedPersona = "";
    const authorityConfig = config(async (policyPersona) => {
      originalCalls += 1;
      requestedPersona = policyPersona;
      return { revision: 1, subscribed: true, default_visible: true };
    });
    const authority = module.createSocialSubscriptionAuthority?.(authorityConfig)
      ?? MISSING_AUTHORITY;
    (authorityConfig as { load_subscription: SocialSubscriptionAuthorityConfig["load_subscription"] })
      .load_subscription = async () => ({
        revision: 2, subscribed: false, default_visible: true,
      });
    const view = await module.resolveSubscribedAgentPolicy?.(authority, inputOf({
      list_candidates: [list], receipt_events: [receipt], target_events: [target],
    })) ?? null;

    expect(originalCalls).toBe(1);
    expect(requestedPersona).toBe(POLICY_PERSONA);
    expect(module.applySubscribedAgentPolicy?.(view, target)?.muted).toBe(true);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects proxy and accessor containers without executing traps", async () => {
    const module = await loadModule();
    let configTrapCalls = 0;
    const proxiedConfig = new Proxy(config(subscribed), {
      get() {
        configTrapCalls += 1;
        throw new Error("config trap must not execute");
      },
    });
    expect(() => module.createSocialSubscriptionAuthority?.(proxiedConfig))
      .toThrow(/social-subscription-authority-invalid/);
    expect(configTrapCalls).toBe(0);

    let configGetterCalls = 0;
    const accessorConfig = Object.defineProperty({
      authority_id: "synthetic-local-social-policy-accessor",
      trusted_now: () => NOW,
      replaceable_selection: selectionAuthority(),
    }, "load_subscription", {
      enumerable: true,
      get() {
        configGetterCalls += 1;
        return subscribed;
      },
    });
    expect(() => module.createSocialSubscriptionAuthority?.(
      accessorConfig as SocialSubscriptionAuthorityConfig,
    )).toThrow(/social-subscription-authority-invalid/);
    expect(configGetterCalls).toBe(0);

    const authority = module.createSocialSubscriptionAuthority?.(config(subscribed))
      ?? MISSING_AUTHORITY;
    let inputTrapCalls = 0;
    const proxiedInput = new Proxy(inputOf({ list_candidates: [] }), {
      get() {
        inputTrapCalls += 1;
        throw new Error("input trap must not execute");
      },
    });
    expect(await module.resolveSubscribedAgentPolicy?.(authority, proxiedInput)).toBeNull();
    expect(inputTrapCalls).toBe(0);

    let arrayTrapCalls = 0;
    const proxiedArray = new Proxy([] as NostrSignedEvent[], {
      get() {
        arrayTrapCalls += 1;
        throw new Error("array trap must not execute");
      },
    });
    expect(await module.resolveSubscribedAgentPolicy?.(authority, inputOf({
      list_candidates: proxiedArray,
    }))).toBeNull();
    expect(arrayTrapCalls).toBe(0);

    const target = await signedTarget();
    const receipt = await signedReceipt({ target });
    const list = await signedList({
      created_at: 1_200,
      entries: [{ author: DEVICE_KEY, receipt }],
    });
    let eventTrapCalls = 0;
    const proxiedEvent = new Proxy(target, {
      get() {
        eventTrapCalls += 1;
        throw new Error("event trap must not execute");
      },
    });
    expect(await module.resolveSubscribedAgentPolicy?.(authority, inputOf({
      list_candidates: [list],
      receipt_events: [receipt],
      target_events: [proxiedEvent],
    }))).toBeNull();
    expect(eventTrapCalls).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects opaque subscription results and event proxies without executing traps", async () => {
    const module = await loadModule();
    let stateTrapCalls = 0;
    const state = new Proxy({
      revision: 1, subscribed: true, default_visible: true,
    }, {
      get() {
        stateTrapCalls += 1;
        throw new Error("subscription trap must not execute");
      },
    });
    const returnOpaqueState = (() => state) as unknown as (
      policyPersona: string,
    ) => Promise<SubscriptionState>;
    const authority = module.createSocialSubscriptionAuthority?.(config(returnOpaqueState))
      ?? MISSING_AUTHORITY;
    expect(await module.resolveSubscribedAgentPolicy?.(
      authority,
      inputOf({ list_candidates: [] }),
    )).toBeNull();
    expect(stateTrapCalls).toBe(0);

    let stateGetterCalls = 0;
    const accessorState = Object.defineProperty({
      revision: 1,
      default_visible: true,
    }, "subscribed", {
      enumerable: true,
      get() {
        stateGetterCalls += 1;
        return true;
      },
    });
    const accessorAuthority = module.createSocialSubscriptionAuthority?.(config(
      async () => accessorState as SubscriptionState,
    )) ?? MISSING_AUTHORITY;
    expect(await module.resolveSubscribedAgentPolicy?.(
      accessorAuthority,
      inputOf({ list_candidates: [] }),
    )).toBeNull();
    expect(stateGetterCalls).toBe(0);

    let eventTrapCalls = 0;
    const event = new Proxy({} as NostrSignedEvent, {
      get() {
        eventTrapCalls += 1;
        throw new Error("event trap must not execute");
      },
    });
    expect(module.applySubscribedAgentPolicy?.(Object.freeze({}), event))
      .toEqual({ visible: true, muted: false });
    expect(eventTrapCalls).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects a hostile member mixed into every evidence collection without executing traps or loading subscription state", async () => {
    const module = await loadModule();
    const target = await signedTarget();
    const receipt = await signedReceipt({ target });
    const adopted = await signedList({
      created_at: 1_200,
      entries: [{ author: DEVICE_KEY, receipt }],
    });
    const correction = await signedCorrection({ receipt, target, created_at: 1_300 });
    const removed = await signedList({ created_at: 1_400, entries: [] });
    const base = inputOf({
      list_candidates: [adopted, removed],
      receipt_events: [receipt],
      target_events: [target],
      correction_events: [correction],
    });
    const keys = [
      "list_candidates",
      "receipt_events",
      "target_events",
      "correction_events",
    ] as const;

    for (const key of keys) {
      let trapCalls = 0;
      let loadCalls = 0;
      let clockCalls = 0;
      const hostile = new Proxy(structuredClone(target), {
        get() {
          trapCalls += 1;
          throw new Error("mixed evidence trap must not execute");
        },
      });
      const authority = module.createSocialSubscriptionAuthority?.({
        ...config(async () => {
          loadCalls += 1;
          return { revision: 1, subscribed: true, default_visible: true };
        }),
        trusted_now: () => {
          clockCalls += 1;
          return NOW;
        },
      }) ?? MISSING_AUTHORITY;
      const mixed = {
        ...base,
        [key]: [...base[key], hostile],
      } as SocialSubscriptionInput;

      expect(await module.resolveSubscribedAgentPolicy?.(authority, mixed)).toBeNull();
      expect(trapCalls).toBe(0);
      expect(clockCalls).toBe(0);
      expect(loadCalls).toBe(0);
    }
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects every malformed mixed evidence shape atomically with zero accessor calls", async () => {
    const module = await loadModule();
    const target = await signedTarget();
    const receipt = await signedReceipt({ target });
    const list = await signedList({
      created_at: 1_200,
      entries: [{ author: DEVICE_KEY, receipt }],
    });
    const base = inputOf({
      list_candidates: [list],
      receipt_events: [receipt],
      target_events: [target],
    });
    const keys = [
      "list_candidates",
      "receipt_events",
      "target_events",
      "correction_events",
    ] as const;
    const variants = ["accessor", "symbol", "extra", "sparse-tags"] as const;

    for (const key of keys) {
      for (const variant of variants) {
        let getterCalls = 0;
        let loadCalls = 0;
        let hostile: NostrSignedEvent;
        if (variant === "accessor") {
          hostile = Object.defineProperty({ ...target }, "content", {
            enumerable: true,
            get() {
              getterCalls += 1;
              return target.content;
            },
          }) as NostrSignedEvent;
        } else if (variant === "symbol") {
          hostile = {
            ...target,
            [Symbol("synthetic-local-hostile")]: true,
          } as NostrSignedEvent;
        } else if (variant === "extra") {
          hostile = { ...target, injected: true } as unknown as NostrSignedEvent;
        } else {
          const sparseTags = new Array<string[]>(2);
          sparseTags[0] = ["L", "network.heterodyne.agent"];
          hostile = { ...target, tags: sparseTags };
        }
        const authority = module.createSocialSubscriptionAuthority?.(config(async () => {
          loadCalls += 1;
          return { revision: 1, subscribed: true, default_visible: true };
        })) ?? MISSING_AUTHORITY;
        const mixed = {
          ...base,
          [key]: [...base[key], hostile],
        } as SocialSubscriptionInput;

        expect(await module.resolveSubscribedAgentPolicy?.(authority, mixed)).toBeNull();
        expect(getterCalls).toBe(0);
        expect(loadCalls).toBe(0);
      }

      let loadCalls = 0;
      const sparseCollection = new Array<NostrSignedEvent>(2);
      sparseCollection[0] = base[key][0] ?? target;
      const authority = module.createSocialSubscriptionAuthority?.(config(async () => {
        loadCalls += 1;
        return { revision: 1, subscribed: true, default_visible: true };
      })) ?? MISSING_AUTHORITY;
      expect(await module.resolveSubscribedAgentPolicy?.(authority, {
        ...base,
        [key]: sparseCollection,
      } as SocialSubscriptionInput)).toBeNull();
      expect(loadCalls).toBe(0);
    }
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects an invalid signature mixed into every evidence collection", async () => {
    const module = await loadModule();
    const target = await signedTarget();
    const receipt = await signedReceipt({ target });
    const adopted = await signedList({
      created_at: 1_200,
      entries: [{ author: DEVICE_KEY, receipt }],
    });
    const correction = await signedCorrection({ receipt, target, created_at: 1_300 });
    const removed = await signedList({ created_at: 1_400, entries: [] });
    const base = inputOf({
      list_candidates: [adopted, removed],
      receipt_events: [receipt],
      target_events: [target],
      correction_events: [correction],
    });
    const keys = [
      "list_candidates",
      "receipt_events",
      "target_events",
      "correction_events",
    ] as const;

    for (const key of keys) {
      let loadCalls = 0;
      const invalid = {
        ...(base[key][0] ?? target),
        sig: "00".repeat(64),
      };
      const authority = module.createSocialSubscriptionAuthority?.(config(async () => {
        loadCalls += 1;
        return { revision: 1, subscribed: true, default_visible: true };
      })) ?? MISSING_AUTHORITY;
      expect(await module.resolveSubscribedAgentPolicy?.(authority, {
        ...base,
        [key]: [...base[key], invalid],
      } as SocialSubscriptionInput)).toBeNull();
      expect(loadCalls).toBe(0);
    }
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects target-receipt-list chronology inversions before loading local state", async () => {
    const module = await loadModule();
    const targetAfterReceipt = await signedTarget({ created_at: 1_200 });
    const backdatedReceipt = await signedReceipt({
      target: targetAfterReceipt,
      created_at: 1_100,
    });
    const laterList = await signedList({
      created_at: 1_300,
      entries: [{ author: DEVICE_KEY, receipt: backdatedReceipt }],
    });
    const ordinaryTarget = await signedTarget({ created_at: 1_000 });
    const ordinaryReceipt = await signedReceipt({
      target: ordinaryTarget,
      created_at: 1_200,
    });
    const backdatedList = await signedList({
      created_at: 1_100,
      entries: [{ author: DEVICE_KEY, receipt: ordinaryReceipt }],
    });

    for (const evidence of [
      inputOf({
        list_candidates: [laterList],
        receipt_events: [backdatedReceipt],
        target_events: [targetAfterReceipt],
      }),
      inputOf({
        list_candidates: [backdatedList],
        receipt_events: [ordinaryReceipt],
        target_events: [ordinaryTarget],
      }),
    ]) {
      let loadCalls = 0;
      const authority = module.createSocialSubscriptionAuthority?.(config(async () => {
        loadCalls += 1;
        return { revision: 1, subscribed: true, default_visible: true };
      })) ?? MISSING_AUTHORITY;
      expect(await module.resolveSubscribedAgentPolicy?.(authority, evidence)).toBeNull();
      expect(loadCalls).toBe(0);
    }
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects a correction signed after its removal list", async () => {
    const module = await loadModule();
    const target = await signedTarget({ created_at: 1_000 });
    const receipt = await signedReceipt({ target, created_at: 1_100 });
    const adopted = await signedList({
      created_at: 1_200,
      entries: [{ author: DEVICE_KEY, receipt }],
    });
    const removedBeforeCorrection = await signedList({ created_at: 1_250, entries: [] });
    const correction = await signedCorrection({ receipt, target, created_at: 1_300 });
    let loadCalls = 0;
    const authority = module.createSocialSubscriptionAuthority?.(config(async () => {
      loadCalls += 1;
      return { revision: 1, subscribed: true, default_visible: true };
    })) ?? MISSING_AUTHORITY;
    const adoptedView = await module.resolveSubscribedAgentPolicy?.(authority, inputOf({
      list_candidates: [adopted],
      receipt_events: [receipt],
      target_events: [target],
    })) ?? null;
    expect(module.applySubscribedAgentPolicy?.(adoptedView, target)?.muted).toBe(true);
    expect(loadCalls).toBe(1);

    expect(await module.resolveSubscribedAgentPolicy?.(authority, inputOf({
      list_candidates: [adopted, removedBeforeCorrection],
      receipt_events: [receipt],
      target_events: [target],
      correction_events: [correction],
    }))).toBeNull();
    expect(loadCalls).toBe(1);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects future signed substitutions in every evidence collection", async () => {
    const module = await loadModule();
    const target = await signedTarget({ created_at: 1_000 });
    const receipt = await signedReceipt({ target, created_at: 1_100 });
    const list = await signedList({
      created_at: 1_200,
      entries: [{ author: DEVICE_KEY, receipt }],
    });
    const correction = await signedCorrection({ receipt, target, created_at: 1_300 });
    const futureTarget = await signedTarget({ created_at: NOW + 901, content: "future" });
    const futureReceipt = await signedReceipt({
      target,
      created_at: NOW + 901,
    });
    const futureList = await signedList({ created_at: NOW + 901, entries: [] });
    const futureCorrection = await signedCorrection({
      receipt,
      target,
      created_at: NOW + 901,
    });
    const variants: SocialSubscriptionInput[] = [
      inputOf({
        list_candidates: [list, futureList],
        receipt_events: [receipt],
        target_events: [target],
      }),
      inputOf({
        list_candidates: [list],
        receipt_events: [receipt, futureReceipt],
        target_events: [target],
      }),
      inputOf({
        list_candidates: [list],
        receipt_events: [receipt],
        target_events: [target, futureTarget],
      }),
      inputOf({
        list_candidates: [list],
        receipt_events: [receipt],
        target_events: [target],
        correction_events: [correction, futureCorrection],
      }),
    ];

    for (const evidence of variants) {
      let loadCalls = 0;
      const authority = module.createSocialSubscriptionAuthority?.(config(async () => {
        loadCalls += 1;
        return { revision: 1, subscribed: true, default_visible: true };
      })) ?? MISSING_AUTHORITY;
      expect(await module.resolveSubscribedAgentPolicy?.(authority, evidence)).toBeNull();
      expect(loadCalls).toBe(0);
    }
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects oversized event and aggregate inputs before loading local state", async () => {
    const module = await loadModule();
    const target = await signedTarget();
    const receipt = await signedReceipt({ target });
    const list = await signedList({
      created_at: 1_200,
      entries: [{ author: DEVICE_KEY, receipt }],
    });
    const base = inputOf({
      list_candidates: [list],
      receipt_events: [receipt],
      target_events: [target],
    });
    const multibyteOversize = await signedTarget({ content: "€".repeat(30_000) });
    const hugeTags = Array.from({ length: 10_000 }, () => ["x"]);
    const hugeWidth = [Array.from({ length: 100 }, () => "x")];
    const cases: SocialSubscriptionInput[] = [
      { ...base, target_events: [target, { ...target, content: "x".repeat(1_000_000) }] },
      { ...base, target_events: [target, multibyteOversize] },
      { ...base, target_events: [target, { ...target, tags: hugeTags }] },
      { ...base, target_events: [target, { ...target, tags: hugeWidth }] },
      { ...base, target_events: [target, { ...target, tags: [["x", "y".repeat(100_000)]] }] },
      { ...base, target_events: Array.from({ length: 300 }, () => target) },
      {
        ...base,
        target_events: Array.from(
          { length: 64 },
          () => ({ ...target, content: "x".repeat(60_000) }),
        ),
      },
      {
        ...base,
        list_candidates: Array.from({ length: 64 }, () => list),
        receipt_events: Array.from({ length: 64 }, () => receipt),
        target_events: Array.from({ length: 64 }, () => target),
        correction_events: Array.from({ length: 64 }, () => target),
      },
    ];

    for (const evidence of cases) {
      let loadCalls = 0;
      let clockCalls = 0;
      const authority = module.createSocialSubscriptionAuthority?.({
        ...config(async () => {
          loadCalls += 1;
          return { revision: 1, subscribed: true, default_visible: true };
        }),
        trusted_now: () => {
          clockCalls += 1;
          return NOW;
        },
      }) ?? MISSING_AUTHORITY;
      expect(await module.resolveSubscribedAgentPolicy?.(authority, evidence)).toBeNull();
      expect(clockCalls).toBe(0);
      expect(loadCalls).toBe(0);
    }
  });
});
