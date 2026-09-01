import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import ts from "typescript";
import { buildWorkspaceCases } from "./workspace.js";
import { buildCommsCases } from "./comms.js";
import { buildCoreCases } from "./core.js";
import { buildAssuranceCases } from "./assurance.js";
import { buildProfileCases } from "./profiles.js";
import { buildSocialCases } from "./social.js";
import { resolveCurrentRepositoryWriterBinding } from "../core-writer-binding.js";
import {
  currentCaseContract,
  currentCaseIds,
} from "./case-contracts.js";
import {
  buildRegisteredCurrentCaseFixtures,
  inspectCurrentBoundaryExecution,
  invokeCurrentBoundary,
  invokeCurrentBoundaryWithTestEvaluatorSubstitution,
  invokeCurrentBoundaryWithTestPlanOmission,
  registeredPrivateCurrentFixtureIds,
} from "./boundary-runners.js";
import {
  certifyBoundaryExecution,
  inspectSemanticBoundaryCertificate,
  semanticPostconditionInventory,
} from "./semantic-certificates.js";
import type { CurrentCaseFixture } from "./types.js";
import { declaredPrivateCurrentFixtureIds } from "./private-fixture-specification.js";

async function workspaceSignatureExecution() {
  const fixture = buildWorkspaceCases().find(({ vector_id }) =>
    vector_id === "workspace/signature-invalid"
  );
  if (fixture === undefined) throw new Error("missing Workspace signature fixture");
  const contract = currentCaseContract(fixture.vector_id);
  const execution = await invokeCurrentBoundary(contract.boundary_id, fixture);
  return { fixture, contract, execution };
}

const RETIRED_TASK_FIFTEEN_CASES = [
  "assurance/retired-key-post-compromise",
  "core/retired-key-authority-window-invalid",
  "comms/dm-invite-revoked-device",
  "comms/dm-invite-unbound-device",
  "control/agent-attribution-bypass-prohibited",
  "control/agent-human-profile-prohibited",
  "control/agent-key-access-prohibited",
  "control/agent-method-prohibited",
  "control/agent-resource-denied",
  "control/request-id-conflict",
  "control/signed-event-invalid",
] as const;

const TASK_FIFTEEN_REAL_MAPPINGS = {
  "comms/agent-sender-proof-invalid": "agent-publication-authorization.authorizeAndSignAgentPublication",
  "comms/agent-workload-token-accepted": "agent-publication-authorization.authorizeAndSignAgentPublication",
  "comms/conversation-rejected": "marmot-admission-authority.verifyMarmotWelcome+admitOrdinaryMarmotWelcome",
  "comms/invite-authentication-invalid": "one-time-invite-authority.redeemOneTimeInvite",
  "comms/marmot-agent-scope-denied": "persona-inbox-admission-authority.admitPersonaInboxBundle",
  "comms/marmot-exact-bytes-durable": "marmot-archive-retention-authority.appendExactMarmotArchive",
  "comms/marmot-expiration-not-erasure": "marmot-archive-retention-authority.appendExactMarmotArchive+expireMarmotPresentation+acknowledgeMarmotArchive",
  "comms/marmot-keypackage-replayed": "persona-inbox-admission-authority.admitPersonaInboxBundle",
  "comms/marmot-ordinary-welcome-held": "marmot-admission-authority.verifyMarmotWelcome+admitOrdinaryMarmotWelcome",
  "comms/marmot-premature-ack": "marmot-archive-retention-authority.acknowledgeMarmotArchive",
  "comms/marmot-private-inbox-nid-required": "persona-inbox-admission-authority.admitPersonaInboxBundle",
  "control/compromise-reset-evidence-invalid": "control-signing.validateCompromiseReset",
  "control/compromise-reset-inventory-mismatch": "control-signing.validateCompromiseReset",
  "control/compromise-reset-unauthenticated": "control-signing.validateCompromiseReset",
  "control/subordinate-reauthorization-required": "control-signing.validateCompromiseReset",
  "control/device-code-display-mismatch": "control-device-authorization.createControlDeviceTransaction+pollControlDeviceAuthorization",
  "control/device-code-invalid": "control-device-authorization.createControlDeviceTransaction+pollControlDeviceAuthorization",
  "control/device-code-rate-limited": "control-device-authorization.createControlDeviceTransaction+pollControlDeviceAuthorization",
  "control/enrollment-unavailable": "control-enrollment-admission.admitControlEnrollment",
  "control/frame-invalid": "profile-negotiation.validateCurrentControlFrameProfile",
  "control/invite-preauthorization-invalid": "control-invite-preauthorization.verifyControlInvitePreauthorization",
  "control/keypackage-invalid": "control-enrollment-admission.admitControlEnrollment",
  "control/keypackage-replenishment-paused": "control-enrollment-admission.admitControlEnrollment",
  "control/signer-effect-indeterminate": "control-signing.executePersistedAutomatedSigning+executePersistedAutomatedSigning",
  "control/token-invalid": "control-token-verifier.verifyControlToken+consumeVerifiedControlToken",
  "core/friend-cache-unsigned": "core-operational-assurance-authority.verifyCacheCandidate",
  "core/profile-repository-selection-required": "canonical-profile-selection-authority.selectCanonicalProfile",
  "core/relay-profile-mutated": "core-operational-assurance-authority.verifyRelayProfileCarrier",
  "core/strict-mode-without-tor": "core-operational-assurance-authority.verifyStrictTransport",
  "workspace/carrier-not-ambient-authority": "workspace.authenticateWorkspaceRepositoryView+resolveWorkspaceEffectiveAuthorization",
  "workspace/current-capability-intersection": "workspace.authenticateWorkspaceRepositoryView+resolveWorkspaceEffectiveAuthorization+consumeWorkspaceInvitationAcceptance+evaluateGrantActivation",
  "workspace/inheritance-escalation-rejected": "workspace.authenticateWorkspaceRepositoryView+resolveWorkspaceEffectiveAuthorization",
  "workspace/invitation-replay": "workspace.authenticateWorkspaceRepositoryView+resolveWorkspaceEffectiveAuthorization+consumeWorkspaceInvitationAcceptance+evaluateGrantActivation+consumeWorkspaceInvitationAcceptance",
  "workspace/revocation-blocks-future-effect": "workspace.authenticateWorkspaceRepositoryView+resolveWorkspaceEffectiveAuthorization",
} as const;

const TASK_FIFTEEN_SOCIAL_COMPOSITES = {
  "social/profile-heterodyne-social-agent-policy-list-v1": "social-subscription-authority.resolveSubscribedAgentPolicy+applySubscribedAgentPolicy",
  "social/profile-heterodyne-social-agent-policy-receipt-v1": "social-subscription-authority.resolveSubscribedAgentPolicy+applySubscribedAgentPolicy",
} as const;

const TASK_FIFTEEN_HOSTILE_MATRIX = Object.entries({
  ...TASK_FIFTEEN_REAL_MAPPINGS,
  ...TASK_FIFTEEN_SOCIAL_COMPOSITES,
});

const MATRIX_CATALOGS = new Map<string, Promise<CurrentCaseFixture[]>>();

function matrixCatalog(name: string): Promise<CurrentCaseFixture[]> {
  let catalog = MATRIX_CATALOGS.get(name);
  if (catalog === undefined) {
    catalog = buildRegisteredCurrentCaseFixtures();
    MATRIX_CATALOGS.set(name, catalog);
  }
  return catalog;
}

async function matrixFixture(name: string, vectorId: string): Promise<CurrentCaseFixture> {
  const fixture = (await matrixCatalog(name)).find(({ vector_id }) => vector_id === vectorId);
  if (fixture === undefined) throw new Error(`missing matrix fixture: ${vectorId}`);
  return fixture;
}

function objectLiteralKeys(source: string, variableName: string): readonly string[] {
  const file = ts.createSourceFile("catalog.ts", source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  let keys: string[] | undefined;
  const unwrap = (expression: ts.Expression): ts.Expression => {
    if (ts.isAsExpression(expression) || ts.isSatisfiesExpression(expression)
      || ts.isParenthesizedExpression(expression)) return unwrap(expression.expression);
    return expression;
  };
  const visit = (node: ts.Node): void => {
    if (ts.isVariableDeclaration(node)
      && ts.isIdentifier(node.name)
      && node.name.text === variableName
      && node.initializer !== undefined
      && ts.isObjectLiteralExpression(unwrap(node.initializer))) {
      const object = unwrap(node.initializer) as ts.ObjectLiteralExpression;
      keys = object.properties.flatMap((property) =>
        ts.isPropertyAssignment(property) || ts.isMethodDeclaration(property)
          ? [property.name.getText(file).replace(/^['"]|['"]$/gu, "")]
          : []
      );
    }
    ts.forEachChild(node, visit);
  };
  visit(file);
  if (keys === undefined) throw new Error(`missing object catalog ${variableName}`);
  return keys;
}

function evaluatorBypasses(source: string): readonly string[] {
  const file = ts.createSourceFile(
    "boundary-runners.ts",
    source,
    ts.ScriptTarget.Latest,
    true,
    ts.ScriptKind.TS,
  );
  const imported = new Set<string>();
  for (const statement of file.statements) {
    if (!ts.isImportDeclaration(statement) || statement.importClause === undefined) continue;
    const bindings = statement.importClause.namedBindings;
    if (bindings !== undefined && ts.isNamespaceImport(bindings)) imported.add(bindings.name.text);
    if (bindings !== undefined && ts.isNamedImports(bindings)) {
      for (const element of bindings.elements) imported.add(element.name.text);
    }
  }
  const evaluatorAuthorities = new Set<string>();
  let insideCanonicalPlan = false;
  const collectAuthorities = (node: ts.Node): void => {
    const wasInside = insideCanonicalPlan;
    if (ts.isFunctionDeclaration(node) && node.name?.text === "actualEvaluatorFunctions") {
      insideCanonicalPlan = true;
    }
    if (insideCanonicalPlan && ts.isIdentifier(node) && imported.has(node.text)) {
      evaluatorAuthorities.add(node.text);
    }
    ts.forEachChild(node, collectAuthorities);
    insideCanonicalPlan = wasInside;
  };
  collectAuthorities(file);
  const boundaryModules = file.statements.find((statement) =>
    ts.isVariableStatement(statement)
    && statement.declarationList.declarations.some((declaration) =>
      ts.isIdentifier(declaration.name) && declaration.name.text === "BOUNDARY_MODULES"
    )
  );
  if (boundaryModules === undefined) throw new Error("missing canonical boundary module catalog");
  const collectBoundaryModules = (node: ts.Node): void => {
    if (ts.isIdentifier(node) && imported.has(node.text)) evaluatorAuthorities.add(node.text);
    ts.forEachChild(node, collectBoundaryModules);
  };
  collectBoundaryModules(boundaryModules);
  const executionRegions = new Set(["executeCurrentBoundary", "executeProfilePrerequisite"]);
  const bypasses: string[] = [];
  let insideExecution = false;
  const visit = (node: ts.Node): void => {
    const wasInside = insideExecution;
    if (ts.isFunctionDeclaration(node) && node.name !== undefined
      && executionRegions.has(node.name.text)) insideExecution = true;
    if (insideExecution && ts.isCallExpression(node)) {
      const expression = node.expression;
      const namespace = ts.isPropertyAccessExpression(expression)
        ? expression.expression.getText(file).split(".")[0]
        : undefined;
      const standalone = ts.isIdentifier(expression) ? expression.text : undefined;
      if ((namespace !== undefined && evaluatorAuthorities.has(namespace))
        || (standalone !== undefined && evaluatorAuthorities.has(standalone))) {
        bypasses.push(expression.getText(file));
      }
    }
    ts.forEachChild(node, visit);
    insideExecution = wasInside;
  };
  visit(file);
  return bypasses;
}

describe("semantic boundary certificates", () => {
  it("BLUE TEAM VALIDATION: synthetic/local rejects a same-verdict unrelated result", async () => {
    // BLUE TEAM VALIDATION: deterministic in-process fixtures are non-deployable and contact no external target.
    const signature = await workspaceSignatureExecution();
    const schemaFixture = buildWorkspaceCases().find(({ vector_id }) =>
      vector_id === "workspace/schema-invalid"
    )!;
    const schemaContract = currentCaseContract(schemaFixture.vector_id);
    const unrelated = await invokeCurrentBoundary(schemaContract.boundary_id, schemaFixture);

    expect(() => certifyBoundaryExecution(
      signature.contract,
      signature.fixture,
      unrelated,
    )).toThrow(/exact boundary execution|postcondition/u);
  }, 30_000);

  it("BLUE TEAM VALIDATION: synthetic/local rejects swapped invariant and reason labels", async () => {
    // BLUE TEAM VALIDATION: deterministic label substitutions exercise only the local certificate boundary.
    const { fixture, contract, execution } = await workspaceSignatureExecution();
    expect(() => certifyBoundaryExecution({
      ...contract,
      invariants: ["WORKSPACE-I-FRESHNESS-BOUNDED"],
    }, fixture, execution)).toThrow(/certificate allocation mismatch/u);
    expect(() => certifyBoundaryExecution({
      ...contract,
      reason_codes: ["workspace_schema_invalid"],
    }, fixture, execution)).toThrow(/certificate allocation mismatch/u);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects a different evaluator identity", async () => {
    // BLUE TEAM VALIDATION: the local fixture invokes two real evaluators without any live system and without any reusable payload.
    const signature = await workspaceSignatureExecution();
    const schemaFixture = buildWorkspaceCases().find(({ vector_id }) =>
      vector_id === "workspace/schema-invalid"
    )!;
    const schemaContract = currentCaseContract(schemaFixture.vector_id);
    const schemaExecution = await invokeCurrentBoundary(
      schemaContract.boundary_id,
      schemaFixture,
    );
    expect(() => certifyBoundaryExecution(
      signature.contract,
      signature.fixture,
      schemaExecution,
    )).toThrow(/exact boundary execution/u);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects a same-ID direct evaluator substitution", async () => {
    // BLUE TEAM VALIDATION: an in-process wrapper returns the same deterministic result; no external system is contacted.
    const { fixture, contract, execution } = await workspaceSignatureExecution();
    const substituted = await invokeCurrentBoundaryWithTestEvaluatorSubstitution(
      contract.boundary_id,
      fixture,
      { direct: () => execution.raw_result },
    );
    expect(substituted.projected_output).toBe(execution.raw_result);
    expect(() => certifyBoundaryExecution(contract, fixture, substituted))
      .toThrow(/exact evaluator implementation/u);
  });

  it("BLUE TEAM VALIDATION: synthetic/local invokes a same-ID node evaluator substitution", async () => {
    // BLUE TEAM VALIDATION: the replacement throws only an inert local sentinel before any network-capable work.
    const fixture = (await buildCoreCases()).find(({ vector_id }) =>
      vector_id === "core/node-advert-dual-proof-valid"
    )!;
    const contract = currentCaseContract(fixture.vector_id);
    const sentinel = new Error("blue-team-node-substitute-called");
    await expect(invokeCurrentBoundaryWithTestEvaluatorSubstitution(
      contract.boundary_id,
      fixture,
      { direct: () => { throw sentinel; } },
    )).rejects.toBe(sentinel);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects a false same-verdict node result semantically", async () => {
    // BLUE TEAM VALIDATION: the substitute returns only inert deterministic local data and performs no I/O.
    const fixture = (await buildCoreCases()).find(({ vector_id }) =>
      vector_id === "core/node-advert-dual-proof-valid"
    )!;
    const contract = currentCaseContract(fixture.vector_id);
    const substituted = await invokeCurrentBoundaryWithTestEvaluatorSubstitution(
      contract.boundary_id,
      fixture,
      {
        direct: () => ({
          status: "accepted",
          rid: "rad:zWrongSyntheticRid",
          endpoint: "wss://wrong.invalid/",
          expiry: 1,
          repo_head: "00".repeat(20),
        }),
      },
    );
    expect(() => certifyBoundaryExecution(contract, fixture, substituted))
      .toThrow(/postcondition failed/u);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects false same-terminal results across families", async () => {
    // BLUE TEAM VALIDATION: all replacements are inert deterministic records consumed only in-process.
    const catalogs = [
      ...(await buildAssuranceCases()),
      ...(await buildCommsCases()),
      ...(await buildProfileCases()),
      ...(await buildSocialCases()),
      ...(await buildWorkspaceCases()),
    ];
    const probes = [
      {
        vectorId: "assurance/authority-at-compromise-cutoff",
        fake: { verdict: "reject", reason_code: "assurance-compromise-cutoff", authoritative: true },
      },
      {
        vectorId: "comms/authorization-view-300-boundary",
        fake: { verdict: "accept", view: { checkpoint: "wrong", evaluated_at: -1 } },
      },
      {
        vectorId: "assurance/profile-heterodyne-assurance-active-key-acceptance-v1",
        fake: { verdict: "accept", normalized: { active_key: "00".repeat(32), head: "wrong" } },
      },
      {
        vectorId: "social/source-neutral-vanilla-authorship",
        fake: { verdict: "accept", event_author: "00".repeat(32) },
      },
      {
        vectorId: "workspace/authority-checkpoint-stale",
        fake: {
          verdict: "reject",
          reason_code: "checkpoint_stale",
          normalized: { checkpoint: "wrong", fresh: true },
        },
      },
    ] as const;
    for (const probe of probes) {
      const fixture = catalogs.find(({ vector_id }) => vector_id === probe.vectorId)!;
      const contract = currentCaseContract(fixture.vector_id);
      const substituted = await invokeCurrentBoundaryWithTestEvaluatorSubstitution(
        contract.boundary_id,
        fixture,
        { direct: () => probe.fake },
      );
      expect(
        () => certifyBoundaryExecution(contract, fixture, substituted),
        probe.vectorId,
      ).toThrow(/postcondition failed/u);
    }
  }, 15_000);

  it("BLUE TEAM VALIDATION: synthetic/local prevents evaluator-call bypasses outside the dispatcher", () => {
    // BLUE TEAM VALIDATION: an AST-only local audit executes no fixture, payload, deployment, or external target.
    const source = readFileSync(new URL("./boundary-runners.ts", import.meta.url), "utf8");
    expect(evaluatorBypasses(source)).toEqual([]);
  });

  it("BLUE TEAM VALIDATION: synthetic/local catches a direct Task15 authority call in every dispatcher region", () => {
    const source = readFileSync(new URL("./boundary-runners.ts", import.meta.url), "utf8");
    const probe = `${source}\nasync function executeProfilePrerequisite() {\n  return agentPublicationAuthorization.authorizeAndSignAgentPublication();\n}`;
    expect(evaluatorBypasses(probe)).toContain(
      "agentPublicationAuthorization.authorizeAndSignAgentPublication",
    );
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects cloned and fabricated private fixtures before certification", async () => {
    const fixture = await matrixFixture("source", "comms/marmot-private-inbox-nid-required");
    const contract = currentCaseContract(fixture.vector_id);
    const clone = structuredClone(fixture);
    await expect(invokeCurrentBoundary(contract.boundary_id, clone))
      .rejects.toThrow(/private boundary fixture/u);
    expect(() => certifyBoundaryExecution(contract, clone, Object.freeze({}) as never))
      .toThrow(/exact boundary execution/u);

    const fabricated = {
      ...fixture,
      input: { expected_terminal: { verdict: "reject", reason_code: contract.reason_codes[0] } },
      boundary_args: [Object.freeze({ private_fixture_id: fixture.vector_id })],
    };
    await expect(invokeCurrentBoundary(contract.boundary_id, fabricated))
      .rejects.toThrow(/private boundary fixture/u);
    expect(() => certifyBoundaryExecution(contract, fabricated, Object.freeze({}) as never))
      .toThrow(/exact boundary execution/u);
  }, 30_000);

  it("BLUE TEAM VALIDATION: synthetic/local rejects clones, fabrications, and cross-build identities for every private fixture", async () => {
    const source = await matrixCatalog("all-private-source");
    const crossBuild = await matrixCatalog("all-private-cross-build");
    const privateIds = registeredPrivateCurrentFixtureIds();
    expect(privateIds).toEqual(declaredPrivateCurrentFixtureIds());
    expect(privateIds).toContain("comms/claim-ledger-rollback");
    expect(privateIds).toContain("comms/claim-ledger-writer-unauthorized");
    expect(privateIds).toContain("comms/ledger-reader-authorized");
    for (const vectorId of privateIds) {
      const fixture = source.find((candidate) => candidate.vector_id === vectorId);
      const second = crossBuild.find((candidate) => candidate.vector_id === vectorId);
      if (fixture === undefined || second === undefined) {
        throw new Error(`missing private provenance fixture: ${vectorId}`);
      }
      const boundaryId = currentCaseContract(vectorId).boundary_id;
      const clone = structuredClone(fixture);
      await expect(invokeCurrentBoundary(boundaryId, clone), `${vectorId}: clone`)
        .rejects.toThrow(/private boundary fixture/u);
      const fabricated = {
        ...fixture,
        input: structuredClone(fixture.input),
        boundary_args: Object.freeze([Object.freeze({ private_fixture_id: vectorId })]),
      };
      await expect(invokeCurrentBoundary(boundaryId, fabricated), `${vectorId}: fabrication`)
        .rejects.toThrow(/private boundary fixture/u);
      await expect(
        invokeCurrentBoundary(boundaryId, { ...fixture, input: second.input }),
        `${vectorId}: cross-build splice`,
      ).rejects.toThrow(/private boundary fixture/u);
      await expect(
        invokeCurrentBoundary(boundaryId, { ...second, input: structuredClone(second.input) }),
        `${vectorId}: cross-build clone`,
      ).rejects.toThrow(/private boundary fixture/u);
    }
  }, 120_000);

  it("BLUE TEAM VALIDATION: synthetic/local rejects Social fixture clones and copied contract labels", async () => {
    const fixture = await matrixFixture(
      "source",
      "social/profile-heterodyne-social-agent-policy-list-v1",
    );
    const contract = currentCaseContract(fixture.vector_id);
    const clone = structuredClone(fixture);
    await expect(invokeCurrentBoundary(contract.boundary_id, clone))
      .rejects.toThrow(/private boundary fixture/u);
    expect(() => certifyBoundaryExecution(contract, clone, Object.freeze({}) as never))
      .toThrow(/exact boundary execution/u);

    const execution = await invokeCurrentBoundary(contract.boundary_id, fixture);
    const copiedContract = {
      ...contract,
      invariants: [...contract.invariants],
      reason_codes: [...contract.reason_codes],
    };
    expect(() => certifyBoundaryExecution(copiedContract, fixture, execution))
      .toThrow(/allocation mismatch/u);
  }, 30_000);

  it("BLUE TEAM VALIDATION: synthetic/local rejects first-call private-ID fabrication before evaluator execution", () => {
    const runner = resolve(import.meta.dirname, "../../node_modules/.bin/tsx");
    const script = `
      void (async () => {
        const {
          invokeCurrentBoundaryWithTestEvaluatorSubstitution,
          registerPrivateCurrentFixture,
        } = await import("./src/current-vectors/boundary-runners.ts");
        const { definePrivateCurrentFixtureSpecification } = await import("./src/current-vectors/private-fixture-specification.ts");
        let evaluatorCalls = 0;
        let failure = "";
        let registrationFailure = "";
        const fabricated = {
          vector_id: "comms/claim-ledger-rollback",
          description: "synthetic local first-call fabrication",
          direction: "consume",
          input: {},
          boundary_args: [[], [], {}, {}],
        };
        try {
          const unmarkedFabrication = {
            ...fabricated,
            boundary_args: undefined,
          };
          registerPrivateCurrentFixture(
            definePrivateCurrentFixtureSpecification(["synthetic/local-unrelated-private-case"]),
            unmarkedFabrication,
            fabricated.boundary_args,
          );
        } catch (error) {
          registrationFailure = error instanceof Error ? error.message : String(error);
        }
        try {
          await invokeCurrentBoundaryWithTestEvaluatorSubstitution(
            "claim-ledger.mergeClaimLedger",
            fabricated,
            { direct: () => {
              evaluatorCalls += 1;
              return { verdict: "reject", reason_code: "claim-ledger-rollback" };
            } },
          );
        } catch (error) {
          failure = error instanceof Error ? error.message : String(error);
        }
        process.stdout.write(JSON.stringify({ evaluatorCalls, failure, registrationFailure }));
      })();
    `;
    const result = spawnSync(runner, ["-e", script], {
      cwd: resolve(import.meta.dirname, "../.."),
      encoding: "utf8",
      timeout: 20_000,
    });
    expect(result.status, result.stderr).toBe(0);
    expect(JSON.parse(result.stdout)).toEqual({
      evaluatorCalls: 0,
      failure: "current private boundary fixture is unavailable: comms/claim-ledger-rollback",
      registrationFailure:
        "private current fixture is outside its family specification: comms/claim-ledger-rollback",
    });
  }, 30_000);

  it("BLUE TEAM VALIDATION: synthetic/local physically removes every retired contract and semantic allocation", () => {
    const contracts = readFileSync(new URL("./case-contracts.ts", import.meta.url), "utf8");
    const allocations = readFileSync(new URL("./semantic-certificates.ts", import.meta.url), "utf8");
    const familySources = ["assurance", "comms", "control", "core"].map((family) =>
      readFileSync(new URL(`./${family}.ts`, import.meta.url), "utf8")
    ).join("\n");
    const contractKeys = objectLiteralKeys(contracts, "CURRENT_CASE_CONTRACTS");
    const allocationKeys = objectLiteralKeys(allocations, "SEMANTIC_ALLOCATIONS");
    for (const vectorId of RETIRED_TASK_FIFTEEN_CASES) {
      expect(contractKeys, vectorId).not.toContain(vectorId);
      expect(allocationKeys, vectorId).not.toContain(vectorId);
      expect(familySources, vectorId).not.toContain(vectorId);
    }
    expect(allocationKeys).not.toContain("comms/auth-rejected-permanent");
    expect(currentCaseIds()).toHaveLength(267);
  });

  it("BLUE TEAM VALIDATION: synthetic/local asserts all 34 reviewed executable-authority mappings", () => {
    expect(Object.keys(TASK_FIFTEEN_REAL_MAPPINGS)).toHaveLength(34);
    for (const [vectorId, boundaryId] of Object.entries(TASK_FIFTEEN_REAL_MAPPINGS)) {
      expect(currentCaseContract(vectorId).boundary_id, vectorId).toBe(boundaryId);
    }
    for (const [vectorId, boundaryId] of Object.entries(TASK_FIFTEEN_SOCIAL_COMPOSITES)) {
      expect(currentCaseContract(vectorId).boundary_id, vectorId).toBe(boundaryId);
    }
  });

  it.each(TASK_FIFTEEN_HOSTILE_MATRIX)(
    "BLUE TEAM VALIDATION: synthetic/local rejects the complete hostile matrix for %s",
    async (vectorId, expectedBoundary) => {
      // BLUE TEAM VALIDATION: every object remains a deterministic in-process synthetic fixture.
      const fixture = await matrixFixture("source", vectorId);
      const crossBuild = await matrixFixture("cross-build", vectorId);
      const contract = currentCaseContract(vectorId);
      expect(contract.boundary_id).toBe(expectedBoundary);

      const clone = structuredClone(fixture);
      await expect(invokeCurrentBoundary(expectedBoundary, clone))
        .rejects.toThrow(/private boundary fixture/u);
      expect(() => certifyBoundaryExecution(contract, clone, Object.freeze({}) as never))
        .toThrow(/exact boundary execution/u);

      const fabricated = {
        ...fixture,
        input: crossBuild.input,
        boundary_args: Object.freeze([
          Object.freeze({ private_fixture_id: vectorId }),
          Object.freeze({ expected_terminal: structuredClone(fixture.input.expected_terminal) }),
        ]),
      };
      await expect(invokeCurrentBoundary(expectedBoundary, fabricated))
        .rejects.toThrow(/private boundary fixture/u);
      expect(() => certifyBoundaryExecution(contract, fabricated, Object.freeze({}) as never))
        .toThrow(/exact boundary execution/u);

      const baselineFixture = await matrixFixture("baseline", vectorId);
      const baseline = await invokeCurrentBoundary(expectedBoundary, baselineFixture);
      expect(() => certifyBoundaryExecution(contract, baselineFixture, baseline)).not.toThrow();
      const copiedContract = {
        ...contract,
        invariants: [...contract.invariants],
        reason_codes: [...contract.reason_codes],
        ...(contract.semantic_reason_codes === undefined
          ? {}
          : { semantic_reason_codes: [...contract.semantic_reason_codes] }),
      };
      expect(() => certifyBoundaryExecution(copiedContract, baselineFixture, baseline))
        .toThrow(/exact current case contract/u);

      const baselineRecord = inspectCurrentBoundaryExecution(
        baseline,
        expectedBoundary,
        baselineFixture,
      );
      const semanticInvocations = baselineRecord.evaluator_invocations.filter(({ step_id }) =>
        step_id.startsWith("semantic:")
      );
      const lastInvocation = semanticInvocations.at(-1);
      if (lastInvocation === undefined) throw new Error(`missing semantic invocation: ${vectorId}`);
      let fabricatedEvaluatorCalled = false;
      const fabricatedTerminal = structuredClone(lastInvocation.result);
      const fabricatedTerminalEvaluator = (): unknown => {
        fabricatedEvaluatorCalled = true;
        return structuredClone(fabricatedTerminal);
      };
      const sameTerminalFixture = await matrixFixture(
        vectorId === "workspace/invitation-replay"
          ? "same-terminal-invitation-replay"
          : "same-terminal",
        vectorId,
      );
      const sameTerminal = await invokeCurrentBoundaryWithTestEvaluatorSubstitution(
        expectedBoundary,
        sameTerminalFixture,
        semanticInvocations.length === 1
          ? { direct: fabricatedTerminalEvaluator }
          : {
              composite_step: {
                index: semanticInvocations.length - 1,
                evaluator: fabricatedTerminalEvaluator,
              },
            },
      );
      expect(fabricatedEvaluatorCalled, `${vectorId}: fabricated evaluator called`).toBe(true);
      expect(sameTerminal.projected_output, `${vectorId}: same terminal`).toEqual(
        baseline.projected_output,
      );
      expect(
        () => certifyBoundaryExecution(contract, sameTerminalFixture, sameTerminal),
        `${vectorId}: fabricated same-terminal certificate`,
      ).toThrow(/exact evaluator implementation|postcondition failed/u);

      const actualEvaluator = lastInvocation.evaluator as unknown as (
        ...args: readonly unknown[]
      ) => unknown;
      const alternateEvaluator = (...args: readonly unknown[]): unknown =>
        Reflect.apply(actualEvaluator, undefined, args);
      const alternateFixture = await matrixFixture("alternate", vectorId);
      const substituted = await invokeCurrentBoundaryWithTestEvaluatorSubstitution(
        expectedBoundary,
        alternateFixture,
        semanticInvocations.length === 1
          ? { direct: alternateEvaluator }
          : {
              composite_step: {
                index: semanticInvocations.length - 1,
                evaluator: alternateEvaluator,
              },
            },
      );
      expect(() => certifyBoundaryExecution(contract, alternateFixture, substituted))
        .toThrow(/exact evaluator implementation/u);

      const omissionFixture = await matrixFixture("omission", vectorId);
      await expect(invokeCurrentBoundaryWithTestPlanOmission(
        expectedBoundary,
        omissionFixture,
        semanticInvocations.length - 1,
      )).rejects.toThrow(/invocation (?:exceeded plan|order mismatch)|plan incomplete/u);
    },
    120_000,
  );

  it("BLUE TEAM VALIDATION: synthetic/local rejects a composite-step substitution", async () => {
    // BLUE TEAM VALIDATION: the wrapper delegates only to the real local Core verifier over synthetic non-deployable keys.
    const fixture = (await buildCoreCases()).find(({ vector_id }) =>
      vector_id === "core/repository-writer-dual-proof-valid"
    )!;
    const contract = currentCaseContract(fixture.vector_id);
    const substituted = await invokeCurrentBoundaryWithTestEvaluatorSubstitution(
      contract.boundary_id,
      fixture,
      {
        composite_step: {
          index: 0,
          evaluator: (...args) => resolveCurrentRepositoryWriterBinding(
            args[0] as Parameters<typeof resolveCurrentRepositoryWriterBinding>[0],
            args[1],
            args[2] as Parameters<typeof resolveCurrentRepositoryWriterBinding>[2],
          ),
        },
      },
    );
    expect(substituted.projected_output).toMatchObject({ verdict: "accept" });
    expect(() => certifyBoundaryExecution(contract, fixture, substituted))
      .toThrow(/exact evaluator implementation/u);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects copied subscription labels and cloned policy views for both Social profiles", async () => {
    // BLUE TEAM VALIDATION: only deterministic local profile fixtures and in-memory clones are used.
    const vectorIds = [
      "social/profile-heterodyne-social-agent-policy-list-v1",
      "social/profile-heterodyne-social-agent-policy-receipt-v1",
    ];
    const profiles = await matrixCatalog("source");
    for (const vectorId of vectorIds) {
      const fixture = profiles.find(({ vector_id }) => vector_id === vectorId)!;
      const contract = currentCaseContract(vectorId);

      const copiedLabels = {
        ...fixture,
        input: {
          ...fixture.input,
          subscribed: true,
          policy_event_selected: true,
          local_policy_applied: true,
        },
      };
      await expect(
        invokeCurrentBoundary(contract.boundary_id, copiedLabels),
        `${vectorId}: copied labels`,
      ).rejects.toThrow(/private boundary fixture/u);
      expect(
        () => certifyBoundaryExecution(contract, copiedLabels, Object.freeze({}) as never),
        `${vectorId}: copied labels certificate`,
      ).toThrow(/exact boundary execution/u);

      const execution = await invokeCurrentBoundary(contract.boundary_id, fixture);
      expect(() => certifyBoundaryExecution(contract, fixture, execution)).not.toThrow();
      const bound = execution.raw_result as {
        semantic_result: { view: object; exact_view_transfer: object };
      };
      const clonedView = structuredClone(bound.semantic_result.view);
      bound.semantic_result.view = clonedView;
      bound.semantic_result.exact_view_transfer = clonedView;
      expect(
        () => certifyBoundaryExecution(contract, fixture, execution),
        `${vectorId}: cloned view`,
      ).toThrow(/result changed after execution|postcondition failed/u);
    }
  }, 30_000);

  it("BLUE TEAM VALIDATION: synthetic/local rejects a plain certificate clone", async () => {
    // BLUE TEAM VALIDATION: a structural in-memory clone proves the module-private certificate record is required.
    const { fixture, contract, execution } = await workspaceSignatureExecution();
    const certificate = certifyBoundaryExecution(contract, fixture, execution);
    expect(() => inspectSemanticBoundaryCertificate({ ...certificate } as never))
      .toThrow(/unrecognized semantic boundary certificate/u);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects fixture and execution-wrapper clones", async () => {
    // BLUE TEAM VALIDATION: local structural clones contain only deterministic synthetic Workspace data.
    const { fixture, contract, execution } = await workspaceSignatureExecution();
    const clonedFixture = {
      ...fixture,
      input: structuredClone(fixture.input),
    };
    expect(() => certifyBoundaryExecution(contract, clonedFixture, execution))
      .toThrow(/exact boundary execution/u);
    expect(() => certifyBoundaryExecution(contract, fixture, { ...execution } as never))
      .toThrow(/exact boundary execution/u);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects a missing certificate and copied static labels", () => {
    // BLUE TEAM VALIDATION: a frozen empty lookalike contains no authority and exercises no external target.
    expect(() => inspectSemanticBoundaryCertificate(Object.freeze({}) as never))
      .toThrow(/unrecognized semantic boundary certificate/u);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects result mutation after execution", async () => {
    // BLUE TEAM VALIDATION: mutate only a disposable in-process result returned by the deterministic fixture.
    const { fixture, contract, execution } = await workspaceSignatureExecution();
    Object.assign(execution.raw_result as object, { reason_code: "workspace_schema_invalid" });
    expect(() => certifyBoundaryExecution(contract, fixture, execution))
      .toThrow(/result changed after execution/u);
  });

  it("BLUE TEAM VALIDATION: synthetic/local bounds certificate descriptor work", async () => {
    // BLUE TEAM VALIDATION: a local inert array proves the certificate digest refuses oversized synthetic input.
    const baseFixture = buildWorkspaceCases().find(({ vector_id }) =>
      vector_id === "workspace/signature-invalid"
    )!;
    const fixture = {
      ...baseFixture,
      input: {
        ...baseFixture.input,
        padding: Array.from({ length: 4_097 }, () => null),
      },
    };
    const contract = currentCaseContract(fixture.vector_id);
    await expect(invokeCurrentBoundary(contract.boundary_id, fixture))
      .rejects.toThrow(/descriptor collection exceeded/u);
  });

  it("audits every invariant-bearing contract against an explicit postcondition", () => {
    const inventory = semanticPostconditionInventory();
    const byVector = new Map(inventory.map((entry) => [entry.vector_id, entry]));
    const invariantCases = currentCaseIds().filter((id) =>
      currentCaseContract(id).invariants.length > 0
    );
    expect([...byVector.keys()].sort()).toEqual([...invariantCases].sort());
    for (const vectorId of invariantCases) {
      const contract = currentCaseContract(vectorId);
      expect(byVector.get(vectorId)).toMatchObject({
        vector_id: vectorId,
        boundary_id: contract.boundary_id,
      });
      expect(byVector.get(vectorId)?.postcondition.length).toBeGreaterThan(0);
      expect(byVector.get(vectorId)?.postcondition).not.toBe("exact-executed-boundary");
    }
    expect(inventory.filter(({ postcondition }) =>
      /boundary-contract|exact-executed|generic|shape/u.test(postcondition)
    )).toEqual([]);
  });

  it("BLUE TEAM VALIDATION: synthetic/local replaces caller-authored shim claims with executable authority", () => {
    const retired = [
      "assurance/retired-key-post-compromise",
      "comms/dm-invite-revoked-device",
      "comms/dm-invite-unbound-device",
      "control/agent-attribution-bypass-prohibited",
      "control/agent-human-profile-prohibited",
      "control/agent-key-access-prohibited",
      "control/agent-method-prohibited",
      "control/agent-resource-denied",
      "control/request-id-conflict",
      "control/signed-event-invalid",
      "core/retired-key-authority-window-invalid",
    ];
    for (const vectorId of retired) expect(() => currentCaseContract(vectorId)).toThrow();
    const terminal = currentCaseContract("comms/auth-rejected-permanent");
    expect(terminal.invariants).toEqual([]);
    expect(terminal.semantic_reason_codes).toEqual([]);
    expect(terminal.terminal_vector_invariants).toEqual(["COMMS-I-MARMOT-UPSTREAM-AUTHORITY"]);
    const inventory = new Map(semanticPostconditionInventory().map((row) => [row.vector_id, row]));
    expect(inventory.has("comms/auth-rejected-permanent")).toBe(false);
    for (const vectorId of currentCaseIds().filter((id) => id !== "comms/auth-rejected-permanent")) {
      expect(inventory.has(vectorId), vectorId).toBe(true);
    }
  });

  it("BLUE TEAM VALIDATION: synthetic/local closes the reviewed Task 15 case inventory", () => {
    // BLUE TEAM VALIDATION: this audits only the deterministic local catalog and invokes no target.
    const retired = [
      "assurance/retired-key-post-compromise",
      "core/retired-key-authority-window-invalid",
      "comms/dm-invite-revoked-device",
      "comms/dm-invite-unbound-device",
      "control/agent-attribution-bypass-prohibited",
      "control/agent-human-profile-prohibited",
      "control/agent-key-access-prohibited",
      "control/agent-method-prohibited",
      "control/agent-resource-denied",
      "control/request-id-conflict",
      "control/signed-event-invalid",
    ];
    expect(currentCaseIds()).toHaveLength(267);
    for (const vectorId of retired) expect(currentCaseIds()).not.toContain(vectorId);
    expect(currentCaseContract("comms/auth-rejected-permanent")).toMatchObject({
      invariants: [],
      semantic_reason_codes: [],
    });
    expect(currentCaseContract("comms/agent-sender-proof-invalid").boundary_id)
      .toBe("agent-publication-authorization.authorizeAndSignAgentPublication");
    expect(currentCaseContract("comms/conversation-rejected").boundary_id)
      .toBe("marmot-admission-authority.verifyMarmotWelcome+admitOrdinaryMarmotWelcome");
    expect(currentCaseContract("control/token-invalid").boundary_id)
      .toBe("control-token-verifier.verifyControlToken+consumeVerifiedControlToken");
    expect(currentCaseContract("workspace/current-capability-intersection").boundary_id)
      .toBe("workspace.authenticateWorkspaceRepositoryView+resolveWorkspaceEffectiveAuthorization+consumeWorkspaceInvitationAcceptance+evaluateGrantActivation");
  });

  it("binds dual-proof coverage only to real Core writer executions", () => {
    const writerCases = currentCaseIds().filter((id) =>
      currentCaseContract(id).invariants.includes("CORE-I-NID-DELEGATION-DUAL-PROOF")
    );
    expect(writerCases).toEqual([
      "core/repository-writer-dual-proof-valid",
      "core/repository-writer-owner-proof-invalid",
    ]);
    expect(writerCases.map((id) => currentCaseContract(id).boundary_id))
      .toEqual([
        "core-writer-binding.resolveCurrentRepositoryWriterBinding+revalidateCurrentRepositoryWriterBinding",
        "core-writer-binding.resolveCurrentRepositoryWriterBinding+revalidateCurrentRepositoryWriterBinding",
      ]);
  });

  it("BLUE TEAM VALIDATION: synthetic/local inventories durable subject-proof replay", () => {
    // BLUE TEAM VALIDATION: this checks only a deterministic in-process replay fixture; no live target and no reusable payload exists.
    expect(currentCaseContract("comms/claim-subject-proof-replayed")).toMatchObject({
      boundary_id: "claim-authorization.authorizeClaimEffect+authorizeClaimEffect",
      reason_codes: ["claim-subject-proof-replayed"],
    });
  });

  it("BLUE TEAM VALIDATION: synthetic/local certifies a durable indeterminate effect terminal", async () => {
    // BLUE TEAM VALIDATION: the synthetic effect reports an unknown local outcome and performs no external action.
    const fixture = (await buildCommsCases()).find(({ vector_id }) =>
      vector_id === "comms/claim-authorization-effect-indeterminate"
    )!;
    const contract = currentCaseContract(fixture.vector_id);
    const execution = await invokeCurrentBoundary(contract.boundary_id, fixture);
    expect(() => certifyBoundaryExecution(contract, fixture, execution)).not.toThrow();
    expect(execution.projected_output).not.toHaveProperty("result");
  }, 15_000);
});
