import { describe, expect, it } from "vitest";
import { buildWorkspaceCases } from "./workspace.js";
import { buildCommsCases } from "./comms.js";
import {
  currentCaseContract,
  currentCaseIds,
} from "./case-contracts.js";
import { invokeCurrentBoundary } from "./boundary-runners.js";
import {
  certifyBoundaryExecution,
  inspectSemanticBoundaryCertificate,
  semanticPostconditionInventory,
} from "./semantic-certificates.js";

async function workspaceSignatureExecution() {
  const fixture = buildWorkspaceCases().find(({ vector_id }) =>
    vector_id === "workspace/signature-invalid"
  );
  if (fixture === undefined) throw new Error("missing Workspace signature fixture");
  const contract = currentCaseContract(fixture.vector_id);
  const execution = await invokeCurrentBoundary(contract.boundary_id, fixture);
  return { fixture, contract, execution };
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
  });

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
    // BLUE TEAM VALIDATION: the local fixture invokes two real evaluators without any live system or reusable payload.
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
    }
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
    // BLUE TEAM VALIDATION: this checks only a deterministic in-process replay fixture; no live target or reusable payload exists.
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
