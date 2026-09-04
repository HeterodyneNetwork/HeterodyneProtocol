import test from 'node:test';
import assert from 'node:assert/strict';
import { scoreRun, scoreTrustedRun } from './score.mjs';

test('an incomplete fast run is not a success', () => {
  const result = scoreRun({ elapsedMs: 1200000, completed: true,
    requiredChecks: [{ id: 'private-evidence', passed: false }], findings: [] });
  assert.equal(result.accepted, false);
});

test('sixty minutes is not less than sixty minutes', () => {
  const result = scoreRun({ elapsedMs: 3600000, completed: true,
    requiredChecks: [{ id: 'independent-oracle', passed: true }], findings: [] });
  assert.equal(result.underBudget, false);
});

test('a complete run with every independent check and no findings is accepted', () => {
  const result = scoreRun({ elapsedMs: 3599999, completed: true,
    requiredChecks: [
      { id: 'private-evidence', passed: true },
      { id: 'independent-oracle', passed: true },
    ], findings: [] });
  assert.equal(result.correct, true);
  assert.equal(result.underBudget, true);
  assert.equal(result.accepted, true);
});

test('missing or duplicate check identifiers are rejected before scoring', () => {
  assert.throws(() => scoreRun({ elapsedMs: 1, completed: true,
    requiredChecks: [{ passed: true }], findings: [] }), /check id/i);
  assert.throws(() => scoreRun({ elapsedMs: 1, completed: true,
    requiredChecks: [{ id: 'oracle', passed: true }, { id: 'oracle', passed: true }], findings: [] }), /duplicate/i);
});

test('trusted scoring rejects an arbitrary passing check and missing isolation', () => {
  const policy = {
    reviewed: true,
    mandatoryCheckIds: ['private-evidence', 'independent-oracle'],
    oracleIdentityDigest: 'oracle-identity',
    expectedTreeDigest: 'tree',
    expectedToolchainDigest: 'toolchain',
    expectedContractDigest: 'contract',
    requireIsolation: true,
  };
  const result = scoreTrustedRun({
    policy,
    run: { elapsedMs: 1, completed: true, requiredChecks: [{ id: 'arbitrary', passed: true }], findings: [],
      oracleIdentityDigest: 'oracle-identity', treeDigest: 'tree', toolchainDigest: 'toolchain', contractDigest: 'contract', isolationEnforced: false },
  });
  assert.equal(result.accepted, false);
  assert.match(result.reasons.join('; '), /mandatory|isolation/i);
});

test('trusted scoring accepts only the reviewed policy and matching oracle identity', () => {
  const policy = {
    reviewed: true,
    mandatoryCheckIds: ['private-evidence', 'independent-oracle'],
    oracleIdentityDigest: 'oracle-identity', expectedTreeDigest: 'tree',
    expectedToolchainDigest: 'toolchain', expectedContractDigest: 'contract', requireIsolation: true,
  };
  const result = scoreTrustedRun({ policy, run: {
    elapsedMs: 3599999, completed: true,
    requiredChecks: [{ id: 'private-evidence', passed: true }, { id: 'independent-oracle', passed: true }], findings: [],
    oracleIdentityDigest: 'oracle-identity', treeDigest: 'tree', toolchainDigest: 'toolchain', contractDigest: 'contract', isolationEnforced: true,
  } });
  assert.equal(result.accepted, true);
});
