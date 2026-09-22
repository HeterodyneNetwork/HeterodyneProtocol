/** Score only evaluator-supplied independent checks and completed findings. */
export function scoreRun({ elapsedMs, requiredChecks, completed, findings }) {
  if (!Number.isFinite(elapsedMs) || elapsedMs < 0) throw new TypeError('elapsedMs must be a non-negative number');
  if (!Array.isArray(requiredChecks) || requiredChecks.length === 0) throw new TypeError('requiredChecks must be non-empty');
  if (!Array.isArray(findings)) throw new TypeError('findings must be an array');
  const ids = new Set();
  for (const check of requiredChecks) {
    if (!check || typeof check.id !== 'string' || check.id.trim() === '') throw new TypeError('check id is required');
    if (ids.has(check.id)) throw new TypeError(`duplicate check id: ${check.id}`);
    ids.add(check.id);
    if (typeof check.passed !== 'boolean') throw new TypeError(`check ${check.id} must have boolean passed`);
  }
  const correct = completed === true && requiredChecks.every(check => check.passed === true) && findings.length === 0;
  const underBudget = elapsedMs < 3600000;
  const reasons = [];
  if (!completed) reasons.push('run did not complete');
  for (const check of requiredChecks) if (!check.passed) reasons.push(`required check failed: ${check.id}`);
  if (findings.length) reasons.push(`${findings.length} finding(s) remain open`);
  if (!underBudget) reasons.push('elapsed time is not under sixty minutes');
  return { correct, underBudget, accepted: correct && underBudget, reasons };
}

function rejectedScore(elapsedMs, reasons) {
  return {
    correct: false,
    underBudget: Number.isFinite(elapsedMs) && elapsedMs >= 0 && elapsedMs < 3600000,
    accepted: false,
    reasons,
  };
}

/**
 * Trusted evaluator entry point. Policy and isolation attestations must come
 * from the evaluator boundary; cooperative worker metadata is not OS
 * enforcement and can never create an acceptance result by itself.
 */
export function scoreTrustedRun({ run = {}, policy = {} }) {
  const reasons = [];
  if (policy.reviewed !== true) reasons.push('mandatory policy is not reviewed');
  if (!Array.isArray(policy.mandatoryCheckIds) || policy.mandatoryCheckIds.length === 0) reasons.push('mandatory check IDs are missing');
  if (policy.requireIsolation !== true) reasons.push('policy does not require enforced isolation');
  for (const [field, label] of [
    ['oracleIdentityDigest', 'independent oracle identity'],
    ['expectedTreeDigest', 'tree'],
    ['expectedToolchainDigest', 'toolchain'],
    ['expectedContractDigest', 'contract'],
  ]) {
    if (typeof policy[field] !== 'string' || policy[field].length === 0) reasons.push(`${label} digest is missing from policy`);
  }
  if (reasons.length) return rejectedScore(run.elapsedMs, reasons);

  const expected = [...new Set(policy.mandatoryCheckIds)].sort();
  const actual = Array.isArray(run.requiredChecks) ? run.requiredChecks.map(check => check?.id).sort() : [];
  if (expected.length !== policy.mandatoryCheckIds.length || expected.join('\u0000') !== actual.join('\u0000')) {
    reasons.push('run checks do not exactly match the reviewed mandatory check IDs');
  }
  if (run.oracleIdentityDigest !== policy.oracleIdentityDigest) reasons.push('independent oracle identity digest mismatch');
  if (run.treeDigest !== policy.expectedTreeDigest) reasons.push('tree digest mismatch');
  if (run.toolchainDigest !== policy.expectedToolchainDigest) reasons.push('toolchain digest mismatch');
  if (run.contractDigest !== policy.expectedContractDigest) reasons.push('contract digest mismatch');
  if (run.isolationEnforced !== true) reasons.push('enforced isolation is absent');
  if (reasons.length) return rejectedScore(run.elapsedMs, reasons);
  return scoreRun(run);
}
