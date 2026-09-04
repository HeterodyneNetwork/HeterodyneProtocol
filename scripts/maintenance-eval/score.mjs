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
