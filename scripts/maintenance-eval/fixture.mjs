import { createHash } from 'node:crypto';
import { access, mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const run = promisify(execFile);
export const REQUIRED_WORKER_HISTORY = Object.freeze({
  first: 'b6416fda157529b708c86f21cc4ea66a7b24384c',
  last: '0dd150682903d14eddd8d14b57892395f750c47f',
});

const ROUND_FIELDS = ['id', 'intent', 'source', 'confidence', 'reveal_after', 'external_inputs', 'checks'];

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}

function digest(value) {
  return createHash('sha256').update(typeof value === 'string' ? value : canonical(value)).digest('hex');
}

async function git(cwd, args, options = {}) {
  const result = await run('git', ['-C', cwd, ...args], { encoding: 'utf8', ...options });
  return result.stdout.trim();
}

async function gitSucceeds(cwd, args) {
  try { await git(cwd, args); return true; } catch { return false; }
}

async function fileDigest(file) {
  try { return createHash('sha256').update(await readFile(file)).digest('hex'); } catch (error) {
    if (error.code === 'ENOENT') return null;
    throw error;
  }
}

function validateRounds(rounds) {
  if (!Array.isArray(rounds) || rounds.length !== 10) throw new TypeError('fixture contract must encode exactly ten rounds');
  const expectedIds = Array.from({ length: 10 }, (_, index) => `round-${index + 1}`);
  for (const [index, round] of rounds.entries()) {
    for (const field of ROUND_FIELDS) {
      if (!(field in round)) throw new TypeError(`round is missing ${field}`);
    }
    if (round.id !== expectedIds[index] || typeof round.intent !== 'string' || round.intent.trim() === '' ||
        typeof round.source !== 'string' || round.source.trim() === '' || typeof round.confidence !== 'string' ||
        round.confidence.trim() === '' || typeof round.reveal_after !== 'string' || round.reveal_after.trim() === '' ||
        !Array.isArray(round.external_inputs) || !Array.isArray(round.checks) || round.checks.length === 0) {
      throw new TypeError(`round ${round.id ?? index + 1} has incomplete intent contract fields`);
    }
  }
  const snapshotIds = new Set(['0efa4a9fca289b53289472e9490f531c5682912a', '8f780cea2119738e3db1a37e7c0c94b4cd200cb3']);
  const finalInputs = new Set(rounds[9].external_inputs);
  if (![...snapshotIds].every(id => finalInputs.has(id))) throw new TypeError('round-10 must identify both external snapshot inputs');
  if (rounds.slice(0, 9).some(round => round.external_inputs.some(input => snapshotIds.has(input)))) {
    throw new TypeError('external snapshot inputs cannot be revealed before round-10');
  }
}

function deriveVisibleContract(contract, mode) {
  const policyMode = mode === 'synthetic' ? 'complete-brief' : mode;
  const modePolicy = contract.mode_contracts?.[policyMode];
  if (!modePolicy) throw new TypeError(`fixture requires ${policyMode} reveal policy`);
  let ids = modePolicy.included_rounds;
  const visible = { contract_version: contract.contract_version, mode, rounds: [] };
  if (mode === 'causal-replay') {
    const cursor = contract.reveal_cursor ?? 'round-1';
    const cursorIndex = contract.rounds.findIndex(round => round.id === cursor);
    if (cursorIndex < 0) throw new TypeError('causal reveal cursor is not a valid round');
    if (cursorIndex > 0 && contract.reviewed_reveal_cursor !== true) {
      throw new TypeError('causal future reveal requires reviewed reveal cursor');
    }
    if (cursorIndex >= 9 && contract.external_snapshot_handoff === 'unresolved-user-decision') {
      throw new TypeError('round-10 reveal requires reviewed external snapshot handoff');
    }
    ids = modePolicy.authorized_rounds.slice(0, cursorIndex + 1);
    visible.reveal_cursor = cursor;
  }
  const allowed = new Set(ids);
  visible.rounds = contract.rounds.filter(round => allowed.has(round.id)).map(round => ({
    id: round.id,
    intent: round.intent,
    source: round.source,
    confidence: round.confidence,
    reveal_after: round.reveal_after,
    external_inputs: round.external_inputs,
    checks: round.checks,
  }));
  if (visible.rounds.length !== ids.length) throw new TypeError('reveal policy references an unknown round');
  if (contract.visibleContract && canonical(contract.visibleContract) !== canonical(visible)) {
    throw new TypeError('supplied visible contract is not the closed derived payload');
  }
  return visible;
}

/**
 * Build a worker-visible repository from only the selected commit's reachable
 * objects. `evidenceRepo` is used by this evaluator-side function and is not
 * returned to workers. A sealed OS boundary still has to be provided by the
 * runner; this function supplies Git object isolation and fail-closed checks.
 */
export async function sealFixture({ evidenceRepo, destination, contract = {}, mode = 'complete-brief' }) {
  if (!evidenceRepo || !destination) throw new TypeError('evidenceRepo and destination are required');
  if (!['complete-brief', 'causal-replay', 'synthetic'].includes(mode)) throw new TypeError(`unsupported fixture mode: ${mode}`);
  if (mode !== 'synthetic') {
    if (!contract.mode_contracts || !contract.mode_contracts[mode]) {
      throw new TypeError(`production fixture requires ${mode} reveal policy`);
    }
  }
  if (contract.rounds == null) throw new TypeError('production fixture requires the reviewed ten-round workload');
  if (mode === 'complete-brief' && contract.external_snapshot_handoff === 'unresolved-user-decision') {
    throw new TypeError('complete-brief external snapshot handoff requires reviewed maintainer decision');
  }
  validateRounds(contract.rounds);
  const history = contract.workerHistory ?? REQUIRED_WORKER_HISTORY;
  if (history.first !== REQUIRED_WORKER_HISTORY.first || history.last !== REQUIRED_WORKER_HISTORY.last) {
    throw new Error('worker history does not match the approved August 28 endpoints');
  }
  const startCommit = contract.startCommit ?? history.first;
  const endCommit = contract.endCommit ?? history.last;
  if (mode !== 'synthetic' && (startCommit !== REQUIRED_WORKER_HISTORY.first || endCommit !== REQUIRED_WORKER_HISTORY.last)) {
    throw new Error('production fixture must use the approved worker start and endpoint');
  }
  if (!/^[0-9a-f]{7,64}$/i.test(startCommit) || !/^[0-9a-f]{7,64}$/i.test(endCommit)) {
    throw new TypeError('startCommit and endCommit must be Git object IDs');
  }
  if (mode !== 'synthetic') {
    for (const object of [history.first, history.last]) {
      if (!await gitSucceeds(evidenceRepo, ['cat-file', '-e', `${object}^{commit}`])) {
        throw new Error(`evidence repository is missing required worker endpoint ${object}`);
      }
    }
  }
  if (!await gitSucceeds(evidenceRepo, ['cat-file', '-e', `${startCommit}^{commit}`])) throw new Error('startCommit is not present');
  if (!await gitSucceeds(evidenceRepo, ['cat-file', '-e', `${endCommit}^{commit}`])) throw new Error('endCommit is not present');
  if (!await gitSucceeds(evidenceRepo, ['merge-base', '--is-ancestor', startCommit, endCommit])) {
    throw new Error('startCommit must be an ancestor of endCommit');
  }

  await mkdir(destination, { recursive: true });
  const entries = await readdir(destination);
  if (entries.length) throw new Error('destination must be empty');
  await git(destination, ['init', '--quiet']);
  // Fetching the base object ID copies only the worker-visible base and its
  // ancestors. The evaluator endpoint is deliberately never fetched.
  await git(destination, ['fetch', '--no-tags', evidenceRepo, startCommit]);
  await git(destination, ['checkout', '--quiet', '--detach', startCommit]);
  const alternates = path.join(destination, '.git', 'objects', 'info', 'alternates');
  try {
    await access(alternates);
    throw new Error('sealed fixture unexpectedly has an object alternate');
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }

  const forbidden = new Set([endCommit, ...(contract.hiddenCommits ?? []), ...(contract.laterCommits ?? [])]);
  for (const object of forbidden) {
    if (object === startCommit) continue;
    if (await gitSucceeds(destination, ['cat-file', '-e', `${object}^{commit}`])) {
      throw new Error(`forbidden later object is readable in worker fixture: ${object}`);
    }
  }

  const baseTree = await git(evidenceRepo, ['rev-parse', `${startCommit}^{tree}`]);
  const visibleTree = await git(destination, ['rev-parse', `${startCommit}^{tree}`]);
  const digestPaths = contract.digestPaths ?? {};
  const visibleDigests = {
    tree: visibleTree,
    lockfile: await fileDigest(path.join(destination, digestPaths.lockfile ?? 'package-lock.json')),
    index: await fileDigest(path.join(destination, digestPaths.index ?? '.git/index')),
    cache: digestPaths.cache ? await fileDigest(path.join(destination, digestPaths.cache)) : null,
  };
  if (contract.visibleDigests) {
    for (const [key, expected] of Object.entries(contract.visibleDigests)) {
      if (visibleDigests[key] !== expected) throw new Error(`visible ${key} digest does not match fixture manifest`);
    }
  }
  const visibleContract = deriveVisibleContract(contract, mode);
  const oracleManifest = contract.oracleManifest ?? {};
  const visibleContractDigest = digest(visibleContract);
  const oracleManifestDigest = digest(oracleManifest);
  if (contract.visibleContractDigest && contract.visibleContractDigest !== visibleContractDigest) throw new Error('visible contract digest mismatch');
  if (contract.oracleManifestDigest && contract.oracleManifestDigest !== oracleManifestDigest) throw new Error('oracle manifest digest mismatch');
  const visibleContractPath = path.join(destination, 'benchmark-contract.json');
  try {
    await access(visibleContractPath);
    throw new Error('worker-visible contract path already exists in base tree');
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  await writeFile(visibleContractPath, `${JSON.stringify(visibleContract, null, 2)}\n`, { flag: 'wx' });
  return { workerRepo: destination, baseTree, visibleContractDigest, oracleManifestDigest, visibleContractPath };
}
