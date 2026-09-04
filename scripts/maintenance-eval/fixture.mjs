import { createHash } from 'node:crypto';
import { access, mkdir, readFile, readdir } from 'node:fs/promises';
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
  if (rounds == null) return;
  if (!Array.isArray(rounds) || rounds.length !== 10) throw new TypeError('fixture contract must encode exactly ten rounds');
  for (const round of rounds) {
    for (const field of ROUND_FIELDS) {
      if (!(field in round)) throw new TypeError(`round is missing ${field}`);
    }
  }
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
  validateRounds(contract.rounds);
  const history = contract.workerHistory ?? REQUIRED_WORKER_HISTORY;
  if (history.first !== REQUIRED_WORKER_HISTORY.first || history.last !== REQUIRED_WORKER_HISTORY.last) {
    throw new Error('worker history does not match the approved August 28 endpoints');
  }
  const startCommit = contract.startCommit ?? history.first;
  const endCommit = contract.endCommit ?? history.last;
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
  // Fetching an object ID copies only that commit and its ancestors. It does
  // not clone source refs, reflogs, alternates, or unreachable future objects.
  await git(destination, ['fetch', '--no-tags', evidenceRepo, endCommit]);
  await git(destination, ['checkout', '--quiet', '--detach', endCommit]);
  const alternates = path.join(destination, '.git', 'objects', 'info', 'alternates');
  try {
    await access(alternates);
    throw new Error('sealed fixture unexpectedly has an object alternate');
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }

  const forbidden = [...(contract.hiddenCommits ?? []), ...(contract.laterCommits ?? [])];
  for (const object of forbidden) {
    if (await gitSucceeds(destination, ['cat-file', '-e', `${object}^{commit}`])) {
      throw new Error(`forbidden later object is readable in worker fixture: ${object}`);
    }
  }

  const baseTree = await git(evidenceRepo, ['rev-parse', `${startCommit}^{tree}`]);
  const visibleTree = await git(destination, ['rev-parse', `${endCommit}^{tree}`]);
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
  const visibleContract = contract.visibleContract ?? {};
  const oracleManifest = contract.oracleManifest ?? {};
  const visibleContractDigest = digest(visibleContract);
  const oracleManifestDigest = digest(oracleManifest);
  if (contract.visibleContractDigest && contract.visibleContractDigest !== visibleContractDigest) throw new Error('visible contract digest mismatch');
  if (contract.oracleManifestDigest && contract.oracleManifestDigest !== oracleManifestDigest) throw new Error('oracle manifest digest mismatch');
  return { workerRepo: destination, baseTree, visibleContractDigest, oracleManifestDigest };
}
