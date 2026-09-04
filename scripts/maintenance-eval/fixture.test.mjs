import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { sealFixture } from './fixture.mjs';
import contract from './contracts/aug28.json' with { type: 'json' };

const FIRST = 'b6416fda157529b708c86f21cc4ea66a7b24384c';
const LAST = '0dd150682903d14eddd8d14b57892395f750c47f';

function git(cwd, ...args) {
  return execFileSync('git', ['-C', cwd, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
}

test('sealed worker cannot read a hidden descendant object or use alternates', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'maintenance-fixture-'));
  const source = path.join(root, 'evidence');
  const destination = path.join(root, 'worker');
  await fs.mkdir(source);
  git(source, 'init', '--quiet');
  git(source, 'config', 'user.email', 'fixture@example.invalid');
  git(source, 'config', 'user.name', 'Fixture');
  await fs.writeFile(path.join(source, 'visible.txt'), 'visible\n');
  git(source, 'add', 'visible.txt');
  git(source, 'commit', '--quiet', '-m', 'visible input');
  const allowed = git(source, 'rev-parse', 'HEAD');
  await fs.writeFile(path.join(source, 'solution.txt'), 'solution\n');
  git(source, 'add', 'solution.txt');
  git(source, 'commit', '--quiet', '-m', 'future solution');
  const solution = git(source, 'rev-parse', 'HEAD');
  await fs.writeFile(path.join(source, 'future.txt'), 'hidden\n');
  git(source, 'add', 'future.txt');
  git(source, 'commit', '--quiet', '-m', 'future solution');
  const hidden = git(source, 'rev-parse', 'HEAD');

  const result = await sealFixture({
    evidenceRepo: source,
    destination,
    mode: 'synthetic',
    contract: {
      startCommit: allowed,
      endCommit: solution,
      hiddenCommits: [solution, hidden],
      workerHistory: { first: FIRST, last: LAST },
      rounds: contract.rounds,
      mode_contracts: contract.mode_contracts,
      external_snapshot_handoff: 'upfront',
      reviewed_external_snapshot_handoff: true,
      oracleManifest: { checks: ['independent-oracle'] },
    },
  });

  assert.equal(result.workerRepo, destination);
  assert.equal(git(destination, 'rev-parse', 'HEAD'), allowed);
  assert.throws(() => git(destination, 'cat-file', '-e', `${solution}^{commit}`));
  assert.throws(() => git(destination, 'cat-file', '-e', `${hidden}^{commit}`));
  await assert.rejects(fs.access(path.join(destination, '.git', 'objects', 'info', 'alternates')));
  const visible = JSON.parse(await fs.readFile(path.join(destination, 'benchmark-contract.json'), 'utf8'));
  assert.equal(visible.mode, 'synthetic');
  assert.deepEqual(visible.rounds.map(round => round.id), ['round-1', 'round-2', 'round-3', 'round-4', 'round-5', 'round-6', 'round-9', 'round-10']);
});

test('the redacted archive contract contains ten reviewable sourced rounds', () => {
  assert.equal(contract.review_required, true);
  assert.equal(contract.rounds.length, 10);
  for (const round of contract.rounds) {
    for (const field of ['id', 'intent', 'source', 'confidence', 'reveal_after', 'external_inputs', 'checks']) {
      assert.ok(round[field] !== undefined, `${round.id} missing ${field}`);
    }
  }
});

test('production sealing rejects a missing reviewed ten-round contract', async () => {
  const destination = await fs.mkdtemp(path.join(os.tmpdir(), 'maintenance-production-contract-'));
  await assert.rejects(
    sealFixture({ evidenceRepo: process.cwd(), destination, mode: 'complete-brief', contract: {} }),
    /ten-round|visible contract|reveal policy|reviewed/i,
  );
});

test('sealing rejects visible payload injection and does not expose a causal future round', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'maintenance-causal-contract-'));
  const source = path.join(root, 'evidence');
  const destination = path.join(root, 'worker');
  await fs.mkdir(source);
  git(source, 'init', '--quiet');
  git(source, 'config', 'user.email', 'fixture@example.invalid');
  git(source, 'config', 'user.name', 'Fixture');
  await fs.writeFile(path.join(source, 'visible.txt'), 'visible\n');
  git(source, 'add', 'visible.txt');
  git(source, 'commit', '--quiet', '-m', 'visible input');
  const base = git(source, 'rev-parse', 'HEAD');
  const causal = {
    ...contract,
    startCommit: base,
    endCommit: base,
    workerHistory: { first: FIRST, last: LAST },
    visibleContract: { mode: 'causal-replay', rounds: contract.rounds, oracleManifest: 'injected' },
    external_snapshot_handoff: 'upfront',
    reviewed_external_snapshot_handoff: true,
    oracleManifest: { checks: ['independent-oracle'] },
  };
  await assert.rejects(sealFixture({ evidenceRepo: source, destination, mode: 'synthetic', contract: causal }), /visible contract|payload|mode/i);
});

test('causal initial payload contains only the reviewed first round', async () => {
  const destination = await fs.mkdtemp(path.join(os.tmpdir(), 'maintenance-causal-initial-'));
  const result = await sealFixture({
    evidenceRepo: process.cwd(),
    destination,
    mode: 'causal-replay',
    contract: {
      ...contract,
      workerHistory: { first: FIRST, last: LAST },
      hiddenCommits: [git(process.cwd(), 'rev-parse', 'HEAD')],
    },
  });
  const visible = JSON.parse(await fs.readFile(result.visibleContractPath, 'utf8'));
  assert.deepEqual(visible.rounds.map(round => round.id), ['round-1']);
  assert.equal(Object.hasOwn(visible, 'oracleManifest'), false);
  assert.equal(Object.hasOwn(visible, 'last_worker_commit'), false);
});

test('mode policy arrays must match the fixed reviewed sequences', async () => {
  const cases = [
    ['complete-brief', ['round-1', 'round-2', 'round-3', 'round-4', 'round-5', 'round-6', 'round-7', 'round-9', 'round-10']],
    ['complete-brief', ['round-1', 'round-2', 'round-3', 'round-4', 'round-5', 'round-6', 'round-9', 'round-9', 'round-10']],
    ['causal-replay', ['round-1', 'round-2', 'round-3', 'round-4', 'round-5', 'round-6', 'round-7', 'round-8', 'round-9']],
    ['causal-replay', ['round-2', 'round-1', 'round-3', 'round-4', 'round-5', 'round-6', 'round-7', 'round-8', 'round-9', 'round-10']],
  ];
  for (const [mode, ids] of cases) {
    const mutated = JSON.parse(JSON.stringify(contract));
    const key = mode === 'complete-brief' ? 'included_rounds' : 'authorized_rounds';
    mutated.mode_contracts[mode][key] = ids;
    mutated.external_snapshot_handoff = 'upfront';
    mutated.reviewed_external_snapshot_handoff = true;
    const destination = await fs.mkdtemp(path.join(os.tmpdir(), 'maintenance-policy-'));
    await assert.rejects(sealFixture({ evidenceRepo: process.cwd(), destination, mode, contract: mutated }), /fixed|sequence|policy|round/i);
  }
});

test('required external handoff rejects unresolved, arbitrary, and unreviewed values', async () => {
  for (const [handoff, reviewed] of [[undefined, undefined], ['unresolved-user-decision', true], ['later', true], ['upfront', false]]) {
    const mutated = { ...contract, external_snapshot_handoff: handoff, reviewed_external_snapshot_handoff: reviewed };
    const destination = await fs.mkdtemp(path.join(os.tmpdir(), 'maintenance-handoff-'));
    await assert.rejects(sealFixture({ evidenceRepo: process.cwd(), destination, mode: 'complete-brief', contract: mutated }), /handoff/i);
  }
});
