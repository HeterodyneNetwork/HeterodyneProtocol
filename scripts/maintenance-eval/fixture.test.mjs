import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { sealFixture } from './fixture.mjs';

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
      endCommit: allowed,
      hiddenCommits: [hidden],
      workerHistory: { first: FIRST, last: LAST },
      visibleContract: { rounds: 10 },
      oracleManifest: { checks: ['independent-oracle'] },
    },
  });

  assert.equal(result.workerRepo, destination);
  assert.equal(git(destination, 'rev-parse', 'HEAD'), allowed);
  assert.throws(() => git(destination, 'cat-file', '-e', `${hidden}^{commit}`));
  await assert.rejects(fs.access(path.join(destination, '.git', 'objects', 'info', 'alternates')));
});
