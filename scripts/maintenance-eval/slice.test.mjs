import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { inspectReferenceSlice, probeAuthoringNoMutation } from './slice.mjs';

const OWNERS = ['core', 'assurance', 'comms', 'control', 'social', 'workspace'];

function git(cwd, ...args) {
  return execFileSync('git', ['-C', cwd, ...args], { encoding: 'utf8' }).trim();
}

async function write(root, relative, contents) {
  const target = path.join(root, relative);
  await fs.mkdir(path.dirname(target), { recursive: true });
  await fs.writeFile(target, contents);
}

function contracts(ref = 'heterodyne:0.6.0#comms-old', boundary = 'comms.evaluate') {
  return `type C = unknown;
const CURRENT_CASE_CONTRACTS = ({
  "comms/cross-owner": {
    boundary_id: "${boundary}",
    owner_document: "comms",
    spec_refs: ["${ref}"],
    invariants: ["COMMS-I-TEST"],
    reason_codes: [],
  },
}) as const satisfies Readonly<Record<string, C>>;
export function currentCaseIds() { return Object.keys(CURRENT_CASE_CONTRACTS); }
`;
}

async function makeRepo({ author = 'guard', contract = contracts() } = {}) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'slice-oracle-'));
  git(root, 'init', '--quiet');
  git(root, 'config', 'user.email', 'slice@example.invalid');
  git(root, 'config', 'user.name', 'Slice fixture');
  for (const owner of OWNERS) {
    const convention = owner === 'core' ? `<a id="core-document-conventions"></a>\n**Family version.** \`heterodyne/0.6.0\`.\n**Qualified references.** \`heterodyne:<semver>#<anchor>\`.\n` : '';
    await write(root, `docs/spec/heterodyne-${owner}.md`, `${convention}<a id="${owner}-old"></a>\n<a id="${owner}-target"></a>\n`);
  }
  await write(root, 'docs/spec/vectors/generator/src/current-vectors/case-contracts.ts', contract);
  const authorSource = author === 'loader-failure'
    ? 'export const broken = ;\n'
    : author === 'write-then-throw'
      ? `import { readFile, writeFile } from 'node:fs/promises';
export async function authorAllVectors(outputDir) {
  const source = await readFile(new URL('./current-vectors/case-contracts.ts', import.meta.url), 'utf8');
  if (!source.includes('synthetic-missing-anchor')) {
    await writeFile(new URL('positive.json', new URL('file://' + outputDir + '/')), '{}');
    return ['positive.json'];
  }
  await writeFile(new URL('retired.json', new URL('file://' + outputDir + '/')), 'changed');
  throw new Error('reference validation rejected synthetic-missing-anchor');
}\n`
      : `import { readFile, writeFile } from 'node:fs/promises';
export async function authorAllVectors(outputDir) {
  const source = await readFile(new URL('./current-vectors/case-contracts.ts', import.meta.url), 'utf8');
  const match = source.match(/heterodyne:0\\.6\\.0#[a-z0-9-]+-synthetic-missing-anchor/);
  if (match) throw new Error('reference validation rejected absent anchor ' + match[0]);
  await writeFile(new URL('positive.json', new URL('file://' + outputDir + '/')), '{}');
  return ['positive.json'];
}\n`;
  await write(root, 'docs/spec/vectors/generator/src/author.ts', authorSource);
  await write(root, 'docs/spec/vectors/generator/package-lock.json', await fs.readFile(path.join(process.cwd(), 'docs/spec/vectors/generator/package-lock.json')));
  await write(root, 'docs/spec/vectors/snapshot.json', '{"frozen":true}\n');
  git(root, 'add', '.');
  git(root, 'commit', '--quiet', '-m', 'base');
  return root;
}

async function candidateFrom(base) {
  const candidate = await fs.mkdtemp(path.join(os.tmpdir(), 'slice-candidate-'));
  await fs.rm(candidate, { recursive: true });
  execFileSync('git', ['clone', '--quiet', base, candidate]);
  return candidate;
}

test('accepts resolved cross-owner refs and reserves their semantics for review', async () => {
  const base = await makeRepo();
  const candidate = await candidateFrom(base);
  await write(candidate, 'docs/spec/vectors/generator/src/current-vectors/case-contracts.ts', contracts('heterodyne:0.6.0#core-target'));

  const result = await inspectReferenceSlice({ baseRepo: base, candidateRepo: candidate, baseRef: 'HEAD' });

  assert.equal(result.accepted, true);
  assert.equal(result.counts.cases, 1);
  assert.equal(result.counts.references, 1);
  assert.equal(result.referenceChanges.length, 1);
  assert.deepEqual(result.referenceChanges[0].after, ['heterodyne:0.6.0#core-target']);
  assert.equal(result.referenceChanges[0].anchorResolution, 'resolved');
  assert.equal(result.referenceChanges[0].governingSemanticReview, 'required');
  assert.deepEqual(result.provenance, {
    familyVersion: '0.6.0',
    sourcePath: 'docs/spec/heterodyne-core.md',
    sourceAnchor: 'core-document-conventions',
    referenceForm: 'heterodyne:<semver>#<anchor>',
  });
});

test('fails closed for a missing anchor and unsupported computed catalog declarations', async () => {
  const base = await makeRepo();
  const candidate = await candidateFrom(base);
  await write(candidate, 'docs/spec/vectors/generator/src/current-vectors/case-contracts.ts', contracts('heterodyne:0.6.0#core-absent'));
  let result = await inspectReferenceSlice({ baseRepo: base, candidateRepo: candidate, baseRef: 'HEAD' });
  assert.equal(result.accepted, false);
  assert.ok(result.findings.some(({ code }) => code === 'reference-anchor-missing'));

  await write(candidate, 'docs/spec/vectors/generator/src/current-vectors/case-contracts.ts', `const key = "comms/cross-owner"; const CURRENT_CASE_CONTRACTS = { [key]: { boundary_id: "x", owner_document: "comms", spec_refs: ["heterodyne:0.6.0#comms-old"], invariants: [], reason_codes: [] } };`);
  result = await inspectReferenceSlice({ baseRepo: base, candidateRepo: candidate, baseRef: 'HEAD' });
  assert.equal(result.accepted, false);
  assert.ok(result.findings.some(({ code }) => code === 'catalog-unsupported-ast'));
});

test('rejects non-reference catalog allocation edits and frozen snapshot changes', async () => {
  const base = await makeRepo();
  const candidate = await candidateFrom(base);
  await write(candidate, 'docs/spec/vectors/generator/src/current-vectors/case-contracts.ts', contracts('heterodyne:0.6.0#core-target', 'comms.changed'));
  await write(candidate, 'docs/spec/vectors/snapshot.json', '{"frozen":false}\n');

  const result = await inspectReferenceSlice({ baseRepo: base, candidateRepo: candidate, baseRef: 'HEAD' });

  assert.equal(result.accepted, false);
  assert.ok(result.findings.some(({ code }) => code === 'catalog-non-reference-changed'), JSON.stringify(result.findings));
  assert.ok(result.findings.some(({ code, path: findingPath }) => code === 'forbidden-path-change' && findingPath === 'docs/spec/vectors/snapshot.json'));
});

test('rejects effective allocation changes in catalog consumer logic after the literal', async () => {
  const base = await makeRepo();
  const candidate = await candidateFrom(base);
  const catalogPath = 'docs/spec/vectors/generator/src/current-vectors/case-contracts.ts';
  const source = await fs.readFile(path.join(candidate, catalogPath), 'utf8');
  await write(candidate, catalogPath, source.replace(
    'return Object.keys(CURRENT_CASE_CONTRACTS);',
    'return [{ ...CURRENT_CASE_CONTRACTS["comms/cross-owner"], boundary_id: "comms.changed" }];',
  ));

  const result = await inspectReferenceSlice({ baseRepo: base, candidateRepo: candidate, baseRef: 'HEAD' });

  assert.equal(result.accepted, false);
  assert.ok(result.findings.some(({ code }) => code === 'catalog-non-reference-changed'));
});

test('new helper acceptance requires exact reviewed bytes and reports patch provenance', async () => {
  const base = await makeRepo();
  const candidate = await candidateFrom(base);
  const helperPath = 'docs/spec/vectors/generator/src/maintenance-reference-validation.ts';
  const contents = 'export const reviewed = true;\n';
  await write(candidate, helperPath, contents);

  let result = await inspectReferenceSlice({ baseRepo: base, candidateRepo: candidate, baseRef: 'HEAD' });
  assert.equal(result.accepted, false);
  assert.ok(result.findings.some(({ code }) => code === 'new-file-scope-review-pending'));
  assert.deepEqual(result.inventory.newReferenceHelpers, [{
    path: helperPath,
    size: Buffer.byteLength(contents),
    sha256: createHash('sha256').update(contents).digest('hex'),
    patchProvenance: 'untracked',
    approved: false,
  }]);

  result = await inspectReferenceSlice({
    baseRepo: base,
    candidateRepo: candidate,
    baseRef: 'HEAD',
    approvedNewFiles: [{ path: helperPath, sha256: '0'.repeat(64) }],
  });
  assert.equal(result.accepted, false);
  assert.ok(result.findings.some(({ code }) => code === 'new-file-scope-review-pending'));

  result = await inspectReferenceSlice({
    baseRepo: base,
    candidateRepo: candidate,
    baseRef: 'HEAD',
    approvedNewFiles: [{ path: helperPath, sha256: createHash('sha256').update(contents).digest('hex') }],
  });
  assert.equal(result.accepted, true);
  assert.equal(result.inventory.newReferenceHelpers[0].approved, true);
});

test('oversized, differently named, wrong-digest, and duplicate helper approvals stay rejected', async () => {
  const base = await makeRepo();
  const candidate = await candidateFrom(base);
  const helperPath = 'docs/spec/vectors/generator/src/maintenance-reference-validation.test.ts';
  const contents = 'x'.repeat(65537);
  const sha256 = createHash('sha256').update(contents).digest('hex');
  await write(candidate, helperPath, contents);
  await write(candidate, 'docs/spec/vectors/generator/src/reference-validation-helper.ts', 'small\n');

  const result = await inspectReferenceSlice({
    baseRepo: base,
    candidateRepo: candidate,
    baseRef: 'HEAD',
    approvedNewFiles: [
      { path: helperPath, sha256 },
      { path: helperPath, sha256 },
      { path: 'docs/spec/vectors/generator/src/reference-validation-helper.ts', sha256: '0'.repeat(64) },
    ],
  });

  assert.equal(result.accepted, false);
  assert.ok(result.findings.some(({ code }) => code === 'new-file-too-large'));
  assert.ok(result.findings.some(({ code }) => code === 'new-file-path-out-of-scope'));
  assert.ok(result.findings.some(({ code }) => code === 'new-file-approval-invalid'));
});

test('rejects untracked nonignored and ignored path additions', async () => {
  const base = await makeRepo();
  const candidate = await candidateFrom(base);
  await write(candidate, '.gitignore', 'hidden.txt\n');
  await write(candidate, 'stray.txt', 'stray\n');
  await write(candidate, 'hidden.txt', 'hidden\n');

  const result = await inspectReferenceSlice({ baseRepo: base, candidateRepo: candidate, baseRef: 'HEAD' });

  assert.equal(result.accepted, false);
  assert.ok(result.findings.some(({ code, path: findingPath }) => code === 'untracked-path' && findingPath === 'stray.txt'));
  assert.ok(result.findings.some(({ code, path: findingPath }) => code === 'ignored-path-change' && findingPath === 'hidden.txt'));
});

test('rejects a symlink escape even at an otherwise editable path', async () => {
  const base = await makeRepo();
  const candidate = await candidateFrom(base);
  const authorPath = path.join(candidate, 'docs/spec/vectors/generator/src/author.ts');
  const outside = path.join(await fs.mkdtemp(path.join(os.tmpdir(), 'slice-outside-')), 'author.ts');
  await fs.writeFile(outside, await fs.readFile(authorPath));
  await fs.unlink(authorPath);
  await fs.symlink(outside, authorPath);

  const result = await inspectReferenceSlice({ baseRepo: base, candidateRepo: candidate, baseRef: 'HEAD' });

  assert.equal(result.accepted, false);
  assert.ok(result.findings.some(({ code, path: findingPath }) => code === 'path-type-unsupported' && findingPath.endsWith('/author.ts')));
});

test('dynamic probe accepts a real pre-mutation missing-reference rejection', async () => {
  const repo = await makeRepo();
  const result = await probeAuthoringNoMutation({ repo });
  assert.equal(result.accepted, true);
  assert.equal(result.positive.status, 'completed');
  assert.equal(result.negative.status, 'boundary-rejected');
  assert.equal(result.negative.started, true);
  assert.equal(result.negative.imported, true);
  assert.equal(result.negative.outputManifestEqual, true);
  assert.equal(result.dependencyProvenance.matched, true);
  assert.match(result.dependencyProvenance.lockSha256, /^[0-9a-f]{64}$/u);
  assert.equal(result.positive.dependencyLockSha256, result.dependencyProvenance.lockSha256);
});

test('dynamic probe detects an author that writes and then throws', async () => {
  const repo = await makeRepo({ author: 'write-then-throw' });
  const result = await probeAuthoringNoMutation({ repo });
  assert.equal(result.accepted, false);
  assert.equal(result.negative.status, 'mutation-before-rejection');
  assert.equal(result.negative.outputManifestEqual, false);
});

test('dynamic probe distinguishes loader failure from reference rejection', async () => {
  const repo = await makeRepo({ author: 'loader-failure' });
  const result = await probeAuthoringNoMutation({ repo });
  assert.equal(result.accepted, false);
  assert.equal(result.positive.status, 'runner-failure');
  assert.equal(result.positive.runnerFailure, true);
  assert.equal(result.positive.boundaryRejected, false);
});

test('dynamic fallback rejects a candidate lockfile that differs from the dependency provider', async () => {
  const repo = await makeRepo();
  await write(repo, 'docs/spec/vectors/generator/package-lock.json', '{"mismatched":true}\n');

  const result = await probeAuthoringNoMutation({ repo });

  assert.equal(result.accepted, false);
  assert.equal(result.positive.status, 'dependency-lock-mismatch');
  assert.equal(result.positive.runnerFailure, true);
  assert.equal(result.negative.status, 'not-run');
});
