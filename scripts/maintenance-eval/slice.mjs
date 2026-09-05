import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const EVALUATOR_ROOT = path.resolve(HERE, '../..');
const GENERATOR = 'docs/spec/vectors/generator';
const CONTRACTS = `${GENERATOR}/src/current-vectors/case-contracts.ts`;
const AUTHOR = `${GENERATOR}/src/author.ts`;
const OWNERS = ['core', 'assurance', 'comms', 'control', 'social', 'workspace'];
const OWNER_SET = new Set(OWNERS);
const EXACT_EDITABLE = new Set([AUTHOR, CONTRACTS]);
const require = createRequire(import.meta.url);
const ts = require(path.join(EVALUATOR_ROOT, GENERATOR, 'node_modules/typescript/lib/typescript.js'));

class OracleError extends Error {
  constructor(code, message, details = {}) {
    super(message);
    this.code = code;
    this.details = details;
  }
}

function finding(code, message, details = {}) {
  return { code, message, ...details };
}

function unwrap(node) {
  while (ts.isParenthesizedExpression(node) || ts.isAsExpression(node) || ts.isSatisfiesExpression(node) || ts.isTypeAssertionExpression(node)) node = node.expression;
  return node;
}

function explicitName(name, context) {
  if (ts.isComputedPropertyName(name)) throw new OracleError('catalog-unsupported-ast', `${context} uses a computed property`);
  if (ts.isIdentifier(name) || ts.isStringLiteral(name) || ts.isNoSubstitutionTemplateLiteral(name) || ts.isNumericLiteral(name)) return name.text;
  throw new OracleError('catalog-unsupported-ast', `${context} uses an unsupported property name`);
}

function canonicalAst(node, placeholders) {
  if (placeholders.has(node)) return ['SpecRefsInitializer'];
  const value = [node.kind];
  if (ts.isIdentifier(node) || ts.isPrivateIdentifier(node) || ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node) || ts.isNumericLiteral(node) || ts.isBigIntLiteral(node)) value.push(node.text);
  const children = [];
  ts.forEachChild(node, child => { children.push(canonicalAst(child, placeholders)); });
  value.push(children);
  return value;
}

function parseCatalog(source, sourcePath) {
  const sourceFile = ts.createSourceFile(sourcePath, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  if (sourceFile.parseDiagnostics.length) throw new OracleError('catalog-unparseable', `${sourcePath} has TypeScript parse diagnostics`);
  const declarations = [];
  let declarationStatement;
  for (const statement of sourceFile.statements) {
    if (!ts.isVariableStatement(statement)) continue;
    for (const declaration of statement.declarationList.declarations) {
      if (ts.isIdentifier(declaration.name) && declaration.name.text === 'CURRENT_CASE_CONTRACTS') {
        declarations.push(declaration);
        declarationStatement = statement;
      }
    }
  }
  if (declarations.length !== 1 || declarations[0].initializer === undefined) throw new OracleError('catalog-unsupported-ast', 'CURRENT_CASE_CONTRACTS must be one initialized declaration');
  const initializer = unwrap(declarations[0].initializer);
  if (!ts.isObjectLiteralExpression(initializer)) throw new OracleError('catalog-unsupported-ast', 'CURRENT_CASE_CONTRACTS must unwrap to an object literal');

  const cases = new Map();
  const placeholders = new Set();
  for (const property of initializer.properties) {
    if (!ts.isPropertyAssignment(property)) throw new OracleError('catalog-unsupported-ast', 'catalog cases must be explicit property assignments');
    const caseId = explicitName(property.name, 'catalog case');
    if (cases.has(caseId)) throw new OracleError('catalog-duplicate-id', `duplicate case ID: ${caseId}`);
    const contract = unwrap(property.initializer);
    if (!ts.isObjectLiteralExpression(contract)) throw new OracleError('catalog-unsupported-ast', `${caseId} must be an object literal`);
    const fields = new Map();
    for (const field of contract.properties) {
      if (!ts.isPropertyAssignment(field)) throw new OracleError('catalog-unsupported-ast', `${caseId} contains an unsupported declaration`);
      const name = explicitName(field.name, caseId);
      if (fields.has(name)) throw new OracleError('catalog-duplicate-field', `${caseId} repeats ${name}`);
      fields.set(name, field.initializer);
    }
    const refsNode = fields.get('spec_refs');
    if (refsNode === undefined) throw new OracleError('catalog-missing-spec-refs', `${caseId} lacks spec_refs`);
    const refsArray = unwrap(refsNode);
    if (!ts.isArrayLiteralExpression(refsArray) || refsArray.elements.length === 0) throw new OracleError('catalog-invalid-spec-refs', `${caseId} spec_refs must be a nonempty array literal`);
    const refs = refsArray.elements.map(element => {
      const value = unwrap(element);
      if (!ts.isStringLiteral(value) && !ts.isNoSubstitutionTemplateLiteral(value)) throw new OracleError('catalog-invalid-spec-refs', `${caseId} spec_refs must contain only string literals`);
      return { value: value.text, start: value.getStart(sourceFile), end: value.end };
    });
    if (new Set(refs.map(({ value }) => value)).size !== refs.length) throw new OracleError('catalog-duplicate-reference', `${caseId} contains duplicate spec_refs`);
    const ownerNode = unwrap(fields.get('owner_document') ?? refsArray);
    const ownerDocument = ts.isStringLiteral(ownerNode) || ts.isNoSubstitutionTemplateLiteral(ownerNode) ? ownerNode.text : null;
    placeholders.add(refsNode);
    cases.set(caseId, { ownerDocument, refs });
  }
  const declarationKind = declarationStatement.declarationList.flags & (ts.NodeFlags.Const | ts.NodeFlags.Let);
  return { cases, skeleton: JSON.stringify([declarationKind, canonicalAst(declarations[0], placeholders)]), sourceFile };
}

function deriveDocuments(read) {
  return Promise.all(OWNERS.map(async owner => {
    const sourcePath = `docs/spec/heterodyne-${owner}.md`;
    const source = await read(sourcePath);
    const anchors = new Set();
    for (const match of source.matchAll(/<a\s+id="([^"]+)"\s*><\/a>/gu)) {
      const anchor = match[1];
      if (!anchor.startsWith(`${owner}-`)) throw new OracleError('document-anchor-owner-mismatch', `${sourcePath} contains non-${owner} anchor ${anchor}`);
      if (anchors.has(anchor)) throw new OracleError('document-duplicate-anchor', `${sourcePath} repeats ${anchor}`);
      anchors.add(anchor);
    }
    return [owner, { sourcePath, source, anchors }];
  })).then(entries => new Map(entries));
}

function deriveVersion(documents) {
  const core = documents.get('core');
  const marker = '<a id="core-document-conventions"></a>';
  const start = core.source.indexOf(marker);
  if (start < 0) throw new OracleError('version-provenance-missing', 'core-document-conventions is absent');
  const remainder = core.source.slice(start + marker.length);
  const nextAnchor = remainder.search(/<a\s+id="/u);
  const section = nextAnchor < 0 ? remainder : remainder.slice(0, nextAnchor);
  const versions = [...section.matchAll(/heterodyne\/(\d+\.\d+\.\d+)/gu)].map(match => match[1]);
  if (new Set(versions).size !== 1) throw new OracleError('version-provenance-ambiguous', 'core-document-conventions must fix exactly one family version');
  if (!section.includes('heterodyne:<semver>#<anchor>')) throw new OracleError('reference-form-provenance-missing', 'core-document-conventions lacks the normative reference form');
  return versions[0];
}

function validateReferences(catalog, documents, version, findings) {
  let count = 0;
  for (const [caseId, contract] of catalog.cases) {
    for (const { value: reference } of contract.refs) {
      count += 1;
      const match = /^heterodyne:(\d+\.\d+\.\d+)#([a-z0-9][a-z0-9-]*)$/u.exec(reference);
      if (!match) {
        findings.push(finding('reference-form-invalid', `${caseId} has an invalid qualified reference`, { caseId, reference }));
        continue;
      }
      const [, citedVersion, anchor] = match;
      const owner = OWNERS.find(candidate => anchor.startsWith(`${candidate}-`));
      if (citedVersion !== version) findings.push(finding('reference-version-mismatch', `${caseId} cites ${citedVersion}, expected ${version}`, { caseId, reference }));
      if (!owner || !OWNER_SET.has(owner)) findings.push(finding('reference-owner-unknown', `${caseId} cites an unowned anchor`, { caseId, reference }));
      else if (!documents.get(owner).anchors.has(anchor)) findings.push(finding('reference-anchor-missing', `${caseId} cites absent ${owner} anchor ${anchor}`, { caseId, reference, document: documents.get(owner).sourcePath }));
    }
  }
  return count;
}

function runGit(cwd, args, { encoding = 'utf8' } = {}) {
  return new Promise((resolve, reject) => execFile('git', ['-C', cwd, ...args], { encoding, maxBuffer: 64 * 1024 * 1024 }, (error, stdout, stderr) => error ? reject(Object.assign(error, { stdout, stderr })) : resolve(stdout)));
}

async function nulGit(cwd, args) {
  const stdout = await runGit(cwd, [...args, '-z'], { encoding: 'buffer' });
  return stdout.toString('utf8').split('\0').filter(Boolean);
}

async function baseBlob(baseRepo, baseRef, relativePath) {
  return runGit(baseRepo, ['show', `${baseRef}:${relativePath}`], { encoding: 'buffer' });
}

function isNewReferenceHelper(relativePath) {
  if (!relativePath.startsWith(`${GENERATOR}/src/`) || !relativePath.endsWith('.ts')) return false;
  const name = path.posix.basename(relativePath).toLowerCase();
  return name.includes('reference') && name.includes('validat');
}

async function sameWorkingFile(leftRoot, rightRoot, relativePath) {
  try {
    const [left, right] = await Promise.all([fs.readFile(path.join(leftRoot, relativePath)), fs.readFile(path.join(rightRoot, relativePath))]);
    return left.equals(right);
  } catch {
    return false;
  }
}

async function inspectPaths({ baseRepo, candidateRepo, baseRef }, findings) {
  const basePaths = await nulGit(baseRepo, ['ls-tree', '-r', '--name-only', baseRef]);
  const candidateTracked = new Set(await nulGit(candidateRepo, ['ls-files']));
  const untracked = await nulGit(candidateRepo, ['ls-files', '--others', '--exclude-standard']);
  const ignored = (await nulGit(candidateRepo, ['ls-files', '--others', '--ignored', '--exclude-standard']))
    .filter(relativePath => !relativePath.split('/').includes('node_modules'));
  const changedPaths = [];
  const newHelpers = [];
  for (const relativePath of basePaths) {
    let equal = false;
    try {
      const stat = await fs.lstat(path.join(candidateRepo, relativePath));
      if (!stat.isFile()) {
        findings.push(finding('path-type-unsupported', `candidate tracked path is not a regular file: ${relativePath}`, { path: relativePath }));
        throw new Error('unsupported candidate path type');
      }
      const [base, candidate] = await Promise.all([baseBlob(baseRepo, baseRef, relativePath), fs.readFile(path.join(candidateRepo, relativePath))]);
      equal = base.equals(candidate);
    } catch {}
    if (!equal) {
      changedPaths.push(relativePath);
      if (!EXACT_EDITABLE.has(relativePath)) findings.push(finding('forbidden-path-change', `tracked base bytes changed outside the slice: ${relativePath}`, { path: relativePath }));
    }
  }
  const additions = [...candidateTracked].filter(relativePath => !basePaths.includes(relativePath));
  for (const relativePath of [...new Set([...additions, ...untracked])]) {
    changedPaths.push(relativePath);
    let regular = false;
    try { regular = (await fs.lstat(path.join(candidateRepo, relativePath))).isFile(); } catch {}
    if (!regular) findings.push(finding('path-type-unsupported', `new candidate path is not a regular file: ${relativePath}`, { path: relativePath }));
    else if (isNewReferenceHelper(relativePath)) newHelpers.push(relativePath);
    else findings.push(finding('untracked-path', `new path is outside the bounded helper allowance: ${relativePath}`, { path: relativePath }));
  }
  for (const relativePath of ignored) {
    if (!await sameWorkingFile(baseRepo, candidateRepo, relativePath)) findings.push(finding('ignored-path-change', `ignored candidate path differs from evaluator base: ${relativePath}`, { path: relativePath }));
  }
  return { changedPaths: [...new Set(changedPaths)].sort(), untrackedPaths: untracked.sort(), ignoredChangedPaths: findings.filter(({ code }) => code === 'ignored-path-change').map(({ path: value }) => value).sort(), newReferenceHelpers: newHelpers.sort(), scopeApprovalRequired: newHelpers.length > 0 };
}

/** Independently inspect the bounded reference-only maintenance slice. */
export async function inspectReferenceSlice({ baseRepo, candidateRepo, baseRef }) {
  if (!baseRepo || !candidateRepo || !baseRef) throw new TypeError('baseRepo, candidateRepo, and baseRef are required');
  const findings = [];
  let inventory = { changedPaths: [], untrackedPaths: [], ignoredChangedPaths: [], newReferenceHelpers: [], scopeApprovalRequired: false };
  let baseCatalog;
  let candidateCatalog;
  let documents;
  let version = null;
  try { inventory = await inspectPaths({ baseRepo, candidateRepo, baseRef }, findings); } catch (error) { findings.push(finding('path-inventory-failed', error.message)); }
  try {
    const [baseSource, candidateSource] = await Promise.all([baseBlob(baseRepo, baseRef, CONTRACTS).then(value => value.toString('utf8')), fs.readFile(path.join(candidateRepo, CONTRACTS), 'utf8')]);
    baseCatalog = parseCatalog(baseSource, `${baseRef}:${CONTRACTS}`);
    candidateCatalog = parseCatalog(candidateSource, CONTRACTS);
    if (baseCatalog.skeleton !== candidateCatalog.skeleton) findings.push(finding('catalog-non-reference-changed', 'catalog AST differs outside spec_refs initializers'));
    documents = await deriveDocuments(relativePath => fs.readFile(path.join(candidateRepo, relativePath), 'utf8'));
    version = deriveVersion(documents);
  } catch (error) {
    findings.push(finding(error.code ?? 'static-inspection-failed', error.message, error.details));
  }
  const references = candidateCatalog && documents && version ? validateReferences(candidateCatalog, documents, version, findings) : 0;
  const referenceChanges = [];
  if (baseCatalog && candidateCatalog) {
    for (const [caseId, candidate] of candidateCatalog.cases) {
      const base = baseCatalog.cases.get(caseId);
      const before = base?.refs.map(({ value }) => value) ?? [];
      const after = candidate.refs.map(({ value }) => value);
      if (JSON.stringify(before) !== JSON.stringify(after)) referenceChanges.push({ caseId, ownerDocument: candidate.ownerDocument, before, after, anchorResolution: after.every(reference => !findings.some(item => item.reference === reference && item.code.startsWith('reference-'))) ? 'resolved' : 'failed', governingSemanticReview: 'required' });
    }
  }
  return {
    accepted: findings.length === 0,
    findings,
    counts: { cases: candidateCatalog?.cases.size ?? 0, references, changedPaths: inventory.changedPaths.length, changedReferences: referenceChanges.length },
    inventory,
    referenceChanges,
    provenance: version ? { familyVersion: version, sourcePath: 'docs/spec/heterodyne-core.md', sourceAnchor: 'core-document-conventions', referenceForm: 'heterodyne:<semver>#<anchor>' } : null,
    semanticVerdict: 'not-established',
  };
}

function digest(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

async function treeManifest(root) {
  const rows = [];
  async function visit(directory, prefix = '') {
    for (const entry of (await fs.readdir(directory, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name))) {
      const relativePath = prefix ? `${prefix}/${entry.name}` : entry.name;
      const target = path.join(directory, entry.name);
      if (entry.isDirectory()) { rows.push({ path: relativePath, type: 'directory' }); await visit(target, relativePath); }
      else if (entry.isFile()) rows.push({ path: relativePath, type: 'file', digest: digest(await fs.readFile(target)) });
      else if (entry.isSymbolicLink()) rows.push({ path: relativePath, type: 'symlink', target: await fs.readlink(target) });
      else rows.push({ path: relativePath, type: 'unsupported' });
    }
  }
  await visit(root);
  return rows;
}

async function copyCandidate(repo, destination) {
  await fs.cp(repo, destination, { recursive: true, filter: source => {
    const relativePath = path.relative(repo, source);
    return relativePath === '' || (!relativePath.split(path.sep).includes('.git') && !relativePath.split(path.sep).includes('node_modules'));
  }});
}

function processRun(command, args) {
  return new Promise(resolve => execFile(command, args, { encoding: 'utf8', maxBuffer: 4 * 1024 * 1024 }, (error, stdout, stderr) => resolve({ exitCode: error?.code ?? 0, signal: error?.signal ?? null, stdout, stderr })));
}

function bounded(value) {
  return String(value ?? '').slice(0, 4000);
}

function parseEvents(stdout) {
  return stdout.split('\n').filter(Boolean).flatMap(line => { try { return [JSON.parse(line)]; } catch { return []; } });
}

async function invokeAuthor({ repoCopy, outputDir, runner, loader }) {
  const authorPath = path.join(repoCopy, AUTHOR);
  const argv = ['--import', loader, runner, authorPath, outputDir];
  const processResult = await processRun(process.execPath, argv);
  const events = parseEvents(processResult.stdout);
  const started = events.some(event => event.event === 'started');
  const imported = events.some(event => event.event === 'imported');
  const completed = events.some(event => event.event === 'completed');
  const errorEvent = events.find(event => event.event === 'import-error' || event.event === 'author-error');
  return { command: process.execPath, argv, started, imported, completed, phase: errorEvent?.event ?? (completed ? 'completed' : 'unknown'), exitCode: processResult.exitCode, signal: processResult.signal, diagnostic: bounded(errorEvent?.error ?? processResult.stderr ?? processResult.stdout) };
}

function classifyPositive(run) {
  if (run.completed && run.exitCode === 0) return { ...run, status: 'completed', runnerFailure: false, boundaryRejected: false };
  const runnerFailure = !run.started || !run.imported || run.phase === 'import-error';
  return { ...run, status: runnerFailure ? 'runner-failure' : 'author-failure', runnerFailure, boundaryRejected: false };
}

/** Exercise the real author against one synthetic absent anchor in a fresh copy. */
export async function probeAuthoringNoMutation({ repo }) {
  if (!repo) throw new TypeError('repo is required');
  const tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'slice-author-probe-'));
  const repoCopy = path.join(tempRoot, 'candidate');
  const positiveDir = path.join(tempRoot, 'positive-output');
  const negativeDir = path.join(tempRoot, 'negative-output');
  const runner = path.join(tempRoot, 'runner.mjs');
  const evaluatorDependencies = path.join(EVALUATOR_ROOT, GENERATOR, 'node_modules');
  let dependencySource = path.join(repo, GENERATOR, 'node_modules');
  try { await fs.access(dependencySource); } catch { dependencySource = evaluatorDependencies; }
  const loader = path.join(dependencySource, 'tsx/dist/loader.mjs');
  await copyCandidate(repo, repoCopy);
  await fs.symlink(dependencySource, path.join(repoCopy, GENERATOR, 'node_modules'), 'dir');
  await Promise.all([fs.mkdir(positiveDir), fs.mkdir(path.join(negativeDir, 'schema'), { recursive: true })]);
  await fs.writeFile(runner, `import { pathToFileURL } from 'node:url';
const [authorPath, outputDir] = process.argv.slice(2);
process.stdout.write(JSON.stringify({event:'started'})+'\\n');
let loaded;
try { loaded = await import(pathToFileURL(authorPath)); process.stdout.write(JSON.stringify({event:'imported'})+'\\n'); }
catch (error) { process.stdout.write(JSON.stringify({event:'import-error',error:String(error?.stack ?? error)})+'\\n'); process.exitCode=21; }
if (loaded) { try { await loaded.authorAllVectors(outputDir); process.stdout.write(JSON.stringify({event:'completed'})+'\\n'); }
catch (error) { process.stdout.write(JSON.stringify({event:'author-error',error:String(error?.stack ?? error)})+'\\n'); process.exitCode=23; } }
`);
  const positive = classifyPositive(await invokeAuthor({ repoCopy, outputDir: positiveDir, runner, loader }));

  await fs.writeFile(path.join(negativeDir, 'sentinel.bin'), Buffer.from([0, 1, 2, 255]));
  await fs.writeFile(path.join(negativeDir, 'fixtures.json'), '{"sentinel":"fixtures"}\n');
  await fs.writeFile(path.join(negativeDir, 'schema/vector.schema.json'), '{"sentinel":"schema"}\n');
  await fs.writeFile(path.join(negativeDir, 'retired.json'), '{"vector_id":"retired/sentinel"}\n');
  const before = await treeManifest(negativeDir);

  let negative;
  try {
    const contractPath = path.join(repoCopy, CONTRACTS);
    const source = await fs.readFile(contractPath, 'utf8');
    const parsed = parseCatalog(source, CONTRACTS);
    const first = [...parsed.cases.values()][0]?.refs[0];
    if (!first) throw new OracleError('probe-fixture-invalid', 'catalog has no reference to replace');
    const match = /^heterodyne:(\d+\.\d+\.\d+)#([a-z0-9]+)-/u.exec(first.value);
    if (!match) throw new OracleError('probe-fixture-invalid', 'first reference is not owner-qualified');
    const syntheticReference = `heterodyne:${match[1]}#${match[2]}-synthetic-missing-anchor`;
    await fs.writeFile(contractPath, `${source.slice(0, first.start)}${JSON.stringify(syntheticReference)}${source.slice(first.end)}`);
    const run = await invokeAuthor({ repoCopy, outputDir: negativeDir, runner, loader });
    const after = await treeManifest(negativeDir);
    const outputManifestEqual = JSON.stringify(before) === JSON.stringify(after);
    const rejectionDiagnostic = run.phase === 'author-error' && run.diagnostic.includes(syntheticReference) && /reference|anchor|spec[_ -]?ref/iu.test(run.diagnostic);
    const runnerFailure = !run.started || !run.imported || run.phase === 'import-error';
    const boundaryRejected = rejectionDiagnostic && run.exitCode !== 0;
    const status = runnerFailure ? 'runner-failure' : run.completed ? 'missing-reference-accepted' : !outputManifestEqual ? 'mutation-before-rejection' : boundaryRejected ? 'boundary-rejected' : 'unrelated-author-failure';
    negative = { ...run, status, runnerFailure, boundaryRejected, outputManifestEqual, beforeManifest: before, afterManifest: after, syntheticReference };
  } catch (error) {
    negative = { status: 'probe-runner-failure', runnerFailure: true, boundaryRejected: false, outputManifestEqual: false, diagnostic: bounded(error.stack ?? error.message) };
  }
  return { accepted: positive.status === 'completed' && negative.status === 'boundary-rejected', dependencySource, positive, negative, limitations: ['exploratory evaluator execution; no OS isolation', 'does not establish governing-semantic correctness or full conformance'] };
}
