import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const adapter = () => import('./vector-trace/sara.mjs');
const graph = {
  items: [
    {semantic_id: 'heterodyne:core#sample', sara_id: '11111111-1111-5111-8111-111111111111', type: 'spec_anchor', source_path: 'docs/spec/heterodyne-core.md', source_digest: 'a'.repeat(64), evidence_kind: 'normative'},
    {semantic_id: 'vector:core/sample', sara_id: '22222222-2222-5222-8222-222222222222', type: 'vector', source_path: 'docs/spec/vectors/core/sample.json', source_digest: 'b'.repeat(64), evidence_kind: 'snapshot'},
  ],
  edges: [{from:'vector:core/sample', to:'heterodyne:core#sample', relation:'covers', source_path:'docs/spec/vectors/coverage/manifest.json'}],
  receipt: {lane:'snapshot', unresolved_references:[]},
};

test('materialization keeps semantic identity, provenance, and exact relation targets', async () => {
  const {withGraph} = await adapter();
  let root;
  await withGraph(graph, {}, async directory => {
    root = directory;
    const text = readFileSync(join(root,'items','22222222-2222-5222-8222-222222222222.md'),'utf8');
    assert.match(text, /vector:core\/sample/);
    assert.match(text, /11111111-1111-5111-8111-111111111111/);
    assert.match(text, /covers/);
    assert.match(text, /evidence_kind/);
    assert.ok(existsSync(join(root,'receipt.json')));
  });
  assert.equal(existsSync(root), false);
});

test('failed graph operation still cleans its owned temporary directory', async () => {
  const {withGraph} = await adapter();
  let root;
  await assert.rejects(withGraph(graph, {}, async directory => { root = directory; throw Error('operation failed'); }), /operation failed/);
  assert.equal(existsSync(root),false);
});

test('explicit output refuses existing directories and repository destinations', async () => {
  const {withGraph} = await adapter();
  const parent = mkdtempSync(join(tmpdir(),'sara-output-test-'));
  try {
    await assert.rejects(withGraph(graph,{output:parent},async()=>{}), /exist/);
    await assert.rejects(withGraph(graph,{repo:parent,output:join(parent,'nested')},async()=>{}), /repository/);
  } finally { rmSync(parent,{recursive:true,force:true}); }
});

test('JSON normalization accepts a preamble but rejects ambiguous or trailing payloads', async () => {
  const {parseSaraJson} = await adapter();
  assert.deepEqual(parseSaraJson('Loaded 2 items\n{"items": []}\n'), {value:{items:[]},preamble:'Loaded 2 items'});
  assert.deepEqual(parseSaraJson('[ITEM] sample\nDownstream\n{"items": []}\n'), {value:{items:[]},preamble:'[ITEM] sample\nDownstream'});
  assert.throws(()=>parseSaraJson('log only'), /JSON/);
  assert.throws(()=>parseSaraJson('{"a":1}\n{"b":2}'), /JSON/);
});

test('version prerequisite rejects missing and unsupported executables', async () => {
  const {saraVersion} = await adapter();
  assert.throws(()=>saraVersion('/no/such/sara'), /cargo install sara-cli/);
  assert.throws(()=>saraVersion(process.execPath), /0\.10/);
});

test('real SARA validates and traverses the generated custom graph', {skip: !process.env.SARA_BIN}, async () => {
  const {withGraph,runSara,saraVersion} = await adapter();
  assert.match(saraVersion(process.env.SARA_BIN), /^0\.10\./);
  await withGraph(graph, {}, async root => {
    const checked = runSara(['check','--format','json'],root,process.env.SARA_BIN);
    assert.equal(checked.status,0,JSON.stringify(checked));
    const result = runSara(['query',graph.items[0].sara_id,'--downstream','--format','json'],root,process.env.SARA_BIN);
    assert.equal(result.status,0,JSON.stringify(result));
    assert.match(JSON.stringify(result.value), /22222222-2222-5222-8222-222222222222/);
  });
});
