import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';

const repo = fileURLToPath(new URL('..',import.meta.url));
const cli = fileURLToPath(new URL('./vector-trace.mjs',import.meta.url));
const run = args => spawnSync(process.execPath,[cli,...args],{cwd:repo,encoding:'utf8',maxBuffer:16*1024*1024});

test('help exposes all commands without requiring optional SARA', () => {
  const result=run(['--help']);
  assert.equal(result.status,0,result.stderr);
  for(const command of ['query','impact','worklist','coverage','matrix','check','receipt']) assert.match(result.stdout,new RegExp(command));
});

test('ambiguous lanes, duplicate flags and unsupported formats fail without JSON output',()=>{
  for(const args of [['receipt'],['receipt','--lane','draft','--lane','snapshot'],['query','missing','--lane','draft','--format','csv'],['impact','--lane','snapshot','--base','HEAD','--head','WORKTREE'],['receipt','--lane','draft','--head','HEAD']]) {
    const result=run(args);
    assert.equal(result.status,2,JSON.stringify({args,result}));
    assert.equal(result.stdout,'');
  }
});

test('snapshot reverse lookup exactly matches the selected coverage manifest',()=>{
  const anchor='heterodyne:assurance#assurance-associated-keys';
  const result=run(['query',anchor,'--lane','snapshot']);
  assert.equal(result.status,0,result.stderr);
  const packet=JSON.parse(result.stdout);
  const expected=JSON.parse(readFileSync(new URL('../docs/spec/vectors/coverage/manifest.json',import.meta.url),'utf8')).filter(entry=>entry.spec_refs.includes(anchor)).map(entry=>'vector:'+entry.vector_id).sort();
  assert.deepEqual(packet.related.filter(item=>item.type==='vector').map(item=>item.semantic_id).sort(),expected);
  assert.equal(packet.receipt.lane,'snapshot');
  assert.equal(packet.receipt.fresh,true);
});

test('draft packet exposes declared case allocation without historical vector evidence',()=>{
  const result=run(['query','heterodyne:comms#comms-issuer-continuity','--lane','draft']);
  assert.equal(result.status,0,result.stderr);
  const packet=JSON.parse(result.stdout);
  assert.ok(packet.related.some(item=>item.semantic_id==='case:comms/oidc-issuer-persona-continuity'));
  assert.equal(packet.related.some(item=>item.type==='vector'),false);
  assert.equal(packet.receipt.vector_ref,null);
  assert.ok(packet.suggested_checks);
});

test('unknown semantic IDs fail explicitly instead of returning empty coverage',()=>{
  const result=run(['query','heterodyne:comms#does-not-exist','--lane','snapshot']);
  assert.notEqual(result.status,0);
  assert.equal(result.stdout,'');
  assert.match(result.stderr,/unknown|not found/i);
});

test('compact query keeps freshness and uncertainty counts without repeating the full input inventory',()=>{
  const result=run(['query','heterodyne:comms#comms-issuer-continuity','--lane','draft','--compact']);
  assert.equal(result.status,0,result.stderr);
  const packet=JSON.parse(result.stdout);
  assert.equal(packet.receipt.fresh,true);
  assert.ok(packet.receipt.input_count>0);
  assert.equal(packet.receipt.inputs,undefined);
  assert.equal(packet.receipt.unresolved_count,packet.unresolved.length);
  assert.match(packet.receipt.graph_sha256,/^[a-f0-9]{64}$/);
});
