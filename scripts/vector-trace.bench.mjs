#!/usr/bin/env node
// Reproducible local edit-loop probe. Writes only into its owned temporary clone.
import {mkdtempSync,readFileSync,writeFileSync,rmSync} from 'node:fs';
import {tmpdir,platform,arch} from 'node:os';
import {join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawnSync,execFileSync} from 'node:child_process';
import assert from 'node:assert/strict';

const repo=resolve(process.argv[2]||fileURLToPath(new URL('..',import.meta.url)));
const cli=fileURLToPath(new URL('./vector-trace.mjs',import.meta.url));
const temporary=mkdtempSync(join(tmpdir(),'heterodyne-trace-benchmark-'));
const clone=join(temporary,'repo');
const head=execFileSync('git',['rev-parse','HEAD'],{cwd:repo,encoding:'utf8'}).trim();
const observations=[];
try {
  execFileSync('git',['clone','--quiet','--shared','--no-checkout',repo,clone]);
  execFileSync('git',['checkout','--quiet',head],{cwd:clone});
  const scenarios=[
    {name:'snapshot anchor reverse lookup',paths:[],args:['query','heterodyne:comms#comms-privacy-tiers','--lane','snapshot']},
    {name:'draft issuer-continuity reverse lookup',paths:[],args:['query','heterodyne:comms#comms-issuer-continuity','--lane','draft']},
    {name:'Comms local draft change',paths:['docs/spec/heterodyne-comms.md']},
    {name:'Workspace with Control and Assurance changes',paths:['docs/spec/heterodyne-workspace.md','docs/spec/heterodyne-control.md','docs/spec/heterodyne-assurance.md']},
    {name:'shared registry and schema change',paths:['docs/spec/registry/proof-domains.json','docs/spec/schemas/comms/oidc-continuity-manifest-v1.schema.json']},
    {name:'unanchored text with intentionally absent relationship',paths:['docs/spec/heterodyne-core.md']},
  ];
  for(const scenario of scenarios) {
    const original=new Map(scenario.paths.map(path=>[path,readFileSync(join(clone,path),'utf8')]));
    for(const [path,text] of original) {
      let changed;
      if(path.endsWith('.json')) changed=text+'\n';
      else if(scenario.name.startsWith('unanchored')) changed='<!-- local benchmark edit -->\n'+text;
      else {
        changed=text.replace(/(<a id="[^"]+"><\/a>\s*\n#{1,6} [^\n]*\n)/,'$1\nSynthetic local benchmark requirement edit.\n');
        if(changed===text) throw Error(`No anchored heading in ${path}`);
      }
      writeFileSync(join(clone,path),changed);
    }
    const args=scenario.args||['impact','--lane','draft','--base',head,'--head','WORKTREE'];
    const samples=[];
    let summary;
    for(let run=0;run<5;run++) {
      const start=performance.now();
      const result=spawnSync(process.execPath,[cli,...args,'--repo',clone],{cwd:repo,encoding:'utf8',maxBuffer:32*1024*1024,timeout:120_000});
      const ms=performance.now()-start;
      if(result.status!==0) throw Error(`${scenario.name}: ${result.stderr||result.error}`);
      const packet=JSON.parse(result.stdout);
      if(!scenario.args) assert.deepEqual([...packet.receipt.changed_paths].sort(),[...scenario.paths].sort());
      if(scenario.name.startsWith('draft issuer')) assert.deepEqual(packet.related.filter(item=>item.type==='draft_case').map(item=>item.semantic_id).sort(),['case:comms/oidc-issuer-mismatch','case:comms/oidc-issuer-persona-continuity']);
      if(scenario.name.startsWith('unanchored')) assert.ok(packet.unresolved.some(entry=>entry.kind==='document_level_impact'),'unanchored text must remain explicit document-level impact');
      samples.push(Math.round(ms*100)/100);
      summary={related:packet.related?.length,changed:packet.changed?.length,unresolved:packet.unresolved?.length,receipt:packet.receipt};
    }
    // The full receipt is unnecessary in benchmark output; identities suffice.
    const receipt=summary.receipt?.after ?? summary.receipt;
    summary.receipt={lane:receipt?.lane,spec_ref:receipt?.spec_ref,vector_ref:receipt?.vector_ref};
    observations.push({scenario:scenario.name,changed_paths:scenario.paths,command:[process.execPath,cli,...args,'--repo','<temporary clone>'],wall_ms:samples,...summary});
    for(const [path,text] of original) writeFileSync(join(clone,path),text);
  }
  console.log(JSON.stringify({head,node:process.version,platform:platform(),arch:arch(),cache:'no persistent graph cache; OS cache uncontrolled; each sample is a new CLI process',observations},null,2));
} finally {rmSync(temporary,{recursive:true,force:true});}
