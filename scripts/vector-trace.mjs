#!/usr/bin/env node
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {buildProjection, verifyReceipt, indexItems, finalizeProjection} from './vector-trace/projection.mjs';

const HELP = `Usage: node scripts/vector-trace.mjs <command> [semantic-id] --lane <lane> [options]

Commands: query, impact, worklist, coverage, matrix, check, receipt
Lanes (required): draft, snapshot, reconciliation

query <semantic-id>    Requirement/case/source packet with provenance
impact, worklist       Require --base <git-ref> --head <git-ref|WORKTREE>
                      and --lane draft; compare current authoring inputs
coverage, matrix      Declared relationships, not executed conformance
check                 Nonzero on unresolved graph relationships
receipt               Input inventory, digests and freshness

--repo <path>          Repository root (default current directory)
--vector-ref <ref>     Required for reconciliation; optional snapshot selection
--direction <value>    upstream, downstream, both (query; default both)
--format <value>       json (default), csv (matrix only)
--backend <value>      core (default), sara (query/check only)
--output <path>        New graph directory outside repository (SARA only)
--keep-graph           Preserve temporary SARA graph
--compact              Omit repeated receipt inventories; keep hashes/counts
--help                Show help without loading dependencies

Draft queries require npm --prefix docs/spec/vectors/generator ci.
SARA backend requires sara 0.10.x (or SARA_BIN executable path).
Protocol authority remains the specs, registry and schemas.
`;
class UsageError extends Error {}
const commands = new Set(['query','impact','worklist','coverage','matrix','check','receipt']);
const options = new Map([['--repo','repo'],['--lane','lane'],['--base','base'],['--head','head'],['--vector-ref','vectorRef'],['--direction','direction'],['--format','format'],['--backend','backend'],['--output','output']]);

function parse(argv) {
  if(argv.length===1 && argv[0]==='--help') return {help:true};
  const [command,...rest]=argv;
  if(!commands.has(command)) throw new UsageError('Unknown command; use --help');
  const result={command,repo:process.cwd(),format:'json',backend:'core',direction:'both'};
  const seen=new Set();
  for(let i=0;i<rest.length;i++) {
    const token=rest[i];
    if(token==='--compact') {if(seen.has(token)) throw new UsageError('Duplicate option');seen.add(token);result.compact=true;continue;}
    if(token==='--keep-graph') {if(seen.has(token)) throw new UsageError('Duplicate option'); seen.add(token);result.keepGraph=true;continue;}
    if(options.has(token)) {
      if(seen.has(token)) throw new UsageError(`Duplicate option ${token}`);
      seen.add(token);
      const value=rest[++i];
      if(!value || value.startsWith('--')) throw new UsageError(`Missing value for ${token}`);
      result[options.get(token)]=value;
    } else if(!token.startsWith('-') && command==='query' && !result.id) result.id=token;
    else throw new UsageError(`Unexpected argument ${token}`);
  }
  if(!['draft','snapshot','reconciliation'].includes(result.lane)) throw new UsageError('Explicit --lane draft|snapshot|reconciliation required');
  if(command==='query'&&!result.id) throw new UsageError('query requires a semantic ID');
  if(!['core','sara'].includes(result.backend)) throw new UsageError('Invalid backend');
  if(!['upstream','downstream','both'].includes(result.direction)) throw new UsageError('Invalid direction');
  if(!['json','csv'].includes(result.format) || result.format==='csv'&&command!=='matrix') throw new UsageError('CSV is supported only for matrix');
  if(seen.has('--direction')&&command!=='query') throw new UsageError('--direction is query-only');
  if(['impact','worklist'].includes(command)) {
    if(!result.base||!result.head||result.lane!=='draft') throw new UsageError('impact/worklist require --lane draft --base <ref> --head <ref|WORKTREE>');
    if(result.base==='WORKTREE') throw new UsageError('--base must be a Git ref');
  } else if(result.base||result.head) throw new UsageError('--base/--head are comparison-only');
  if(result.lane==='draft'&&result.vectorRef) throw new UsageError('Draft lane cannot include historical vectors');
  if(result.lane==='reconciliation'&&!result.vectorRef) throw new UsageError('Reconciliation requires --vector-ref');
  if(result.backend==='sara'&&!['query','check'].includes(command)) throw new UsageError('SARA backend supports query/check');
  if((result.output||result.keepGraph)&&result.backend!=='sara') throw new UsageError('Graph output requires --backend sara');
  return result;
}

function canonical(value) {
  if(Array.isArray(value)) return value.map(canonical);
  if(value&&typeof value==='object') return Object.fromEntries(Object.keys(value).sort().map(key=>[key,canonical(value[key])]));
  return value;
}
const hash = value => createHash('sha256').update(value).digest('hex');

export async function buildGraph(options) {
  const projection=await buildProjection(options);
  if(options.lane==='draft'||options.lane==='reconciliation') {
    const {enrichDraft}=await import('./vector-trace/draft.mjs');
    await enrichDraft(projection,{repo:options.repo});
  }
  projection.items.sort((a,b)=>a.semantic_id<b.semantic_id?-1:a.semantic_id>b.semantic_id?1:0);
  projection.edges.sort((a,b)=>JSON.stringify(canonical(a)).localeCompare(JSON.stringify(canonical(b)),'en'));
  indexItems(projection.items);
  projection.receipt.graph_version='3';
  finalizeProjection(projection);
  projection.receipt.tool_sha256=hash(['./vector-trace.mjs','./vector-trace/projection.mjs','./vector-trace/history.mjs','./vector-trace/draft.mjs','./vector-trace/impact.mjs','./vector-trace/sara.mjs','./sara/model.yaml'].map(path=>readFileSync(new URL(path,import.meta.url),'utf8')).join('\0'));
  const freshness=verifyReceipt(projection);
  if(!freshness.fresh) throw Error(freshness.issues.join('; '));
  projection.receipt.fresh=true;
  return projection;
}

export async function main(argv,io={stdout:process.stdout,stderr:process.stderr}) {
  try {
    const config=parse(argv);
    if(config.help) {io.stdout.write(HELP);return 0;}
    const reports=await import('./vector-trace/impact.mjs');
    let projection, result, status=0;
    if(config.base) {
      const before=await buildGraph({...config,ref:config.base});
      projection=await buildGraph({...config,ref:config.head});
      result=reports.compareProjections(before,projection);
      if(config.command==='worklist') result=reports.buildWorklist(result);
    } else {
      projection=await buildGraph(config);
      if(config.command==='receipt') result=projection.receipt;
      if(config.command==='query') result=reports.queryPacket(projection,config.id,{direction:config.direction});
      if(config.command==='coverage') result={coverage:reports.coverageReport(projection),receipt:projection.receipt};
      if(config.command==='matrix') result={matrix:reports.traceabilityMatrix(projection),receipt:projection.receipt};
      if(config.command==='check') {
        const ids=new Set(projection.items.map(item=>item.semantic_id));
        const missing=projection.edges.filter(edge=>!ids.has(edge.from)||!ids.has(edge.to));
        const unresolved=[...projection.receipt.unresolved_references,...missing];
        result={valid:unresolved.length===0,unresolved,receipt:projection.receipt};
        status=result.valid?0:1;
      }
    }
    if(config.backend==='sara') {
      const {saraVersion,withGraph,runSara}=await import('./vector-trace/sara.mjs');
      projection.receipt.sara_version=saraVersion();
      const materialized=await withGraph(projection,config,async root=>{
        const calls=config.command==='check'?[['check','--format','json']]:
          (config.direction==='both'?['upstream','downstream']:[config.direction]).map(direction=>['query',projection.items.find(item=>item.semantic_id===config.id).sara_id,`--${direction}`,'--format','json']);
        return calls.map(args=>runSara(args,root));
      });
      const semanticIds=new Map(projection.items.map(item=>[item.sara_id,item.semantic_id]));
      const normalize=value=>typeof value==='string'?(semanticIds.get(value)??value):Array.isArray(value)?value.map(normalize):value&&typeof value==='object'?Object.fromEntries(Object.entries(value).map(([key,v])=>[key,normalize(v)])):value;
      result.sara=normalize(materialized.result);
      result.graph_path=materialized.graph_path;
      if(materialized.result.some(call=>call.status!==0)) status=1;
    }
    if(config.format==='csv') {
      const rows=result.matrix;
      const columns=['anchor_id','owner','heading','vector_id','profile','vector_path','lane'];
      const quote=value=>'"'+String(value??'').replaceAll('"','""')+'"';
      io.stdout.write([columns.join(','),...rows.map(row=>columns.map(key=>quote(row[key])).join(','))].join('\r\n')+'\r\n');
    } else {
      if(config.compact) {
        const compactReceipt=receipt=>{
          if(!receipt||typeof receipt!=='object') return receipt;
          if(receipt.before||receipt.after) return {...receipt,before:compactReceipt(receipt.before),after:compactReceipt(receipt.after)};
          const {inputs,unresolved_references,...rest}=receipt;
          return {...rest,input_count:inputs?.length??0,unresolved_count:unresolved_references?.length??0};
        };
        result=config.command==='receipt'?compactReceipt(result):{...result,receipt:compactReceipt(result.receipt)};
      }
      io.stdout.write(JSON.stringify(result,null,2)+'\n');
    }
    return status;
  } catch(error) {
    io.stderr.write(`${error.message}\n`);
    return error instanceof UsageError?2:3;
  }
}

if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href) process.exitCode=await main(process.argv.slice(2));
