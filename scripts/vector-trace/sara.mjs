import { mkdir, mkdtemp, readFile, writeFile, rm, realpath } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve, sep } from 'node:path';
import { spawnSync } from 'node:child_process';

const INSTALL = 'cargo install sara-cli --version 0.10.0 --locked';

export function saraVersion(binary = process.env.SARA_BIN || 'sara') {
  const result = spawnSync(binary, ['--version'], {encoding:'utf8',timeout:10_000});
  const match = result.stdout?.trim().match(/^sara(?:-cli)?\s+(0\.10\.\d+)$/i);
  if (result.status !== 0 || !match) throw Error(`SARA 0.10.x required; install with: ${INSTALL}`);
  return match[1];
}

export function parseSaraJson(stdout) {
  // A preamble is allowed only before the first JSON object/array line. Parse
  // the entire suffix, so multiple values and trailing garbage cannot pass.
  const offset = stdout.search(/^[\t ]*(?:\{|\[(?!ITEM\]))/m);
  if (offset < 0) throw Error('SARA did not return JSON');
  try { return {value:JSON.parse(stdout.slice(offset)),preamble:stdout.slice(0,offset).trim()}; }
  catch { throw Error('SARA returned invalid or ambiguous JSON'); }
}

export function runSara(args, root, binary = process.env.SARA_BIN || 'sara') {
  const result = spawnSync(binary,args,{
    cwd:root,encoding:'utf8',timeout:60_000,maxBuffer:32*1024*1024,
    env:{...process.env,SARA_CONFIG:join(root,'sara.toml'),NO_COLOR:'1'},
  });
  if (result.error) throw Error(`SARA invocation failed: ${result.error.message}`);
  if (result.status !== 0) return {status:result.status ?? 1,value:null,diagnostics:{stdout:result.stdout,stderr:result.stderr}};
  const parsed = parseSaraJson(result.stdout);
  return {status:0,value:parsed.value,diagnostics:{sara_preamble:parsed.preamble,stderr:result.stderr}};
}

export async function withGraph(projection, {output,keepGraph=false,repo=process.cwd()} = {}, operation) {
  let root;
  if (output) {
    const parent = await realpath(dirname(resolve(output)));
    root = join(parent,resolve(output).split(sep).at(-1));
    const repository = await realpath(repo);
    if (root === repository || root.startsWith(repository+sep)) throw Error('SARA output must be outside the repository');
    await mkdir(root); // Deliberately refuses an existing directory.
  } else root = await mkdtemp(join(tmpdir(),'heterodyne-sara-'));
  try {
    await mkdir(join(root,'items'));
    await writeFile(join(root,'model.yaml'),await readFile(new URL('../sara/model.yaml',import.meta.url)));
    await writeFile(join(root,'sara.toml'),'model_schema = "model.yaml"\n[repositories]\npaths = ["./items"]\n[output]\ncolors = false\nemojis = false\n');
    const byId = new Map(projection.items.map(item=>[item.semantic_id,item]));
    const model = await readFile(new URL('../sara/model.yaml',import.meta.url),'utf8');
    const relationNames = new Set([...model.matchAll(/\{id: ([a-z_]+),/g)].map(match=>match[1]));
    const typeNames = new Set([...model.matchAll(/^  - id: ([a-z_]+)$/gm)].map(match=>match[1]));
    for (const item of [...projection.items].sort((a,b)=>a.semantic_id.localeCompare(b.semantic_id,'en'))) {
      if (!/^[0-9a-f-]{36}$/.test(item.sara_id) || !typeNames.has(item.type)) throw Error(`Invalid SARA item: ${item.semantic_id}`);
      const metadata = {id:item.sara_id,type:item.type,name:item.semantic_id,
        semantic_id:item.semantic_id,source_path:item.source_path,
        source_digest:item.source_digest,evidence_kind:item.evidence_kind};
      for (const edge of projection.edges.filter(edge=>edge.from===item.semantic_id)) {
        if (!relationNames.has(edge.relation)) throw Error(`Unsupported SARA relation: ${edge.relation}`);
        const target = byId.get(edge.to);
        if (!target) throw Error(`Unresolved SARA target: ${edge.to}`);
        (metadata[edge.relation] ??= []).push(target.sara_id);
      }
      for (const [key,value] of Object.entries(metadata)) if (Array.isArray(value)) metadata[key]=[...new Set(value)].sort();
      await writeFile(join(root,'items',item.sara_id+'.md'),'---\n'+JSON.stringify(metadata,null,2)+'\n---\n\nDerived traceability; consult the recorded repository source.\n');
    }
    await writeFile(join(root,'index.json'),JSON.stringify(Object.fromEntries(projection.items.map(i=>[i.sara_id,i.semantic_id])),null,2)+'\n');
    await writeFile(join(root,'receipt.json'),JSON.stringify(projection.receipt,null,2)+'\n');
    const result = await operation(root);
    return {result,graph_path:output || keepGraph ? root : null};
  } finally {
    if (!output && !keepGraph) await rm(root,{recursive:true,force:true});
  }
}
