import { sha1 } from "@noble/hashes/legacy";
import { bytesToHex, hexToBytes, utf8Bytes } from "./hex.js";
import { jcsCanonicalize } from "./jcs.js";

// OID-level derivation of the OPTIONAL materialized-KEL ref profile
// (spec §10.1.2, ADR-032): refs/xyz.heterodyne.keri/log and
// refs/xyz.heterodyne.keri/state. These are byte-identical git objects
// (sha1, "<type> <len>\0<content>"), scoped to object derivation only -
// no packfiles. Cross-checked against git hash-object / mktree /
// commit-tree in keri-materialized.test.ts.

// The pinned author/committer identity and message rules (§10.1.2).
const GIT_ACTOR = "Heterodyne KERI <keri@heterodyne.invalid>";

function gitObjectOid(type: string, content: Uint8Array): string {
  const header = utf8Bytes(`${type} ${content.length}\0`);
  const object = new Uint8Array(header.length + content.length);
  object.set(header, 0);
  object.set(content, header.length);
  return bytesToHex(sha1(object));
}

export function gitBlobOid(content: Uint8Array): string {
  return gitObjectOid("blob", content);
}

// A single-entry tree (the profile's trees hold exactly one entry).
// Tree content is "<mode> <path>\0<20 raw oid bytes>".
export function gitTreeOidSingle(mode: string, path: string, blobOid: string): string {
  const prefix = utf8Bytes(`${mode} ${path}\0`);
  const rawOid = hexToBytes(blobOid);
  const content = new Uint8Array(prefix.length + rawOid.length);
  content.set(prefix, 0);
  content.set(rawOid, prefix.length);
  return gitObjectOid("tree", content);
}

// A commit with the pinned deterministic-derivation headers (§10.1.2):
// no encoding/gpgsig headers; author == committer == GIT_ACTOR; both
// timestamps the event's decimal created_at with +0000; message is the
// lowercase 64-hex event id followed by exactly one LF.
export function gitCommitOid(treeOid: string, parents: string[], createdAt: number, eventId: string): string {
  const lines = [`tree ${treeOid}`];
  for (const parent of parents) {
    lines.push(`parent ${parent}`);
  }
  lines.push(`author ${GIT_ACTOR} ${createdAt} +0000`);
  lines.push(`committer ${GIT_ACTOR} ${createdAt} +0000`);
  const text = `${lines.join("\n")}\n\n${eventId}\n`;
  return gitObjectOid("commit", utf8Bytes(text));
}

// The materialized key state after applying one KEL event (§10.1.2 schema).
export type MaterializedState = {
  cold_root: string;
  s: number;
  epoch_key: string;
  witnesses: Array<{ id: string; weight: number }>;
  threshold: number;
  producing_event_id: string;
};

export type KelEntry = {
  event_id: string;
  created_at: number;
  nip01_raw: string;
  state: MaterializedState;
};

export type LogCommit = { blob: string; tree: string; commit: string; parents: string[] };
export type StateCommit = LogCommit & { state_json: string };

export type MaterializedRefs = {
  log: LogCommit[];
  state: StateCommit[];
  log_tip: string | null;
  state_tip: string | null;
};

// Derive the log and state commit chains from an accepted KEL (spec §10.1.2).
// An empty accepted KEL yields empty chains and null tips (both refs deleted).
export function deriveMaterializedRefs(kel: KelEntry[]): MaterializedRefs {
  const log: LogCommit[] = [];
  const state: StateCommit[] = [];

  kel.forEach((entry, index) => {
    const logBlob = gitBlobOid(utf8Bytes(entry.nip01_raw));
    const logTree = gitTreeOidSingle("100644", "event.nip01", logBlob);
    const logParents = index === 0 ? [] : [log[index - 1].commit];
    const logCommit = gitCommitOid(logTree, logParents, entry.created_at, entry.event_id);
    log.push({ blob: logBlob, tree: logTree, commit: logCommit, parents: logParents });

    const stateJson = jcsCanonicalize(entry.state);
    const stateBlob = gitBlobOid(utf8Bytes(stateJson));
    const stateTree = gitTreeOidSingle("100644", "state.json", stateBlob);
    const stateParents = index === 0 ? [log[0].commit] : [state[index - 1].commit, log[index].commit];
    const stateCommit = gitCommitOid(stateTree, stateParents, entry.created_at, entry.event_id);
    state.push({ blob: stateBlob, tree: stateTree, commit: stateCommit, parents: stateParents, state_json: stateJson });
  });

  return {
    log,
    state,
    log_tip: log.length > 0 ? log[log.length - 1].commit : null,
    state_tip: state.length > 0 ? state[state.length - 1].commit : null,
  };
}
