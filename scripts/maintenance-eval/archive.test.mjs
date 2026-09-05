import test from 'node:test';
import assert from 'node:assert/strict';
import { summarizeArchive } from './archive.mjs';

for (const [name, source] of [
  ['regex literal', 'const pattern = /tools.exec_command()/;'],
  ['nested receiver', 'const value = other.tools.exec_command();'],
]) {
  test(`${name} is only a lexical candidate, not an observed nested invocation`, () => {
    const result = summarizeArchive([{ type: 'custom_tool_call', payload: {
      call_id: 'outer-1', name: 'exec', input: source,
    } }]);
    assert.equal(result.outerCalls, 1);
    assert.equal(result.nestedCalls, null);
    assert.equal(result.processes, null);
    assert.deepEqual(result.provenance.counts.lexicalNestedCallCandidates, {
      status: 'lexical-candidates', total: 1, byKind: { exec_command: 1 },
      syntax: 'tools.<name>( tokens outside comments and quoted/template strings; may include regex literals and nested receivers',
    });
    assert.equal(result.provenance.counts.staticNestedCallSites, undefined);
  });
}

test('a yielded command and polls count one process with its start-to-exit duration', () => {
  const records = [
    { line: 1, timestamp: '2026-08-28T11:13:53.000Z', type: 'event_msg', payload: { type: 'task_started', task_id: 'r1' } },
    { line: 2, timestamp: '2026-08-28T11:14:00.000Z', type: 'custom_tool_call', payload: { call_id: 'call-1', name: 'exec', status: 'started', arguments: { command: 'scripts/conformance-ci.sh' } } },
    { line: 3, timestamp: '2026-08-28T11:14:01.000Z', type: 'custom_tool_call_output', payload: { call_id: 'call-1', status: 'yielded', process: { id: 'proc-1', started_at_ms: 1000, command: ['scripts/conformance-ci.sh'] } } },
    { line: 4, timestamp: '2026-08-28T11:14:02.000Z', type: 'custom_tool_call', payload: { call_id: 'poll-1', name: 'wait', status: 'started', process_id: 'proc-1' } },
    { line: 5, timestamp: '2026-08-28T11:14:04.000Z', type: 'custom_tool_call_output', payload: { call_id: 'poll-1', status: 'running', process: { id: 'proc-1', started_at_ms: 1000 } } },
    { line: 6, timestamp: '2026-08-28T11:14:09.000Z', type: 'event_msg', payload: { type: 'process_exit', process_id: 'proc-1', exited_at_ms: 9000, exit_code: 0 } },
    { line: 7, timestamp: '2026-08-28T11:14:10.000Z', type: 'event_msg', payload: { type: 'task_complete', task_id: 'r1' } },
  ];

  const result = summarizeArchive(records);

  assert.equal(result.processes, 1);
  assert.deepEqual(result.taskIntervalsMs, [17000]);
  assert.equal(result.confirmedGateLaunches, 1);
  assert.equal(result.provenance.processes[0].durationMs, 8000);
  assert.deepEqual(result.provenance.processes[0].lines, [3, 4, 5, 6]);
});

test('observed outer and explicitly nested records have separate counting levels', () => {
  const records = [
    { line: 1, timestamp: 1000, type: 'function_call', payload: { call_id: 'outer-1', name: 'exec' } },
    { line: 2, timestamp: 1100, type: 'function_call', payload: { call_id: 'nested-1', name: 'apply_patch', parent_call_id: 'outer-1' } },
    { line: 3, timestamp: 1200, type: 'function_call', payload: { call_id: 'outer-1', name: 'exec' } },
  ];

  const result = summarizeArchive(records);

  assert.equal(result.outerCalls, 1);
  assert.equal(result.nestedCalls, null);
  assert.deepEqual(result.provenance.counts.observedNestedCalls, {
    status: 'observed-lower-bound',
    total: 1,
    byKind: { apply_patch: 1 },
  });
  assert.deepEqual(result.provenance.counts.lexicalNestedCallCandidates, {
    status: 'lexical-candidates',
    total: 0,
    byKind: {},
    syntax: 'tools.<name>( tokens outside comments and quoted/template strings; may include regex literals and nested receivers',
  });
});

test('wrapper session fields and source mentions do not become processes or launches', () => {
  const records = [
    { line: 1, timestamp: 1000, type: 'response_item', payload: { type: 'function_call', call_id: 'exec-1', name: 'exec', arguments: { command: 'scripts/conformance-ci.sh' } } },
    { line: 2, timestamp: 1001, type: 'response_item', payload: { type: 'function_call_output', call_id: 'exec-1', session_id: 'session-1', output: 'Command running in session session-1' } },
    { line: 3, timestamp: 1100, type: 'response_item', payload: { type: 'function_call', call_id: 'poll-1', name: 'write_stdin', arguments: { session_id: 'session-1', chars: '' } } },
    { line: 4, timestamp: 2000, type: 'response_item', payload: { type: 'function_call_output', call_id: 'poll-1', session_id: 'session-1', exit_code: 0, output: 'completed' } },
    { line: 5, timestamp: 2100, type: 'response_item', payload: { type: 'function_call', call_id: 'mention', name: 'exec', arguments: { command: 'printf scripts/conformance-ci.sh' } } },
    { line: 6, timestamp: 2101, type: 'response_item', payload: { type: 'function_call_output', call_id: 'mention', output: 'printed a path; no process launched' } },
  ];
  const result = summarizeArchive(records);
  assert.equal(result.processes, null);
  assert.equal(result.confirmedGateLaunches, 0);
  assert.deepEqual(result.provenance.processes, []);
  assert.equal(result.provenance.counts.processes.status, 'unknown');
});

test('a direct exec_command record leaves process count unknown without instrumentation', () => {
  const result = summarizeArchive([
    { line: 1, timestamp: 1000, type: 'function_call', payload: {
      call_id: 'exec-command-1', name: 'exec_command', arguments: { cmd: 'npm test' },
    } },
  ]);

  assert.equal(result.processes, null);
  assert.equal(result.provenance.counts.processes.status, 'unknown');
});

test('an exec record with unavailable source leaves process count unknown', () => {
  const result = summarizeArchive([
    { line: 1, timestamp: 1000, type: 'custom_tool_call', payload: {
      call_id: 'exec-opaque-1', name: 'exec',
    } },
  ]);

  assert.equal(result.processes, null);
  assert.equal(result.provenance.counts.processes.status, 'unknown');
});

test('an orphan write_stdin result does not fabricate a process start', () => {
  const result = summarizeArchive([
    { line: 1, timestamp: 1000, type: 'response_item', payload: { type: 'function_call', call_id: 'poll-1', name: 'write_stdin', arguments: { session_id: 'orphan-session', chars: '' } } },
    { line: 2, timestamp: 2000, type: 'response_item', payload: { type: 'function_call_output', call_id: 'poll-1', session_id: 'orphan-session', exited_at_ms: 2000, exit_code: 0, output: 'completed' } },
  ]);
  assert.equal(result.processes, null);
  assert.equal(result.confirmedGateLaunches, 0);
  assert.deepEqual(result.provenance.processes, []);
});

test('a functions.wait cell result is unknown without a correlated exec launch', () => {
  const result = summarizeArchive([
    { line: 1, timestamp: 1000, type: 'response_item', payload: { type: 'function_call', call_id: 'wait-1', name: 'wait', arguments: { cell_id: 'orphan-cell' } } },
    { line: 2, timestamp: 2000, type: 'response_item', payload: { type: 'function_call_output', call_id: 'wait-1', cell_id: 'orphan-cell', output: 'Script running with cell ID orphan-cell' } },
    { line: 3, timestamp: 3000, type: 'response_item', payload: { type: 'function_call_output', call_id: 'wait-1', cell_id: 'orphan-cell', output: 'completed' } },
  ]);
  assert.equal(result.processes, null);
  assert.deepEqual(result.provenance.processes, []);
});

test('real task event fields match turn_id and prefer reported duration without mixing clocks', () => {
  const completion = {
    type: 'task_complete',
    turn_id: 'turn-1',
    started_at: 1787915633,
    completed_at: 1787918279,
    duration_ms: 2646074,
    time_to_first_token_ms: 5792,
  };
  Object.defineProperty(completion, 'last_agent_message', {
    enumerable: true,
    get() { throw new Error('private text must not be read'); },
  });
  const result = summarizeArchive([
    { line: 2, timestamp: '2026-08-28T11:13:53.350Z', type: 'event_msg', payload: {
      type: 'task_started', turn_id: 'turn-1', started_at: 1787915633,
      model_context_window: 258400, collaboration_mode_kind: 'default',
    } },
    { line: 1251, timestamp: '2026-08-28T11:57:59.365Z', type: 'event_msg', payload: completion },
  ]);

  assert.deepEqual(result.taskIntervalsMs, [2646074]);
  assert.deepEqual(result.provenance.tasks, [{
    id: 'turn-1',
    lines: [2, 1251],
    startMs: 1787915633350,
    endMs: 1787918279365,
    observedEventSpanMs: 2646015,
    reportedDurationMs: 2646074,
    intervalMs: 2646074,
    intervalSource: 'task_complete.duration_ms',
  }]);
});

test('reports observed outer calls separately from lexical nested call candidates', () => {
  const result = summarizeArchive([
    { line: 1, timestamp: 1000, type: 'response_item', payload: {
      type: 'custom_tool_call', call_id: 'outer-1', name: 'exec', input: String.raw`
        await tools.exec_command({cmd: 'scripts/conformance-ci.sh'});
        await tools.write_stdin({session_id: 7, chars: ''});
        await tools.apply_patch('patch');
        await tools.mcp__semble__search({query: 'x'});
        await tools.update_plan({plan: []});
        // await tools.exec_command({cmd: 'comment only'});
        const example = "tools.apply_patch('literal only')";
      `,
    } },
    { line: 2, timestamp: 2000, type: 'response_item', payload: {
      type: 'function_call', call_id: 'outer-2', name: 'wait', arguments: '{"cell_id":"cell-1"}',
    } },
  ]);

  assert.equal(result.outerCalls, 2);
  assert.equal(result.nestedCalls, null);
  assert.deepEqual(result.provenance.counts.observedOuterCalls.byKind, { exec: 1, wait: 1 });
  assert.deepEqual(result.provenance.counts.lexicalNestedCallCandidates, {
    status: 'lexical-candidates',
    total: 5,
    byKind: {
      apply_patch: 1,
      exec_command: 1,
      mcp__semble__search: 1,
      update_plan: 1,
      write_stdin: 1,
    },
    syntax: 'tools.<name>( tokens outside comments and quoted/template strings; may include regex literals and nested receivers',
  });
  assert.equal(result.processes, null);
  assert.equal(result.confirmedGateLaunches, 0);
});
