import test from 'node:test';
import assert from 'node:assert/strict';
import { summarizeArchive } from './archive.mjs';

test('a yielded command and polls count one process with its start-to-exit duration', () => {
  const records = [
    { line: 1, timestamp: '2026-08-28T11:13:53.000Z', type: 'event_msg', payload: { type: 'task_started', task_id: 'r1' } },
    { line: 2, timestamp: '2026-08-28T11:14:00.000Z', type: 'custom_tool_call', payload: { call_id: 'call-1', name: 'exec', status: 'started', arguments: { command: 'scripts/conformance-ci.sh' } } },
    { line: 3, timestamp: '2026-08-28T11:14:01.000Z', type: 'custom_tool_call_output', payload: { call_id: 'call-1', status: 'yielded', process: { id: 'proc-1', started_at_ms: 1000 } } },
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

test('outer calls and nested patch operations have separate counting levels', () => {
  const records = [
    { line: 1, timestamp: 1000, type: 'function_call', payload: { call_id: 'outer-1', name: 'exec' } },
    { line: 2, timestamp: 1100, type: 'function_call', payload: { call_id: 'nested-1', name: 'apply_patch', parent_call_id: 'outer-1' } },
    { line: 3, timestamp: 1200, type: 'function_call', payload: { call_id: 'outer-1', name: 'exec' } },
  ];

  const result = summarizeArchive(records);

  assert.equal(result.outerCalls, 1);
  assert.equal(result.nestedCalls, 1);
});
