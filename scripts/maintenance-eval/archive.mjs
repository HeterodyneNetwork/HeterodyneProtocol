/**
 * Summarise an event archive without treating wrapper polls as work.
 *
 * The importer intentionally consumes event metadata only.  It never needs
 * message text, model output, or private prompt fields; callers can pass
 * parsed JSONL records or records with a `line` field for provenance.
 */

const TOOL_CALL_TYPES = new Set(['custom_tool_call', 'function_call']);
const TASK_START_TYPES = new Set(['task_started', 'task_start']);
const TASK_END_TYPES = new Set(['task_complete', 'task_completed', 'task_finished', 'task_end']);

function payloadOf(record) {
  return record && record.payload && typeof record.payload === 'object'
    ? record.payload
    : (record && typeof record.payload === 'string' ? safeJson(record.payload) : {});
}

function safeJson(value) {
  try { return JSON.parse(value); } catch { return {}; }
}

function eventType(record, payload) {
  return payload.type || record.type || payload.event || record.event || '';
}

function timestampMs(record, payload) {
  const value = record.timestamp ?? payload.timestamp ?? payload.timestamp_ms;
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string') {
    const numeric = Number(value);
    if (Number.isFinite(numeric) && value.trim() !== '') return numeric;
    const parsed = Date.parse(value);
    if (!Number.isNaN(parsed)) return parsed;
  }
  return null;
}

function lineOf(record, index) {
  return Number.isInteger(record?.line) ? record.line : index + 1;
}

function idOf(payload, record, fallback) {
  return String(payload.call_id ?? payload.id ?? record.id ?? fallback);
}

function sessionFromOutput(output) {
  if (typeof output !== 'string') return null;
  const match = output.match(/(?:session|cell)(?:\s+with)?\s+(?:ID\s+)?[`'\"]?([A-Za-z0-9_-]+)[`'\"]?/i);
  return match?.[1] ?? null;
}

function textContains(value, pattern) {
  if (typeof value === 'string') return pattern.test(value);
  if (Array.isArray(value)) return value.some(item => textContains(item, pattern));
  if (value && typeof value === 'object') return Object.values(value).some(item => textContains(item, pattern));
  return false;
}

function processDetails(payload, type) {
  const output = typeof payload.output === 'string' ? payload.output : '';
  const outputSession = sessionFromOutput(output);
  if (!payload.process && payload.process_id == null && payload.session_id == null && payload.cell_id == null &&
      outputSession == null && payload.started_at_ms == null && payload.exited_at_ms == null && !String(type).startsWith('process_')) return null;
  const process = payload.process && typeof payload.process === 'object' ? payload.process : payload;
  const id = process.id ?? process.process_id ?? payload.process_id ?? payload.session_id ?? payload.cell_id ?? outputSession;
  if (id == null) return null;
  const started = process.started_at_ms ?? process.start_ms ?? payload.started_at_ms;
  const exited = process.exited_at_ms ?? process.exit_ms ?? payload.exited_at_ms;
  const outputExit = payload.exit_code != null || /\b(?:completed|exited|finished|exit\s+code)\b/i.test(output);
  return { id: String(id), started, exited, outputExit, callId: payload.call_id ?? null };
}

/**
 * @param {Array<object>} records parsed JSONL archive records
 * @returns {{spanMs:number, taskIntervalsMs:number[], outerCalls:number,
 *   nestedCalls:number, processes:number, confirmedGateLaunches:number,
 *   provenance:object}}
 */
export function summarizeArchive(records) {
  if (!Array.isArray(records)) throw new TypeError('records must be an array');

  const seenCalls = new Map();
  const seenNested = new Map();
  const processes = new Map();
  const tasks = new Map();
  const timestamps = [];
  let confirmedGateLaunches = 0;
  const gateCandidates = new Set();
  const gateCalls = new Set();

  records.forEach((record, index) => {
    const payload = payloadOf(record);
    const type = eventType(record, payload);
    const line = lineOf(record, index);
    const timestamp = timestampMs(record, payload);
    if (timestamp != null) timestamps.push(timestamp);

    if (TOOL_CALL_TYPES.has(record.type) || TOOL_CALL_TYPES.has(type)) {
      const id = idOf(payload, record, `call-${index}`);
      const name = payload.name ?? record.name ?? '';
      const patchOperation = textContains(payload.arguments ?? payload.input ?? payload.command ?? payload, /apply_patch/i);
      const nested = payload.nested === true || payload.parent_call_id != null ||
        /^(apply[_ -]?patch|patch)$/i.test(String(name));
      if (!nested && !seenCalls.has(id)) seenCalls.set(id, { id, line, timestampMs: timestamp, name: String(name) });
      if ((nested || patchOperation) && !seenNested.has(id)) {
        seenNested.set(id, { id, line, timestampMs: timestamp, name: String(name) });
      }
      if (!nested && textContains(payload.arguments ?? payload.input ?? payload.command ?? payload, /scripts\/conformance-ci\.sh/)) {
        gateCandidates.add(id);
      }
    }

    const process = processDetails(payload, type);
    if (process) {
      const current = processes.get(process.id) ?? { id: process.id, started: null, exited: null, callId: null, lines: [] };
      current.lines.push(line);
      if (current.callId == null && process.callId != null) current.callId = String(process.callId);
      if (current.started == null && process.started == null && process.callId != null && timestamp != null) {
        const launch = records.find(candidate => {
          const candidatePayload = payloadOf(candidate);
          return idOf(candidatePayload, candidate, '') === String(process.callId) &&
            (TOOL_CALL_TYPES.has(candidate.type) || TOOL_CALL_TYPES.has(eventType(candidate, candidatePayload)));
        });
        if (launch != null) current.started = timestampMs(launch, payloadOf(launch));
      }
      if (process.started != null && current.started == null) current.started = Number(process.started);
      if (process.exited != null) current.exited = Number(process.exited);
      if (process.outputExit && current.exited == null && timestamp != null) current.exited = timestamp;
      if (type === 'process_start' && current.started == null && timestamp != null) current.started = timestamp;
      if (type === 'process_exit' && current.exited == null && timestamp != null) current.exited = timestamp;
      processes.set(process.id, current);
      if (current.callId != null && gateCandidates.has(current.callId) && current.started != null) gateCalls.add(current.callId);
    }

    const taskId = payload.task_id ?? payload.taskId ?? payload.id;
    if (taskId != null && (TASK_START_TYPES.has(type) || TASK_END_TYPES.has(type))) {
      const task = tasks.get(String(taskId)) ?? { id: String(taskId), started: null, ended: null, startLine: null, endLine: null };
      if (TASK_START_TYPES.has(type)) { task.started = timestamp; task.startLine = line; }
      if (TASK_END_TYPES.has(type)) { task.ended = timestamp; task.endLine = line; }
      tasks.set(String(taskId), task);
    }
  });

  const taskIntervalsMs = [];
  const taskProvenance = [];
  for (const task of tasks.values()) {
    if (task.started != null && task.ended != null && task.ended >= task.started) {
      taskIntervalsMs.push(task.ended - task.started);
      taskProvenance.push({ id: task.id, lines: [task.startLine, task.endLine], startMs: task.started, endMs: task.ended });
    }
  }
  const processProvenance = [];
  for (const process of processes.values()) {
    const durationMs = process.started != null && process.exited != null && process.exited >= process.started
      ? process.exited - process.started : null;
    processProvenance.push({ id: process.id, lines: process.lines, startMs: process.started, endMs: process.exited, durationMs });
  }
  const spanMs = timestamps.length ? Math.max(...timestamps) - Math.min(...timestamps) : 0;
  return {
    spanMs,
    taskIntervalsMs,
    outerCalls: seenCalls.size,
    nestedCalls: seenNested.size,
    processes: processes.size,
    confirmedGateLaunches: gateCalls.size,
    provenance: {
      source: 'event metadata',
      rules: [
        'count unique call_id values; repeated output and poll records are not launches',
        'count nested patch calls separately from outer tool/orchestration calls',
        'process duration is explicit process start-to-exit time, never wrapper yield/poll time',
        'task intervals use task start and completion event timestamps',
      ],
      calls: [...seenCalls.values()],
      nestedCalls: [...seenNested.values()],
      processes: processProvenance,
      tasks: taskProvenance,
    },
  };
}
