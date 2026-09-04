/**
 * Summarise public event metadata without treating source text or wrapper
 * output as observed nested work.
 */

const TOOL_CALL_TYPES = new Set(['custom_tool_call', 'function_call']);
const TASK_START_TYPES = new Set(['task_started', 'task_start']);
const TASK_END_TYPES = new Set(['task_complete', 'task_completed', 'task_finished', 'task_end']);
const STATIC_SITE_SYNTAX = 'direct tools.<name>(...) call sites outside comments and literals';

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

function sortedCounts(counts) {
  return Object.fromEntries([...counts].sort(([left], [right]) => left.localeCompare(right)));
}

function increment(counts, key) {
  counts.set(key, (counts.get(key) ?? 0) + 1);
}

/**
 * Parse only direct dotted call sites. Quoted strings, template literals, and
 * comments are skipped, so the result is deliberately a static lower bound.
 */
function directToolCallSites(source) {
  if (typeof source !== 'string') return [];
  const sites = [];
  let index = 0;

  const skipSpace = () => {
    while (index < source.length && /\s/.test(source[index])) index += 1;
  };
  const identifier = () => {
    if (!/[A-Za-z_$]/.test(source[index] ?? '')) return null;
    const start = index;
    index += 1;
    while (index < source.length && /[A-Za-z0-9_$]/.test(source[index])) index += 1;
    return source.slice(start, index);
  };
  const skipQuoted = quote => {
    index += 1;
    while (index < source.length) {
      if (source[index] === '\\') {
        index += 2;
      } else if (source[index] === quote) {
        index += 1;
        return;
      } else {
        index += 1;
      }
    }
  };

  while (index < source.length) {
    if (source[index] === '/' && source[index + 1] === '/') {
      index += 2;
      while (index < source.length && source[index] !== '\n') index += 1;
      continue;
    }
    if (source[index] === '/' && source[index + 1] === '*') {
      index += 2;
      while (index < source.length && !(source[index] === '*' && source[index + 1] === '/')) index += 1;
      index = Math.min(source.length, index + 2);
      continue;
    }
    if (source[index] === '\'' || source[index] === '"' || source[index] === '`') {
      skipQuoted(source[index]);
      continue;
    }

    const start = index;
    const root = identifier();
    if (root === null) {
      index += 1;
      continue;
    }
    if (root !== 'tools') continue;
    skipSpace();
    if (source[index] !== '.') {
      index = Math.max(index, start + root.length);
      continue;
    }
    index += 1;
    skipSpace();
    const name = identifier();
    if (name === null) continue;
    skipSpace();
    if (source[index] === '(') sites.push(name);
  }
  return sites;
}

function explicitProcessDetails(payload, type) {
  const embedded = payload.process && typeof payload.process === 'object' ? payload.process : null;
  const isProcessEvent = String(type).startsWith('process_');
  if (!embedded && !isProcessEvent) return null;
  const process = embedded ?? payload;
  const id = process.id ?? process.process_id ?? payload.process_id;
  if (id == null) return null;
  return {
    id: String(id),
    started: process.started_at_ms ?? process.start_ms ?? payload.started_at_ms ?? null,
    exited: process.exited_at_ms ?? process.exit_ms ?? payload.exited_at_ms ?? null,
    command: process.command ?? payload.command ?? null,
  };
}

function commandIsGate(command) {
  if (Array.isArray(command)) return command.some(part => part === 'scripts/conformance-ci.sh');
  return command === 'scripts/conformance-ci.sh';
}

/**
 * @param {Array<object>} records parsed JSONL archive records
 * @returns {{spanMs:number, taskIntervalsMs:number[], outerCalls:number,
 *   nestedCalls:number|null, processes:number|null, confirmedGateLaunches:number,
 *   provenance:object}}
 */
export function summarizeArchive(records) {
  if (!Array.isArray(records)) throw new TypeError('records must be an array');

  const observedOuterCalls = new Map();
  const observedOuterByKind = new Map();
  const observedNestedCalls = new Map();
  const observedNestedByKind = new Map();
  const staticSitesByKind = new Map();
  const staticSites = [];
  const instrumentedProcesses = new Map();
  const tasks = new Map();
  const timestamps = [];
  const confirmedGateProcessIds = new Set();

  records.forEach((record, index) => {
    const payload = payloadOf(record);
    const type = eventType(record, payload);
    const line = lineOf(record, index);
    const timestamp = timestampMs(record, payload);
    if (timestamp != null) timestamps.push(timestamp);

    if (TOOL_CALL_TYPES.has(record.type) || TOOL_CALL_TYPES.has(type)) {
      const id = idOf(payload, record, `call-${index}`);
      const name = String(payload.name ?? record.name ?? 'unknown');
      const explicitlyNested = payload.nested === true || payload.parent_call_id != null;
      if (explicitlyNested && !observedNestedCalls.has(id)) {
        observedNestedCalls.set(id, { id, line, timestampMs: timestamp, name });
        increment(observedNestedByKind, name);
      } else if (!explicitlyNested && !observedOuterCalls.has(id)) {
        observedOuterCalls.set(id, { id, line, timestampMs: timestamp, name });
        increment(observedOuterByKind, name);
        if (name === 'exec') {
          const source = typeof payload.input === 'string' ? payload.input : null;
          for (const siteName of directToolCallSites(source)) {
            increment(staticSitesByKind, siteName);
            staticSites.push({ outerCallId: id, line, name: siteName });
          }
        }
      }
    }

    const process = explicitProcessDetails(payload, type);
    if (process) {
      const current = instrumentedProcesses.get(process.id) ?? {
        id: process.id, started: null, exited: null, lines: [], gate: false,
      };
      current.lines.push(line);
      if (process.started != null && current.started == null) current.started = Number(process.started);
      if (process.exited != null) current.exited = Number(process.exited);
      if (commandIsGate(process.command)) current.gate = true;
      instrumentedProcesses.set(process.id, current);
      if (current.gate && current.started != null) confirmedGateProcessIds.add(process.id);
    } else if (payload.process_id != null && instrumentedProcesses.has(String(payload.process_id))) {
      instrumentedProcesses.get(String(payload.process_id)).lines.push(line);
    }

    const taskId = payload.task_id ?? payload.taskId ?? payload.turn_id ?? payload.id;
    if (taskId != null && (TASK_START_TYPES.has(type) || TASK_END_TYPES.has(type))) {
      const key = String(taskId);
      const task = tasks.get(key) ?? {
        id: key, started: null, ended: null, startLine: null, endLine: null,
        reportedDurationMs: null,
      };
      if (TASK_START_TYPES.has(type)) {
        task.started = timestamp;
        task.startLine = line;
      }
      if (TASK_END_TYPES.has(type)) {
        task.ended = timestamp;
        task.endLine = line;
        if (typeof payload.duration_ms === 'number' && Number.isFinite(payload.duration_ms) && payload.duration_ms >= 0) {
          task.reportedDurationMs = payload.duration_ms;
        }
      }
      tasks.set(key, task);
    }
  });

  const taskIntervalsMs = [];
  const taskProvenance = [];
  for (const task of tasks.values()) {
    if (task.started == null || task.ended == null || task.ended < task.started) continue;
    const observedEventSpanMs = task.ended - task.started;
    const intervalMs = task.reportedDurationMs ?? observedEventSpanMs;
    taskIntervalsMs.push(intervalMs);
    taskProvenance.push({
      id: task.id,
      lines: [task.startLine, task.endLine],
      startMs: task.started,
      endMs: task.ended,
      observedEventSpanMs,
      reportedDurationMs: task.reportedDurationMs,
      intervalMs,
      intervalSource: task.reportedDurationMs == null
        ? 'outer event timestamps'
        : 'task_complete.duration_ms',
    });
  }

  const processProvenance = [];
  for (const process of instrumentedProcesses.values()) {
    const durationMs = process.started != null && process.exited != null && process.exited >= process.started
      ? process.exited - process.started
      : null;
    processProvenance.push({
      id: process.id,
      lines: process.lines,
      startMs: process.started,
      endMs: process.exited,
      durationMs,
      timing: durationMs == null ? 'unknown' : 'explicit-instrumentation',
    });
  }

  const processCount = instrumentedProcesses.size > 0
    ? instrumentedProcesses.size
    : null;
  const processStatus = instrumentedProcesses.size > 0
    ? 'observed-instrumented-lower-bound'
    : 'unknown';
  const spanMs = timestamps.length ? Math.max(...timestamps) - Math.min(...timestamps) : 0;
  return {
    spanMs,
    taskIntervalsMs,
    outerCalls: observedOuterCalls.size,
    nestedCalls: null,
    processes: processCount,
    confirmedGateLaunches: confirmedGateProcessIds.size,
    provenance: {
      source: 'public event metadata and static parsing of orchestration source',
      rules: [
        'outer calls count unique observed call_id values; repeated outputs are not calls',
        'nested runtime invocation totals are unknown; static direct call sites are reported separately and are not execution evidence',
        'wrapper session/cell identifiers and free-form output do not establish a shell process or timing',
        'gate launches require structured process instrumentation with the gate command',
        'task intervals prefer task_complete.duration_ms and retain the outer event span separately',
      ],
      counts: {
        observedOuterCalls: {
          status: 'observed',
          total: observedOuterCalls.size,
          byKind: sortedCounts(observedOuterByKind),
        },
        observedNestedCalls: {
          status: observedNestedCalls.size > 0 ? 'observed-lower-bound' : 'unknown',
          total: observedNestedCalls.size > 0 ? observedNestedCalls.size : null,
          ...(observedNestedCalls.size > 0 ? { byKind: sortedCounts(observedNestedByKind) } : {}),
        },
        staticNestedCallSites: {
          status: 'parsed-static-lower-bound',
          total: staticSites.length,
          byKind: sortedCounts(staticSitesByKind),
          syntax: STATIC_SITE_SYNTAX,
        },
        processes: {
          status: processStatus,
          total: processCount,
          durations: processProvenance.map(process => process.durationMs),
        },
        confirmedGateLaunches: {
          status: 'confirmed-by-explicit-process-instrumentation',
          total: confirmedGateProcessIds.size,
        },
      },
      calls: [...observedOuterCalls.values()],
      staticNestedCallSites: staticSites,
      processes: processProvenance,
      tasks: taskProvenance,
    },
  };
}
