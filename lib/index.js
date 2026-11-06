/**
 * dsh-workspace-acl-guard — read-only guard for the DSH Windows sandbox's
 * resident workspace ACL side effects.
 *
 * What it does:
 *   - probes the session workspace root and the Windows known folders;
 *   - recognizes the ACL signatures DSH writes (current and legacy);
 *   - records a baseline and every later change in a local JSONL journal;
 *   - contributes one warning line to the system prompt when the current
 *     workspace root is risky;
 *   - exposes acl_status / acl_scan / acl_journal tools.
 *
 * What it never does:
 *   - writes a security descriptor, changes an owner, or edits an ACL;
 *   - wraps, replaces, or disables any DSH service;
 *   - throws out of apply(): a failure disables this plugin only.
 *
 * @module dsh-workspace-acl-guard
 */
import path from 'node:path';
import { probe } from './probe.js';
import { analyze } from './detect.js';
import { appendEntry, journalDir, readEntries } from './journal.js';
import { formatJournal, formatScan, formatStatus, formatWarning } from './messages.js';

export const name = 'workspace-acl-guard';

/** Only the tool registry is required; every other service is optional. */
export const inject = Object.freeze(['tools']);

const DEFAULTS = Object.freeze({
  locale: 'zh',
  watch: true,
  scanKnownFolders: true,
  intervalMs: 15_000,
  timeoutMs: 20_000,
});

export const Config = {
  '~standard': {
    version: 1,
    vendor: 'dsh-workspace-acl-guard',
    validate(value) {
      const input = value !== null && typeof value === 'object' ? value : {};
      const locale = input.locale === 'en' ? 'en' : 'zh';
      const intervalMs = Number.isFinite(input.intervalMs)
        ? Math.min(600_000, Math.max(5_000, Math.round(input.intervalMs)))
        : DEFAULTS.intervalMs;
      return {
        value: {
          locale,
          watch: input.watch !== false,
          scanKnownFolders: input.scanKnownFolders !== false,
          intervalMs,
          timeoutMs: DEFAULTS.timeoutMs,
        },
      };
    },
  },
};

function keyOf(value) {
  return process.platform === 'win32' ? String(value).toLowerCase() : String(value);
}

function textResult(text) {
  return [{ type: 'text', text: String(text) }];
}

function service(ctx, name) {
  try {
    return ctx?.[name];
  } catch {
    return undefined;
  }
}

/** Effective session directory: committed working directory, else the header. */
function sessionCwd(ctx, session) {
  if (!session) return null;
  try {
    const directory = service(ctx, 'workingDirectory');
    const current = directory?.get?.(session);
    if (typeof current === 'string' && current !== '') return current;
  } catch {
    // fall through to the immutable header
  }
  const header = session?.header?.cwd;
  return typeof header === 'string' && header !== '' ? header : null;
}

function resolveTarget(ctx, exec, args) {
  const base = sessionCwd(ctx, exec?.agent?.session);
  const raw = typeof args?.path === 'string' ? args.path.trim() : '';
  if (raw !== '') {
    if (path.isAbsolute(raw)) return raw;
    return base ? path.resolve(base, raw) : path.resolve(raw);
  }
  return base;
}

export function createState(cfg) {
  return {
    cfg,
    /** key -> analyzed record */
    cache: new Map(),
    /** key -> { signature, sddl } last journaled */
    written: new Map(),
    /** key -> original path currently watched */
    watch: new Map(),
    timer: null,
  };
}

async function remember(state, record) {
  const analysis = analyze(record);
  const key = keyOf(record.path);
  state.cache.set(key, analysis);

  const previous = state.written.get(key);
  const current = { signature: analysis.signature, sddl: record.sddl ?? null };
  const changed = !previous || previous.sddl !== current.sddl || previous.signature !== current.signature;
  if (!changed) return analysis;

  state.written.set(key, current);
  try {
    await appendEntry({
      ts: new Date().toISOString(),
      event: previous ? 'change' : 'baseline',
      path: record.path,
      role: analysis.role,
      signature: analysis.signature,
      verdict: analysis.verdict,
      label: analysis.label,
      writeDac: analysis.writeDac,
      writeOwner: analysis.writeOwner,
      sddl: record.sddl ?? null,
      previousSddl: previous?.sddl ?? null,
    });
  } catch {
    // The journal is best effort; never fail a probe because of it.
  }
  return analysis;
}

async function refresh(state, paths, options = {}) {
  const includeKnown = options.includeKnown === true;
  const list = [...new Set(
    (Array.isArray(paths) ? paths : [])
      .filter((value) => typeof value === 'string' && value.trim() !== '')
      .map((value) => value.trim()),
  )];
  if (list.length === 0 && !includeKnown) return [];

  const records = await probe(list, { includeKnown, timeoutMs: state.cfg.timeoutMs });
  const analyses = [];
  for (const record of records) analyses.push(await remember(state, record));
  return analyses;
}

async function tick(state) {
  const paths = [...state.watch.values()];
  try {
    await refresh(state, paths, { includeKnown: state.cfg.scanKnownFolders });
  } catch {
    // A failed probe (PowerShell missing, timeout) leaves the previous cache.
  }
}

function buildTools(ctx, state) {
  const locale = () => state.cfg.locale;

  const status = {
    name: 'acl_status',
    description:
      'Inspect one directory\'s Windows security descriptor for DSH sandbox side effects: ' +
      'owner, DACL, integrity label, protection flag, effective WRITE_DAC/WRITE_OWNER, ' +
      'recognized DSH ACL signatures and a risk verdict. Read-only: writes no ACL.',
    parameters: {
      type: 'object',
      properties: {
        path: {
          type: 'string',
          description: 'Absolute directory to inspect; defaults to the session workspace root.',
        },
      },
      additionalProperties: false,
    },
    output: {
      schema: { type: 'object', additionalProperties: true },
      render: (_args, value) => textResult(
        value?.ok === false
          ? `acl_status failed: ${value.error ?? 'unknown error'}`
          : formatStatus(locale(), value),
      ),
    },
    execute: async (args, exec) => {
      const target = resolveTarget(ctx, exec, args);
      if (!target) return { ok: false, error: 'no path: pass path or run inside a session' };
      let record;
      try {
        [record] = await probe([target], { timeoutMs: state.cfg.timeoutMs });
      } catch (error) {
        return { ok: false, path: target, error: error instanceof Error ? error.message : String(error) };
      }
      if (!record) return { ok: false, path: target, error: 'probe returned no record' };
      const analysis = await remember(state, record);
      return { ok: true, ...analysis };
    },
  };

  const scan = {
    name: 'acl_scan',
    description:
      'Scan Windows known folders plus the given directories for DSH sandbox ACL signatures. ' +
      'Read-only: writes no ACL.',
    parameters: {
      type: 'object',
      properties: {
        paths: {
          type: 'array',
          items: { type: 'string' },
          description: 'Extra absolute directories to scan; known folders are always included.',
        },
      },
      additionalProperties: false,
    },
    output: {
      schema: { type: 'object', additionalProperties: true },
      render: (_args, value) => textResult(
        value?.ok === false
          ? `acl_scan failed: ${value.error ?? 'unknown error'}`
          : formatScan(locale(), value),
      ),
    },
    execute: async (args) => {
      const extra = Array.isArray(args?.paths) ? args.paths.filter((value) => typeof value === 'string') : [];
      let records;
      try {
        records = await probe(extra, { includeKnown: true, timeoutMs: state.cfg.timeoutMs });
      } catch (error) {
        return { ok: false, error: error instanceof Error ? error.message : String(error) };
      }

      const items = records.map((record) => {
        const analysis = analyze(record);
        state.cache.set(keyOf(analysis.path), analysis);
        return {
          path: analysis.path,
          verdict: analysis.verdict,
          signature: analysis.signature,
          level: analysis.level,
          role: analysis.role,
        };
      });

      const counts = { ok: 0, polluted: 0, willFail: 0, risky: 0, unknown: 0 };
      for (const item of items) {
        if (item.verdict === 'ok') counts.ok += 1;
        else if (item.verdict === 'polluted') counts.polluted += 1;
        else if (item.verdict === 'will-fail') counts.willFail += 1;
        else if (item.verdict === 'risky-root') counts.risky += 1;
        else counts.unknown += 1;
      }
      const bad = items.length - counts.ok - counts.unknown;

      return { ok: true, total: items.length, bad, counts, items };
    },
  };

  const journal = {
    name: 'acl_journal',
    description:
      'Read the local ACL guard journal: baselines and detected security-descriptor changes. ' +
      'Read-only; the journal lives under $DSH_HOME/acl-guard.',
    parameters: {
      type: 'object',
      properties: {
        since: { type: 'string', description: 'ISO timestamp; only later entries are returned.' },
        limit: { type: 'number', description: 'Maximum entries, default 50.' },
      },
      additionalProperties: false,
    },
    output: {
      schema: { type: 'object', additionalProperties: true },
      render: (_args, value) => textResult(
        value?.ok === false
          ? `acl_journal failed: ${value.error ?? 'unknown error'}`
          : formatJournal(locale(), value.entries, value.dir),
      ),
    },
    execute: async (args) => {
      const entries = await readEntries({
        since: typeof args?.since === 'string' ? args.since : null,
        limit: Number.isFinite(args?.limit) ? args.limit : 50,
      });
      return { ok: true, dir: journalDir(), entries };
    },
  };

  return [status, scan, journal];
}

export function installPromptWarning(ctx, state) {
  if (typeof ctx.on !== 'function') return;

  ctx.on('system-prompt/assemble', async (_assembly, context, next) => {
    const result = await next();
    try {
      const session = context?.agent?.session;
      const cwd = sessionCwd(ctx, session);
      if (!cwd) return result;

      const key = keyOf(cwd);
      if (!state.watch.has(key)) {
        state.watch.set(key, cwd);
        void refresh(state, [cwd]).catch(() => {});
      }

      const analysis = state.cache.get(key);
      if (!analysis || analysis.verdict === 'ok') return result;
      if (!Array.isArray(result?.contexts)) return result;

      const text = formatWarning(state.cfg.locale, analysis);
      const existing = result.contexts.find((entry) => entry && entry.name === 'acl-guard:warning');
      if (existing) existing.text = text;
      else result.contexts.push({ name: 'acl-guard:warning', text, interpolate: false });
    } catch {
      // A warning must never break prompt assembly.
    }
    return result;
  });
}

/**
 * Register tools, the prompt warning, and the background watcher.
 *
 * @param {object} ctx - Cordis host context.
 * @param {object} [config] - validated or raw plugin config.
 * @returns {(() => void)|undefined} disposer.
 */
export function apply(ctx, config = {}) {
  try {
    if (process.platform !== 'win32') return undefined;
    if (!ctx || !ctx.tools || typeof ctx.tools.register !== 'function') return undefined;

    const cfg = Config['~standard'].validate(config).value;
    const state = createState(cfg);
    const disposers = [];

    for (const tool of buildTools(ctx, state)) {
      const dispose = ctx.effect(() => ctx.tools.register(tool), `workspace-acl-guard: ${tool.name}`);
      if (typeof dispose === 'function') disposers.push(dispose);
    }

    installPromptWarning(ctx, state);

    if (cfg.watch) {
      const timer = setInterval(() => {
        void tick(state);
      }, cfg.intervalMs);
      timer.unref?.();
      state.timer = timer;
      void tick(state);
    }

    return () => {
      if (state.timer) clearInterval(state.timer);
      for (const dispose of disposers.reverse()) {
        try {
          dispose();
        } catch {
          // ignore disposal failures
        }
      }
    };
  } catch (error) {
    try {
      ctx?.logger?.warn?.(`workspace-acl-guard disabled: ${error instanceof Error ? error.message : String(error)}`);
    } catch {
      // ignore logger failures
    }
    return undefined;
  }
}

export default { name, inject, Config, apply };
