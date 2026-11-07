/**
 * Thin wrapper around the read-only PowerShell probe.
 *
 * The probe is the only component that touches Win32. It runs in a separate
 * process, with a hard timeout, and never writes a security descriptor: a
 * crash or a hang can only fail this call, never the DSH host.
 */
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const SCRIPT_PATH = fileURLToPath(new URL('../assets/acl-probe.ps1', import.meta.url));
const DEFAULT_TIMEOUT_MS = 20_000;

/** Attach a stable code so the tool layer can localize the failure. */
function probeError(code, message, extra = {}) {
  const error = new Error(message);
  error.code = code;
  Object.assign(error, extra);
  return error;
}

/** The interpreter can be overridden for tests or unusual installs. */
export function powershellPath() {
  return process.env.DSH_ACL_GUARD_POWERSHELL || 'powershell.exe';
}

/**
 * Probe absolute paths.
 *
 * @param {string[]} paths - absolute paths to inspect.
 * @param {{includeKnown?: boolean, timeoutMs?: number}} [options]
 * @returns {Promise<object[]>} one record per path, in the probe's shape.
 */
export function probe(paths, options = {}) {
  if (process.platform !== 'win32') return Promise.resolve([]);

  const includeKnown = options.includeKnown === true;
  const timeoutMs = Number.isFinite(options.timeoutMs) ? options.timeoutMs : DEFAULT_TIMEOUT_MS;
  const list = [...new Set(
    (Array.isArray(paths) ? paths : [paths])
      .filter((value) => typeof value === 'string' && value.trim() !== '')
      .map((value) => value.trim()),
  )];

  if (list.length === 0 && !includeKnown) return Promise.resolve([]);

  const payload = Buffer.from(JSON.stringify(list), 'utf8').toString('base64');
  const args = [
    '-NoProfile',
    '-NonInteractive',
    '-ExecutionPolicy',
    'Bypass',
    '-File',
    SCRIPT_PATH,
    '-PathsBase64',
    payload,
  ];
  if (includeKnown) args.push('-IncludeKnown');

  return new Promise((resolve, reject) => {
    let child;
    try {
      child = spawn(powershellPath(), args, {
        windowsHide: true,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
    } catch (error) {
      reject(probeError('spawn', error.message, { detail: error.message }));
      return;
    }

    const stdout = [];
    const stderr = [];
    let settled = false;

    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error) reject(error);
      else resolve(value);
    };

    const timer = setTimeout(() => {
      try { child.kill(); } catch { /* ignore */ }
      finish(probeError('timeout', `acl probe timed out after ${timeoutMs} ms`, { timeoutMs }));
    }, timeoutMs);
    timer.unref?.();

    child.stdout.on('data', (chunk) => stdout.push(chunk));
    child.stderr.on('data', (chunk) => stderr.push(chunk));

    child.on('error', (error) => finish(probeError('spawn', error.message, { detail: error.message })));

    child.on('close', (code) => {
      if (code !== 0) {
        const detail = Buffer.concat(stderr).toString('utf8').trim();
        finish(probeError('exit', `acl probe exited with ${code}${detail ? `: ${detail}` : ''}`, { exitCode: code, detail }));
        return;
      }
      const text = Buffer.concat(stdout).toString('utf8').replace(/^\uFEFF/, '').trim();
      if (text === '') {
        finish(probeError('empty', 'acl probe returned no output'));
        return;
      }
      try {
        const parsed = JSON.parse(text);
        finish(null, Array.isArray(parsed) ? parsed : [parsed]);
      } catch (error) {
        finish(probeError('invalidJson', `acl probe returned invalid JSON: ${error.message}`, { detail: error.message }));
      }
    });
  });
}
