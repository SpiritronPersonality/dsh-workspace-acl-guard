/**
 * Local JSONL journal: one line per baseline or detected change.
 *
 * The journal lives under $DSH_HOME/acl-guard, is plain text, and is never read
 * by DSH itself. A write failure must never affect the plugin's read-only work,
 * so every caller is expected to swallow errors.
 */
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

export function dshHome() {
  const fromEnv = process.env.DSH_HOME;
  if (typeof fromEnv === 'string' && fromEnv.trim() !== '') return fromEnv.trim();
  return path.join(os.homedir(), '.dsh');
}

export function journalDir() {
  return path.join(dshHome(), 'acl-guard');
}

function monthFile(date) {
  const year = date.getUTCFullYear();
  const month = String(date.getUTCMonth() + 1).padStart(2, '0');
  return path.join(journalDir(), `${year}-${month}.jsonl`);
}

export async function appendEntry(entry) {
  const file = monthFile(new Date());
  await fs.mkdir(path.dirname(file), { recursive: true });
  await fs.appendFile(file, `${JSON.stringify(entry)}\n`, 'utf8');
}

export async function readEntries({ since = null, limit = 50 } = {}) {
  const dir = journalDir();
  let names;
  try {
    names = await fs.readdir(dir);
  } catch {
    return [];
  }

  const files = names.filter((name) => name.endsWith('.jsonl')).sort();
  const entries = [];
  for (const name of files) {
    let text;
    try {
      text = await fs.readFile(path.join(dir, name), 'utf8');
    } catch {
      continue;
    }
    for (const line of text.split('\n')) {
      if (line.trim() === '') continue;
      try {
        const entry = JSON.parse(line);
        if (since && typeof entry.ts === 'string' && entry.ts < since) continue;
        entries.push(entry);
      } catch {
        // A torn trailing line is expected after a crash; ignore it.
      }
    }
  }

  return entries.slice(-Math.max(1, Math.min(500, limit)));
}
