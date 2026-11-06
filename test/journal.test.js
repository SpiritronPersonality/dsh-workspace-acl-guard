import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs/promises';

process.env.DSH_HOME = await fs.mkdtemp(path.join(os.tmpdir(), 'acl-guard-test-'));

const { appendEntry, journalDir, readEntries } = await import('../lib/journal.js');

test('journal round-trips entries and skips torn lines', async () => {
  await appendEntry({ ts: '2026-01-01T00:00:00.000Z', event: 'baseline', path: 'F:\\a', signature: 'clean' });
  await appendEntry({ ts: '2026-01-02T00:00:00.000Z', event: 'change', path: 'F:\\a', signature: 'dsh-current' });

  const files = await fs.readdir(journalDir());
  assert.ok(files.some((name) => name.endsWith('.jsonl')));

  await fs.appendFile(path.join(journalDir(), files[0]), '{broken\n', 'utf8');

  const all = await readEntries({ limit: 10 });
  assert.equal(all.length, 2);
  assert.equal(all[1].signature, 'dsh-current');

  const recent = await readEntries({ since: '2026-01-01T12:00:00.000Z', limit: 10 });
  assert.equal(recent.length, 1);
  assert.equal(recent[0].event, 'change');
});
