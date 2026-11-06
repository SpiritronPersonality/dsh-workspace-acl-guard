import test from 'node:test';
import assert from 'node:assert/strict';

import { analyze, parseFlags, parseRights, parseSddl } from '../lib/detect.js';

const CLEAN =
  'O:S-1-5-21-1-2-3-1001D:AI(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIID;FA;;;S-1-5-21-1-2-3-1001)' +
  'S:AI(ML;OICI;NW;;;ME)';

const CURRENT =
  'O:S-1-5-21-1-2-3-1001D:AI(A;OICI;0x110156;;;S-1-4-111-222)(D;CI;0x40;;;WD)' +
  '(A;OICIID;FA;;;S-1-5-21-1-2-3-1001)S:AI(ML;OICI;NW;;;LW)';

const LEGACY =
  'O:S-1-5-21-1-2-3-1001D:PAI(D;CI;DT;;;WD)(A;OICI;0x110156;;;S-1-4-333-444)' +
  '(A;;FA;;;BA)S:AI(ML;OICI;NW;;;ME)';

test('parseRights understands hex, short and concatenated forms', () => {
  assert.equal(parseRights('0x40'), 0x40);
  assert.equal(parseRights('FA'), 0x001f01ff);
  assert.equal(parseRights('DT'), 0x00010000);
  assert.equal(parseRights('SDGXGWGR'), (0x10000 | 0x20000000 | 0x40000000 | 0x80000000) >>> 0);
  assert.equal(parseRights('ZZ'), null);
});

test('parseFlags splits two-letter flags', () => {
  const flags = parseFlags('OICIID');
  assert.deepEqual([...flags].sort(), ['CI', 'ID', 'OI']);
});

test('parseSddl extracts owner, protection and label', () => {
  const parsed = parseSddl(CLEAN);
  assert.equal(parsed.owner, 'S-1-5-21-1-2-3-1001');
  assert.equal(parsed.protected, false);
  assert.equal(parsed.label, 'ME');
  assert.equal(parsed.aces.length, 4);
  assert.equal(parsed.aces.filter((ace) => ace.type === 'label').length, 1);
});

test('a clean ordinary directory is ok', () => {
  const analysis = analyze({
    path: 'F:\\work', role: 'directory', sddl: CLEAN, ownerIsSelf: true,
    writeDac: true, writeOwner: true, label: 'ME', protected: false,
  });
  assert.equal(analysis.verdict, 'ok');
  assert.equal(analysis.signature, 'clean');
  assert.equal(analysis.level, 'low');
});

test('a clean known folder is still a risky root', () => {
  const analysis = analyze({
    path: 'C:\\Users\\x\\Desktop', role: 'desktop', sddl: CLEAN, ownerIsSelf: true,
    writeDac: true, writeOwner: true, label: 'ME', protected: false,
  });
  assert.equal(analysis.verdict, 'risky-root');
  assert.equal(analysis.level, 'critical');
});

test('the current DSH signature is recognized', () => {
  const analysis = analyze({
    path: 'F:\\work', role: 'directory', sddl: CURRENT, ownerIsSelf: true,
    writeDac: true, writeOwner: true, label: 'LW', protected: false,
  });
  assert.equal(analysis.signature, 'dsh-current');
  assert.equal(analysis.verdict, 'polluted');
  assert.equal(analysis.level, 'high');
  assert.deepEqual(analysis.capabilitySids, ['S-1-4-111-222']);
  assert.ok(analysis.evidence.includes('world-deny-delete-child'));
  assert.ok(analysis.evidence.includes('low-integrity-label'));
});

test('the legacy DSH signature is recognized', () => {
  const analysis = analyze({
    path: 'F:\\work', role: 'directory', sddl: LEGACY, ownerIsSelf: false,
    writeDac: false, writeOwner: false, label: 'ME', protected: true,
  });
  assert.equal(analysis.signature, 'dsh-legacy');
  assert.equal(analysis.verdict, 'polluted');
  assert.ok(analysis.evidence.includes('protected-dacl'));
  assert.ok(analysis.evidence.includes('world-deny-delete'));
});

test('a directory without WRITE_DAC predicts error 5', () => {
  const analysis = analyze({
    path: 'F:\\data', role: 'directory', sddl: CLEAN, ownerIsSelf: false,
    writeDac: false, writeOwner: false, label: 'ME', protected: false,
  });
  assert.equal(analysis.verdict, 'will-fail');
  assert.ok(analysis.evidence.includes('no-write-dac'));
  assert.ok(analysis.evidence.includes('owner-mismatch'));
});

test('probe errors stay unknown instead of guessing', () => {
  const analysis = analyze({ path: 'Z:\\missing', role: 'directory', error: 'not-found' });
  assert.equal(analysis.verdict, 'unknown');
});
