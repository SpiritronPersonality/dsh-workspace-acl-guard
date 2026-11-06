import test from 'node:test';
import assert from 'node:assert/strict';

import { createState, installPromptWarning } from '../lib/index.js';
import { analyze } from '../lib/detect.js';

const POLLUTED =
  'O:S-1-5-21-1-2-3-1001D:AI(A;OICI;0x110156;;;S-1-4-111-222)(D;CI;0x40;;;WD)' +
  '(A;OICIID;FA;;;S-1-5-21-1-2-3-1001)S:AI(ML;OICI;NW;;;LW)';

const CLEAN =
  'O:S-1-5-21-1-2-3-1001D:AI(A;OICIID;FA;;;S-1-5-21-1-2-3-1001)S:AI(ML;OICI;NW;;;ME)';

function stateFor(path, sddl, extra = {}) {
  const state = createState({
    locale: 'zh', watch: false, scanKnownFolders: false, intervalMs: 15_000, timeoutMs: 20_000,
  });
  state.watch.set(path.toLowerCase(), path);
  state.cache.set(path.toLowerCase(), analyze({
    path, role: 'directory', sddl, label: sddl.includes('LW') ? 'LW' : 'ME',
    writeDac: true, writeOwner: true, ownerIsSelf: true, ...extra,
  }));
  return state;
}

function ctxFor(path, handlers) {
  return {
    on(event, fn) {
      if (event === 'system-prompt/assemble') handlers.push(fn);
    },
    workingDirectory: { get: () => path },
  };
}

test('a polluted workspace contributes one warning context', async () => {
  const path = 'F:\\risky';
  const handlers = [];
  const state = stateFor(path, POLLUTED);
  installPromptWarning(ctxFor(path, handlers), state);

  assert.equal(handlers.length, 1);
  const assembly = { contexts: [] };
  const result = await handlers[0](assembly, { agent: { session: {} } }, async () => assembly);

  assert.equal(result.contexts.length, 1);
  assert.equal(result.contexts[0].name, 'acl-guard:warning');
  assert.ok(result.contexts[0].text.includes('acl-guard'));
});

test('a clean workspace contributes nothing', async () => {
  const path = 'F:\\clean';
  const handlers = [];
  const state = stateFor(path, CLEAN);
  installPromptWarning(ctxFor(path, handlers), state);

  const assembly = { contexts: [] };
  const result = await handlers[0](assembly, { agent: { session: {} } }, async () => assembly);
  assert.equal(result.contexts.length, 0);
});

test('the warning is replaced, not duplicated, on a later turn', async () => {
  const path = 'F:\\risky';
  const handlers = [];
  const state = stateFor(path, POLLUTED);
  installPromptWarning(ctxFor(path, handlers), state);

  const assembly = { contexts: [] };
  await handlers[0](assembly, { agent: { session: {} } }, async () => assembly);
  await handlers[0](assembly, { agent: { session: {} } }, async () => assembly);
  assert.equal(assembly.contexts.filter((entry) => entry.name === 'acl-guard:warning').length, 1);
});

test('a broken assembly is returned untouched', async () => {
  const path = 'F:\\risky';
  const handlers = [];
  const state = stateFor(path, POLLUTED);
  installPromptWarning(ctxFor(path, handlers), state);

  const result = await handlers[0](null, { agent: { session: {} } }, async () => null);
  assert.equal(result, null);
});
