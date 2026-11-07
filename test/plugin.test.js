import test from 'node:test';
import assert from 'node:assert/strict';

import { apply } from '../lib/index.js';

function mockContext(tools) {
  return {
    tools: {
      register(tool) {
        tools.push(tool);
        return () => {};
      },
    },
    effect(fn) {
      return fn();
    },
    logger: { warn() {} },
  };
}

test('apply registers the three read-only tools', () => {
  const tools = [];
  const close = apply(mockContext(tools), { watch: false });
  assert.deepEqual(tools.map((tool) => tool.name).sort(), ['acl_journal', 'acl_scan', 'acl_status']);
  assert.equal(typeof close, 'function');
  close();
});

test('tool text is Chinese by default', async () => {
  const tools = [];
  const close = apply(mockContext(tools), { watch: false });
  const status = tools.find((tool) => tool.name === 'acl_status');

  assert.match(status.description, /[\u4e00-\u9fff]/);
  assert.match(status.parameters.properties.path.description, /[\u4e00-\u9fff]/);

  const failure = await status.execute({}, {});
  assert.equal(failure.ok, false);
  assert.match(failure.error, /[\u4e00-\u9fff]/);

  close();
});

test('locale en switches tool text to English', () => {
  const tools = [];
  const close = apply(mockContext(tools), { watch: false, locale: 'en' });
  const status = tools.find((tool) => tool.name === 'acl_status');

  assert.match(status.description, /Inspect/);
  assert.doesNotMatch(status.description, /[\u4e00-\u9fff]/);

  close();
});

test('apply never throws on a broken context', () => {
  assert.doesNotThrow(() => apply(null, {}));
  assert.doesNotThrow(() => apply({}, {}));
  assert.doesNotThrow(() => apply({ tools: {} }, {}));
});

test('apply survives a register that throws', () => {
  const ctx = {
    tools: {
      register() {
        throw new Error('boom');
      },
    },
    effect(fn) {
      return fn();
    },
    logger: { warn() {} },
  };
  assert.doesNotThrow(() => apply(ctx, { watch: false }));
});
