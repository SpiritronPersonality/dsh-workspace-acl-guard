import test from 'node:test';
import assert from 'node:assert/strict';

import { apply } from '../lib/index.js';

function mockContext(names) {
  return {
    tools: {
      register(tool) {
        names.push(tool.name);
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
  const names = [];
  const close = apply(mockContext(names), { watch: false });
  assert.deepEqual(names.sort(), ['acl_journal', 'acl_scan', 'acl_status']);
  assert.equal(typeof close, 'function');
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
