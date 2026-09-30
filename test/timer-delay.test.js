import test from 'node:test';
import assert from 'node:assert/strict';
import { scheduleTimer, cancelTimer } from '../src/timers.js';

test('long notification delay is chunked; replaced or cancelled callbacks cannot deliver', async () => {
  const originalLater = globalThis.setTimeout, originalClear = globalThis.clearTimeout, originalNow = Date.now;
  const callbacks = [], cleared = [], sent = []; let now = 1000;
  globalThis.setTimeout = (fn, delay) => { callbacks.push({ fn, delay }); return callbacks.length; };
  globalThis.clearTimeout = id => cleared.push(id); Date.now = () => now;
  try {
    const ends = now + 2147483647 + 5000;
    scheduleTimer('u', 'long', 'old', ends, (_, __, name) => sent.push(name));
    assert.equal(callbacks[0].delay, 2147483647);
    now += 2147483647; callbacks[0].fn(); assert.equal(callbacks[1].delay, 5000); assert.deepEqual(sent, []);
    scheduleTimer('u', 'long', 'new', now + 1000, (_, __, name) => sent.push(name));
    now += 6000; callbacks[1].fn(); await Promise.resolve(); assert.deepEqual(sent, []);
    cancelTimer('long'); callbacks[2].fn(); await Promise.resolve(); assert.deepEqual(sent, []);
    assert.ok(cleared.length >= 2);
  } finally { globalThis.setTimeout = originalLater; globalThis.clearTimeout = originalClear; Date.now = originalNow; cancelTimer('long'); }
});
