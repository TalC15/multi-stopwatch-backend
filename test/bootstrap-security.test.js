import test from 'node:test';
import assert from 'node:assert/strict';

test('bootstrap fails closed on lookup failure/missing PIN and never logs a configured PIN', async () => {
  Object.assign(process.env, { SUPABASE_URL: 'http://127.0.0.1:54321', SUPABASE_SERVICE_KEY: 'local-only-key' });
  const originalFetch = globalThis.fetch, originalLog = console.log, logs = [], inserts = [];
  let mode = 'none';
  console.log = (...args) => logs.push(args.join(' '));
  globalThis.fetch = async (request, options = {}) => {
    if (options.method === 'POST') { inserts.push(JSON.parse(options.body)); return new Response(null, { status: 201 }); }
    return mode === 'error' ? Response.json({ message: 'DB down' }, { status: 503 }) : Response.json(mode === 'existing' ? { id: 'admin' } : null);
  };
  try {
    const { createSuperAdminIfNotExists } = await import('../src/auth.js');
    delete process.env.SUPERADMIN_PIN;
    await createSuperAdminIfNotExists(); assert.equal(inserts.length, 0);
    process.env.SUPERADMIN_PIN = 'private-test-pin'; mode = 'error';
    await createSuperAdminIfNotExists(); assert.equal(inserts.length, 0);
    mode = 'none'; await createSuperAdminIfNotExists(); assert.equal(inserts.length, 1);
    assert.equal(logs.some(line => line.includes(process.env.SUPERADMIN_PIN)), false);
    mode = 'existing'; await createSuperAdminIfNotExists(); assert.equal(inserts.length, 1);
  } finally { globalThis.fetch = originalFetch; console.log = originalLog; delete process.env.SUPERADMIN_PIN; }
});
