import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { ids } from './support/database.js';

test('commercial provisioning and webhook enforce their authority at HTTP boundaries', async t => {
  Object.assign(process.env, { JWT_SECRET: 'local-commercial-test-secret', SUPABASE_URL: 'http://127.0.0.1:54321',
    SUPABASE_SERVICE_KEY: 'local-only-key', PORT: '0', TELEGRAM_WEBHOOK_SECRET: 'local-only-webhook-secret-32-characters' });
  const users = new Map([
    [ids.manager, { id: ids.manager, username: 'manager', role: 'manager', workspace_id: ids.company }],
    [ids.worker, { id: ids.worker, username: 'worker', role: 'worker', workspace_id: ids.company }],
    [ids.outsider, { id: ids.outsider, username: 'unassigned', role: 'manager', workspace_id: null }],
    [ids.superadmin, { id: ids.superadmin, username: 'admin', role: 'superadmin', workspace_id: null }],
  ]);
  const originalFetch = globalThis.fetch, writes = [], telegram = [];
  let workspaceError = false, membersError = false;
  globalThis.fetch = async (request, options = {}) => {
    const url = new URL(request.url ?? request);
    if (url.hostname === 'api.telegram.org') { telegram.push(url); return Response.json({ ok: true }); }
    if (url.port !== '54321') return originalFetch(request, options);
    const table = url.pathname.split('/').at(-1), method = options.method ?? request.method ?? 'GET';
    const eq = key => url.searchParams.get(key)?.replace(/^eq\./, '');
    if (method !== 'GET') {
      const body = options.body ? JSON.parse(options.body) : null; writes.push({ table, method, body });
      if (table === 'workspaces') return Response.json({ id: ids.company, ...body });
      if (table === 'users' && method === 'POST') return Response.json({ id: ids.secondManager, ...body });
      return new Response(null, { status: 204 });
    }
    if (table === 'sessions') return Response.json({ id: ids.session, revoked_at: null });
    if (table === 'workspaces') return workspaceError ? Response.json({ message: 'unavailable' }, { status: 503 }) : Response.json({ id: ids.company, shared_mode_enabled: true });
    if (table === 'users') {
      if (membersError && eq('workspace_id')) return Response.json({ message: 'unavailable' }, { status: 503 });
      if (eq('username')) return Response.json({ code: 'PGRST116', message: 'none' }, { status: 406 });
      return Response.json(users.get(eq('id')) ?? users.get(ids.superadmin));
    }
    throw Error('Unexpected mock table ' + table);
  };
  let httpServer;
  try {
    const { generateAccessToken } = await import('../src/auth.js');
    ({ httpServer } = await import('../src/server.js'));
    if (!httpServer.listening) await once(httpServer, 'listening');
    const origin = `http://127.0.0.1:${httpServer.address().port}`;
    const request = async (path, actor, body, method = 'POST', extra = {}) => {
      const response = await originalFetch(origin + path, { method, headers: { 'Content-Type': 'application/json',
        ...(actor ? { Authorization: 'Bearer ' + generateAccessToken(users.get(actor), ids.session) } : {}), ...extra }, body: JSON.stringify(body) });
      return { status: response.status, text: await response.text() };
    };
    for (const actor of [ids.manager, ids.worker, ids.outsider]) for (const [path, body] of [
      ['/workspace/create', { name: 'New company' }], ['/workspace/join', { inviteCode: 'LOCAL' }],
      ['/workspace/refresh-invite', {}], ['/users/create', { username: 'new', pin: '654321', role: 'worker' }],
    ]) await t.test(`${users.get(actor).username} cannot provision through ${path}`, async () => {
      const count = writes.length; assert.equal((await request(path, actor, body)).status, 403); assert.equal(writes.length, count);
    });
    await t.test('superadmin creates a company without moving their own membership', async () => {
      const count = writes.length; const result = await request('/workspace/create', ids.superadmin, { name: '  Company  ' });
      assert.equal(result.status, 200); assert.equal(writes.length, count + 1);
      assert.equal(writes.at(-1).table, 'workspaces'); assert.equal(writes.at(-1).body.name, 'Company');
      assert.match(writes.at(-1).body.invite_code, /^[A-F0-9]{24}$/);
    });
    await t.test('superadmin provisions a manager with selected company and hashed PIN', async () => {
      const result = await request('/users/create', ids.superadmin, { username: 'new-manager', pin: '654321', role: 'manager', workspace_id: ids.company });
      assert.equal(result.status, 200); assert.equal(writes.at(-1).body.workspace_id, ids.company);
      assert.equal(writes.at(-1).body.role, 'manager'); assert.notEqual(writes.at(-1).body.pin_hash, '654321');
      assert.doesNotMatch(result.text, /pin_hash/);
    });
    await t.test('missing/wrong account fields and bcrypt truncation inputs cause 400 before write', async () => {
      for (const body of [{}, { username: [], pin: '654321', role: 'worker' }, { username: 'new', pin: '1234', role: 'worker' },
        { username: 'new', pin: '654321', role: 'owner' }, { username: 'new', pin: '654321', role: 'worker', workspace_id: [] },
        { username: 'new', pin: '界'.repeat(25), role: 'worker' }]) {
        const count = writes.length; assert.equal((await request('/users/create', ids.superadmin, body)).status, 400); assert.equal(writes.length, count);
      }
    });
    await t.test('company membership and role changes remain protected even for administrative editing', async () => {
      for (const [role, workspace_id] of [['manager', ids.company], ['worker', null], ['superadmin', ids.company]]) {
        const count = writes.length;
        assert.equal((await request('/admin/users/' + ids.worker, ids.superadmin, { username: 'worker', role, workspace_id }, 'PATCH')).status, 409);
        assert.equal(writes.length, count);
      }
    });
    await t.test('admin cannot demote their own superadmin role', async () => {
      assert.equal((await request('/admin/users/' + ids.superadmin, ids.superadmin,
        { username: 'admin', role: 'worker', workspace_id: null }, 'PATCH')).status, 409);
    });
    await t.test('assigning a previously unassigned account closes its previous sessions', async () => {
      const count = writes.length;
      const result = await request('/admin/users/' + ids.outsider, ids.superadmin,
        { username: 'unassigned', role: 'manager', workspace_id: ids.company }, 'PATCH');
      assert.equal(result.status, 200); assert.equal(writes.length, count + 2);
      assert.equal(writes.at(-1).table, 'sessions'); assert.ok(writes.at(-1).body.revoked_at);
    });
    await t.test('manager retains shared-mode control; failed read does not toggle anything', async () => {
      workspaceError = true; const count = writes.length;
      assert.equal((await request('/workspace/toggle-shared', ids.manager, {})).status, 503); assert.equal(writes.length, count);
      workspaceError = false; assert.equal((await request('/workspace/toggle-shared', ids.manager, {})).status, 200);
    });
    await t.test('wrong types at login/refresh fail clearly', async () => {
      assert.equal((await request('/auth/login', null, { username: {}, pin: {} })).status, 400);
      assert.equal((await request('/auth/refresh', null, { refreshToken: {} })).status, 400);
    });
    await t.test('failed member lookup is not presented as a verified empty company', async () => {
      membersError = true;
      assert.equal((await request('/admin/workspaces/' + ids.company, ids.superadmin, undefined, 'GET')).status, 503);
      membersError = false;
    });
    await t.test('webhook rejects spoofed and unconfigured requests without any Telegram send', async () => {
      const body = { message: { chat: { id: 123 }, text: '/start' } };
      const count = telegram.length;
      assert.equal((await request('/webhook', null, body)).status, 403);
      assert.equal((await request('/webhook', null, body, 'POST', { 'X-Telegram-Bot-Api-Secret-Token': 'wrong' })).status, 403);
      const secret = process.env.TELEGRAM_WEBHOOK_SECRET; delete process.env.TELEGRAM_WEBHOOK_SECRET;
      assert.equal((await request('/webhook', null, body)).status, 503); process.env.TELEGRAM_WEBHOOK_SECRET = secret;
      process.env.TELEGRAM_WEBHOOK_SECRET = 'weak'; assert.equal((await request('/webhook', null, body)).status, 503); process.env.TELEGRAM_WEBHOOK_SECRET = secret;
      assert.equal(telegram.length, count);
      assert.equal((await request('/webhook', null, body, 'POST', { 'X-Telegram-Bot-Api-Secret-Token': secret })).status, 200);
      assert.equal(telegram.length, count + 1);
      assert.equal((await request('/webhook', null, { message: {} }, 'POST', { 'X-Telegram-Bot-Api-Secret-Token': secret })).status, 200);
    });
    await t.test('malformed JSON exposes no stack; account API responses prohibit caching', async () => {
      const invalid = await originalFetch(origin + '/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{' });
      assert.equal(invalid.status, 400); assert.doesNotMatch(await invalid.text(), /SyntaxError|node_modules|stack/);
      const health = await originalFetch(origin + '/health');
      assert.equal(health.headers.get('Cache-Control'), 'no-store'); assert.equal(health.headers.get('X-Content-Type-Options'), 'nosniff');
    });
  } finally {
    globalThis.fetch = originalFetch;
    if (httpServer?.listening) { httpServer.closeAllConnections(); await new Promise(resolve => httpServer.close(resolve)); }
  }
});
