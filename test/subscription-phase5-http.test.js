import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { randomUUID } from 'node:crypto';
import jwt from 'jsonwebtoken';
import { database, actor, user, seededCustomer, put, resolve, scope } from './support/subscriptionPhase5.js';

test('Phase 5 real HTTP: private ownership, strict authority, Telegram and closed company/socket/login paths', async t => {
  const db = await database(t), admin = await actor(db, 'superadmin'), agent = await actor(db);
  const accounts = {};
  for (const [name, period] of [['active', { starts_at: '2000-01-01Z', ends_at: '2100-01-01Z' }],
    ['other', { starts_at: '2000-01-01Z', ends_at: '2100-01-01Z' }],
    ['expired', { starts_at: '2000-01-01Z', ends_at: '2001-01-01Z' }],
    ['pending', { starts_at: '2100-01-01Z', ends_at: '2101-01-01Z' }]]) accounts[name] = await seededCustomer(db, agent, period);
  accounts.company = { id: await user(db), session: randomUUID() };
  await db.query('INSERT INTO sessions(id,user_id,refresh_token_hash) VALUES($1,$2,$3)', [accounts.company.session, accounts.company.id, 'fixture']);
  process.env.JWT_SECRET = 'phase5-only-test-signing-secret'; process.env.SUPABASE_URL = 'http://127.0.0.1:54321';
  process.env.SUPABASE_SERVICE_KEY = 'phase5-only-test-service'; process.env.PORT = '0';
  process.env.AUTH_ALLOWED_ORIGINS = 'https://fixture.example';
  const auth = await import('../src/auth.js'), original = globalThis.fetch, engines = [], telegram = [];
  for (const a of Object.values(accounts)) a.token = auth.generateAccessToken({ id: a.id }, a.session);
  let scopeFault = null, subscriptionFault = null;
  const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } });
  globalThis.fetch = async (request, options = {}) => {
    const url = new URL(request.url ?? request), body = options.body ? JSON.parse(options.body) : null;
    if (url.hostname === 'api.telegram.org') { telegram.push({ url: url.pathname, body }); return json({ ok: true }); }
    if (url.origin !== 'http://127.0.0.1:54321') { assert.equal(url.hostname, '127.0.0.1', 'No live services'); return original(request, options); }
    const table = url.pathname.split('/').at(-1), eq = key => url.searchParams.get(key)?.replace(/^eq\./, '');
    try {
      if (table === 'keeptimer_resolve_entitlement') return json(subscriptionFault || await resolve(db, body.p_user_id));
      if (table === 'keeptimer_phase5_scope') return json(scopeFault || await scope(db, body.p_actor, body.p_write));
      if (table === 'keeptimer_sync_personal') return json((await db.query('SELECT keeptimer_sync_personal($1,$2,$3,$4,$5,$6) r',
        [body.p_actor_id, body.p_timer_id, body.p_mutation_id, body.p_expected_revision, JSON.stringify(body.p_state), body.p_session_id ?? null])).rows[0].r);
      if (table === 'keeptimer_delete_personal') return json((await db.query('SELECT keeptimer_delete_personal($1,$2,$3,$4,$5) r',
        [body.p_actor_id, body.p_timer_id, body.p_mutation_id, body.p_expected_revision, body.p_session_id ?? null])).rows[0].r);
      if (table === 'keeptimer_phase5_telegram') return json((await db.query('SELECT keeptimer_phase5_telegram($1,$2,$3) r', [body.p_actor, body.p_chat_id, body.p_session_id])).rows[0].r);
      if (table === 'users' && options.method === 'PATCH') {
        assert.deepEqual(Object.keys(body), ['telegram_chat_id']);
        assert.ok(eq('id'), 'Telegram write must target the authenticated actor');
        const rows = (await db.query('UPDATE users SET telegram_chat_id=$1 WHERE id=$2 RETURNING telegram_chat_id', [body.telegram_chat_id, eq('id')])).rows;
        return json(rows);
      }
      const allowed = new Set(['users', 'sessions', 'timers']); assert.ok(allowed.has(table), `Unexpected resource ${table}`);
      const conditions = [], values = [];
      for (const column of ['id', 'user_id', 'workspace_id', 'role', 'username', 'is_shared', 'record_status']) if (eq(column)) {
        conditions.push(`${column}=$${values.push(column === 'is_shared' ? eq(column) === 'true' : eq(column))}`);
      }
      if (url.searchParams.get('archived_at') === 'is.null') conditions.push('archived_at IS NULL');
      if (url.searchParams.get('disabled_at') === 'is.null') conditions.push('disabled_at IS NULL');
      if (table === 'timers' && url.searchParams.get('id')?.startsWith('gt.')) {
        conditions.push(`id>$${values.push(url.searchParams.get('id').slice(3))}`);
      }
      const rows = (await db.query(`SELECT * FROM ${table}${conditions.length ? ' WHERE '+conditions.join(' AND ') : ''} ORDER BY id`, values)).rows;
      if (options.headers?.Accept?.includes('vnd.pgrst.object') || new Headers(options.headers).get('accept')?.includes('vnd.pgrst.object')) return rows[0] ? json(rows[0]) : json({ code: 'PGRST116' }, 406);
      return json(rows);
    } catch (error) { return json({ code: error.code || 'P0001', message: error.message }, 400); }
  };
  const { httpServer } = await import('../src/server.js'); if (!httpServer.listening) await once(httpServer, 'listening');
  const base = `http://127.0.0.1:${httpServer.address().port}`;
  t.after(async () => { for (const e of engines) await original(e, { method: 'POST', body: '1' }).catch(() => {});
    globalThis.fetch = original; httpServer.closeAllConnections(); await new Promise(done => httpServer.close(done)); });
  const call = (name, path, method = 'GET', body, token) => original(base+path, { method,
    headers: { Authorization: `Bearer ${token || accounts[name].token}`, 'Content-Type': 'application/json' },
    ...(body ? { body: JSON.stringify(body) } : {}) });
  const state = extra => ({ dataMode: 'workspace-personal', mutationId: randomUUID(), expectedRevision: 0,
    name: 'HTTP own', type: 'down', targetMinutes: 5, isPay: false, status: 'idle', endsAt: null,
    endedAt: null, durationMs: null, accumulatedMs: 0, pausedCount: 0, ...extra });
  const id = randomUUID();
  await t.test('active status/feature response is minimal, no-store, server-derived and excludes another requested account', async () => {
    const response = await call('active', '/account/experience?userId='+accounts.other.id+'&plan_code=team');
    assert.equal(response.status, 200); assert.equal(response.headers.get('cache-control'), 'no-store');
    const body = await response.json(); assert.equal(body.account.userId, accounts.active.id); assert.equal(body.account.workspaceId, accounts.active.workspace);
    assert.equal(body.account.kind, 'individual'); assert.equal(body.shared, false); assert.equal(body.loginReady, false);
    assert.deepEqual(body.features, { tts: true, telegram: true, presets: true });
    assert.doesNotMatch(JSON.stringify(body), /password|pin_hash|refresh|createdBy|amountMinor|requiresSubscription/);
    const company = await (await call('company', '/account/experience')).json();
    assert.equal(company.account.kind, 'company'); assert.equal(company.shared, true); assert.equal(company.features.tts, true);
  });
  await t.test('only own personal records can be read, created, updated or deleted', async () => {
    const body = state(); const created = await call('active', '/timers/personal/'+id, 'PUT', body);
    assert.equal(created.status, 201); assert.equal((await created.json()).timer.user_id, accounts.active.id);
    const retry = await call('active', '/timers/personal/'+id, 'PUT', body); assert.equal(retry.status, 200); assert.equal((await retry.json()).duplicate, true);
    const ownResponse = await call('active', '/timers/personal?syncPage=1'); const own = await ownResponse.json(); assert.equal(ownResponse.status, 200, JSON.stringify(own)); assert.deepEqual(own.timers.map(t => t.id), [id]);
    const other = await (await call('other', '/timers/personal?syncPage=1&userId='+accounts.active.id)).json(); assert.equal(other.timers.length, 0);
    assert.equal((await call('other', '/timers/personal/'+id, 'PUT', state())).status, 403);
    const denied = await call('other', '/timers/personal/'+id, 'DELETE', { dataMode: 'workspace-personal', mutationId: randomUUID(), expectedRevision: 1 });
    assert.equal(denied.status, 403); assert.equal((await denied.json()).code, 'PERSONAL_TIMER_FORBIDDEN');
    assert.equal((await call('active', '/timers/personal/'+randomUUID(), 'PUT', state({ user_id: accounts.other.id }))).status, 400);
  });
  await t.test('pending/expired read their own records but cannot write, register Telegram or schedule paid delivery', async () => {
    for (const name of ['pending', 'expired']) {
      const response = await call(name, '/account/experience'); assert.equal(response.status, 200);
      const data = await response.json(); assert.equal(data.personal.readable, true); assert.equal(data.personal.writable, false);
      assert.deepEqual(data.features, { tts: false, telegram: false, presets: false });
      assert.equal((await call(name, '/timers/personal?syncPage=1')).status, 200);
      for (const [path, body] of [['/timers/personal/'+randomUUID(), state()], ['/register', { chatId: '1234' }], ['/timer/start', { timerId: id, timerName: 'spoof', endsAt: Date.now()+1000 }]]) {
        assert.equal((await call(name, path, path.startsWith('/timers') ? 'PUT' : 'POST', body)).status, 403);
      }
    }
    assert.equal(telegram.length, 0);
  });
  await t.test('no company, invite, shared, legacy timer or privileged route opens for Individual', async () => {
    for (const [method, path] of [['GET', '/workspace'], ['POST', '/workspace/join'], ['POST', '/workspace/leave'],
      ['POST', '/workspace/create'], ['GET', '/admin/users'], ['POST', '/users/create'], ['POST', '/timers'], ['PATCH', '/timers/'+id],
      ['DELETE', '/timers/'+id], ['GET', '/timers/shared?protocol=5'], ['POST', '/timers/shared/commands']]) {
      const res = await call('active', path, method, method === 'GET' ? null : { userId: admin.id, role: 'superadmin' });
      assert.equal(res.status, 403); assert.equal((await res.json()).code, 'INDIVIDUAL_SCOPE_NOT_READY');
    }
    assert.equal((await call('active', '/admin/agents')).status, 403);
  });
  await t.test('JWT paid claims, malformed RPC and mismatched private scope cannot mint rights', async () => {
    const a = accounts.expired;
    const forged = jwt.sign({ id: a.id, sessionId: a.session, type: 'access', isEntitled: true, plan_code: 'individual', workspace_id: accounts.active.workspace }, process.env.JWT_SECRET, { expiresIn: '15m' });
    assert.equal((await call('expired', '/register', 'POST', { chatId: '1234' }, forged)).status, 403);
    const good = await scope(db, accounts.active.id);
    for (const bad of [{ ...good, workspaceId: accounts.other.workspace }, { ...good, userId: accounts.other.id },
      { ...good, kind: 'company' }, { ...good, entitlement: { ...good.entitlement, code: ['ACCOUNT_DISABLED'] } }]) {
      scopeFault = bad; const res = await call('active', '/account/experience'); assert.equal(res.status, 503); assert.equal((await res.json()).code, 'SUBSCRIPTION_UNAVAILABLE');
    }
    scopeFault = null; subscriptionFault = { ...(await resolve(db, accounts.active.id)), code: 'UNKNOWN_CODE' };
    assert.equal((await call('active', '/timers/personal')).status, 503); subscriptionFault = null;
  });
  await t.test('active Telegram attachment uses own actor/session; subscription expiry at delivery drops the message', async () => {
    const res = await call('active', '/register', 'POST', { chatId: '1234' }); assert.equal(res.status, 200);
    assert.equal((await db.query('SELECT telegram_chat_id FROM users WHERE id=$1', [accounts.active.id])).rows[0].telegram_chat_id, '1234');
    const start = await call('active', '/timer/start', 'POST', { timerId: id, timerName: 'Own', endsAt: Date.now()+150 }); assert.equal(start.status, 200);
    await db.query('UPDATE subscriptions SET cancelled_at=clock_timestamp(),cancelled_by_user_id=$1 WHERE user_id=$2', [agent.id, accounts.active.id]);
    await new Promise(done => setTimeout(done, 250));
    assert.equal(telegram.length, 1, 'only attachment test message; cancelled subscription sends no alarm');
    assert.equal((await call('active', '/telegram/cancel', 'PATCH', { user_id: accounts.active.id })).status, 200);
    assert.equal((await db.query('SELECT telegram_chat_id FROM users WHERE id=$1', [accounts.active.id])).rows[0].telegram_chat_id, null);
  });
  await t.test('expired/pending/cancelled read only their connection and may unlink without gaining paid rights', async () => {
    for (const name of ['expired', 'pending', 'active']) {
      const a = accounts[name]; // active was cancelled by the preceding delivery regression.
      await db.query('UPDATE users SET telegram_chat_id=$1 WHERE id=$2', ['987654', a.id]);
      const response = await call(name, '/telegram/control', 'POST', { user_id: a.id });
      assert.equal(response.status, 200); assert.equal(response.headers.get('cache-control'), 'no-store');
      assert.deepEqual(await response.json(), { success: true, connected: true });
      for (const [path, method] of [['/telegram/control', 'POST'], ['/telegram/cancel', 'PATCH']]) {
        assert.equal((await call(name, path, method, { user_id: accounts.other.id })).status, 403);
      }
      assert.equal((await call(name, '/telegram/cancel', 'PATCH', { user_id: a.id })).status, 200);
      assert.equal((await db.query('SELECT telegram_chat_id FROM users WHERE id=$1', [a.id])).rows[0].telegram_chat_id, null);
      assert.deepEqual(await (await call(name, '/telegram/control', 'POST')).json(), { success: true, connected: false });
      assert.equal((await call(name, '/register', 'POST', { chatId: '1234' })).status, 403);
      const experience = await (await call(name, '/account/experience')).json();
      assert.deepEqual(experience.features, { tts: false, telegram: false, presets: false });
    }
  });
  await t.test('active Individual and company attach, read minimal own state and unlink', async () => {
    for (const name of ['other', 'company']) {
      assert.equal((await call(name, '/register', 'POST', { chatId: '4321' })).status, 200);
      assert.deepEqual(await (await call(name, '/telegram/control', 'POST')).json(), { success: true, connected: true });
      assert.equal((await call(name, '/telegram/cancel', 'PATCH')).status, 200);
      assert.deepEqual(await (await call(name, '/telegram/control', 'POST')).json(), { success: true, connected: false });
    }
  });
  await t.test('invalid and revoked sessions cannot read or manage Telegram connections', async () => {
    for (const [path, method] of [['/telegram/control', 'POST'], ['/telegram/cancel', 'PATCH'], ['/register', 'POST']]) {
      assert.equal((await call('expired', path, method, { chatId: '1234' }, 'invalid-token')).status, 401);
    }
    await db.query('UPDATE sessions SET revoked_at=clock_timestamp() WHERE id=$1', [accounts.other.session]);
    for (const [path, method] of [['/telegram/control', 'POST'], ['/telegram/cancel', 'PATCH'], ['/register', 'POST']]) {
      assert.equal((await call('other', path, method, { chatId: '1234' })).status, 401);
    }
    await db.query('UPDATE sessions SET revoked_at=NULL WHERE id=$1', [accounts.other.session]);
  });
  await t.test('private sockets fail before joining rooms; new password customers remain unable to PIN-login', async () => {
    const opened = await original(base+'/socket.io/?EIO=4&transport=polling'); const { sid } = JSON.parse((await opened.text()).slice(1));
    const endpoint = `${base}/socket.io/?EIO=4&transport=polling&sid=${sid}`; engines.push(endpoint);
    await original(endpoint, { method: 'POST', body: `40${JSON.stringify({ token: accounts.other.token })}` });
    assert.match(await (await original(endpoint, { signal: AbortSignal.timeout(2000) })).text(), /^44/);
    const username = (await db.query('SELECT username FROM users WHERE id=$1', [accounts.other.id])).rows[0].username;
    for (const path of ['/auth/login', '/auth/native/login']) {
      const res = await original(base+path, { method: 'POST', headers: { 'Content-Type': 'application/json', ...(path === '/auth/login' ? { Origin: 'https://fixture.example', 'X-KeepTimer-CSRF': '1' } : {}) }, body: JSON.stringify({ username, pin: 'Synthetic-Test-Password-2026!' }) });
      assert.equal(res.status, 401);
    }
    assert.equal((await db.query('SELECT enabled FROM keeptimer_sales_release')).rows[0].enabled, false);
  });
});
