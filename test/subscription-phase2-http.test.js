import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { randomUUID } from 'node:crypto';
import jwt from 'jsonwebtoken';
import express from 'express';
import { createSubscriptionCore } from '../src/subscriptions.js';
import { database, user, subscription, resolve } from './support/subscriptionPhase2.js';

test('Phase 2 real backend HTTP + DB authority; credentials remain independent', async t => {
  const db = await database(t);
  process.env.JWT_SECRET = 'phase2-test-only-signing-secret';
  process.env.SUPABASE_URL = 'http://127.0.0.1:54321';
  process.env.SUPABASE_SERVICE_KEY = 'phase2-test-only-service-key';
  process.env.AUTH_ALLOWED_ORIGINS = 'https://fixture.example';
  process.env.PORT = '0';
  const auth = await import('../src/auth.js');
  const hash = await auth.hashPin('fixture-pin');
  await user(db, 'superadmin'); // No bootstrap writes.
  const accounts = {};
  for (const name of ['legacy', 'active', 'pending', 'expired', 'cancelled', 'team', 'enterprise', 'classified']) {
    const id = await user(db, 'worker', { username: name, pin_hash: hash,
      ...(name === 'classified' ? { plan_code: 'individual' } : {}) });
    const session = randomUUID();
    const refresh = auth.generateRefreshToken({ id }, session);
    await db.query('INSERT INTO sessions(id,user_id,refresh_token_hash) VALUES($1,$2,$3)', [session, id, auth.hashToken(refresh)]);
    accounts[name] = { id, session, refresh, token: auth.generateAccessToken({ id }, session) };
    if (!['legacy', 'classified'].includes(name)) await subscription(db, {
      user_id: id, starts_at: name === 'pending' ? '2100-01-01Z' : '2000-01-01Z',
      ends_at: name === 'pending' ? '2101-01-01Z' : name === 'expired' ? '2001-01-01Z' : '2100-01-01Z',
      plan_code: ['team', 'enterprise'].includes(name) ? name : 'individual',
      ...(name === 'cancelled' ? { cancelled_at: '2020-01-01Z', cancelled_by_user_id: id } : {}),
    });
  }
  const originalFetch = globalThis.fetch, calls = [], engines = [];
  let fault = null, resourceCalls = 0;
  const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } });
  globalThis.fetch = async (request, options = {}) => {
    const url = new URL(request.url ?? request);
    if (url.origin !== 'http://127.0.0.1:54321') {
      assert.equal(url.hostname, '127.0.0.1', 'No live services in tests');
      return originalFetch(request, options);
    }
    const table = url.pathname.split('/').at(-1);
    const body = options.body ? JSON.parse(options.body) : null;
    const eq = key => url.searchParams.get(key)?.replace(/^eq\./, '');
    if (table === 'keeptimer_resolve_entitlement') {
      calls.push(body);
      if (fault === 'error') return json({ message: 'private DB failure' }, 503);
      if (fault) return json(fault);
      return json(await resolve(db, body.p_user_id));
    }
    if (table === 'users') {
      const result = await db.query('SELECT * FROM users WHERE ($1::uuid IS NULL OR id=$1) AND ($2::text IS NULL OR role=$2) AND ($3::text IS NULL OR username=$3)', [eq('id') || null, eq('role') || null, eq('username') || null]);
      return result.rows[0] ? json(result.rows[0]) : json({ code: 'PGRST116' }, 406);
    }
    if (table === 'sessions') {
      if (options.method === 'POST') {
        await db.query('INSERT INTO sessions(id,user_id,refresh_token_hash,user_agent) VALUES($1,$2,$3,$4)', [body.id, body.user_id, body.refresh_token_hash, body.user_agent]);
        return json(null, 201);
      }
      const result = await db.query('SELECT * FROM sessions WHERE id=$1 AND ($2::uuid IS NULL OR user_id=$2)', [eq('id'), eq('user_id') || null]);
      return result.rows[0] ? json(result.rows[0]) : json({ code: 'PGRST116' }, 406);
    }
    if (table === 'keeptimer_refresh_session') return json((await db.query('SELECT keeptimer_refresh_session($1,$2,$3) AS valid', [body.p_user_id, body.p_session_id, body.p_token_hash])).rows[0].valid);
    resourceCalls++;
    throw new Error(`Unexpected resource access: ${table}`);
  };
  const { httpServer } = await import('../src/server.js');
  if (!httpServer.listening) await once(httpServer, 'listening');
  const base = `http://127.0.0.1:${httpServer.address().port}`;
  t.after(async () => {
    for (const endpoint of engines) await originalFetch(endpoint, { method: 'POST', body: '1', signal: AbortSignal.timeout(1000) }).catch(() => {});
    globalThis.fetch = originalFetch;
    httpServer.closeAllConnections(); await new Promise(done => httpServer.close(done));
  });
  const request = (name, path = '/timers/personal', method = 'GET', body, token) => originalFetch(base + path, {
    method, headers: { Authorization: `Bearer ${token || accounts[name].token}`, 'Content-Type': 'application/json' },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });

  for (const [name, code] of [['pending', 'SUBSCRIPTION_PENDING'], ['expired', 'SUBSCRIPTION_EXPIRED'],
    ['cancelled', 'SUBSCRIPTION_CANCELLED'], ['team', 'PLAN_DISABLED'], ['enterprise', 'PLAN_DISABLED'],
    ['classified', 'SUBSCRIPTION_REQUIRED'], ['active', 'INDIVIDUAL_SCOPE_NOT_READY']]) {
    await t.test(`${name} cannot enter legacy timer/group/shared fallback`, async () => {
      for (const [method, path] of [['GET', '/timers/personal'], ['POST', '/timers'], ['PUT', `/timers/personal/${randomUUID()}`],
        ['GET', '/timers/shared?protocol=5'], ['POST', '/timers/shared/commands'], ['POST', '/timer/start'],
        ['GET', '/workspace'], ['POST', '/workspace/join']]) {
        const res = await request(name, path, method, method === 'GET' ? null : { plan_code: 'individual', status: 'active', endsAt: '2200-01-01Z', now: '2000-01-01Z' });
        assert.equal(res.status, 403); assert.equal((await res.json()).code, code);
      }
      assert.equal(resourceCalls, 0);
    });
  }
  await t.test('legacy standalone account retains existing behavior', async () => {
    assert.equal((await request('legacy')).status, 200);
    assert.equal((await request('legacy', '/workspace')).status, 200);
  });
  await t.test('stale signed JWT and client body cannot override live history', async () => {
    const a = accounts.expired;
    const stale = jwt.sign({ id: a.id, sessionId: a.session, type: 'access', plan_code: 'individual', isEntitled: true, endsAt: '2200-01-01Z' }, process.env.JWT_SECRET, { expiresIn: '15m' });
    const res = await request('expired', '/timers', 'POST', { user_id: accounts.active.id, status: 'active', plan_code: 'individual' }, stale);
    assert.equal(res.status, 403); assert.equal((await res.json()).code, 'SUBSCRIPTION_EXPIRED');
    assert.deepEqual(calls.at(-1), { p_user_id: a.id });
  });
  await t.test('own status endpoint is available when expired, minimal, no-store and ignores target/time claims', async () => {
    const res = await request('expired', `/account/subscription?userId=${accounts.active.id}&now=2000-01-01&plan_code=individual`);
    assert.equal(res.status, 200); assert.equal(res.headers.get('cache-control'), 'no-store');
    const body = await res.json(); assert.equal(body.code, 'SUBSCRIPTION_EXPIRED');
    assert.deepEqual(Object.keys(body.subscription).sort(), ['endsAt', 'isEntitled', 'planCode', 'startsAt', 'status']);
    assert.equal(body.subscription.status, 'expired'); assert.equal(body.subscription.isEntitled, false);
    assert.deepEqual(calls.at(-1), { p_user_id: accounts.expired.id });
    const active = await (await request('active', '/account/subscription')).json();
    assert.equal(active.subscription.isEntitled, true); assert.equal(active.subscription.status, 'active');
    const unauth = await originalFetch(base + '/account/subscription'); assert.equal(unauth.status, 401);
  });
  await t.test('RPC failure and malformed/unknown plan results fail closed without leaking DB details', async () => {
    const good = await resolve(db, accounts.active.id);
    for (const value of ['error', {}, { ...good, planCode: 'forged' }, { ...good, requiresSubscription: false }, { ...good, endsAt: null }, { ...good, isEntitled: 'true' }]) {
      fault = value;
      const response = await request('legacy'); assert.equal(response.status, 503);
      assert.deepEqual(await response.json(), { code: 'SUBSCRIPTION_UNAVAILABLE', error: 'Abonelik doğrulanamadı' });
    }
    fault = null;
    assert.equal(resourceCalls, 0);
  });
  await t.test('status endpoint rejects malformed RPC code types and keeps valid error mappings', async t => {
    const denied = { planCode: null, status: null, startsAt: null, endsAt: null,
      isEntitled: false, requiresSubscription: true };
    try {
      for (const [name, code] of [
        ['account array', ['ACCOUNT_DISABLED']], ['conflict array', ['SUBSCRIPTION_CONFLICT']],
        ['unavailable array', ['SUBSCRIPTION_UNAVAILABLE']], ['object', {}],
        ['number', 123], ['boolean', true], ['unknown', 'UNKNOWN_CODE'], ['missing', undefined],
      ]) await t.test(name, async () => {
        fault = { ...denied, code };
        for (const path of ['/account/subscription', '/timers/personal']) {
          const response = await request('legacy', path);
          assert.equal(response.status, 503);
          assert.deepEqual(await response.json(), { code: 'SUBSCRIPTION_UNAVAILABLE', error: 'Abonelik doğrulanamadı' });
          if (path === '/account/subscription') assert.equal(response.headers.get('cache-control'), 'no-store');
        }
      });
      for (const [code, status] of [['ACCOUNT_DISABLED', 401], ['SUBSCRIPTION_CONFLICT', 409], ['SUBSCRIPTION_UNAVAILABLE', 503]]) {
        fault = { ...denied, code };
        const response = await request('legacy', '/account/subscription');
        assert.equal(response.status, status); assert.equal((await response.json()).code, code);
      }
      assert.equal(resourceCalls, 0);
    } finally { fault = null; }
  });
  await t.test('DB microsecond periods reach HTTP status without losing precision', async () => {
    const id = accounts.legacy.id;
    try {
      for (const [sequence_no, starts_at, ends_at, timeZone] of [
        [1, '2000-10-01T00:00:00.000001Z', '2000-10-01T00:00:00.000002Z', 'UTC'],
        [2, '2000-10-01T03:00:00.000001+03:00', '2000-09-30T20:00:00.000002-04:00', 'Asia/Kathmandu'],
      ]) {
        await db.query("SELECT set_config('TimeZone',$1,false)", [timeZone]);
        await subscription(db, { user_id: id, sequence_no, starts_at, ends_at });
        const result = await resolve(db, id);
        assert.equal(result.status, 'expired'); assert.equal(result.code, 'SUBSCRIPTION_EXPIRED');
        const response = await request('legacy', '/account/subscription');
        assert.equal(response.status, 200); assert.equal(response.headers.get('cache-control'), 'no-store');
        assert.deepEqual(await response.json(), { subscription: {
          planCode: result.planCode, status: result.status, startsAt: result.startsAt,
          endsAt: result.endsAt, isEntitled: false,
        }, code: 'SUBSCRIPTION_EXPIRED' });
        const resource = await request('legacy');
        assert.equal(resource.status, 403); assert.equal((await resource.json()).code, 'SUBSCRIPTION_EXPIRED');
      }
    } finally { await db.exec("SET TIME ZONE 'UTC'"); }
    assert.equal(resourceCalls, 0);
  });
  await t.test('status endpoint compares microsecond offsets and rejects invalid periods', async t => {
    const good = await resolve(db, accounts.active.id);
    try {
      for (const [name, startsAt, endsAt, status] of [
        ['offset-ordered active', '2026-10-01T03:00:00.000001+03:00', '2026-09-30T20:00:00.000002-04:00', 200],
        ['equal instants', '2026-10-01T03:00:00.000001+03:00', '2026-09-30T20:00:00.000001-04:00', 503],
        ['reversed microseconds', '2026-10-01T00:00:00.000002Z', '2026-10-01T00:00:00.000001Z', 503],
        ['invalid calendar date', '2026-02-30T00:00:00Z', '2026-11-01T00:00:00Z', 503],
        ['invalid timestamp', 'malformed', '2026-11-01T00:00:00Z', 503],
      ]) await t.test(name, async () => {
        fault = { ...good, startsAt, endsAt };
        const response = await request('active', '/account/subscription');
        assert.equal(response.status, status);
        const body = await response.json();
        if (status === 200) {
          assert.equal(body.code, null); assert.equal(body.subscription.isEntitled, true);
          assert.equal(body.subscription.startsAt, startsAt); assert.equal(body.subscription.endsAt, endsAt);
        } else assert.equal(body.code, 'SUBSCRIPTION_UNAVAILABLE');
        const resource = await request('active');
        assert.equal(resource.status, status === 200 ? 403 : 503);
        assert.equal((await resource.json()).code, status === 200 ? 'INDIVIDUAL_SCOPE_NOT_READY' : 'SUBSCRIPTION_UNAVAILABLE');
      });
    } finally { fault = null; }
    assert.equal(resourceCalls, 0);
  });
  await t.test('login/refresh stay valid when subscription expired; paid access still denied', async () => {
    const response = await originalFetch(base + '/auth/login', { method: 'POST',
      headers: { Origin: 'https://fixture.example', 'Content-Type': 'application/json', 'X-KeepTimer-CSRF': '1' }, body: JSON.stringify({ username: 'expired', pin: 'fixture-pin' }) });
    assert.equal(response.status, 200); assert.match(response.headers.get('set-cookie'), /HttpOnly/);
    const loggedIn = await response.json(); assert.equal(Object.hasOwn(loggedIn, 'refreshToken'), false);
    const cookie = response.headers.get('set-cookie').split(';')[0];
    const refreshed = await originalFetch(base + '/auth/refresh', { method: 'POST',
      headers: { Origin: 'https://fixture.example', 'Content-Type': 'application/json', 'X-KeepTimer-CSRF': '1', Cookie: cookie },
      body: JSON.stringify({ sessionId: loggedIn.sessionId }) });
    assert.equal(refreshed.status, 200);
    const fresh = await refreshed.json();
    assert.equal((await request('expired', '/timers/personal', 'GET', null, fresh.accessToken)).status, 403);
    assert.equal((await db.query('SELECT disabled_at FROM users WHERE id=$1', [accounts.expired.id])).rows[0].disabled_at, null);
  });
  await t.test('current catalog/cancellation and overlap decisions replace any earlier token decision', async () => {
    const account = accounts.active;
    await db.exec("UPDATE subscription_plans SET enabled=false WHERE code='individual'");
    const disabled = await request('active');
    assert.equal(disabled.status, 403); assert.equal((await disabled.json()).code, 'PLAN_DISABLED');
    await db.exec("UPDATE subscription_plans SET enabled=true WHERE code='individual'");
    await subscription(db, { user_id: account.id, sequence_no: 2, starts_at: '2000-01-01Z', ends_at: '2100-01-01Z' });
    const conflict = await request('active', '/account/subscription');
    assert.equal(conflict.status, 409); assert.equal((await conflict.json()).code, 'SUBSCRIPTION_CONFLICT');
    await db.query('UPDATE subscriptions SET cancelled_at=clock_timestamp(),cancelled_by_user_id=$1 WHERE user_id=$1', [account.id]);
    const denied = await request('active');
    assert.equal(denied.status, 403); assert.equal((await denied.json()).code, 'SUBSCRIPTION_CANCELLED');
    const state = await (await request('active', '/account/subscription')).json();
    assert.equal(state.subscription.status, 'cancelled'); assert.equal(state.subscription.isEntitled, false);
    assert.equal(resourceCalls, 0);
  });
  await t.test('paid socket connection denied before joining user/workspace rooms', async () => {
    for (const name of ['active', 'expired', 'team']) {
      const opened = await originalFetch(base + '/socket.io/?EIO=4&transport=polling');
      const { sid } = JSON.parse((await opened.text()).slice(1));
      const endpoint = `${base}/socket.io/?EIO=4&transport=polling&sid=${sid}`; engines.push(endpoint);
      await originalFetch(endpoint, { method: 'POST', body: `40${JSON.stringify({ token: accounts[name].token })}` });
      const packet = await (await originalFetch(endpoint, { signal: AbortSignal.timeout(2000) })).text();
      assert.match(packet, /^44/); assert.equal(JSON.parse(packet.slice(2)).data.status, 403);
    }
  });
});

test('Phase 2 reusable entitlement guard allows active Individual only and never caches', async t => {
  const db = await database(t), id = await user(db);
  const row = await subscription(db, { user_id: id, starts_at: '2000-01-01Z', ends_at: '2100-01-01Z' });
  const core = createSubscriptionCore({ rpc: async (_name, args) => ({ data: await resolve(db, args.p_user_id), error: null }) });
  const app = express(); app.use((req, _res, next) => { req.user = { id }; next(); });
  let operations = 0;
  app.post('/paid-read-preflight', core.requireIndividualEntitlement, (_req, res) => { operations++; res.sendStatus(204); });
  const server = app.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => { server.closeAllConnections(); await new Promise(done => server.close(done)); });
  const call = () => fetch(`http://127.0.0.1:${server.address().port}/paid-read-preflight`, { method: 'POST' });
  assert.equal((await call()).status, 204);
  await db.query('UPDATE subscriptions SET cancelled_at=clock_timestamp(),cancelled_by_user_id=$1 WHERE id=$2', [id, row.id]);
  const second = await call(); assert.equal(second.status, 403);
  assert.equal((await second.json()).code, 'SUBSCRIPTION_CANCELLED'); assert.equal(operations, 1);
});
