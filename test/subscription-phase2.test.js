import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { database, user, subscription, resolve, asRole, phase2 } from './support/subscriptionPhase2.js';

const past = { starts_at: '2000-01-01Z', ends_at: '2000-02-01Z' };
const active = { starts_at: '2000-01-01Z', ends_at: '2100-01-01Z' };
const future = { starts_at: '2100-01-01Z', ends_at: '2100-02-01Z' };
const expired = { starts_at: '1999-01-01Z', ends_at: '1999-02-01Z' };

test('Phase 2 DB status, history selection, policy and preservation', async t => {
  const db = await database(t);
  for (const [name, cancelled, at, expected] of [
    ['cancelled', '2026-10-02Z', '2026-10-20Z', 'cancelled'],
    ['future start', null, '2026-09-30T23:59:59.999999Z', 'pending'],
    ['exact start', null, '2026-10-01T00:00:00Z', 'active'],
    ['active', null, '2026-10-20Z', 'active'],
    ['exact end', null, '2026-11-01T00:00:00Z', 'expired'],
    ['after end', null, '2026-11-02Z', 'expired'],
    ['cancelled future', '2026-09-01Z', '2026-09-20Z', 'cancelled'],
    ['cancelled active', '2026-10-02Z', '2026-10-10Z', 'cancelled'],
  ]) await t.test(name, async () => {
    const row = (await db.query("SELECT public.keeptimer_subscription_state($1,'2026-10-01Z','2026-11-01Z',$2) AS state", [cancelled, at])).rows[0];
    assert.equal(row.state, expected);
  });

  async function history(rows, extra = {}) {
    const id = await user(db, 'worker', extra);
    for (const [i, values] of rows.entries()) await subscription(db, { user_id: id, sequence_no: i + 1, ...values,
      ...(values.cancelled_at ? { cancelled_by_user_id: id } : {}) });
    return { id, result: await resolve(db, id) };
  }
  for (const [name, rows, status, start] of [
    ['expired old + active current', [expired, active], 'active', active.starts_at],
    ['active current + future renewal', [active, future], 'active', active.starts_at],
    ['expired old + future period', [expired, future], 'pending', future.starts_at],
    ['multiple expired rows', [expired, past], 'expired', past.starts_at],
    ['cancelled newest retains older active', [active, { ...future, cancelled_at: '2026-01-01Z' }], 'active', active.starts_at],
    ['only cancelled newest, no valid active/future', [expired, { ...past, cancelled_at: '2026-01-01Z' }], 'cancelled', past.starts_at],
    ['earliest pending before higher-sequence later renewal', [future, { starts_at: '2101-01-01Z', ends_at: '2101-02-01Z' }], 'pending', future.starts_at],
  ]) await t.test(name, async () => {
    const { result } = await history(rows);
    assert.equal(result.status, status); assert.equal(result.isEntitled, status === 'active');
    assert.equal(Date.parse(result.startsAt), Date.parse(start));
    if (status !== 'active') assert.equal(result.code, `SUBSCRIPTION_${status.toUpperCase()}`);
  });
  await t.test('overlapping active history fails closed, including cross-plan overlap', async () => {
    for (const plan_code of ['individual', 'team']) {
      const { result } = await history([active, { ...active, plan_code }]);
      assert.equal(result.isEntitled, false); assert.equal(result.code, 'SUBSCRIPTION_CONFLICT');
      assert.equal(result.status, null); assert.equal(result.planCode, null);
    }
  });
  await t.test('classification is not authority; enabled individual grants by history', async () => {
    const { id, result } = await history([active], { plan_code: 'team' });
    assert.equal(result.planCode, 'individual'); assert.equal(result.isEntitled, true);
    await db.query('UPDATE users SET plan_code=NULL WHERE id=$1', [id]);
    assert.equal((await resolve(db, id)).requiresSubscription, true);
    const classified = await user(db, 'worker', { plan_code: 'individual' });
    const missing = await resolve(db, classified);
    assert.equal(missing.isEntitled, false); assert.equal(missing.requiresSubscription, true);
    assert.equal(missing.code, 'SUBSCRIPTION_REQUIRED');
  });
  await t.test('team and enterprise deny even if an operator enables catalog flags', async () => {
    for (const plan_code of ['team', 'enterprise']) {
      const { id, result } = await history([{ ...active, plan_code }]);
      assert.equal(result.status, 'active'); assert.equal(result.isEntitled, false); assert.equal(result.code, 'PLAN_DISABLED');
      await db.query('UPDATE subscription_plans SET enabled=true WHERE code=$1', [plan_code]);
      assert.equal((await resolve(db, id)).code, 'PLAN_DISABLED');
      await db.query('UPDATE subscription_plans SET enabled=false WHERE code=$1', [plan_code]);
    }
  });
  await t.test('disabling individual immediately denies entitlement; unknown plans reject', async () => {
    const { id } = await history([active]);
    await db.exec("UPDATE subscription_plans SET enabled=false WHERE code='individual'");
    assert.equal((await resolve(db, id)).code, 'PLAN_DISABLED');
    await db.exec("UPDATE subscription_plans SET enabled=true WHERE code='individual'");
    await assert.rejects(() => subscription(db, { user_id: id, sequence_no: 2, plan_code: 'forged' }), e => e.code === '23503');
    await assert.rejects(() => db.exec("INSERT INTO subscription_plans(code,display_name) VALUES('forged','Forged')"), e => e.code === '23514');
  });
  await t.test('disabled account, missing account, no history and non-worker role deny', async () => {
    const { id } = await history([active]);
    await db.query('UPDATE users SET disabled_at=clock_timestamp() WHERE id=$1', [id]);
    assert.equal((await resolve(db, id)).code, 'ACCOUNT_DISABLED');
    assert.equal((await resolve(db, randomUUID())).code, 'ACCOUNT_DISABLED');
    const empty = await user(db);
    assert.equal((await resolve(db, empty)).code, 'SUBSCRIPTION_REQUIRED');
    assert.equal((await resolve(db, empty)).requiresSubscription, false);
    await db.query('UPDATE users SET disabled_at=clock_timestamp() WHERE id=$1', [empty]);
    assert.equal((await resolve(db, empty)).requiresSubscription, true);
    const manager = await user(db, 'manager');
    await subscription(db, { user_id: manager, ...active });
    assert.equal((await resolve(db, manager)).code, 'SUBSCRIPTION_FORBIDDEN');
  });
  await t.test('expired scope resolution changes no user, session, timer or subscription rows', async () => {
    const { id } = await history([past]);
    await db.query("INSERT INTO timers(user_id,name,type,target_minutes) VALUES($1,'retained','up',1)", [id]);
    await db.query("INSERT INTO sessions(user_id,refresh_token_hash) VALUES($1,'synthetic-hash')", [id]);
    const snapshot = () => db.query(`SELECT (SELECT jsonb_agg(u) FROM users u WHERE id=$1) AS users,
      (SELECT jsonb_agg(s) FROM sessions s WHERE user_id=$1) AS sessions,
      (SELECT jsonb_agg(t) FROM timers t WHERE user_id=$1) AS timers,
      (SELECT jsonb_agg(h) FROM subscriptions h WHERE user_id=$1) AS history`, [id]);
    const before = (await snapshot()).rows;
    const result = await resolve(db, id);
    assert.equal(result.code, 'SUBSCRIPTION_EXPIRED');
    await assert.rejects(() => db.query('SELECT keeptimer_require_individual_entitlement($1)', [id]), /SUBSCRIPTION_EXPIRED/);
    assert.deepEqual((await snapshot()).rows, before);
  });
  await t.test('private marker classifies scope but does not create or expose a workspace', async () => {
    const id = await user(db);
    const workspace = (await db.query("INSERT INTO workspaces(name,owner_id,kind,shared_mode_enabled) VALUES('Hidden',$1,'individual_private',false) RETURNING id", [id])).rows[0].id;
    await db.query('UPDATE users SET workspace_id=$1 WHERE id=$2', [workspace, id]);
    const result = await resolve(db, id);
    assert.equal(result.requiresSubscription, true); assert.equal(result.code, 'SUBSCRIPTION_REQUIRED');
    assert.equal(Object.hasOwn(result, 'workspace_id'), false);
  });
  await t.test('RPC ACL is service-only; no table privilege expansion', async () => {
    const { id } = await history([active]);
    for (const role of ['anon', 'authenticated']) await asRole(db, role, async () => {
      await assert.rejects(() => resolve(db, id), e => e.code === '42501');
      await assert.rejects(() => db.query('SELECT keeptimer_require_individual_entitlement($1)', [id]), e => e.code === '42501');
    });
    await asRole(db, 'service_role', async () => {
      assert.equal((await resolve(db, id)).isEntitled, true);
      await db.query('SELECT keeptimer_require_individual_entitlement($1)', [id]);
      await assert.rejects(() => db.exec("UPDATE subscription_plans SET enabled=true"), e => e.code === '42501');
      await assert.rejects(() => db.exec('DELETE FROM subscriptions'), e => e.code === '42501');
      await assert.rejects(() => db.exec("SELECT keeptimer_subscription_state(NULL,now(),now(),now())"), e => e.code === '42501');
    });
  });
  await t.test('higher isolation is explicitly rejected instead of stale snapshot authorization', async () => {
    const { id } = await history([active]);
    await db.exec('BEGIN ISOLATION LEVEL REPEATABLE READ');
    try { await assert.rejects(() => resolve(db, id), /SUBSCRIPTION_ISOLATION_UNSUPPORTED/); }
    finally { await db.exec('ROLLBACK'); }
  });
  await t.test('phase2 replay preserves data and original history protections', async () => {
    const query = 'SELECT (SELECT jsonb_agg(s ORDER BY id) FROM subscriptions s) AS s, (SELECT jsonb_agg(t ORDER BY id) FROM timers t) AS t';
    const before = (await db.query(query)).rows;
    await db.exec(phase2);
    assert.deepEqual((await db.query(query)).rows, before);
    await assert.rejects(() => db.exec('UPDATE subscriptions SET amount_minor=0'), /HISTORY_IMMUTABLE/);
    await assert.rejects(() => db.exec('DELETE FROM admin_audit_log'), /APPEND_ONLY/);
  });
});
