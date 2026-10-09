import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { database, actor, seededCustomer, resolve, put, scope, asRole, phase6,
  enableIsolatedFixture, command, renewal, cancel, state } from './support/subscriptionPhase6.js';
import { createAccountExperience } from '../src/accountExperience.js';

const snapshot = async (db, customer) => (await db.query(`SELECT
  (SELECT to_jsonb(u) FROM users u WHERE id=$1) u,
  (SELECT jsonb_agg(t ORDER BY id) FROM timers t WHERE user_id=$1) t,
  (SELECT jsonb_agg(s ORDER BY sequence_no) FROM subscriptions s WHERE user_id=$1) s`, [customer])).rows[0];

test('Phase 6: lifecycle on final schema (PGlite unless guarded PG is supplied)', async t => {
  const db = await database(t), agent = await actor(db);
  await t.test('migration keeps release OFF and does not grant additional execution/table access', async () => {
    assert.equal((await db.query('SELECT enabled FROM keeptimer_sales_release')).rows[0].enabled, false);
    for (const role of ['anon', 'authenticated']) await asRole(db, role, async () => {
      await assert.rejects(() => resolve(db, agent.id), e => e.code === '42501');
      await assert.rejects(() => db.query('SELECT keeptimer_phase3_subscription_json($1)', [randomUUID()]), e => e.code === '42501');
    });
    await asRole(db, 'service_role', async () => {
      await assert.rejects(() => db.exec('UPDATE keeptimer_sales_release SET enabled=true'), e => e.code === '42501');
      await assert.rejects(() => db.exec('DELETE FROM subscriptions'), e => e.code === '42501');
    });
  });
  for (const [at, expected] of [
    ['2028-02-29T00:00:00.000000Z', 'pending'], ['2028-02-29T00:00:00.000001Z', 'active'],
    ['2028-03-29T00:00:00.000000Z', 'active'], ['2028-03-29T00:00:00.000001Z', 'expired'],
  ]) await t.test('microsecond boundary '+at, async () => {
    const r = (await db.query("SELECT keeptimer_subscription_state(NULL,'2028-02-29T00:00:00.000001Z','2028-03-29T00:00:00.000001Z',$1) s", [at])).rows[0];
    assert.equal(r.s, expected);
  });
  for (const [start, end] of [
    ['2027-01-28T12:00:00.123456Z','2027-02-28T12:00:00.123456Z'],
    ['2027-01-29T12:00:00.123456Z','2027-02-28T12:00:00.123456Z'],
    ['2027-01-30T12:00:00.123456Z','2027-02-28T12:00:00.123456Z'],
    ['2028-01-31T12:00:00.123456Z','2028-02-29T12:00:00.123456Z'],
    ['2028-02-29T12:00:00.123456Z','2028-03-29T12:00:00.123456Z'],
    ['2026-03-08T01:30:00.123456-05:00','2026-04-08T06:30:00.123456Z'],
  ]) await t.test('UTC calendar months '+start, async () => {
    for (const zone of ['UTC','Europe/Istanbul','America/New_York']) {
      await db.query("SELECT set_config('TimeZone',$1,false)", [zone]);
      assert.equal((await db.query('SELECT keeptimer_phase3_add_months($1,1)=$2::timestamptz ok', [start,end])).rows[0].ok, true);
    }
  });
  await db.exec("SET TIME ZONE 'UTC'");
  await enableIsolatedFixture(db);
  const c = await seededCustomer(db, agent, { starts_at:'2000-01-01Z', ends_at:'2100-01-31T00:00:00.123456Z' });
  const timer = randomUUID(), mutation = randomUUID(); await put(db, c.id, timer, mutation);
  let next;
  await t.test('active renewal uses exact ending instant and retries create one pending sale', async () => {
    const key = randomUUID(); next = await command(db, agent, 'subscription_renew', renewal(c.id), key);
    assert.deepEqual(await command(db, agent, 'subscription_renew', renewal(c.id), key), next);
    assert.equal(next.subscription.status, 'pending');
    assert.equal((await db.query('SELECT a.ends_at=b.starts_at ok FROM subscriptions a,subscriptions b WHERE a.id=$1 AND b.id=$2', [c.subscription.id,next.subscription.id])).rows[0].ok, true);
    await assert.rejects(() => command(db, agent, 'subscription_renew', renewal(c.id)), /PENDING_PERIOD_EXISTS/);
    assert.equal((await resolve(db, c.id)).status, 'active');
  });
  await t.test('cancel pending only; active survives; audit actor/reason/time retained', async () => {
    const result = await command(db, agent, 'subscription_cancel', cancel(c.id,next.subscription.id));
    assert.equal(result.subscription.cancelledBy, agent.id); assert.equal(result.subscription.cancellationReason, 'customer_request');
    assert.ok(result.subscription.cancelledAt); assert.equal(result.subscription.status, 'cancelled');
    assert.equal((await resolve(db, c.id)).isEntitled, true);
    assert.equal((await db.query('SELECT cancelled_at FROM subscriptions WHERE id=$1', [c.subscription.id])).rows[0].cancelled_at, null);
  });
  await t.test('active cancellation blocks writes while timers/workspace remain readable', async () => {
    await command(db, agent, 'subscription_cancel', cancel(c.id,c.subscription.id));
    const before = await snapshot(db, c.id);
    assert.equal((await scope(db, c.id)).workspaceId, c.workspace);
    await assert.rejects(() => put(db, c.id, timer, randomUUID(), 1), /SUBSCRIPTION_CANCELLED/);
    assert.deepEqual(await snapshot(db,c.id), before);
  });
  await t.test('reactivation through existing sale API keeps identity, timer, revision and old history', async () => {
    const before = await snapshot(db,c.id);
    const result = await command(db, agent, 'subscription_renew', renewal(c.id));
    assert.equal(result.subscription.status,'active'); assert.equal(result.loginReady,false);
    const after = await snapshot(db,c.id);
    assert.deepEqual(after.u,before.u); assert.deepEqual(after.t,before.t); assert.deepEqual(after.s.slice(0,2),before.s);
    assert.equal((await scope(db,c.id,true)).workspaceId,c.workspace);
    assert.equal((await put(db,c.id,timer,mutation)).duplicate,true);
    assert.equal((await put(db,c.id,timer,randomUUID(),1,state({name:'Continued'}))).timer.sync_revision,2);
  });
  await t.test('expired renewal starts between database observations, no JS date calculation', async () => {
    const expired=await seededCustomer(db,agent,{starts_at:'2000-01-01Z',ends_at:'2000-02-01Z'});
    const before=(await resolve(db,expired.id)).evaluatedAt;
    const sale=await command(db,agent,'subscription_renew',renewal(expired.id));
    const after=(await resolve(db,expired.id)).evaluatedAt;
    assert.equal((await db.query('SELECT $1::timestamptz <= $2::timestamptz AND $2::timestamptz <= $3::timestamptz ok',[before,sale.subscription.startsAt,after])).rows[0].ok,true);
    assert.equal((await scope(db,expired.id,true)).workspaceId,expired.workspace);
  });
  await t.test('DB clock reaches account HTTP projection without exposing history or granting from local time', async () => {
    const e=await resolve(db,c.id); assert.ok(e.evaluatedAt);
    const scoped=await scope(db,c.id);
    const account=createAccountExperience({rpc:async()=>({data:scoped})},{resolveSubscriptionEntitlement:async()=>e});
    let body; const res={set(){},json(value){body=value;},status(){return this;}};
    await account.getExperience({user:{id:c.id,workspace_id:c.workspace,role:'worker'}},res);
    assert.equal(body.evaluatedAt,scoped.entitlement.evaluatedAt);
    assert.ok(body.evaluatedAt); assert.equal(body.subscription.isEntitled,true);
    assert.equal('history' in body,false); assert.equal(body.loginReady,false);
  });
  await t.test('forward migration replay preserves data and function security', async () => {
    const before=await snapshot(db,c.id); await db.exec(phase6); assert.deepEqual(await snapshot(db,c.id),before);
    const config=(await db.query("SELECT proconfig FROM pg_proc WHERE oid='public.keeptimer_resolve_entitlement(uuid)'::regprocedure")).rows[0].proconfig;
    assert.ok(config.some(x=>x.startsWith('search_path=')));
    await assert.rejects(()=>db.exec('UPDATE subscriptions SET amount_minor=0'),/HISTORY_IMMUTABLE/);
  });
});
