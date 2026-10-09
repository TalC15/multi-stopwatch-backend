import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { database, actor, user, seededCustomer, subscription, scope, state, put, remove, asRole, migration } from './support/subscriptionPhase5.js';

test('Phase 5 DB: scoped private sync, lifecycle, company compatibility, RLS and closed release', async t => {
  const db = await database(t), agent = await actor(db);
  const a = await seededCustomer(db, agent, { starts_at: '2000-01-01Z', ends_at: new Date(Date.now()+1500).toISOString() });
  const b = await seededCustomer(db, agent, { starts_at: '2000-01-01Z', ends_at: '2100-01-01Z' });
  const timer = randomUUID(), mutation = randomUUID();
  await t.test('active owner creates, retries, updates and deletes; another owner cannot steal the UUID', async () => {
    assert.equal((await scope(db, a.id, true)).kind, 'individual');
    const first = await asRole(db, 'service_role', () => put(db, a.id, timer, mutation));
    assert.equal(first.created, true); assert.equal(first.timer.user_id, a.id); assert.equal(first.timer.workspace_id, a.workspace);
    const retry = await put(db, a.id, timer, mutation); assert.equal(retry.duplicate, true);
    await assert.rejects(() => put(db, b.id, timer, randomUUID()), /KEEPTIMER_TIMER_FORBIDDEN/);
    await assert.rejects(() => remove(db, b.id, timer, randomUUID(), 1), /KEEPTIMER_TIMER_FORBIDDEN/);
    assert.equal((await put(db, a.id, timer, randomUUID(), 1, state({ name: 'Own update' }))).timer.sync_revision, 2);
  });
  await t.test('expired writes fail; records and duplicate markers survive; renewal reopens the same workspace', async () => {
    await new Promise(done => setTimeout(done, Math.max(0, new Date(a.subscription.ends_at).getTime()-Date.now())+30));
    assert.equal((await scope(db, a.id)).entitlement.code, 'SUBSCRIPTION_EXPIRED');
    await assert.rejects(() => put(db, a.id, randomUUID(), randomUUID()), /SUBSCRIPTION_EXPIRED/);
    await assert.rejects(() => remove(db, a.id, timer, randomUUID(), 2), /SUBSCRIPTION_EXPIRED/);
    assert.equal((await db.query('SELECT name FROM timers WHERE id=$1', [timer])).rows[0].name, 'Own update');
    await subscription(db, { user_id: a.id, sequence_no: 2, starts_at: '2002-01-01Z', ends_at: '2100-01-01Z' });
    assert.equal((await scope(db, a.id, true)).workspaceId, a.workspace);
    assert.equal((await remove(db, a.id, timer, randomUUID(), 2)).timer.record_status, 'deleted');
  });
  await t.test('pending and cancelled never grant writes; cancelled renewal does not cancel an older active period', async () => {
    const pending = await seededCustomer(db, agent, { starts_at: '2100-01-01Z', ends_at: '2101-01-01Z' });
    await assert.rejects(() => put(db, pending.id, randomUUID(), randomUUID()), /SUBSCRIPTION_PENDING/);
    assert.equal((await scope(db, pending.id)).entitlement.status, 'pending');
    await db.query('UPDATE subscriptions SET cancelled_at=clock_timestamp(),cancelled_by_user_id=$1 WHERE user_id=$2', [agent.id, pending.id]);
    await assert.rejects(() => put(db, pending.id, randomUUID(), randomUUID()), /SUBSCRIPTION_CANCELLED/);
    await subscription(db, { user_id: b.id, sequence_no: 2, starts_at: '2100-01-01Z', ends_at: '2101-01-01Z', cancelled_at: '2026-01-01Z', cancelled_by_user_id: agent.id });
    assert.equal((await scope(db, b.id, true)).entitlement.isEntitled, true);
  });
  await t.test('private membership/type/shared/invites are immutable; legacy mutation RPC cannot enter private resources', async () => {
    const outsider = await user(db), sa = await user(db, 'superadmin');
    await assert.rejects(() => db.query('UPDATE users SET workspace_id=$1 WHERE id=$2', [a.workspace, outsider]), /PHASE3_PRIVATE_OWNER_ONLY/);
    await assert.rejects(() => db.query("UPDATE workspaces SET kind='team' WHERE id=$1", [a.workspace]), /PHASE3_PRIVATE_WORKSPACE_IMMUTABLE/);
    await assert.rejects(() => db.query("UPDATE workspaces SET invite_code='PRIVATE' WHERE id=$1", [a.workspace]), /workspaces_private_shape_check/);
    await assert.rejects(() => db.query('SELECT keeptimer_change_timer($1,$2,$3,false)', [sa, timer, '{}']), /INDIVIDUAL_SCOPE_NOT_READY/);
    await assert.rejects(() => db.query('SELECT keeptimer_shared_request($1,$2)', [b.id, '{}']), /INDIVIDUAL_SCOPE_NOT_READY/);
    const own = (await put(db, b.id, randomUUID(), randomUUID())).timer;
    await assert.rejects(() => db.query('UPDATE timers SET workspace_id=NULL WHERE id=$1', [own.id]), /PHASE5_PRIVATE_TIMER_IMMUTABLE/);
    await assert.rejects(() => asRole(db, 'service_role', () => db.query("UPDATE timers SET name='bypass' WHERE id=$1", [own.id])), /PHASE5_PRIVATE_RPC_REQUIRED/);
    await assert.rejects(() => asRole(db, 'service_role', () => db.query('DELETE FROM timers WHERE id=$1', [own.id])), /PHASE5_PRIVATE_RPC_REQUIRED/);
  });
  await t.test('restrictive RLS defeats a pre-existing permissive policy; unchecked RPCs are owner-only', async () => {
    for (const table of ['users', 'workspaces', 'timers']) await db.exec(`CREATE POLICY fixture_legacy_allow ON ${table} TO anon,authenticated USING(true) WITH CHECK(true)`);
    await db.exec('GRANT SELECT ON users,workspaces,timers TO anon,authenticated');
    for (const role of ['anon', 'authenticated']) await asRole(db, role, async () => {
      assert.equal((await db.query('SELECT id FROM workspaces WHERE id=$1', [a.workspace])).rows.length, 0);
      assert.equal((await db.query('SELECT id FROM users WHERE id=$1', [a.id])).rows.length, 0);
      assert.equal((await db.query('SELECT id FROM timers WHERE workspace_id=$1', [b.workspace])).rows.length, 0);
      await assert.rejects(() => scope(db, a.id), /permission denied/);
    });
    await assert.rejects(() => asRole(db, 'service_role', () => db.query('SELECT keeptimer_phase5_delete_personal_internal($1,$2,$3,0)', [a.id, timer, randomUUID()])), /permission denied/);
  });
  await t.test('company local-first RPC remains usable and migration can safely be rerun', async () => {
    const manager = await user(db, 'manager');
    const w = (await db.query("INSERT INTO workspaces(name,owner_id,kind) VALUES('Company',$1,'team') RETURNING id", [manager])).rows[0].id;
    const worker = await user(db, 'worker', { workspace_id: w });
    const own = await put(db, worker, randomUUID(), randomUUID());
    assert.equal((await scope(db, worker, true)).kind, 'company');
    assert.equal(own.timer.workspace_id, w);
    await db.query('UPDATE workspaces SET shared_mode_enabled=true WHERE id=$1', [w]);
    const sharedId = randomUUID();
    const rpc = request => db.query('SELECT keeptimer_shared_request($1,$2::jsonb) r', [worker, JSON.stringify(request)]).then(x => x.rows[0].r);
    const shared = await rpc({ protocol: 5, command: 'create', timerId: sharedId, mutationId: randomUUID(), expectedRevision: '0', name: 'Company shared', type: 'up', targetMinutes: 1 });
    assert.equal(shared.timer.id, sharedId); assert.equal(shared.timer.workspace_id, w);
    const started = await rpc({ protocol: 5, command: 'start', timerId: sharedId, mutationId: randomUUID(), expectedRevision: '1' });
    assert.equal(started.timer.status, 'running');
    assert.equal((await rpc({ protocol: 5, command: 'snapshot' })).timers[0].id, sharedId);
    await db.exec(migration);
    assert.equal((await put(db, worker, own.timer.id, randomUUID(), 1, state({ name: 'Company update' }))).timer.name, 'Company update');
    assert.equal((await db.query('SELECT enabled FROM keeptimer_sales_release')).rows[0].enabled, false);
  });
  await t.test('private mutation and Telegram RPCs require an owned unrevoked session, without leaving records', async () => {
    const id = randomUUID(), mutation = randomUUID();
    await assert.rejects(() => db.query('SELECT keeptimer_sync_personal($1,$2,$3,0,$4)', [b.id,id,mutation,JSON.stringify(state())]), /AUTH_SESSION_INVALID/);
    await assert.rejects(() => db.query('SELECT keeptimer_sync_personal($1,$2,$3,0,$4,$5)', [b.id,id,mutation,JSON.stringify(state()),a.session]), /AUTH_SESSION_INVALID/);
    await db.query('UPDATE sessions SET revoked_at=clock_timestamp() WHERE id=$1', [b.session]);
    await assert.rejects(() => put(db,b.id,id,mutation), /AUTH_SESSION_INVALID/);
    await assert.rejects(() => db.query('SELECT keeptimer_phase5_telegram($1,$2,$3)', [b.id,'123456',b.session]), /AUTH_SESSION_INVALID/);
    assert.equal((await db.query('SELECT id FROM timers WHERE id=$1', [id])).rows.length,0);
    assert.equal((await db.query('SELECT telegram_chat_id FROM users WHERE id=$1', [b.id])).rows[0].telegram_chat_id,null);
  });
  await t.test('Telegram active bind/unlink, expired cleanup and company behavior use real SQL', async () => {
    const c=await seededCustomer(db,agent,{starts_at:'2000-01-01Z',ends_at:'2100-01-01Z'});
    const telegram=(who,chat)=>db.query('SELECT keeptimer_phase5_telegram($1,$2,$3) result',[who.id,chat,who.session]);
    const current=async()=> (await db.query('SELECT telegram_chat_id FROM users WHERE id=$1',[c.id])).rows[0].telegram_chat_id;
    assert.equal((await telegram(c,'1234')).rows[0].result,true);assert.equal(await current(),'1234');
    await telegram(c,null);assert.equal(await current(),null);
    const expired=await seededCustomer(db,agent,{starts_at:'2000-01-01Z',ends_at:'2001-01-01Z'});
    await db.query('UPDATE users SET telegram_chat_id=$1 WHERE id=$2',['5678',expired.id]);
    await assert.rejects(()=>telegram(expired,'9999'),/SUBSCRIPTION_EXPIRED/);
    assert.equal((await db.query('SELECT telegram_chat_id FROM users WHERE id=$1',[expired.id])).rows[0].telegram_chat_id,'5678');
    await telegram(expired,null);
    assert.equal((await db.query('SELECT telegram_chat_id FROM users WHERE id=$1',[expired.id])).rows[0].telegram_chat_id,null);
    const company={id:await user(db),session:null};await telegram(company,'1234');await telegram(company,null);
    assert.equal((await db.query('SELECT telegram_chat_id FROM users WHERE id=$1',[company.id])).rows[0].telegram_chat_id,null);
  });
});
