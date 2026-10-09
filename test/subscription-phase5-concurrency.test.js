import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { database, actor, user, seededCustomer, connect, localTestUrl, put, remove, state } from './support/subscriptionPhase5.js';
const options = { skip: localTestUrl() ? false : 'Requires guarded isolated disposable PostgreSQL cluster; no live DB fallback' };

async function observeWait(db, waiter, blocker, customer) {
  const deadline = Date.now()+4000;
  do {
    const r = (await db.query(`SELECT $2=ANY(pg_catalog.pg_blocking_pids($1)) waiting,
      EXISTS(SELECT 1 FROM subscriptions WHERE user_id=$3 AND cancelled_at IS NULL AND starts_at<=clock_timestamp() AND clock_timestamp()<ends_at) valid`, [waiter, blocker, customer])).rows[0];
    if (r.waiting) { assert.equal(r.valid, true, 'actual resource wait must occur while entitlement is still active'); return; }
    await new Promise(done => setTimeout(done, 15));
  } while (Date.now()<deadline);
  assert.fail('Resource wait was not observed; a preflight denial cannot satisfy this regression');
}
for (const operation of ['insert', 'update', 'delete']) test('Phase 5 PG: subscription expires during personal '+operation+' lock wait; write and mutation marker roll back', options, async t => {
  const db = await database(t), a = await connect(t), b = await connect(t), agent = await actor(db);
  const c = await seededCustomer(db, agent, { starts_at: '2000-01-01Z', ends_at: new Date(Date.now()+2500).toISOString() });
  const id = randomUUID(), oldMutation = randomUUID(), attempted = randomUUID();
  if (operation !== 'insert') await put(db, c.id, id, oldMutation);
  const blocker = (await a.query('SELECT pg_backend_pid() pid')).rows[0].pid, waiter = (await b.query('SELECT pg_backend_pid() pid')).rows[0].pid;
  await b.exec("SET lock_timeout='8s'"); await a.exec('BEGIN'); let denied;
  try {
    if (operation === 'insert') {
      await a.query(`INSERT INTO timers(id,user_id,created_by,workspace_id,name,type,target_minutes,is_shared,status,record_status,accumulated_ms,paused_count)
        VALUES($1,$2,$2,$3,'uncommitted blocker','down',5,false,'idle','active',0,0)`, [id,c.id,c.workspace]);
    } else await a.query('SELECT id FROM timers WHERE id=$1 FOR UPDATE', [id]);
    const pending = operation === 'delete' ? remove(b, c.id, id, attempted, 1) : put(b, c.id, id, attempted, operation === 'insert' ? 0 : 1, state({ name: 'Must roll back' }));
    denied = assert.rejects(pending, e => e.code === 'P0001' && e.message === 'SUBSCRIPTION_EXPIRED'); denied.catch(() => {});
    await observeWait(db, waiter, blocker, c.id);
    await a.query("SELECT pg_sleep(GREATEST(0,extract(epoch FROM ($1::timestamptz-clock_timestamp())))+0.05)", [c.subscription.ends_at]);
    await a.exec('ROLLBACK'); await denied;
    const rows = (await db.query('SELECT name,record_status,sync_revision,last_sync_mutation_id FROM timers WHERE id=$1', [id])).rows;
    if (operation === 'insert') assert.equal(rows.length, 0);
    else { assert.equal(rows[0].name, 'Private fixture'); assert.equal(rows[0].record_status, 'active'); assert.equal(Number(rows[0].sync_revision), 1); assert.equal(rows[0].last_sync_mutation_id, oldMutation); }
  } finally { await a.exec('ROLLBACK'); if (denied) await denied; }
});

const telegram = (db, customer, chat) => db.query('SELECT public.keeptimer_phase5_telegram($1,$2,$3) result', [customer.id, chat, customer.session]);
const pid = async db => (await db.query('SELECT pg_backend_pid() pid')).rows[0].pid;
async function waitForBlock(db, waiter, blockers) {
  const deadline = Date.now()+4000;
  do {
    const blocking = (await db.query('SELECT pg_catalog.pg_blocking_pids($1) pids', [waiter])).rows[0].pids;
    if (blockers.some(p => blocking.includes(p))) return blocking;
    await new Promise(done => setTimeout(done, 15));
  } while (Date.now()<deadline);
  assert.fail('Actual PostgreSQL row lock wait was not observed');
}
for (const second of ['5678', null]) test('Phase 5 PG Telegram: concurrent bind/'+(second === null ? 'unlink' : 'bind')+' completes without 40P01', options, async t => {
  const db = await database(t), a = await connect(t), b = await connect(t), agent = await actor(db);
  const c = await seededCustomer(db, agent, { starts_at:'2000-01-01Z', ends_at:'2100-01-01Z' });
  const gate = await pid(db), first = await pid(a), next = await pid(b);
  await a.exec("SET statement_timeout='8s'"); await b.exec("SET statement_timeout='8s'");
  // Test-only row gate: old RPCs can both acquire user SHARE before waiting
  // here; the revised RPC instead serializes B on A's user UPDATE lock.
  await db.exec('BEGIN');
  await db.query("SELECT code FROM subscription_plans WHERE code='individual' FOR UPDATE");
  const jobs = [];
  try {
    jobs.push(telegram(a,c,'1234').then(result=>({result}),error=>({error})));
    await waitForBlock(db,first,[gate]);
    jobs.push(telegram(b,c,second).then(result=>({result}),error=>({error})));
    await waitForBlock(db,next,[gate,first]);
    await db.exec('COMMIT');
    const results = await Promise.all(jobs);
    for (const result of results) {
      assert.notEqual(result.error?.code,'40P01','concurrent Telegram calls must not deadlock');
      assert.equal(result.error,undefined,result.error?.message);
      assert.equal(result.result.rows[0].result,true);
    }
    assert.equal((await db.query('SELECT telegram_chat_id FROM users WHERE id=$1',[c.id])).rows[0].telegram_chat_id,second);
  } finally { await db.exec('ROLLBACK'); await Promise.all(jobs); }
});

for (const target of ['user', 'session']) test('Phase 5 PG Telegram: '+target+' row wait crosses expiry; bind rolls back and expired unlink allowed', options, async t => {
  const db = await database(t), a = await connect(t), b = await connect(t), agent = await actor(db);
  const c = await seededCustomer(db,agent,{starts_at:'2000-01-01Z',ends_at:new Date(Date.now()+2500).toISOString()});
  const waiter=await pid(b),blocker=await pid(a);
  await telegram(db,c,'1234'); await b.exec("SET statement_timeout='8s'"); await a.exec('BEGIN');
  if (target === 'user') await a.query('SELECT id FROM users WHERE id=$1 FOR UPDATE',[c.id]);
  else await a.query('SELECT id FROM sessions WHERE id=$1 FOR UPDATE',[c.session]);
  let pending;
  try {
    pending=telegram(b,c,'5678').then(result=>({result}),error=>({error}));
    await observeWait(db,waiter,blocker,c.id);
    await a.query("SELECT pg_sleep(GREATEST(0,extract(epoch FROM ($1::timestamptz-clock_timestamp())))+0.05)",[c.subscription.ends_at]);
    await a.exec('ROLLBACK');
    const result=await pending; assert.equal(result.error?.code,'P0001'); assert.equal(result.error?.message,'SUBSCRIPTION_EXPIRED');
    assert.equal((await db.query('SELECT telegram_chat_id FROM users WHERE id=$1',[c.id])).rows[0].telegram_chat_id,'1234');
    assert.equal((await telegram(b,c,null)).rows[0].result,true);
    assert.equal((await db.query('SELECT telegram_chat_id FROM users WHERE id=$1',[c.id])).rows[0].telegram_chat_id,null);
  } finally { await a.exec('ROLLBACK'); if(pending)await pending; }
});

test('Phase 5 PG Telegram: distinct Individual users do not serialize on the user lock', options, async t => {
  const db=await database(t),a=await connect(t),b=await connect(t),agent=await actor(db);
  const period={starts_at:'2000-01-01Z',ends_at:'2100-01-01Z'};
  const one=await seededCustomer(db,agent,period),two=await seededCustomer(db,agent,period);
  await b.exec("SET statement_timeout='2s'"); await a.exec('BEGIN');
  try {
    await telegram(a,one,'1234');
    assert.equal((await telegram(b,two,'5678')).rows[0].result,true,'B completes before A commits');
    await a.exec('COMMIT');
    assert.deepEqual((await db.query('SELECT telegram_chat_id FROM users WHERE id=ANY($1::uuid[]) ORDER BY telegram_chat_id',[[one.id,two.id]])).rows.map(r=>r.telegram_chat_id),['1234','5678']);
  } finally { await a.exec('ROLLBACK'); }
});

test('Phase 5 PG Telegram: foreign/missing/revoked sessions denied; active and company behavior retained', options, async t => {
  const db=await database(t),agent=await actor(db);
  const c=await seededCustomer(db,agent,{starts_at:'2000-01-01Z',ends_at:'2100-01-01Z'});
  for(const session of [null,randomUUID(),agent.session]) {
    await assert.rejects(telegram(db,{...c,session},'1234'),e=>e.code==='P0001'&&e.message==='AUTH_SESSION_INVALID');
  }
  await db.query('UPDATE sessions SET revoked_at=clock_timestamp() WHERE id=$1',[c.session]);
  await assert.rejects(telegram(db,c,'1234'),e=>e.message==='AUTH_SESSION_INVALID');
  assert.equal((await db.query('SELECT telegram_chat_id FROM users WHERE id=$1',[c.id])).rows[0].telegram_chat_id,null);
  await db.query('UPDATE sessions SET revoked_at=NULL WHERE id=$1',[c.session]);
  await telegram(db,c,'1234');await telegram(db,c,null);
  const company={id:await user(db),session:null};
  await telegram(db,company,'5678');await telegram(db,company,null);
  assert.equal((await db.query('SELECT telegram_chat_id FROM users WHERE id=$1',[company.id])).rows[0].telegram_chat_id,null);
});
