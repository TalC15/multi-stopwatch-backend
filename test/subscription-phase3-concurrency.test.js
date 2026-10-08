import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { database,actor,enableIsolatedFixture,command,saleData,connect,localTestUrl,resolve,user,fixtureHash } from './support/subscriptionPhase3.js';
const options={skip:localTestUrl()?false:'Requires guarded isolated disposable PostgreSQL cluster; no live DB fallback'};
async function setup(t) {
  const db=await database(t),a=await connect(t),b=await connect(t);
  await enableIsolatedFixture(db);const agent=await actor(db),sa=await actor(db,'superadmin');
  await a.exec("SET lock_timeout='300ms'");await b.exec("SET lock_timeout='300ms'");
  return {db,a,b,agent,sa};
}
const renewal=id=>({customer_id:id,plan_code:'individual',term_months:1,amount_minor:10000,currency:'TRY'});
const locked=fn=>assert.rejects(fn,e=>e.code==='55P03');

test('Phase 3 PG: simultaneous same-key customer requests serialize and replay once',options,async t=>{
  const {db,a,b,agent}=await setup(t),data=saleData(),key=randomUUID();await a.exec('BEGIN');
  try {
    const first=await command(a,agent,'customer_create',data,key);
    await locked(()=>command(b,agent,'customer_create',data,key));await a.exec('COMMIT');
    assert.deepEqual(await command(b,agent,'customer_create',data,key),first);
    assert.equal((await db.query('SELECT count(*)::int n FROM keeptimer_individual_customers')).rows[0].n,1);
    assert.equal((await db.query('SELECT count(*)::int n FROM admin_audit_log')).rows[0].n,2);
  }catch(e){await a.exec('ROLLBACK');throw e;}
});
test('Phase 3 PG: concurrent renewals cannot allocate duplicate sequence or overlapping pending sales',options,async t=>{
  const {db,a,b,agent}=await setup(t),c=await command(db,agent,'customer_create',saleData()),data=renewal(c.customerId);
  await a.exec('BEGIN');
  try {
    await command(a,agent,'subscription_renew',data);await locked(()=>command(b,agent,'subscription_renew',data));await a.exec('COMMIT');
    await assert.rejects(()=>command(b,agent,'subscription_renew',data),/PENDING_PERIOD_EXISTS/);
    assert.deepEqual((await db.query('SELECT sequence_no FROM subscriptions WHERE user_id=$1 ORDER BY sequence_no',[c.customerId])).rows.map(x=>x.sequence_no),[1,2]);
  }catch(e){await a.exec('ROLLBACK');throw e;}
});
test('Phase 3 PG: revocation first blocks in-flight sales and invalidates old session',options,async t=>{
  const {a,b,agent,sa}=await setup(t);await a.exec('BEGIN');
  try {
    await command(a,sa,'agent_revoke',{agent_id:agent.id});await locked(()=>command(b,agent,'customer_create',saleData()));await a.exec('COMMIT');
    await assert.rejects(()=>command(b,agent,'customer_create',saleData()),/SALES_FORBIDDEN/);
  }catch(e){await a.exec('ROLLBACK');throw e;}
});
test('Phase 3 PG: sale first commits before revocation; no later sale is authorized',options,async t=>{
  const {a,b,agent,sa}=await setup(t);await a.exec('BEGIN');
  try {
    await command(a,agent,'customer_create',saleData());await locked(()=>command(b,sa,'agent_revoke',{agent_id:agent.id}));await a.exec('COMMIT');
    await command(b,sa,'agent_revoke',{agent_id:agent.id});await assert.rejects(()=>command(b,agent,'customer_create',saleData()),/SALES_FORBIDDEN/);
  }catch(e){await a.exec('ROLLBACK');throw e;}
});
test('Phase 3 PG: Phase 2 resolver locks serialize the sale without phantom history',options,async t=>{
  const {db,a,b,agent}=await setup(t),c=await command(db,agent,'customer_create',saleData());await a.exec('BEGIN');
  try {
    await resolve(a,c.customerId);await locked(()=>command(b,agent,'subscription_renew',renewal(c.customerId)));await a.exec('COMMIT');
    assert.equal((await command(b,agent,'subscription_renew',renewal(c.customerId))).subscription.sequenceNo,2);
  }catch(e){await a.exec('ROLLBACK');throw e;}
});
test('Phase 3 PG: catalog disable is observed after waiting; rollback leaves no sale',options,async t=>{
  const {db,a,b,agent}=await setup(t),c=await command(db,agent,'customer_create',saleData());await a.exec('BEGIN');
  try {
    await a.exec("UPDATE subscription_plans SET enabled=false WHERE code='individual'");
    await locked(()=>command(b,agent,'subscription_renew',renewal(c.customerId)));await a.exec('COMMIT');
    await assert.rejects(()=>command(b,agent,'subscription_renew',renewal(c.customerId)),/PLAN_NOT_AVAILABLE/);
    assert.equal((await db.query('SELECT count(*)::int n FROM subscriptions WHERE user_id=$1',[c.customerId])).rows[0].n,1);
  }catch(e){await a.exec('ROLLBACK');throw e;}
});
test('Phase 3 PG: MFA expiring during customer-lock wait cannot authorize a sale',options,async t=>{
  const {db,a,b,agent}=await setup(t),c=await command(db,agent,'customer_create',saleData());
  await b.exec("SET lock_timeout='5s'");await a.exec('BEGIN');
  await a.query('SELECT id FROM users WHERE id=$1 FOR UPDATE',[c.customerId]);
  const expiry=(await db.query("UPDATE keeptimer_privileged_web_sessions SET verified_at=clock_timestamp(),expires_at=clock_timestamp()+interval '500 milliseconds' WHERE session_id=$1 RETURNING expires_at",[agent.session])).rows[0].expires_at;
  const pending=command(b,agent,'subscription_renew',renewal(c.customerId));
  const denied=assert.rejects(()=>pending,/PRIVILEGED_MFA_REQUIRED/);
  try {
    await a.query("SELECT pg_sleep(GREATEST(0,extract(epoch FROM ($1::timestamptz-clock_timestamp())))+0.03)",[expiry]);
    await a.exec('COMMIT');await denied;
    assert.equal((await db.query('SELECT count(*)::int n FROM subscriptions WHERE user_id=$1',[c.customerId])).rows[0].n,1);
  }catch(e){await a.exec('ROLLBACK');await denied;throw e;}
});
test('Phase 3 PG: outsider cannot join a newly provisioned private workspace before or after commit',options,async t=>{
  const {db,a,b,agent}=await setup(t),other=await user(db);await a.exec('BEGIN');
  try {
    const c=await command(a,agent,'customer_create',saleData());
    const workspace=(await a.query('SELECT workspace_id FROM users WHERE id=$1',[c.customerId])).rows[0].workspace_id;
    await assert.rejects(()=>b.query('UPDATE users SET workspace_id=$1 WHERE id=$2',[workspace,other]),/PHASE3_WORKSPACE_NOT_FOUND/);
    await a.exec('COMMIT');
    await assert.rejects(()=>b.query('UPDATE users SET workspace_id=$1 WHERE id=$2',[workspace,other]),/PHASE3_PRIVATE_OWNER_ONLY/);
    assert.equal((await db.query('SELECT count(*)::int n FROM users WHERE workspace_id=$1',[workspace])).rows[0].n,1);
  }catch(e){await a.exec('ROLLBACK');throw e;}
});

async function observedInsertWait(db,waiter,blocker,session,table) {
  const deadline=Date.now()+4000;
  do {
    const row=(await db.query(`SELECT
      EXISTS(SELECT 1 FROM pg_catalog.pg_locks WHERE pid=$1 AND NOT granted
        AND locktype=$4 AND mode=$6 AND ($5::regclass IS NULL OR relation=$5::regclass)) AS waiting,
      $2=ANY(pg_catalog.pg_blocking_pids($1)) AS fixture_blocker,
      (SELECT expires_at>clock_timestamp() FROM public.keeptimer_privileged_web_sessions WHERE session_id=$3) AS mfa_valid`,
      [waiter,blocker,session,table?'relation':'transactionid',table?'public.'+table:null,table?'RowExclusiveLock':'ShareLock'])).rows[0];
    if(row.waiting&&row.fixture_blocker) {
      assert.equal(row.mfa_valid,true,'MFA must still be valid when the actual INSERT wait is observed');
      return;
    }
    await new Promise(done=>setTimeout(done,15));
  }while(Date.now()<deadline);
  assert.fail('Expected INSERT lock wait was not observed; an initial MFA denial cannot pass this test');
}

for(const [stage,table] of [['agent INSERT unique check',null],['audit INSERT','admin_audit_log'],['idempotency INSERT','keeptimer_sales_requests']]) {
  test('Phase 3 PG: MFA expires during '+stage+' wait; agent/audit/request all roll back',options,async t=>{
    const {db,a,b,agent,sa}=await setup(t);
    await db.query('UPDATE users SET disabled_at=clock_timestamp() WHERE id=$1',[agent.id]);
    const data={username:'wait_'+randomUUID().slice(0,8),password_hash:fixtureHash,mfa_email:'fixture@example.invalid'},key=randomUUID();
    const before=(await db.query(`SELECT (SELECT count(*)::int FROM users) users,
      (SELECT count(*)::int FROM admin_audit_log) audit,(SELECT count(*)::int FROM keeptimer_sales_requests) requests`)).rows[0];
    const blocker=(await a.query('SELECT pg_backend_pid() AS pid')).rows[0].pid;
    const waiter=(await b.query('SELECT pg_backend_pid() AS pid')).rows[0].pid;
    await b.exec("SET lock_timeout='8s'");await a.exec('BEGIN');
    let denied;
    try {
      if(table)await a.exec(`LOCK TABLE public.${table} IN SHARE MODE`);
      else await user(a,'worker',{username:data.username}); // Uncommitted unique username; no active agent is visible.
      const expiry=(await db.query("UPDATE keeptimer_privileged_web_sessions SET verified_at=clock_timestamp(),expires_at=clock_timestamp()+interval '2 seconds' WHERE session_id=$1 RETURNING expires_at",[sa.session])).rows[0].expires_at;
      const pending=command(b,sa,'agent_create',data,key);
      denied=assert.rejects(pending,e=>e.code==='P0001'&&e.message==='PRIVILEGED_MFA_REQUIRED');
      denied.catch(()=>{}); // Keep the pending assertion handled while observing the lock.
      await observedInsertWait(db,waiter,blocker,sa.session,table);
      await a.query("SELECT pg_sleep(GREATEST(0,extract(epoch FROM ($1::timestamptz-clock_timestamp())))+0.05)",[expiry]);
      // Rollback releases the unique conflict as well, so the agent INSERT can
      // complete. A uniqueness error must not masquerade as the MFA regression.
      await a.exec('ROLLBACK');await denied;
      assert.deepEqual((await db.query(`SELECT (SELECT count(*)::int FROM users) users,
        (SELECT count(*)::int FROM admin_audit_log) audit,(SELECT count(*)::int FROM keeptimer_sales_requests) requests`)).rows[0],before);
      assert.equal((await db.query('SELECT count(*)::int n FROM users WHERE username=$1',[data.username])).rows[0].n,0);
      assert.equal((await db.query('SELECT count(*)::int n FROM keeptimer_sales_requests WHERE actor_id=$1 AND request_id=$2',[sa.id,key])).rows[0].n,0);
    }finally{await a.exec('ROLLBACK');if(denied)await denied;}
  });
}
