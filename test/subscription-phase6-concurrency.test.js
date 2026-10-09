import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { database, connect, localTestUrl, actor, seededCustomer, resolve, put,
  command, enableIsolatedFixture, renewal, cancel } from './support/subscriptionPhase6.js';
const options={skip:localTestUrl()?false:'Requires guarded disposable real PostgreSQL; PGlite is not concurrency evidence'};
const pid=async db=>(await db.query('SELECT pg_backend_pid() pid')).rows[0].pid;
async function wait(db,waiter,blocker) {
  const deadline=Date.now()+4000;
  do {
    if((await db.query('SELECT $2=ANY(pg_blocking_pids($1)) blocked',[waiter,blocker])).rows[0].blocked)return;
    await new Promise(done=>setTimeout(done,15));
  }while(Date.now()<deadline);
  assert.fail('Actual PostgreSQL lock wait not observed');
}
async function setup(t) {
  const db=await database(t),a=await connect(t),b=await connect(t),agent=await actor(db);
  await enableIsolatedFixture(db);await b.exec("SET statement_timeout='8s'");
  const customer=await seededCustomer(db,agent,{starts_at:'2000-01-01Z',ends_at:'2100-01-01Z'});
  return {db,a,b,agent,customer};
}
for(const sameKey of [false,true])test('Phase 6 PG: overlapping renewal requests '+(sameKey?'replay same key':'reject second pending'),options,async t=>{
  const {db,a,b,agent,customer:c}=await setup(t),key=randomUUID();let pending;
  const blocker=await pid(a),waiter=await pid(b);await a.exec('BEGIN');
  try {
    const first=await command(a,agent,'subscription_renew',renewal(c.id),key);
    pending=command(b,agent,'subscription_renew',renewal(c.id),sameKey?key:randomUUID()).then(result=>({result}),error=>({error}));
    await wait(db,waiter,blocker);await a.exec('COMMIT');const second=await pending;
    if(sameKey)assert.deepEqual(second.result,first);else assert.equal(second.error?.message,'PENDING_PERIOD_EXISTS');
    assert.equal((await db.query('SELECT count(*)::int n FROM subscriptions WHERE user_id=$1',[c.id])).rows[0].n,2);
  }finally{await a.exec('ROLLBACK');if(pending)await pending;}
});
for(const firstAction of ['renew','cancel'])test('Phase 6 PG: '+firstAction+' first in active cancellation/renewal race preserves selected period',options,async t=>{
  const {db,a,b,agent,customer:c}=await setup(t);let pending;
  const blocker=await pid(a),waiter=await pid(b);await a.exec('BEGIN');
  const run=(conn,action)=>command(conn,agent,action==='renew'?'subscription_renew':'subscription_cancel',action==='renew'?renewal(c.id):cancel(c.id,c.subscription.id));
  try {
    await run(a,firstAction);pending=run(b,firstAction==='renew'?'cancel':'renew').then(result=>({result}),error=>({error}));
    await wait(db,waiter,blocker);await a.exec('COMMIT');const result=await pending;assert.equal(result.error,undefined,result.error?.message);
    const rows=(await db.query('SELECT id,cancelled_at FROM subscriptions WHERE user_id=$1 ORDER BY sequence_no',[c.id])).rows;
    assert.equal(rows.length,2);assert.equal(rows[0].id,c.subscription.id);assert.ok(rows[0].cancelled_at);assert.equal(rows[1].cancelled_at,null);
    assert.equal((await resolve(db,c.id)).status,firstAction==='renew'?'pending':'active');
  }finally{await a.exec('ROLLBACK');if(pending)await pending;}
});
for(const revoked of ['subscription','session'])test('Phase 6 PG: '+revoked+' revoked before blocked outbox write is rechecked',options,async t=>{
  const {db,a,b,agent,customer:c}=await setup(t),timer=randomUUID(),mutation=randomUUID();let pending;
  const blocker=await pid(a),waiter=await pid(b);await a.exec('BEGIN');
  try {
    if(revoked==='subscription')await command(a,agent,'subscription_cancel',cancel(c.id,c.subscription.id));
    else await a.query('UPDATE sessions SET revoked_at=clock_timestamp() WHERE id=$1',[c.session]);
    pending=put(b,c.id,timer,mutation).then(result=>({result}),error=>({error}));
    await wait(db,waiter,blocker);await a.exec('COMMIT');const result=await pending;
    assert.equal(result.error?.message,revoked==='subscription'?'SUBSCRIPTION_CANCELLED':'AUTH_SESSION_INVALID');
    assert.equal((await db.query('SELECT id FROM timers WHERE id=$1',[timer])).rows.length,0);
    assert.equal((await db.query('SELECT workspace_id FROM users WHERE id=$1',[c.id])).rows[0].workspace_id,c.workspace);
  }finally{await a.exec('ROLLBACK');if(pending)await pending;}
});
test('Phase 6 PG: revoking agent while sale waits cannot produce another sale',options,async t=>{
  const {db,a,b,agent,customer:c}=await setup(t),sa=await actor(db,'superadmin');let pending;
  const blocker=await pid(a),waiter=await pid(b);await a.exec('BEGIN');
  try {
    await command(a,sa,'agent_revoke',{agent_id:agent.id});
    pending=command(b,agent,'subscription_renew',renewal(c.id)).then(result=>({result}),error=>({error}));
    await wait(db,waiter,blocker);await a.exec('COMMIT');assert.equal((await pending).error?.message,'SALES_FORBIDDEN');
    assert.equal((await db.query('SELECT count(*)::int n FROM subscriptions WHERE user_id=$1',[c.id])).rows[0].n,1);
  }finally{await a.exec('ROLLBACK');if(pending)await pending;}
});

for(const boundary of ['start','end'])test('Phase 6 PG: resolver crosses '+boundary+' during a real lock wait and reports fresh DB observation',options,async t=>{
  const db=await database(t),a=await connect(t),b=await connect(t),agent=await actor(db);
  const instant=(await db.query("SELECT (clock_timestamp()+interval '2.5 seconds')::text n")).rows[0].n;
  const c=await seededCustomer(db,agent,boundary==='start'?{starts_at:instant,ends_at:'2100-01-01Z'}:{starts_at:'2000-01-01Z',ends_at:instant});
  const blocker=await pid(a),waiter=await pid(b);await b.exec("SET statement_timeout='8s'");await a.exec('BEGIN');let pending;
  try {
    await a.query('SELECT id FROM users WHERE id=$1 FOR UPDATE',[c.id]);
    pending=resolve(b,c.id).then(result=>({result}),error=>({error}));await wait(db,waiter,blocker);
    assert.equal((await db.query('SELECT clock_timestamp()<$1::timestamptz before',[instant])).rows[0].before,true);
    await a.query('SELECT pg_sleep(GREATEST(0,extract(epoch FROM ($1::timestamptz-clock_timestamp())))+0.02)',[instant]);
    await a.exec('COMMIT');const {result,error}=await pending;assert.equal(error,undefined,error?.message);
    assert.equal(result.status,boundary==='start'?'active':'expired');assert.equal(result.isEntitled,boundary==='start');
    assert.equal((await db.query('SELECT $1::timestamptz>=$2::timestamptz fresh',[result.evaluatedAt,instant])).rows[0].fresh,true);
  }finally{await a.exec('ROLLBACK');if(pending)await pending;}
});
