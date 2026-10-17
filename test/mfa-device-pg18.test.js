import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {database,privileged,command,start,accept,verify,connect,localTestUrl} from './support/mfaDevice.js';
const options={skip:localTestUrl()?false:'SKIP: guarded disposable real PostgreSQL 18 unavailable; no PGlite concurrency substitution'};
async function setup(t){
 const probe=await connect(t);const version=Number((await probe.query('SHOW server_version_num')).rows[0].server_version_num);assert.ok(version>=180000&&version<190000);
 const db=await database(t),p=await privileged(db),started=await start(db,p);await accept(db,started.args);
 const a=await connect(t),b=await connect(t);for(const c of [a,b])await c.exec("SET statement_timeout='6s'");
 return {db,a,b,...started};
}
const pid=async c=>(await c.query('SELECT pg_backend_pid() AS pid')).rows[0].pid;
async function blocked(db,waiter,blocker){
 const end=Date.now()+3000;
 while(Date.now()<end){if((await db.query('SELECT $2=ANY(pg_blocking_pids($1)) AS yes',[waiter,blocker])).rows[0].yes)return;await new Promise(r=>setTimeout(r,10));}
 assert.fail('real PostgreSQL lock wait was not observed');
}
test('PG18 MFA: simultaneous correct OTP consumption creates exactly one session',options,async t=>{
 const {db,a,b,args}=await setup(t);const r=await Promise.all([command(a,'verify',verify(args)),command(b,'verify',verify(args))]);
 assert.equal(r.filter(x=>x.ok).length,1);assert.equal((await db.query('SELECT count(*)::int AS n FROM sessions')).rows[0].n,1);
});
for(const sameOperation of [false,true])test(`PG18 MFA: concurrent resend extends only once (same operation=${sameOperation})`,options,async t=>{
 const {db,a,b,args}=await setup(t);
 await db.exec("UPDATE keeptimer_mfa_sends SET created_at=clock_timestamp()-interval '61 seconds';UPDATE keeptimer_mfa_challenges SET expires_at=clock_timestamp()+interval '40 seconds'");
 const old=(await db.query('SELECT expires_at FROM keeptimer_mfa_challenges')).rows[0].expires_at;
 const request={...args,challenge_id:args.new_challenge_id,operation_id:randomUUID(),proof_digest:'e'.repeat(64)};
 const result=await Promise.all([command(a,'resend',request),command(b,'resend',{...request,operation_id:sameOperation?request.operation_id:randomUUID()})]);
 assert.equal(result.filter(x=>x.ok).length,sameOperation?2:1);
 assert.equal((await db.query('SELECT extract(epoch FROM expires_at-$1::timestamptz)::int AS delta FROM keeptimer_mfa_challenges',[old])).rows[0].delta,30);
 assert.equal((await db.query('SELECT count(*)::int AS n FROM keeptimer_mfa_sends')).rows[0].n,2);
});
for(const table of ['keeptimer_mfa_contexts','keeptimer_mfa_challenges','keeptimer_mfa_sends'])test(`PG18 MFA: expiry during observed ${table} lock wait denies verification`,options,async t=>{
 const {db,a,b,args}=await setup(t);await db.exec("UPDATE keeptimer_mfa_challenges SET expires_at=clock_timestamp()+interval '1 second'");
 const blocker=await pid(a),waiter=await pid(b);await a.exec('BEGIN');let work;
 try{
  await a.query(`SELECT id FROM ${table} FOR UPDATE`);
  work=command(b,'verify',verify(args));await blocked(db,waiter,blocker);
  while((await db.query('SELECT expires_at>clock_timestamp() AS valid FROM keeptimer_mfa_challenges')).rows[0].valid)await new Promise(r=>setTimeout(r,15));
  await a.exec('COMMIT');assert.equal((await work).code,'MFA_CODE_EXPIRED');
  assert.equal((await db.query('SELECT count(*)::int AS n FROM sessions')).rows[0].n,0);
 }finally{await a.exec('ROLLBACK');if(work)await work;}
});
test('PG18 MFA: expired resend waiting on challenge cannot revive old OTP',options,async t=>{
 const {db,a,b,args}=await setup(t);await db.exec("UPDATE keeptimer_mfa_sends SET created_at=clock_timestamp()-interval '61 seconds';UPDATE keeptimer_mfa_challenges SET expires_at=clock_timestamp()+interval '1 second'");
 const blocker=await pid(a),waiter=await pid(b);await a.exec('BEGIN');let work;
 try{
  await a.query('SELECT id FROM keeptimer_mfa_challenges FOR UPDATE');
  work=command(b,'resend',{...args,challenge_id:args.new_challenge_id,operation_id:randomUUID(),proof_digest:'e'.repeat(64)});await blocked(db,waiter,blocker);
  while((await db.query('SELECT expires_at>clock_timestamp() AS valid FROM keeptimer_mfa_challenges')).rows[0].valid)await new Promise(r=>setTimeout(r,15));
  await a.exec('COMMIT');assert.equal((await work).code,'MFA_CODE_EXPIRED');
  assert.equal((await db.query('SELECT count(*)::int AS n FROM keeptimer_mfa_sends')).rows[0].n,1);
 }finally{await a.exec('ROLLBACK');if(work)await work;}
});
test('PG18 MFA: retention skips an in-flight context without waiting or consuming a live challenge',options,async t=>{
 const {db,a,b}=await setup(t);await a.exec('BEGIN');
 try{
  await a.query('SELECT id FROM keeptimer_mfa_contexts FOR UPDATE');
  await b.exec("SET statement_timeout='500ms'");await b.query('SELECT keeptimer_mfa_maintain()');
  assert.equal((await db.query('SELECT consumed_at FROM keeptimer_mfa_challenges')).rows[0].consumed_at,null);
 }finally{await a.exec('ROLLBACK');}
});
test('PG18 MFA: duplicate wrong-code POST consumes one attempt under concurrency',options,async t=>{
 const {db,a,b,args}=await setup(t),v=verify(args,{proof_digest:'0'.repeat(64)});
 const r=await Promise.all([command(a,'verify',v),command(b,'verify',v)]);assert.ok(r.every(x=>x.code==='MFA_INVALID_CODE'));
 assert.equal((await db.query('SELECT attempts FROM keeptimer_mfa_contexts')).rows[0].attempts,1);
});
