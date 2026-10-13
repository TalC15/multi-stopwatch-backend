import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {database,connect,localTestUrl,customer,privileged,enable,ready,command,issued,consumeData,fixtureHash} from './support/passwordAuth.js';
const options={skip:localTestUrl()?false:'Requires guarded disposable PostgreSQL 18; PGlite is not concurrency evidence'};
const pid=async db=>(await db.query('SELECT pg_backend_pid() AS pid')).rows[0].pid;
async function wait(db,waiter,blocker){
 const end=Date.now()+4000;
 do {if((await db.query('SELECT $2=ANY(pg_blocking_pids($1)) AS blocked',[waiter,blocker])).rows[0].blocked)return;
  await new Promise(resolve=>setTimeout(resolve,15));}while(Date.now()<end);
 assert.fail('Real PostgreSQL lock wait not observed');
}
async function setup(t){
 // Version check is read-only and BEFORE the guarded schema-reset helper.
 const verify=await connect(t),version=Number((await verify.query('SHOW server_version_num')).rows[0].server_version_num);
 assert.ok(version>=180000 && version<190000,'This Phase7 concurrency suite requires PostgreSQL 18');
 const db=await database(t);await enable(db);const a=await connect(t),b=await connect(t);
 await a.exec("SET statement_timeout='8s'");await b.exec("SET statement_timeout='8s'");return {db,a,b};
}
for(const purpose of ['activation','reset','mfa'])test('Phase7 PG18: '+purpose+' has exactly one concurrent consumer',options,async t=>{
 const {db,a,b}=await setup(t),target=purpose==='mfa'?await privileged(db):await customer(db);
 if(purpose!=='activation')await ready(db,target.id);
 const d=await issued(db,target.id,purpose),payload=consumeData(d);let pending;
 const blocker=await pid(a),waiter=await pid(b);await a.exec('BEGIN');
 try{
  assert.equal((await command(a,'consume',payload)).ok,true);
  pending=command(b,'consume',{...payload,session_id:randomUUID()}).then(result=>({result}),error=>({error}));
  await wait(db,waiter,blocker);await a.exec('COMMIT');assert.equal((await pending).result?.ok,false);
  assert.equal((await db.query('SELECT count(*)::int AS n FROM sessions WHERE user_id=$1',[target.id])).rows[0].n,purpose==='mfa'?1:0);
 }finally{await a.exec('ROLLBACK');if(pending)await pending;}
});
test('Phase7 PG18: revoking all sessions while MFA waits invalidates its challenge',options,async t=>{
 const {db,a,b}=await setup(t),p=await privileged(db);await ready(db,p.id);
 const d=await issued(db,p.id,'mfa'),v=consumeData(d);await command(db,'consume',v);
 await db.query("UPDATE keeptimer_auth_challenges SET last_sent_at=clock_timestamp()-interval '61 seconds' WHERE id=$1",[d.challenge_id]);
 const next=await issued(db,p.id,'mfa');let pending;
 const blocker=await pid(a),waiter=await pid(b);await a.exec('BEGIN');
 try{
  assert.equal((await command(a,'revoke_sessions',{user_id:p.id,session_id:v.session_id,transport:'web'})).ok,true);
  pending=command(b,'consume',consumeData(next)).then(result=>({result}),error=>({error}));
  await wait(db,waiter,blocker);await a.exec('COMMIT');assert.equal((await pending).result?.ok,false);
  assert.equal((await db.query('SELECT count(*)::int AS n FROM sessions WHERE user_id=$1 AND revoked_at IS NULL',[p.id])).rows[0].n,0);
 }finally{await a.exec('ROLLBACK');if(pending)await pending;}
});
test('Phase7 PG18: Agent deactivation blocks waiting MFA and management/session validation',options,async t=>{
 const {db,a,b}=await setup(t),p=await privileged(db,'agent@example.test','agent');await ready(db,p.id);
 const d=await issued(db,p.id,'mfa');let pending;
 const blocker=await pid(a),waiter=await pid(b);await a.exec('BEGIN');
 try{
  await a.query('UPDATE users SET disabled_at=clock_timestamp() WHERE id=$1',[p.id]);
  pending=command(b,'consume',consumeData(d)).then(result=>({result}),error=>({error}));
  await wait(db,waiter,blocker);await a.exec('COMMIT');assert.equal((await pending).result?.ok,false);
  assert.equal((await db.query('SELECT count(*)::int AS n FROM sessions WHERE user_id=$1',[p.id])).rows[0].n,0);
 }finally{await a.exec('ROLLBACK');if(pending)await pending;}
});
test('Phase7 PG18: credential change while privileged refresh waits rejects old session',options,async t=>{
 const {db,a,b}=await setup(t),p=await privileged(db);await ready(db,p.id);
 const d=await issued(db,p.id,'mfa'),v=consumeData(d);await command(db,'consume',v);let pending;
 const blocker=await pid(a),waiter=await pid(b);await a.exec('BEGIN');
 try{
  assert.equal((await command(a,'change',{user_id:p.id,session_id:v.session_id,transport:'web',expected_hash:fixtureHash,password_hash:fixtureHash})).ok,true);
  pending=b.query('SELECT keeptimer_auth_session($1,$2,$3,$4) AS ok',[p.id,v.session_id,'web',v.refresh_hash]).then(result=>({result}),error=>({error}));
  await wait(db,waiter,blocker);await a.exec('COMMIT');assert.equal((await pending).result?.rows[0].ok,false);
 }finally{await a.exec('ROLLBACK');if(pending)await pending;}
});
test('Phase7 PG18: Individual credential update while activation waits invalidates old version',options,async t=>{
 const {db,a,b}=await setup(t),c=await customer(db),d=await issued(db,c.id);let pending;
 const blocker=await pid(a),waiter=await pid(b);await a.exec('BEGIN');
 try{
  await a.query('SELECT id FROM users WHERE id=$1 FOR UPDATE',[c.id]);
  await a.query('UPDATE keeptimer_auth_accounts SET version=version+1 WHERE user_id=$1',[c.id]);
  pending=command(b,'consume',consumeData(d)).then(result=>({result}),error=>({error}));
  await wait(db,waiter,blocker);await a.exec('COMMIT');assert.equal((await pending).result?.ok,false);
  assert.equal((await db.query('SELECT workspace_id FROM users WHERE id=$1',[c.id])).rows[0].workspace_id,c.workspace);
  assert.equal((await db.query('SELECT activated_at FROM keeptimer_auth_accounts WHERE user_id=$1',[c.id])).rows[0].activated_at,null);
 }finally{await a.exec('ROLLBACK');if(pending)await pending;}
});

test('Phase7 PG18: Agent revocation while management list waits denies the transaction',options,async t=>{
 const {db,a,b}=await setup(t),p=await privileged(db,'agent@example.test','agent');await ready(db,p.id);
 const d=await issued(db,p.id,'mfa'),v=consumeData(d);await command(db,'consume',v);
 await db.exec('UPDATE keeptimer_sales_release SET enabled=true');let pending;
 const blocker=await pid(a),waiter=await pid(b);await a.exec('BEGIN');
 try{
  await a.query('UPDATE users SET disabled_at=clock_timestamp() WHERE id=$1',[p.id]);
  pending=b.query("SELECT keeptimer_phase3_list($1,$2,'customers',NULL,NULL,25)",[p.id,v.session_id]).then(result=>({result}),error=>({error}));
  await wait(db,waiter,blocker);await a.exec('COMMIT');assert.equal((await pending).error?.message,'SALES_FORBIDDEN');
 }finally{await a.exec('ROLLBACK');if(pending)await pending;}
});
