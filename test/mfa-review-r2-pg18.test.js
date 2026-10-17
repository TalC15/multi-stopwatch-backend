import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {database,privileged,scope,command,start,accept,verify,connect,localTestUrl} from './support/mfaDevice.js';
const options={skip:localTestUrl()?false:'SKIP real guarded PostgreSQL 18 unavailable; PGlite is not concurrency evidence'};
async function setup(t){
 const probe=await connect(t);assert.equal(Math.floor(Number((await probe.query('SHOW server_version_num')).rows[0].server_version_num)/10000),18);
 const db=await database(t),p=await privileged(db),pending=await start(db,p);await accept(db,pending.args);
 const a=await connect(t),b=await connect(t);for(const c of [a,b])await c.exec("SET statement_timeout='5s'");
 return {db,p,a,b,...pending};
}
const pid=async c=>(await c.query('SELECT pg_backend_pid() AS n')).rows[0].n;
async function blocked(db,waiter,blocker){const end=Date.now()+2500;while(Date.now()<end){if((await db.query('SELECT $2=ANY(pg_blocking_pids($1)) AS yes',[waiter,blocker])).rows[0].yes)return;await new Promise(r=>setTimeout(r,10));}assert.fail('expected PostgreSQL wait not observed');}
for(const finish of ['COMMIT','ROLLBACK'])test(`PG18 P2-2 retention precedes release-close; close ${finish}`,options,async t=>{
 const {db,a,b,args}=await setup(t),pa=await pid(a),pb=await pid(b);let closing;
 await a.exec('BEGIN');await b.exec('BEGIN');
 try{
  await a.query('SELECT keeptimer_mfa_maintain()');closing=b.exec('UPDATE keeptimer_auth_release SET enabled=false');
  await blocked(db,pb,pa);await a.exec('COMMIT');await closing;await b.exec(finish);
  if(finish==='ROLLBACK'){assert.equal((await command(db,'status',args)).state.phase,'challenge');assert.equal((await command(db,'verify',verify(args))).ok,true);}
  else{assert.equal((await db.query('SELECT enabled FROM keeptimer_auth_release')).rows[0].enabled,false);await assert.rejects(command(db,'verify',verify(args)),/AUTH_NOT_READY/);}
 }finally{await a.exec('ROLLBACK');await b.exec('ROLLBACK');if(closing)await closing.catch(()=>{});}
});
test('PG18 P2-2 release-close rollback releases waiting maintenance without losing live OTP',options,async t=>{
 const {db,a,b,args}=await setup(t),pa=await pid(a),pb=await pid(b);let cleaning;await a.exec('BEGIN');
 try{await a.exec('UPDATE keeptimer_auth_release SET enabled=false');cleaning=b.query('SELECT keeptimer_mfa_maintain()');await blocked(db,pb,pa);await a.exec('ROLLBACK');await cleaning;assert.equal((await command(db,'verify',verify(args))).ok,true);}
 finally{await a.exec('ROLLBACK');if(cleaning)await cleaning.catch(()=>{});}
});
for(const table of ['keeptimer_mfa_sends','keeptimer_mfa_verifications'])test(`PG18 P2-2/P3 skipped ${table} is never waited on via cascade`,options,async t=>{
 const {db,a,b,args}=await setup(t);
 await db.query("INSERT INTO keeptimer_mfa_verifications(id,context_id,challenge_id,proof_digest,result) VALUES($1,$2,$3,$4,'{}')",[randomUUID(),args.context_id,args.new_challenge_id,'a'.repeat(64)]);
 await db.exec("UPDATE keeptimer_mfa_challenges SET expires_at=clock_timestamp()-interval '8 days';UPDATE keeptimer_mfa_contexts SET updated_at=clock_timestamp()-interval '31 days'");
 await a.exec('BEGIN');try{
  await a.query(`SELECT id FROM ${table} FOR UPDATE`);await b.exec("SET statement_timeout='700ms'");
  const r=(await b.query('SELECT keeptimer_mfa_maintain() AS r')).rows[0].r;assert.equal(r.challenges,0);assert.equal(r.contexts,0);
  assert.equal((await db.query(`SELECT count(*)::int AS n FROM ${table}`)).rows[0].n,1);
  await a.exec('COMMIT');const cleaned=(await b.query('SELECT keeptimer_mfa_maintain() AS r')).rows[0].r;assert.equal(cleaned.challenges,1);assert.equal(cleaned.contexts,1);
 }finally{await a.exec('ROLLBACK');}
});
for(const finish of ['COMMIT','ROLLBACK'])test(`PG18 P2-1 revoke-all precedes waiting OTP; revoke ${finish}`,options,async t=>{
 const {db,p,a,b,args}=await setup(t),issued=verify(args);await command(db,'verify',issued);
 const pending=await start(db,p,scope('b'));await accept(db,pending.args);const pa=await pid(a),pb=await pid(b);let checking;
 await a.exec('BEGIN');try{
  await a.query("SELECT keeptimer_auth_command('revoke_sessions',$1)",[JSON.stringify({user_id:p.id,session_id:issued.session_id,transport:'web'})]);
  checking=command(b,'verify',verify(pending.args));await blocked(db,pb,pa);await a.exec(finish);
  assert.equal((await checking).ok,finish==='ROLLBACK');
  if(finish==='COMMIT')assert.equal((await db.query('SELECT count(*)::int AS n FROM sessions WHERE revoked_at IS NULL')).rows[0].n,0);
 }finally{await a.exec('ROLLBACK');if(checking)await checking.catch(()=>{});}
});
test('PG18 P2-1 OTP wins first; following revoke-all also revokes the newly created session',options,async t=>{
 const {db,p,a,b,args}=await setup(t),issued=verify(args);await command(db,'verify',issued);
 const pending=await start(db,p,scope('b'));await accept(db,pending.args);const pa=await pid(a),pb=await pid(b);let revoking;
 await a.exec('BEGIN');try{
  assert.equal((await command(a,'verify',verify(pending.args))).ok,true);
  revoking=b.query("SELECT keeptimer_auth_command('revoke_sessions',$1)",[JSON.stringify({user_id:p.id,session_id:issued.session_id,transport:'web'})]);
  await blocked(db,pb,pa);await a.exec('COMMIT');await revoking;
  assert.equal((await db.query('SELECT count(*)::int AS n FROM sessions WHERE revoked_at IS NULL')).rows[0].n,0);
 }finally{await a.exec('ROLLBACK');if(revoking)await revoking.catch(()=>{});}
});
