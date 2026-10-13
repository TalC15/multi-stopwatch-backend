import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {database as phase6} from './support/subscriptionPhase6.js';
import {database,connect,localTestUrl,migration,management,cutover,enable,salesActor,privileged,ready,customer,issued,consumeData,command,fixtureHash} from './support/passwordAuth.js';
const options={skip:localTestUrl()?false:'Requires guarded disposable PostgreSQL 18; no PGlite concurrency substitution'};
async function version(t){const db=await connect(t);const n=Number((await db.query('SHOW server_version_num')).rows[0].server_version_num);assert.ok(n>=180000&&n<190000);return db;}
async function setup(t){await version(t);const db=await database(t);await enable(db);const a=await connect(t),b=await connect(t);for(const c of [a,b])await c.exec("SET statement_timeout='8s'");return {db,a,b};}
const pid=async db=>(await db.query('SELECT pg_backend_pid() AS id')).rows[0].id;
async function blocked(db,waiter,blocker){const end=Date.now()+4000;do{if((await db.query('SELECT $2=ANY(pg_blocking_pids($1)) AS yes',[waiter,blocker])).rows[0].yes)return;await new Promise(r=>setTimeout(r,10));}while(Date.now()<end);assert.fail('Expected PostgreSQL lock wait not observed');}
const sale=(db,p,request,action,data)=>db.query('SELECT keeptimer_phase3_command($1,$2,$3,$4,$5,$6) AS r',[p.id,p.session,request,action,'f'.repeat(64),JSON.stringify(data)]);
const capture=p=>p.then(value=>({value}),error=>({error}));

test('PG18 revision: wrong dependency owner rolls all preparation back; right catalog owner and ACL work',options,async t=>{
 await version(t);const db=await phase6(t);const owner=(await db.query('SELECT current_user AS owner')).rows[0].owner;
 await db.exec('SET ROLE service_role');
 try { await assert.rejects(db.exec(migration),/permission denied|PHASE7_TRUSTED_OWNER_REQUIRED/); }
 finally { await db.exec('ROLLBACK');await db.exec('RESET ROLE'); }
 assert.equal((await db.query("SELECT to_regclass('keeptimer_auth_release') AS t")).rows[0].t,null);
 await db.exec('ALTER FUNCTION keeptimer_phase3_require_actor(uuid,uuid,text) OWNER TO anon');
 await assert.rejects(db.exec(migration),/PHASE7_DEPENDENCY_OWNER_MISMATCH/);await db.exec('ROLLBACK');
 assert.equal((await db.query("SELECT to_regclass('keeptimer_auth_release') AS t")).rows[0].t,null);
 await db.exec(`ALTER FUNCTION keeptimer_phase3_require_actor(uuid,uuid,text) OWNER TO "${owner.replaceAll('"','""')}"`);
 await db.exec(migration);await db.exec(management);
 const acl=(await db.query("SELECT has_function_privilege('service_role','keeptimer_auth_command(text,jsonb)','EXECUTE') AS command,has_function_privilege('anon','keeptimer_auth_command(text,jsonb)','EXECUTE') AS anon,has_function_privilege('service_role','keeptimer_auth_recover_privileged(uuid,text,uuid)','EXECUTE') AS recover")).rows[0];
 assert.deepEqual(acl,{command:true,anon:false,recover:false});
 await assert.rejects(db.exec(cutover),/PHASE7_MAINTENANCE_CONFIRMATION_REQUIRED/);await db.exec('ROLLBACK');
 await db.exec("SET keeptimer.phase7_cutover='confirmed-maintenance'");await db.exec(cutover);
 assert.deepEqual((await db.query('SELECT enabled,cutover FROM keeptimer_auth_release')).rows[0],{enabled:false,cutover:true});
 await enable(db);const p=await salesActor(db,'superadmin');
 assert.ok(Array.isArray((await db.query("SELECT keeptimer_auth_management($1,$2,'users','{}') AS r",[p.id,p.session])).rows[0].r.users));
 await db.exec('UPDATE keeptimer_auth_release SET enabled=false');
 assert.equal((await db.query('SELECT revoked_at IS NOT NULL AS ended FROM sessions WHERE id=$1',[p.session])).rows[0].ended,true);
 await assert.rejects(db.query('SELECT keeptimer_auth_session($1,$2)',[p.id,p.session]),/AUTH_NOT_READY/);
});
for(const action of ['agent_create','customer_create'])test(`PG18 revision: ${action} MFA expiry after old RPC, while wrapper INSERT waits, rolls back all writes`,options,async t=>{
 const {db,a,b}=await setup(t),p=await salesActor(db,action==='agent_create'?'superadmin':'agent');await db.exec('UPDATE keeptimer_sales_release SET enabled=true');
 await db.query("UPDATE keeptimer_privileged_web_sessions SET verified_at=clock_timestamp()-interval '1 minute',expires_at=clock_timestamp()+interval '1 second' WHERE session_id=$1",[p.session]);
 const request=randomUUID(),username=action==='agent_create'?'blocked-agent':'blocked-customer';
 const data=action==='agent_create'?{username,password_hash:fixtureHash,mfa_email:'blocked@example.test',email:'blocked@example.test'}:
  {username,password_hash:fixtureHash,plan_code:'individual',term_months:1,amount_minor:10000,currency:'TRY',email:'blocked@example.test'};
 const blocker=await pid(a),waiter=await pid(b);await a.exec('BEGIN');let pending;
 try{
  await a.exec('LOCK TABLE keeptimer_auth_accounts IN SHARE MODE');
  pending=capture(sale(b,p,request,action,data));await blocked(db,waiter,blocker);
  while((await db.query('SELECT expires_at>clock_timestamp() AS active FROM keeptimer_privileged_web_sessions WHERE session_id=$1',[p.session])).rows[0].active)await new Promise(r=>setTimeout(r,15));
  await a.exec('COMMIT');assert.match((await pending).error?.message||'',/PRIVILEGED_MFA_REQUIRED/);
  assert.equal((await db.query('SELECT count(*)::int AS n FROM users WHERE username=$1',[username])).rows[0].n,0);
  assert.equal((await db.query('SELECT count(*)::int AS n FROM keeptimer_sales_requests WHERE request_id=$1',[request])).rows[0].n,0);
  assert.equal((await db.query('SELECT count(*)::int AS n FROM admin_audit_log WHERE actor_user_id=$1',[p.id])).rows[0].n,0);
 }finally{await a.exec('ROLLBACK');if(pending)await pending;}
});
test('PG18 revision: committed session revoke wins against a waiting sale, with no audit/idempotency write',options,async t=>{
 const {db,a,b}=await setup(t),p=await salesActor(db);await db.exec('UPDATE keeptimer_sales_release SET enabled=true');
 const blocker=await pid(a),waiter=await pid(b),request=randomUUID();await a.exec('BEGIN');let pending;
 try{
  await a.query('SELECT id FROM users WHERE id=$1 FOR UPDATE',[p.id]);await a.query('UPDATE sessions SET revoked_at=clock_timestamp() WHERE id=$1',[p.session]);
  pending=capture(sale(b,p,request,'customer_create',{username:'revoked-sale',password_hash:fixtureHash,email:'revoked@example.test',plan_code:'individual',term_months:1,amount_minor:10000,currency:'TRY'}));
  await blocked(db,waiter,blocker);await a.exec('COMMIT');assert.match((await pending).error?.message||'',/SALES_SESSION_INVALID|PRIVILEGED_MFA_REQUIRED/);
  assert.equal((await db.query('SELECT count(*)::int AS n FROM keeptimer_sales_requests WHERE request_id=$1',[request])).rows[0].n,0);
 }finally{await a.exec('ROLLBACK');if(pending)await pending;}
});
test('PG18 revision: management final guard catches MFA expiry during audit lock wait',options,async t=>{
 const {db,a,b}=await setup(t),p=await salesActor(db,'superadmin');
 await db.query("UPDATE keeptimer_privileged_web_sessions SET verified_at=clock_timestamp()-interval '1 minute',expires_at=clock_timestamp()+interval '1 second' WHERE session_id=$1",[p.session]);
 const blocker=await pid(a),waiter=await pid(b);await a.exec('BEGIN');let pending;
 try{
  await a.exec('LOCK TABLE keeptimer_auth_management_audit IN SHARE MODE');
  pending=capture(b.query("SELECT keeptimer_auth_management($1,$2,'user_create',$3)",[p.id,p.session,JSON.stringify({username:'blocked-managed',pin_hash:fixtureHash,role:'worker',workspace_id:null})]));
  await blocked(db,waiter,blocker);
  while((await db.query('SELECT expires_at>clock_timestamp() AS active FROM keeptimer_privileged_web_sessions WHERE session_id=$1',[p.session])).rows[0].active)await new Promise(r=>setTimeout(r,15));
  await a.exec('COMMIT');assert.match((await pending).error?.message||'',/AUTH_FORBIDDEN/);
  assert.equal((await db.query("SELECT count(*)::int AS n FROM users WHERE username='blocked-managed'")).rows[0].n,0);
 }finally{await a.exec('ROLLBACK');if(pending)await pending;}
});
test('PG18 revision: retention skips locked expired challenge while new activation and live counters survive',options,async t=>{
 const {db,a,b}=await setup(t),c=await customer(db),d=await issued(db,c.id);
 await db.query("UPDATE keeptimer_auth_challenges SET created_at=clock_timestamp()-interval '8 days 15 minutes',expires_at=clock_timestamp()-interval '8 days' WHERE id=$1",[d.challenge_id]);
 await a.exec('BEGIN');
 try{
  await a.query('SELECT id FROM keeptimer_auth_challenges WHERE id=$1 FOR UPDATE',[d.challenge_id]);
  assert.equal((await b.query('SELECT keeptimer_auth_maintain() AS r')).rows[0].r.challenges,0);
  await a.exec('COMMIT');assert.equal((await b.query('SELECT keeptimer_auth_maintain() AS r')).rows[0].r.challenges,1);
  const active=await issued(db,c.id);await b.query('SELECT keeptimer_auth_maintain()');assert.equal((await command(db,'consume',consumeData(active))).ok,true);
  for(let i=0;i<10;i++)assert.equal((await b.query("SELECT keeptimer_auth_limit('login',$1,$2) AS ok",['e'.repeat(64),'f'.repeat(64)])).rows[0].ok,true);
  await a.query('SELECT keeptimer_auth_maintain()');assert.equal((await b.query("SELECT keeptimer_auth_limit('login',$1,$2) AS ok",['e'.repeat(64),'f'.repeat(64)])).rows[0].ok,false);
 }finally{await a.exec('ROLLBACK');}
});
test('PG18 revision: recovery operator/target audit, challenge binding, auth and sales release closed',options,async t=>{
 const {db}=await setup(t),p=await privileged(db);await ready(db,p.id);const d=await issued(db,p.id,'mfa'),v=consumeData(d);
 assert.equal((await command(db,'consume',{...v,binding_digest:'e'.repeat(64)})).ok,false);assert.equal((await command(db,'consume',v)).ok,true);
 await assert.rejects(db.query("SELECT keeptimer_phase3_access($1,$2,'superadmin')",[p.id,v.session_id]),/PRIVILEGED_MFA_NOT_READY/);
 const caseId=randomUUID();await db.query("INSERT INTO keeptimer_auth_recovery_cases(id,target_user_id,operator_login,reason,evidence_ref,expires_at) VALUES($1,$2,session_user,'Independent verification completed','case-PG18-fixture',clock_timestamp()+interval '1 hour')",[caseId,p.id]);
 await db.query('SELECT keeptimer_auth_recover_privileged($1,$2,$3)',[p.id,fixtureHash,caseId]);
 const audit=(await db.query('SELECT target_user_id,operator_login=session_user AS operator_ok,executing_owner=current_user AS owner_ok FROM keeptimer_auth_recovery_audit')).rows[0];
 assert.deepEqual(audit,{target_user_id:p.id,operator_ok:true,owner_ok:true});
 await db.exec('UPDATE keeptimer_auth_release SET enabled=false');await assert.rejects(command(db,'lookup',{email:'admin@example.test'}),/AUTH_NOT_READY/);
});
test('PG18 revision: direct logout revocation never waits on a held actor lock and next management is denied',options,async t=>{
 const {db,a,b}=await setup(t),p=await salesActor(db,'superadmin');
 await a.exec('BEGIN');
 try{
  await a.query('SELECT id FROM users WHERE id=$1 FOR UPDATE',[p.id]);
  await b.exec("SET statement_timeout='1s'; SET ROLE service_role");
  await b.query('UPDATE sessions SET revoked_at=clock_timestamp() WHERE id=$1',[p.session]);
  await b.exec('RESET ROLE');
  await assert.rejects(a.query("SELECT keeptimer_auth_management($1,$2,'users','{}')",[p.id,p.session]),/AUTH_FORBIDDEN/);
 }finally{await a.exec('ROLLBACK');await b.exec('RESET ROLE');}
 assert.equal((await db.query('SELECT revoked_at IS NOT NULL AS ended FROM sessions WHERE id=$1',[p.session])).rows[0].ended,true);
});
test('PG18 revision: renewal readiness waits on private workspace past MFA expiry and rolls history back',options,async t=>{
 const {db,a,b}=await setup(t),p=await salesActor(db),c=await customer(db);await ready(db,c.id);
 await db.exec('UPDATE keeptimer_sales_release SET enabled=true');
 await db.query("UPDATE keeptimer_privileged_web_sessions SET verified_at=clock_timestamp()-interval '1 minute',expires_at=clock_timestamp()+interval '1 second' WHERE session_id=$1",[p.session]);
 const before=(await db.query('SELECT (SELECT count(*) FROM subscriptions)::int AS subscriptions,(SELECT count(*) FROM admin_audit_log)::int AS audit')).rows[0];
 const blocker=await pid(a),waiter=await pid(b),request=randomUUID();let pending;await a.exec('BEGIN');
 try{
  // Legacy renewal locks user/subscriptions. Only the added readiness shape
  // acquires this private workspace SHARE row lock after the old RPC returns.
  await a.query('SELECT id FROM workspaces WHERE id=$1 FOR UPDATE',[c.workspace]);
  pending=capture(sale(b,p,request,'subscription_renew',{customer_id:c.id,plan_code:'individual',term_months:1,amount_minor:10000,currency:'TRY'}));
  await blocked(db,waiter,blocker);
  while((await db.query('SELECT expires_at>clock_timestamp() AS active FROM keeptimer_privileged_web_sessions WHERE session_id=$1',[p.session])).rows[0].active)await new Promise(r=>setTimeout(r,15));
  await a.exec('COMMIT');assert.match((await pending).error?.message||'',/PRIVILEGED_MFA_REQUIRED/);
  assert.deepEqual((await db.query('SELECT (SELECT count(*) FROM subscriptions)::int AS subscriptions,(SELECT count(*) FROM admin_audit_log)::int AS audit')).rows[0],before);
  assert.equal((await db.query('SELECT count(*)::int AS n FROM keeptimer_sales_requests WHERE request_id=$1',[request])).rows[0].n,0);
 }finally{await a.exec('ROLLBACK');if(pending)await pending;}
});
for(const kind of ['actor','session'])test(`PG18 revision: committed ${kind} revoke defeats a waiting renewal`,options,async t=>{
 const {db,a,b}=await setup(t),p=await salesActor(db),c=await customer(db);await db.exec('UPDATE keeptimer_sales_release SET enabled=true');
 const blocker=await pid(a),waiter=await pid(b),request=randomUUID();let pending;await a.exec('BEGIN');
 const before=(await db.query('SELECT (SELECT count(*) FROM subscriptions)::int AS subscriptions,(SELECT count(*) FROM admin_audit_log)::int AS audit')).rows[0];
 try{
  await a.query('SELECT id FROM users WHERE id=$1 FOR UPDATE',[p.id]);
  if(kind==='actor')await a.query('UPDATE users SET disabled_at=clock_timestamp() WHERE id=$1',[p.id]);
  else await a.query('UPDATE sessions SET revoked_at=clock_timestamp() WHERE id=$1',[p.session]);
  pending=capture(sale(b,p,request,'subscription_renew',{customer_id:c.id,plan_code:'individual',term_months:1,amount_minor:10000,currency:'TRY'}));
  await blocked(db,waiter,blocker);await a.exec('COMMIT');assert.match((await pending).error?.message||'',/SALES_FORBIDDEN|SALES_SESSION_INVALID|PRIVILEGED_MFA_REQUIRED/);
  assert.deepEqual((await db.query('SELECT (SELECT count(*) FROM subscriptions)::int AS subscriptions,(SELECT count(*) FROM admin_audit_log)::int AS audit')).rows[0],before);
  assert.equal((await db.query('SELECT count(*)::int AS n FROM keeptimer_sales_requests WHERE request_id=$1',[request])).rows[0].n,0);
 }finally{await a.exec('ROLLBACK');if(pending)await pending;}
});
