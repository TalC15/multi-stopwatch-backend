import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {database as phase6,user,asRole} from './support/subscriptionPhase6.js';
import {database,migration,management,cutover,enable,privileged,customer,ready,salesActor,command,issued,consumeData,fixtureHash,rpcAdapter} from './support/passwordAuth.js';
import {createPasswordAuth} from '../src/passwordAuth.js';
const owner=async db=>(await db.query('SELECT current_user AS name')).rows[0].name;
const admin=(db,p,action,data={})=>db.query('SELECT keeptimer_auth_management($1,$2,$3,$4) AS result',[p.id,p.session,action,JSON.stringify(data)]).then(r=>r.rows[0].result);

test('preparation preserves old PIN admin sessions/functions; cutover is explicit and gates stay closed',async t=>{
 const db=await phase6(t),id=await user(db,'superadmin'),session=randomUUID();
 await db.query('INSERT INTO sessions(id,user_id,refresh_token_hash) VALUES($1,$2,$3)',[session,id,'old-pin-session']);
 const before=(await db.query("SELECT oid,proowner,proacl::text,pg_get_functiondef(oid) AS definition FROM pg_proc WHERE oid='keeptimer_phase3_command(uuid,uuid,uuid,text,text,jsonb)'::regprocedure")).rows[0];
 await db.exec(migration);await db.exec(management);
 assert.deepEqual((await db.query("SELECT oid,proowner,proacl::text,pg_get_functiondef(oid) AS definition FROM pg_proc WHERE oid='keeptimer_phase3_command(uuid,uuid,uuid,text,text,jsonb)'::regprocedure")).rows[0],before);
 assert.equal((await db.query('SELECT revoked_at FROM sessions WHERE id=$1',[session])).rows[0].revoked_at,null);
 await asRole(db,'service_role',()=>db.query('INSERT INTO sessions(id,user_id,refresh_token_hash) VALUES($1,$2,$3)',[randomUUID(),id,'legacy-preparation-only']));
 await assert.rejects(db.exec(cutover),/PHASE7_MAINTENANCE_CONFIRMATION_REQUIRED/);await db.exec('ROLLBACK');
 await assert.rejects(db.exec('UPDATE keeptimer_auth_release SET enabled=true'),/check constraint/);
 await db.exec("SET keeptimer.phase7_cutover='confirmed-maintenance'");await db.exec(cutover);
 assert.equal((await db.query('SELECT revoked_at IS NOT NULL AS ended FROM sessions WHERE id=$1',[session])).rows[0].ended,true);
 assert.deepEqual((await db.query('SELECT enabled,cutover FROM keeptimer_auth_release')).rows[0],{enabled:false,cutover:true});
 assert.equal((await db.query('SELECT enabled FROM keeptimer_sales_release')).rows[0].enabled,false);
 await assert.rejects(asRole(db,'service_role',()=>db.query('INSERT INTO sessions(id,user_id,refresh_token_hash) VALUES($1,$2,$3)',[randomUUID(),id,'old-backend-after-cutover'])),/AUTH_FORBIDDEN/);
});
test('catalog owner mismatch rolls preparation completely back; matching owner and private ACL succeed',async t=>{
 const db=await phase6(t),own=await owner(db);
 await db.exec('SET ROLE service_role');
 try { await assert.rejects(db.exec(migration),/permission denied|PHASE7_TRUSTED_OWNER_REQUIRED/); }
 finally { await db.exec('ROLLBACK');await db.exec('RESET ROLE'); }
 assert.equal((await db.query("SELECT to_regclass('keeptimer_auth_release') AS table")).rows[0].table,null);
 await db.exec('ALTER FUNCTION keeptimer_phase3_require_actor(uuid,uuid,text) OWNER TO anon');
 await assert.rejects(db.exec(migration),/PHASE7_DEPENDENCY_OWNER_MISMATCH/);await db.exec('ROLLBACK');
 assert.equal((await db.query("SELECT to_regclass('keeptimer_auth_release') AS table, to_regprocedure('keeptimer_auth_assert_owner()') AS helper")).rows[0].table,null);
 assert.equal((await db.query("SELECT to_regprocedure('keeptimer_auth_assert_owner()') AS helper")).rows[0].helper,null);
 await db.exec(`ALTER FUNCTION keeptimer_phase3_require_actor(uuid,uuid,text) OWNER TO "${own.replaceAll('"','""')}"`);
 await db.exec(migration);await db.exec(management);
 const functions=(await db.query("SELECT proname,prosecdef,proconfig,proowner=(SELECT oid FROM pg_roles WHERE rolname=current_user) AS owner_ok FROM pg_proc WHERE proname LIKE 'keeptimer_auth_%'")).rows;
 for(const f of functions){assert.equal(f.owner_ok,true);assert.ok(f.proconfig.includes('search_path=""'));if(f.proname!=='keeptimer_auth_assert_owner')assert.equal(f.prosecdef,true);}
 for(const role of ['anon','authenticated','service_role'])for(const table of ['keeptimer_auth_accounts','keeptimer_auth_link_queue','keeptimer_auth_recovery_cases','keeptimer_auth_recovery_audit','keeptimer_auth_management_audit']){
  await assert.rejects(asRole(db,role,()=>db.query(`SELECT * FROM ${table}`)),/permission denied/);
 }
 for(const role of ['anon','authenticated'])for(const fn of ["keeptimer_auth_management(NULL,NULL,'users','{}')","keeptimer_auth_maintain()","keeptimer_auth_link_queue_rpc('claim','{}')"]){
  await assert.rejects(asRole(db,role,()=>db.query('SELECT '+fn)),/permission denied/);
 }
});
test('recovery audit has DB operator/owner, target and verified case; no counterfeit user actor or replay',async t=>{
 const db=await database(t),p=await privileged(db);await ready(db,p.id);
 const id=randomUUID();
 await db.query("INSERT INTO keeptimer_auth_recovery_cases(id,target_user_id,operator_login,reason,evidence_ref,expires_at) VALUES($1,$2,session_user,'Independently verified identity','case-reference-001',clock_timestamp()+interval '1 hour')",[id,p.id]);
 await assert.rejects(db.query('SELECT keeptimer_auth_recover_privileged($1,$2,$3)',[p.id,fixtureHash,randomUUID()]),/AUTH_FORBIDDEN/);
 await db.query('SELECT keeptimer_auth_recover_privileged($1,$2,$3)',[p.id,fixtureHash,id]);
 const row=(await db.query('SELECT * FROM keeptimer_auth_recovery_audit')).rows[0];
 assert.equal(row.operator_login,await owner(db));assert.equal(row.executing_owner,await owner(db));assert.equal(row.target_user_id,p.id);assert.equal(row.case_id,id);
 assert.ok(!JSON.stringify(row).includes(fixtureHash));
 assert.equal((await db.query("SELECT count(*)::int AS n FROM admin_audit_log WHERE action='password_reset'")).rows[0].n,0);
 await assert.rejects(db.query('SELECT keeptimer_auth_recover_privileged($1,$2,$3)',[p.id,fixtureHash,id]),/AUTH_FORBIDDEN/);
 await assert.rejects(asRole(db,'service_role',()=>db.exec('DELETE FROM keeptimer_auth_recovery_audit')),/permission denied/);
});
test('bounded indexed retention preserves active budgets and challenges, including recently used/failed',async t=>{
 const db=await database(t),c=await customer(db);await enable(db);const d=await issued(db,c.id);
 await db.exec("INSERT INTO keeptimer_auth_limits SELECT lpad(to_hex(n),64,'0'),clock_timestamp()-interval '25 hours',1 FROM generate_series(1,100) n");
 await db.query('SELECT keeptimer_auth_limit($1,$2,$3)',['login','a'.repeat(64),'b'.repeat(64)]);
 const clean=(await db.query('SELECT keeptimer_auth_maintain() AS r')).rows[0].r;
 assert.equal(clean.limits,64);assert.equal(clean.challenges,0);
 assert.equal((await db.query("SELECT count FROM keeptimer_auth_limits WHERE key=$1",['a'.repeat(64)])).rows[0].count,1);
 await db.query("UPDATE keeptimer_auth_challenges SET created_at=clock_timestamp()-interval '8 days 15 minutes',expires_at=clock_timestamp()-interval '8 days',consumed_at=clock_timestamp()-interval '8 days' WHERE id=$1",[d.challenge_id]);
 assert.equal((await db.query('SELECT keeptimer_auth_maintain() AS r')).rows[0].r.challenges,1);
 assert.equal((await db.query('SELECT count(*)::int AS n FROM keeptimer_auth_challenges')).rows[0].n,0);
});
test('queue accepts unknown/pending/ready/disabled equally, is capacity bounded, and only worker looks up eligibility',async t=>{
 const db=await database(t),c=await customer(db),p=await privileged(db);await enable(db);await ready(db,p.id);
 const adapter=rpcAdapter(db),seen=[],sent=[];
 const wrapped={rpc:async(name,args)=>{seen.push([name,args.p_action]);return adapter.rpc(name,args);}};
 const env={AUTH_TOKEN_HMAC_KEY:'a'.repeat(64),AUTH_RATE_HMAC_KEY:'b'.repeat(64),AUTH_PUBLIC_ORIGIN:'https://fixture.example',AUTH_ALLOWED_ORIGINS:'https://fixture.example'};
 const core=createPasswordAuth({db:wrapped,tokens:{},env,mail:{configured:()=>true,send:async value=>{sent.push(value);return {accepted:true};}}});
 const responses=[];
 for(const [email,purpose] of [['missing@example.test','activation'],['owner@example.test','activation'],['admin@example.test','reset']])responses.push(await core.requestLink({email},'127.0.0.1',purpose));
 assert.deepEqual(responses[0],responses[1]);assert.deepEqual(responses[1],responses[2]);
 assert.equal(sent.length,0);assert.ok(!seen.some(([_,action])=>['lookup','issue'].includes(action)));
 await core.drainLinks();assert.equal(sent.length,1);assert.equal(sent[0].to,'owner@example.test');assert.equal(sent[0].purpose,'activation');
 assert.equal((await db.query('SELECT count(*)::int AS n FROM keeptimer_auth_link_queue')).rows[0].n,0);
 await db.exec("INSERT INTO keeptimer_auth_link_queue(id,email,purpose) SELECT gen_random_uuid(),'unknown@example.test','reset' FROM generate_series(1,200)");
 await assert.rejects(core.requestLink({email:'different@example.test'},'127.0.0.1','reset'),e=>e.code==='AUTH_UNAVAILABLE');
 assert.equal((await db.query('SELECT activated_at FROM keeptimer_auth_accounts WHERE user_id=$1',[c.id])).rows[0].activated_at,null);
});
test('Superadmin company management works with MFA and sales closed; Agent and private data stay excluded',async t=>{
 const db=await database(t);await enable(db);const p=await salesActor(db,'superadmin');
 const created=await admin(db,p,'workspace_create',{name:'Company',invite_code:'A'.repeat(24)});const ws=created.workspace.id;
 const worker=(await admin(db,p,'user_create',{username:'company-worker',pin_hash:fixtureHash,role:'worker',workspace_id:ws})).user;
 assert.ok((await admin(db,p,'users')).users.some(u=>u.id===worker.id));
 assert.ok((await admin(db,p,'workspaces')).workspaces.some(w=>w.id===ws));
 assert.ok((await admin(db,p,'workspace_detail',{id:ws})).members.some(u=>u.id===worker.id));
 assert.equal((await admin(db,p,'user_update',{id:worker.id,username:'renamed-worker',role:'worker',workspace_id:ws})).success,true);
 assert.equal((await admin(db,p,'workspace_toggle')).shared_mode_enabled,true);
 assert.equal((await admin(db,p,'workspace_invite',{invite_code:'B'.repeat(24)})).invite_code,'B'.repeat(24));
 await admin(db,p,'workspace_leave');assert.equal((await admin(db,p,'workspace')).workspace,null);
 await admin(db,p,'workspace_join',{inviteCode:'B'.repeat(24)});
 const session=randomUUID();await db.query('INSERT INTO sessions(id,user_id,refresh_token_hash) VALUES($1,$2,$3)',[session,worker.id,'fixture']);
 await admin(db,p,'force_logout',{id:worker.id});assert.notEqual((await db.query('SELECT revoked_at FROM sessions WHERE id=$1',[session])).rows[0].revoked_at,null);
 await admin(db,p,'user_disable',{id:worker.id});assert.notEqual((await db.query('SELECT disabled_at FROM users WHERE id=$1',[worker.id])).rows[0].disabled_at,null);
 assert.equal((await db.query('SELECT enabled FROM keeptimer_sales_release')).rows[0].enabled,false);
 const c=await customer(db);
 await assert.rejects(admin(db,p,'workspace_detail',{id:c.workspace}),/AUTH_RESOURCE_NOT_FOUND/);
 await assert.rejects(admin(db,p,'user_update',{id:c.id,username:'private-owner',role:'manager',workspace_id:ws}),/AUTH_FORBIDDEN/);
 await assert.rejects(admin(db,p,'user_create',{username:'forged-admin',pin_hash:fixtureHash,role:'superadmin',workspace_id:null}),/AUTH_INPUT_INVALID/);
 const agentId=(await db.query("SELECT id FROM users WHERE role='agent'")).rows[0].id;
 await assert.rejects(admin(db,{id:agentId,session:randomUUID()},'users'),/AUTH_FORBIDDEN/);
 await db.query("UPDATE keeptimer_privileged_web_sessions SET expires_at=clock_timestamp()-interval '1 second',verified_at=clock_timestamp()-interval '2 minutes' WHERE session_id=$1",[p.session]);
 await assert.rejects(admin(db,p,'users'),/AUTH_FORBIDDEN/);
});
test('MFA resend/verify reject a different server-bound browser session',async t=>{
 const db=await database(t),p=await privileged(db);await enable(db);await ready(db,p.id);const d=await issued(db,p.id,'mfa'),v=consumeData(d);
 await db.query("UPDATE keeptimer_auth_challenges SET last_sent_at=clock_timestamp()-interval '61 seconds' WHERE id=$1",[d.challenge_id]);
 assert.equal((await command(db,'resend',{...v,binding_digest:'e'.repeat(64)})).ok,false);
 assert.equal((await command(db,'consume',{...v,binding_digest:'e'.repeat(64)})).ok,false);
 assert.equal((await command(db,'consume',v)).ok,true);
});
