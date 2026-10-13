import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {database,customer,privileged,enable,ready,command,issued,consumeData,asRole,fixtureHash,user} from './support/passwordAuth.js';

test('Phase7 forward migration: closed gates, private tables and EXECUTE ACL',async t=>{
 const db=await database(t);
 assert.equal((await db.query('SELECT enabled FROM keeptimer_sales_release')).rows[0].enabled,false);
 assert.equal((await db.query('SELECT enabled FROM keeptimer_auth_release')).rows[0].enabled,false);
 await assert.rejects(command(db,'lookup',{email:'a@example.test'}),/AUTH_NOT_READY/);
 for(const role of ['anon','authenticated','service_role'])for(const table of ['accounts','challenges','sessions','limits','release'])await assert.rejects(asRole(db,role,()=>db.query(`SELECT * FROM keeptimer_auth_${table}`)),/permission denied/);
 for(const role of ['anon','authenticated'])await assert.rejects(asRole(db,role,()=>command(db,'lookup',{})),/permission denied/);
 await assert.rejects(asRole(db,'service_role',()=>db.query('SELECT keeptimer_auth_prepare($1,$2,$3)',[randomUUID(),'x@example.test',fixtureHash])),/permission denied/);
});
test('pending account cannot login; activation atomically keeps same user/workspace and single use',async t=>{
 const db=await database(t), c=await customer(db);await enable(db);
 assert.equal((await command(db,'lookup',{email:'owner@example.test'})).ready,false);
 assert.equal((await command(db,'login',{user_id:c.id,expected_hash:fixtureHash,transport:'web',session_id:randomUUID(),refresh_hash:'d'.repeat(64)})).ok,false);
 const data=await issued(db,c.id),consume=consumeData(data);
 assert.equal((await command(db,'consume',{...consume,proof_digest:'d'.repeat(64)})).ok,false);
 assert.equal((await command(db,'consume',consume)).loginReady,true);
 assert.equal((await command(db,'consume',consume)).ok,false);
 assert.equal((await db.query('SELECT workspace_id FROM users WHERE id=$1',[c.id])).rows[0].workspace_id,c.workspace);
 assert.equal((await db.query('SELECT count(*) AS n FROM sessions WHERE user_id=$1',[c.id])).rows[0].n,0);
 assert.equal((await command(db,'lookup',{email:'owner@example.test'})).ready,true);
});
test('activation expiry and context/purpose binding; target id cannot redirect activation',async t=>{
 const db=await database(t),c=await customer(db);await enable(db);
 const d=await issued(db,c.id),v=consumeData(d);
 for(const fields of [{context_digest:'c'.repeat(64)},{purpose:'reset'},{transport:'native'},{challenge_id:randomUUID()}])assert.equal((await command(db,'consume',{...v,...fields})).ok,false);
 await db.query("UPDATE keeptimer_auth_challenges SET expires_at=clock_timestamp()-interval '1 second',created_at=clock_timestamp()-interval '29 minutes' WHERE id=$1",[d.challenge_id]);
 assert.equal((await command(db,'consume',v)).ok,false);
 assert.equal((await command(db,'lookup',{email:'owner@example.test'})).ready,false);
});
test('MFA verified first factor, fresh session/proof, one use and absolute expiry',async t=>{
 const db=await database(t),p=await privileged(db);await enable(db);
 assert.equal((await command(db,'issue',{user_id:p.id,purpose:'mfa',expected_hash:fixtureHash})).ok,false);
 await ready(db,p.id);
 const d=await issued(db,p.id,'mfa'),v=consumeData(d);
 assert.equal((await db.query('SELECT count(*) AS n FROM sessions')).rows[0].n,0);
 assert.equal((await command(db,'consume',{...v,proof_digest:'e'.repeat(64)})).ok,false);
 assert.equal((await command(db,'consume',v)).user.id,p.id);
 assert.equal((await command(db,'consume',v)).ok,false);
 assert.equal((await db.query('SELECT keeptimer_auth_session($1,$2,$3,NULL) AS ok',[p.id,v.session_id,'web'])).rows[0].ok,true);
 await db.query("UPDATE keeptimer_privileged_web_sessions SET expires_at=clock_timestamp()-interval '1 second',verified_at=clock_timestamp()-interval '15 minutes' WHERE session_id=$1",[v.session_id]);
 assert.equal((await db.query('SELECT keeptimer_auth_session($1,$2,$3,NULL) AS ok',[p.id,v.session_id,'web'])).rows[0].ok,false);
});
test('OTP five attempts commit; resend cooldown; pending/failed delivery cannot consume',async t=>{
 const db=await database(t),p=await privileged(db);await enable(db);await ready(db,p.id);
 const d=await issued(db,p.id,'mfa'),v=consumeData(d);
 assert.equal((await command(db,'resend',{...v,proof_digest:'f'.repeat(64)})).code,'AUTH_RATE_LIMITED');
 for(let i=0;i<5;i++)assert.equal((await command(db,'consume',{...v,proof_digest:'f'.repeat(64)})).ok,false);
 assert.equal((await command(db,'consume',v)).ok,false);
 assert.equal((await db.query('SELECT attempts FROM keeptimer_auth_challenges WHERE id=$1',[d.challenge_id])).rows[0].attempts,5);
 await db.query("UPDATE keeptimer_auth_challenges SET last_sent_at=clock_timestamp()-interval '61 seconds' WHERE id=$1",[d.challenge_id]);
 assert.equal((await command(db,'resend',v)).ok,false);
 const c=await customer(db),d2={...d,user_id:c.id,purpose:'activation',challenge_id:randomUUID()};assert.equal((await command(db,'issue',d2)).ok,true);
 assert.equal((await command(db,'consume',consumeData(d2))).ok,false);
 await command(db,'delivery',{challenge_id:d2.challenge_id,proof_digest:d2.proof_digest,accepted:false});
 assert.equal((await command(db,'consume',consumeData(d2))).ok,false);
});
test('reset cannot activate pending account; single use, session revocation, immutable identity',async t=>{
 const db=await database(t),c=await customer(db);await enable(db);
 assert.equal((await command(db,'issue',{user_id:c.id,purpose:'reset'})).ok,false);
 await ready(db,c.id);
 const login={user_id:c.id,expected_hash:fixtureHash,transport:'web',session_id:randomUUID(),refresh_hash:'c'.repeat(64)};
 assert.equal((await command(db,'login',login)).ok,true);
 const before=(await db.query('SELECT id,role,workspace_id,plan_code FROM users WHERE id=$1',[c.id])).rows[0];
 const d=await issued(db,c.id,'reset');assert.equal((await command(db,'consume',consumeData(d))).ok,true);
 assert.equal((await command(db,'consume',consumeData(d))).ok,false);
 assert.deepEqual((await db.query('SELECT id,role,workspace_id,plan_code FROM users WHERE id=$1',[c.id])).rows[0],before);
 assert.equal((await db.query('SELECT revoked_at IS NOT NULL AS revoked FROM sessions WHERE id=$1',[login.session_id])).rows[0].revoked,true);
});
test('distributed counters deny without rolling back; fixed budgets',async t=>{
 const db=await database(t);await enable(db);let last;
 for(let i=0;i<11;i++)last=(await db.query('SELECT keeptimer_auth_limit($1,$2,$3) AS ok',['login','a'.repeat(64),'b'.repeat(64)])).rows[0].ok;
 assert.equal(last,false);assert.equal((await db.query('SELECT count FROM keeptimer_auth_limits WHERE key=$1',['a'.repeat(64)])).rows[0].count,11);
 await assert.rejects(db.query('SELECT keeptimer_auth_limit($1,$2,$3)',['other','a'.repeat(64),'b'.repeat(64)]),/AUTH_INPUT_INVALID/);
});
test('service-role privileged issuance/direct password mutation denied; company PIN unchanged',async t=>{
 const db=await database(t),p=await privileged(db);await enable(db);
 await assert.rejects(asRole(db,'service_role',()=>db.query('INSERT INTO sessions(id,user_id,refresh_token_hash) VALUES($1,$2,$3)',[randomUUID(),p.id,'old-backend'])),/AUTH_FORBIDDEN/);
 await assert.rejects(asRole(db,'service_role',()=>db.query('UPDATE users SET password_hash=$1 WHERE id=$2',['$2b$12$'+'a'.repeat(53),p.id])),/AUTH_FORBIDDEN/);
 assert.equal((await db.query('SELECT keeptimer_auth_session($1,$2,NULL,NULL) AS ok',[p.id,randomUUID()])).rows[0].ok,false);
 const pin=await user(db);await asRole(db,'service_role',()=>db.query('INSERT INTO sessions(id,user_id,refresh_token_hash) VALUES($1,$2,$3)',[randomUUID(),pin,'company-pin']));
});

test('MFA resend rotates code without resetting attempts/deadline and stops after three sends',async t=>{
 const db=await database(t),p=await privileged(db);await enable(db);await ready(db,p.id);
 const d=await issued(db,p.id,'mfa'),v=consumeData(d),expiry=(await db.query('SELECT expires_at FROM keeptimer_auth_challenges WHERE id=$1',[d.challenge_id])).rows[0].expires_at;
 for(const digest of ['c'.repeat(64),'d'.repeat(64)]){
  await db.query("UPDATE keeptimer_auth_challenges SET last_sent_at=clock_timestamp()-interval '61 seconds' WHERE id=$1",[d.challenge_id]);
  assert.equal((await command(db,'resend',{...v,proof_digest:digest})).ok,true);
  assert.equal((await command(db,'consume',v)).ok,false); // pending delivery also cannot consume
  await command(db,'delivery',{challenge_id:d.challenge_id,proof_digest:digest,accepted:true});
  assert.equal((await command(db,'consume',v)).ok,false); // old code now counts as wrong
 }
 await db.query("UPDATE keeptimer_auth_challenges SET last_sent_at=clock_timestamp()-interval '61 seconds' WHERE id=$1",[d.challenge_id]);
 assert.equal((await command(db,'resend',{...v,proof_digest:'e'.repeat(64)})).code,'AUTH_RATE_LIMITED');
 const row=(await db.query('SELECT sends,attempts,expires_at FROM keeptimer_auth_challenges WHERE id=$1',[d.challenge_id])).rows[0];
 assert.equal(row.sends,3);assert.equal(row.attempts,2);assert.deepEqual(row.expires_at,expiry);
 assert.equal((await command(db,'consume',{...v,proof_digest:'d'.repeat(64)})).ok,true);
});
test('password change checks old credential after lock, revokes every session and pending link; privileged reset still needs MFA',async t=>{
 const db=await database(t),p=await privileged(db);await enable(db);await ready(db,p.id);
 const d=await issued(db,p.id,'mfa'),v=consumeData(d);await command(db,'consume',v);
 assert.equal((await command(db,'issue',{user_id:p.id,purpose:'reset'})).ok,false);
 await db.query("UPDATE keeptimer_auth_challenges SET last_sent_at=clock_timestamp()-interval '61 seconds' WHERE id=$1",[d.challenge_id]);
 const reset=await issued(db,p.id,'mfa');
 const data={user_id:p.id,session_id:v.session_id,transport:'web',expected_hash:'wrong',password_hash:fixtureHash};
 assert.equal((await command(db,'change',data)).ok,false);
 assert.equal((await command(db,'change',{...data,expected_hash:fixtureHash})).ok,true);
 assert.equal((await db.query('SELECT keeptimer_auth_session($1,$2,NULL,NULL) AS ok',[p.id,v.session_id])).rows[0].ok,false);
 assert.equal((await command(db,'consume',consumeData(reset))).ok,false);
 assert.equal((await db.query('SELECT count(*)::int AS n FROM keeptimer_privileged_web_sessions WHERE user_id=$1',[p.id])).rows[0].n,0);
 assert.equal((await command(db,'login',{user_id:p.id,expected_hash:fixtureHash,transport:'web',session_id:randomUUID(),refresh_hash:'c'.repeat(64)})).ok,false);
});
test('verified expired Individual login preserves private data and does not grant entitlement; unique mailbox binding',async t=>{
 const db=await database(t),c=await customer(db,'expired@example.test',{starts_at:'2000-01-01Z',ends_at:'2000-02-01Z'});await enable(db);await ready(db,c.id);
 const other=await customer(db,'other@example.test');
 const before=(await db.query('SELECT count(*)::int AS n FROM timers WHERE user_id=$1',[c.id])).rows[0].n;
 const login={user_id:c.id,expected_hash:fixtureHash,transport:'native',session_id:randomUUID(),refresh_hash:'e'.repeat(64)};
 assert.equal((await command(db,'login',login)).user.workspace_id,c.workspace);
 const entitlement=(await db.query('SELECT keeptimer_resolve_entitlement($1) AS result',[c.id])).rows[0].result;
 assert.equal(entitlement.status,'expired');assert.equal(entitlement.isEntitled,false);assert.ok(entitlement.evaluatedAt);
 assert.equal((await db.query('SELECT count(*)::int AS n FROM timers WHERE user_id=$1',[c.id])).rows[0].n,before);
 await assert.rejects(db.query('UPDATE keeptimer_auth_accounts SET email=$1 WHERE user_id=$2',['expired@example.test',other.id]),/unique/);
 assert.equal((await db.query('SELECT keeptimer_auth_session($1,$2,NULL,NULL) AS ok',[other.id,login.session_id])).rows[0].ok,false);
 const activation=await issued(db,other.id);assert.equal((await command(db,'consume',{...consumeData(activation),user_id:c.id})).ok,true);
 assert.equal((await command(db,'lookup',{email:'other@example.test'})).ready,true);
 assert.equal((await db.query('SELECT workspace_id FROM users WHERE id=$1',[other.id])).rows[0].workspace_id,other.workspace);
});
test('old migration owner expectations, default gate and previous actor/sale are not service-role escape hatches',async t=>{
 const db=await database(t),p=await privileged(db);await enable(db);await ready(db,p.id);
 for(const name of ['keeptimer_phase7_previous_actor','keeptimer_phase7_previous_sale']){
  const sql=name.endsWith('actor')?'SELECT keeptimer_phase7_previous_actor($1,$2,$3)':'SELECT keeptimer_phase7_previous_sale($1,$2,$3,$4,$5,$6)';
  const values=name.endsWith('actor')?[p.id,randomUUID(),'superadmin']:[p.id,randomUUID(),randomUUID(),'agent_create','a'.repeat(64),'{}'];
  await assert.rejects(asRole(db,'service_role',()=>db.query(sql,values)),/permission denied/);
 }
 const d=await issued(db,p.id,'mfa');await db.query("UPDATE keeptimer_auth_challenges SET expires_at=clock_timestamp()-interval '1 second',created_at=clock_timestamp()-interval '9 minutes' WHERE id=$1",[d.challenge_id]);
 assert.equal((await command(db,'consume',consumeData(d))).ok,false);
});

test('closing auth rollout atomically invalidates old-backend-readable sessions and pending challenges',async t=>{
 const db=await database(t),p=await privileged(db);await enable(db);await ready(db,p.id);
 const d=await issued(db,p.id,'mfa'),v=consumeData(d);await command(db,'consume',v);
 await db.query("UPDATE keeptimer_auth_challenges SET last_sent_at=clock_timestamp()-interval '61 seconds' WHERE id=$1",[d.challenge_id]);
 const pending=await issued(db,p.id,'mfa');
 await db.exec('UPDATE keeptimer_auth_release SET enabled=false');
 assert.equal((await db.query('SELECT revoked_at IS NOT NULL AS revoked FROM sessions WHERE id=$1',[v.session_id])).rows[0].revoked,true);
 assert.equal((await db.query('SELECT consumed_at IS NOT NULL AS consumed FROM keeptimer_auth_challenges WHERE id=$1',[pending.challenge_id])).rows[0].consumed,true);
 assert.equal((await db.query('SELECT count(*)::int AS n FROM keeptimer_privileged_web_sessions')).rows[0].n,0);
 await assert.rejects(command(db,'consume',consumeData(pending)),/AUTH_NOT_READY/);
 await enable(db);assert.equal((await command(db,'consume',consumeData(pending))).ok,false);
});


test('privileged recovery requires trusted DB owner; preserves mailbox/role and requires activation plus new MFA',async t=>{
 const db=await database(t),p=await privileged(db);await enable(db);await ready(db,p.id);
 const recoveryCase=randomUUID();
 await db.query("INSERT INTO keeptimer_auth_recovery_cases(id,target_user_id,operator_login,reason,evidence_ref,expires_at) VALUES($1,$2,session_user,'Independent owner verification','CASE-FIXTURE-ONLY',clock_timestamp()+interval '1 hour')",[recoveryCase,p.id]);
 await assert.rejects(asRole(db,'service_role',()=>db.query('SELECT keeptimer_auth_recover_privileged($1,$2,$3)',[p.id,fixtureHash,recoveryCase])),/permission denied/);
 assert.equal((await command(db,'issue',{user_id:p.id,purpose:'reset'})).ok,false);
 await db.query('SELECT keeptimer_auth_recover_privileged($1,$2,$3)',[p.id,fixtureHash,recoveryCase]);
 assert.equal((await command(db,'lookup',{email:'admin@example.test'})).ready,false);
 const activation=await issued(db,p.id);await command(db,'consume',consumeData(activation));
 assert.equal((await command(db,'login',{user_id:p.id,expected_hash:fixtureHash,transport:'web',session_id:randomUUID(),refresh_hash:'f'.repeat(64)})).ok,false);
 const mfa=await issued(db,p.id,'mfa');assert.equal((await command(db,'consume',consumeData(mfa))).user.role,'superadmin');
});

test('private scope tamper is rejected by existing DB constraint and leaves activation pending',async t=>{
 const db=await database(t),c=await customer(db);await enable(db);const d=await issued(db,c.id);
 await assert.rejects(db.query('UPDATE workspaces SET shared_mode_enabled=true WHERE id=$1',[c.workspace]),/workspaces_private_shape_check/);
 assert.equal((await db.query('SELECT shared_mode_enabled FROM workspaces WHERE id=$1',[c.workspace])).rows[0].shared_mode_enabled,false);
 assert.equal((await command(db,'lookup',{email:'owner@example.test'})).ready,false);
 assert.ok(d.challenge_id);
 assert.equal((await db.query('SELECT activated_at FROM keeptimer_auth_accounts WHERE user_id=$1',[c.id])).rows[0].activated_at,null);
});
