import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {database,migration,privileged,scope,command,start,accept,verify} from './support/mfaDevice.js';

test('MFA preparation preserves closed gates, legacy link ACLs, owner-only state and rerun rollback',async t=>{
 const db=await database(t,{enabled:false});
 assert.deepEqual((await db.query('SELECT enabled,cutover FROM keeptimer_auth_release')).rows[0],{enabled:false,cutover:false});
 assert.equal((await db.query('SELECT enabled FROM keeptimer_sales_release')).rows[0].enabled,false);
 const acl=(await db.query("SELECT has_function_privilege('service_role','keeptimer_mfa_command(text,jsonb)','EXECUTE') AS backend,has_function_privilege('anon','keeptimer_mfa_command(text,jsonb)','EXECUTE') AS browser,has_function_privilege('service_role','keeptimer_mfa_state(text)','EXECUTE') AS state,has_function_privilege('service_role','keeptimer_auth_command_pre_device(text,jsonb)','EXECUTE') AS legacy")).rows[0];
 assert.deepEqual(acl,{backend:true,browser:false,state:false,legacy:false});
 await assert.rejects(db.exec(migration),/already exists/);await db.exec('ROLLBACK');
 assert.equal((await db.query('SELECT count(*)::int AS n FROM keeptimer_mfa_contexts')).rows[0].n,0);
});
test('120 seconds, six attempts and sliding sends are DB-owned; no client deadline fields accepted as authority',async t=>{
 const db=await database(t),p=await privileged(db),{args,result}=await start(db,p);
 assert.equal(result.ok,true);assert.equal(result.state.attemptsRemaining,6);
 const row=(await db.query('SELECT extract(epoch FROM expires_at-created_at)::int AS ttl FROM keeptimer_mfa_challenges')).rows[0];assert.equal(row.ttl,120);
 assert.equal((await command(db,'resend',{...args,challenge_id:args.new_challenge_id,operation_id:randomUUID(),expiresIn:999999})).code,'MFA_RESEND_COOLDOWN');
 await accept(db,args);const before=await command(db,'status',args);
 const dup=await command(db,'start',{...args,new_challenge_id:randomUUID()});assert.equal(dup.state.challengeId,args.new_challenge_id);
 assert.equal((await db.query('SELECT count(*)::int AS n FROM keeptimer_mfa_sends')).rows[0].n,1);
 assert.equal(before.state.expiresAt,dup.state.expiresAt);
});
test('resend adds exactly 30 seconds to remaining 40, invalidates old code, preserves attempts, duplicate has no extra cost',async t=>{
 const db=await database(t),p=await privileged(db),{args}=await start(db,p);await accept(db,args);
 await command(db,'verify',verify(args,{proof_digest:'0'.repeat(64)}));
 await db.exec("UPDATE keeptimer_mfa_sends SET created_at=clock_timestamp()-interval '61 seconds';UPDATE keeptimer_mfa_challenges SET expires_at=clock_timestamp()+interval '40 seconds'");
 const old=(await db.query('SELECT expires_at FROM keeptimer_mfa_challenges')).rows[0].expires_at;
 const resend={...args,challenge_id:args.new_challenge_id,operation_id:randomUUID(),proof_digest:'e'.repeat(64)};
 await assert.rejects(command(db,'resend',{...resend,proof_digest:args.proof_digest}),/AUTH_UNAVAILABLE/);
 assert.equal((await db.query('SELECT count(*)::int AS n FROM keeptimer_mfa_sends')).rows[0].n,1);
 const r=await command(db,'resend',resend);assert.equal(Date.parse(r.state.expiresAt)-new Date(old).getTime(),30_000);assert.equal(r.state.attemptsRemaining,5);
 assert.equal((await command(db,'resend',resend)).state.expiresAt,r.state.expiresAt);
 assert.equal((await command(db,'resend',{...resend,operation_id:randomUUID()})).code,'MFA_RESEND_COOLDOWN');
 await accept(db,args);assert.equal((await command(db,'verify',verify(args))).code,'MFA_INVALID_CODE');
 assert.equal((await db.query('SELECT count(*)::int AS n FROM keeptimer_mfa_sends')).rows[0].n,2);
});
test('sixth wrong locks only this context for ten minutes; repeated verification, reload and new first factor cannot reset it',async t=>{
 const db=await database(t),p=await privileged(db),a=await start(db,p);await accept(db,a.args);
 for(let i=1;i<=6;i++){
  const v=verify(a.args,{proof_digest:'0'.repeat(64)}),r=await command(db,'verify',v);
  assert.equal(r.code,i===6?'MFA_ATTEMPTS_EXHAUSTED':'MFA_INVALID_CODE');assert.equal(r.state.attemptsRemaining,6-i);
  const retry=await command(db,'verify',v);assert.equal(retry.ok,false);
 }
 const locked=await command(db,'status',a.args);assert.equal(locked.code,'MFA_DEVICE_LOCKED');
 assert.ok(Date.parse(locked.state.lockedUntil)-Date.parse(locked.state.serverNow)>599_000);
 assert.equal((await command(db,'start',{...a.args,operation_id:randomUUID(),new_challenge_id:randomUUID()})).code,'MFA_DEVICE_LOCKED');
 const b=await start(db,p,scope('b'));assert.equal(b.result.ok,true);await accept(db,b.args);
 assert.equal((await command(db,'verify',verify(b.args))).ok,true);
 await db.exec("UPDATE keeptimer_mfa_contexts SET locked_until=clock_timestamp()-interval '1 second' WHERE attempts=6");
 const unlocked=await command(db,'start',{...a.args,operation_id:randomUUID(),new_challenge_id:randomUUID()});
 // The independent 60-second send cooldown remains even after lock expiry.
 assert.equal(unlocked.code,'MFA_RESEND_COOLDOWN');assert.equal(unlocked.state.attemptsRemaining,6);
});
test('send window includes first send across fresh challenges; quota does not invalidate last code',async t=>{
 const db=await database(t),p=await privileged(db);let latest;
 for(let i=0;i<3;i++){
  if(i)await db.exec("UPDATE keeptimer_mfa_sends SET created_at=created_at-interval '61 seconds';UPDATE keeptimer_mfa_challenges SET expires_at=clock_timestamp()-interval '1 second'");
  latest=await start(db,p);assert.equal(latest.result.ok,true);await accept(db,latest.args);
 }
 await db.exec("UPDATE keeptimer_mfa_sends SET created_at=created_at-interval '61 seconds'");
 assert.equal((await command(db,'resend',{...latest.args,challenge_id:latest.args.new_challenge_id,operation_id:randomUUID()})).code,'MFA_SEND_LIMIT_REACHED');
 assert.equal((await command(db,'verify',verify(latest.args))).ok,true);
});
test('expired and consumed codes cannot revive or double-consume; changed session binding is rejected',async t=>{
 const db=await database(t),p=await privileged(db),a=await start(db,p);await accept(db,a.args);
 assert.equal((await command(db,'verify',verify(a.args,{binding_digest:'e'.repeat(64)}))).code,'MFA_CHALLENGE_INVALID');
 const v=verify(a.args);assert.equal((await command(db,'verify',v)).ok,true);assert.equal((await command(db,'verify',v)).ok,false);
 assert.equal((await db.query('SELECT count(*)::int AS n FROM sessions')).rows[0].n,1);
 const b=await start(db,p,scope('b'));await accept(db,b.args);
 await db.query("UPDATE keeptimer_mfa_challenges SET expires_at=clock_timestamp() WHERE id=$1",[b.args.new_challenge_id]);
 assert.equal((await command(db,'verify',verify(b.args))).code,'MFA_CODE_EXPIRED');
 assert.equal((await command(db,'resend',{...b.args,challenge_id:b.args.new_challenge_id,operation_id:randomUUID()})).code,'MFA_CODE_EXPIRED');
});
test('delivery lease retry reuses persisted nonce and operation; unknown/rejected never grant MFA',async t=>{
 const db=await database(t),p=await privileged(db),a=await start(db,p);
 const job=(await command(db,'claim',{...a.args,challenge_id:a.args.new_challenge_id})).job;
 assert.equal((await command(db,'claim',{...a.args,challenge_id:a.args.new_challenge_id})).job,undefined);
 await command(db,'delivery',{...a.args,challenge_id:a.args.new_challenge_id,operation_id:job.id,lease:job.lease,delivery:'unknown'});
 assert.equal((await command(db,'verify',verify(a.args))).code,'EMAIL_DELIVERY_UNAVAILABLE');
 await db.exec("UPDATE keeptimer_mfa_sends SET lease_until=clock_timestamp()-interval '1 second'");
 const retry=(await command(db,'claim',{...a.args,challenge_id:a.args.new_challenge_id})).job;
 assert.equal(retry.nonce,job.nonce);assert.equal(retry.id,job.id);assert.notEqual(retry.lease,job.lease);
 await command(db,'delivery',{...a.args,challenge_id:a.args.new_challenge_id,operation_id:retry.id,lease:retry.lease,delivery:'accepted'});
 assert.equal((await command(db,'verify',verify(a.args))).ok,true);
});
test('retention preserves current challenges and active lock; legacy MFA and closed release cannot bypass',async t=>{
 const db=await database(t),p=await privileged(db),a=await start(db,p);await accept(db,a.args);
 await db.query('SELECT keeptimer_mfa_maintain()');assert.equal((await command(db,'status',a.args)).state.phase,'challenge');
 await assert.rejects(db.query("SELECT keeptimer_auth_command('issue',$1)",[JSON.stringify({purpose:'mfa'})]),/AUTH_NOT_READY/);
 await db.exec('UPDATE keeptimer_auth_release SET enabled=false');
 assert.ok((await db.query('SELECT consumed_at FROM keeptimer_mfa_challenges')).rows[0].consumed_at);
 await assert.rejects(command(db,'verify',verify(a.args)),/AUTH_NOT_READY/);
});
test('six sends across contexts cause only a bounded unfamiliar-context delay, never an account-wide lock',async t=>{
 const db=await database(t),p=await privileged(db);let trusted;
 for(const name of ['a','b'])for(let i=0;i<3;i++){
  await db.exec("UPDATE keeptimer_mfa_sends SET created_at=created_at-interval '61 seconds';UPDATE keeptimer_mfa_challenges SET expires_at=clock_timestamp()-interval '1 second'");
  const x=await start(db,p,scope(name));assert.equal(x.result.ok,true);await accept(db,x.args);trusted=x;
 }
 const delayed=await start(db,p,scope('c'));assert.equal(delayed.result.state.phase,'risk_wait');
 assert.ok(Date.parse(delayed.result.state.riskUntil)-Date.parse(delayed.result.state.serverNow)<=60000);
 assert.equal((await command(db,'verify',verify(trusted.args))).ok,true);
 await db.exec("UPDATE keeptimer_mfa_contexts SET risk_until=clock_timestamp()-interval '1 second' WHERE risk_until IS NOT NULL");
 const resumed=await start(db,p,scope('c'));assert.equal(resumed.result.ok,true);
 assert.equal((await db.query("SELECT count(*)::int AS n FROM keeptimer_mfa_risk_audit WHERE event='unfamiliar_context_delay'")).rows[0].n,1);
});
test('retention deletes old evidence in bounds while live challenge and current lock remain intact',async t=>{
 const db=await database(t),p=await privileged(db),live=await start(db,p);await accept(db,live.args);
 const old=await start(db,p,scope('b'));
 await db.query("UPDATE keeptimer_mfa_challenges SET expires_at=clock_timestamp()-interval '8 days' WHERE id=$1",[old.args.new_challenge_id]);
 await db.exec("UPDATE keeptimer_mfa_contexts SET updated_at=clock_timestamp()-interval '31 days',locked_until=clock_timestamp()+interval '10 minutes' WHERE id=repeat('b',64)");
 const r=(await db.query('SELECT keeptimer_mfa_maintain() AS r')).rows[0].r;
 assert.equal(r.challenges,1);assert.equal(r.contexts,0);
 assert.equal((await command(db,'status',live.args)).state.phase,'challenge');
 assert.equal((await db.query('SELECT count(*)::int AS n FROM keeptimer_mfa_contexts')).rows[0].n,2);
});
test('changing a cookie/context does not reset the shared network request budget',async t=>{
 const db=await database(t);
 for(let i=0;i<25;i++)assert.equal((await db.query("SELECT keeptimer_auth_limit('send',$1,$2) AS ok",[i.toString(16).padStart(64,'0'),'f'.repeat(64)])).rows[0].ok,true);
 assert.equal((await db.query("SELECT keeptimer_auth_limit('send',$1,$2) AS ok",['e'.repeat(64),'f'.repeat(64)])).rows[0].ok,false);
});
