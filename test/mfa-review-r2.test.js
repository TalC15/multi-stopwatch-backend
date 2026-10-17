import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import bcrypt from 'bcrypt';
import {database,privileged,scope,command,start,accept,verify,fixtureHash} from './support/mfaDevice.js';
import {user} from './support/subscriptionPhase6.js';
async function agent(db){const id=await user(db,'agent');await db.query('SELECT keeptimer_auth_prepare($1,$2,$3)',[id,'agent@example.test',fixtureHash]);await db.query('UPDATE keeptimer_auth_accounts SET verified_at=clock_timestamp(),activated_at=clock_timestamp() WHERE user_id=$1',[id]);await db.query('UPDATE users SET must_change_password=false WHERE id=$1',[id]);return {id};}
async function session(db,p,s=scope()){const a=await start(db,p,s);await accept(db,a.args);const v=verify(a.args);assert.equal((await command(db,'verify',v)).ok,true);return v.session_id;}
test('P2-1 revoke-all invalidates another device first factor and OTP atomically',async t=>{
 const db=await database(t),p=await privileged(db),sid=await session(db,p),pending=await start(db,p,scope('b'));await accept(db,pending.args);
 const r=(await db.query("SELECT keeptimer_auth_command('revoke_sessions',$1) AS r",[JSON.stringify({user_id:p.id,session_id:sid,transport:'web'})])).rows[0].r;assert.equal(r.ok,true);
 assert.equal((await command(db,'verify',verify(pending.args))).ok,false);
 assert.equal((await db.query('SELECT count(*)::int AS n FROM sessions WHERE revoked_at IS NULL')).rows[0].n,0);
});
test('P2-1 privileged force-logout invalidates pending MFA even with zero target sessions',async t=>{
 const db=await database(t),admin=await privileged(db),sid=await session(db,admin),target=await agent(db),pending=await start(db,target,scope('b'));await accept(db,pending.args);
 const r=(await db.query("SELECT keeptimer_auth_management($1,$2,'force_logout',$3) AS r",[admin.id,sid,JSON.stringify({id:target.id})])).rows[0].r;assert.equal(r.success,true);
 assert.equal((await command(db,'verify',verify(pending.args))).ok,false);
});
test('P2-1 authenticated password change invalidates a different device OTP in the same transaction',async t=>{
 const db=await database(t),p=await privileged(db),sid=await session(db,p),pending=await start(db,p,scope('b'));await accept(db,pending.args);
 const password_hash=await bcrypt.hash('Fresh-Synthetic-Password-Only!',12);
 const result=(await db.query("SELECT keeptimer_auth_command('change',$1) AS r",[JSON.stringify({user_id:p.id,session_id:sid,transport:'web',expected_hash:fixtureHash,password_hash})])).rows[0].r;
 assert.equal(result.ok,true);assert.equal((await command(db,'verify',verify(pending.args))).ok,false);
 assert.equal((await db.query('SELECT count(*)::int AS n FROM sessions WHERE revoked_at IS NULL')).rows[0].n,0);
});
test('P2-2/P3 catalog forbids MFA child cascades and retains backend-only cleanup ACL',async t=>{
 const db=await database(t);
 const rows=(await db.query("SELECT confdeltype FROM pg_constraint WHERE contype='f' AND conrelid IN ('keeptimer_mfa_contexts'::regclass,'keeptimer_mfa_challenges'::regclass,'keeptimer_mfa_sends'::regclass,'keeptimer_mfa_verifications'::regclass)")).rows;
 assert.ok(rows.length>=6);assert.ok(rows.every(r=>r.confdeltype!=='c'));
 assert.equal((await db.query("SELECT has_function_privilege('authenticated','keeptimer_mfa_maintain()','EXECUTE') AS allowed")).rows[0].allowed,false);
});
test('P2-1 direct session revoke/delete fences earlier first factors without reverse parent locking',async t=>{
 for(const action of ['UPDATE sessions SET revoked_at=clock_timestamp() WHERE id=$1','DELETE FROM sessions WHERE id=$1']){
  const db=await database(t),p=await privileged(db),sid=await session(db,p),pending=await start(db,p,scope('b'));await accept(db,pending.args);
  if(action.startsWith('DELETE')){await db.query('DELETE FROM keeptimer_privileged_web_sessions WHERE session_id=$1',[sid]);await db.query('DELETE FROM keeptimer_auth_sessions WHERE session_id=$1',[sid]);}
  await db.query(action,[sid]);assert.equal((await command(db,'verify',verify(pending.args))).ok,false);
 }
});
test('P2-1 credential/version/disable changes and rollback cannot revive stale first factors',async t=>{
 const db=await database(t),p=await privileged(db),a=await start(db,p);await accept(db,a.args);
 await db.exec('BEGIN');await db.query('UPDATE keeptimer_auth_accounts SET version=version+1 WHERE user_id=$1',[p.id]);await db.exec('ROLLBACK');
 assert.equal((await command(db,'status',a.args)).state.phase,'challenge');
 await db.query('UPDATE users SET must_change_password=true WHERE id=$1',[p.id]);await db.query('UPDATE users SET must_change_password=false WHERE id=$1',[p.id]);
 assert.equal((await command(db,'verify',verify(a.args))).ok,false);
 const target=await agent(db),b=await start(db,target,scope('b'));await accept(db,b.args);
 await db.query('UPDATE users SET disabled_at=clock_timestamp() WHERE id=$1',[target.id]);await assert.rejects(db.query('UPDATE users SET disabled_at=NULL WHERE id=$1',[target.id]),/REACTIVATION_BLOCKED/);
 assert.equal((await command(db,'verify',verify(b.args))).ok,false);
});
test('P2-2 release-close rollback restores live OTP and first factor; commit consumes both',async t=>{
 const db=await database(t),p=await privileged(db),a=await start(db,p);await accept(db,a.args);
 await db.exec('BEGIN');await db.exec('UPDATE keeptimer_auth_release SET enabled=false');
 assert.ok((await db.query('SELECT consumed_at FROM keeptimer_mfa_challenges')).rows[0].consumed_at);
 await db.exec('ROLLBACK');assert.equal((await command(db,'status',a.args)).state.phase,'challenge');
 await db.exec('UPDATE keeptimer_auth_release SET enabled=false');
 assert.ok((await db.query('SELECT consumed_at FROM keeptimer_mfa_challenges')).rows[0].consumed_at);
 assert.equal(new Date((await db.query('SELECT verified_at FROM keeptimer_mfa_contexts')).rows[0].verified_at).getTime(),0);
});
test('pending and unknown sends retain quota reservations alongside accepted sends',async t=>{
 const db=await database(t),p=await privileged(db);let latest;
 for(const delivery of ['pending','unknown','accepted']){
  await db.exec("UPDATE keeptimer_mfa_sends SET created_at=created_at-interval '61 seconds';UPDATE keeptimer_mfa_challenges SET expires_at=clock_timestamp()-interval '1 second'");
  latest=await start(db,p);assert.equal(latest.result.ok,true);
  if(delivery!=='pending'){const job=(await command(db,'claim',{...latest.args,challenge_id:latest.args.new_challenge_id})).job;await command(db,'delivery',{...latest.args,challenge_id:latest.args.new_challenge_id,operation_id:job.id,lease:job.lease,delivery});}
 }
 await db.exec("UPDATE keeptimer_mfa_sends SET created_at=created_at-interval '61 seconds'");
 const r=await command(db,'resend',{...latest.args,challenge_id:latest.args.new_challenge_id,operation_id:randomUUID(),proof_digest:'e'.repeat(64)});
 assert.equal(r.code,'MFA_SEND_LIMIT_REACHED');assert.ok(r.state.sendLimitAvailableAt);
 assert.equal((await command(db,'verify',verify(latest.args))).ok,true);
});
test('quota refunds only definitive rejected sends; pending/unknown/accepted reserve budget and terminal result is immutable',async t=>{
 const db=await database(t),p=await privileged(db);let current;
 for(let i=0;i<4;i++){
  if(i)await db.exec("UPDATE keeptimer_mfa_sends SET created_at=created_at-interval '61 seconds';UPDATE keeptimer_mfa_challenges SET expires_at=clock_timestamp()-interval '1 second'");
  current=await start(db,p);assert.equal(current.result.ok,true);
  const job=(await command(db,'claim',{...current.args,challenge_id:current.args.new_challenge_id})).job;
  const args={...current.args,challenge_id:current.args.new_challenge_id,operation_id:job.id,lease:job.lease};
  const r=await command(db,'delivery',{...args,delivery:i<3?'rejected':'accepted'});assert.equal(r.state.sendLimitAvailableAt,null);
  if(i===3){await command(db,'delivery',{...args,delivery:'rejected'});assert.equal((await command(db,'status',current.args)).state.delivery,'accepted');}
 }
 assert.equal((await command(db,'verify',verify(current.args))).ok,true);
});
test('P3 retention counts actual deletes, never cascades beyond 64 or deletes a nonempty context',async t=>{
 const db=await database(t),p=await privileged(db),a=await start(db,p);
 for(let i=0;i<100;i++){
  const id=randomUUID(),send=randomUUID();await db.query("INSERT INTO keeptimer_mfa_challenges VALUES($1,$2,clock_timestamp()-interval '9 days',clock_timestamp()-interval '8 days',NULL,$3,$4)",[id,a.args.context_id,send,'c'.repeat(64)]);
  await db.query("INSERT INTO keeptimer_mfa_sends(id,context_id,challenge_id,action,created_at,nonce,expires_at) VALUES($1,$2,$3,'start',clock_timestamp()-interval '9 days',$4,clock_timestamp()-interval '8 days')",[send,a.args.context_id,id,'b'.repeat(64)]);
 }
 await db.exec("UPDATE keeptimer_mfa_challenges SET expires_at=clock_timestamp()-interval '8 days';UPDATE keeptimer_mfa_sends SET expires_at=clock_timestamp()-interval '8 days';UPDATE keeptimer_mfa_contexts SET updated_at=clock_timestamp()-interval '31 days'");
 const r=(await db.query('SELECT keeptimer_mfa_maintain() AS r')).rows[0].r;
 const left=(await db.query('SELECT count(*)::int AS n FROM keeptimer_mfa_challenges')).rows[0].n;
 assert.ok(101-left<=64);assert.equal(r.challenges,101-left);assert.equal(r.contexts,0);assert.equal(r.sends,64);
 const next=(await db.query('SELECT keeptimer_mfa_maintain() AS r')).rows[0].r;assert.equal(next.challenges,37);assert.equal(next.sends,37);assert.equal(next.contexts,1);
});
