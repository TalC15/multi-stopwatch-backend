// The SAME tests run against original Phase7 and the security revision.
// Trigger/function fault injection is confined to disposable test DBs; it is
// deterministic rollback evidence, NOT real PostgreSQL lock scheduling proof.
import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {database as phase6} from './support/subscriptionPhase6.js';
import {database,migration,enable,customer,privileged,ready,salesActor,fixtureHash,fixturePassword,rpcAdapter,issued,user} from './support/passwordAuth.js';
import {createPasswordAuth} from '../src/passwordAuth.js';
const env={AUTH_TOKEN_HMAC_KEY:'a'.repeat(64),AUTH_RATE_HMAC_KEY:'b'.repeat(64),AUTH_PUBLIC_ORIGIN:'https://fixture.example',AUTH_ALLOWED_ORIGINS:'https://fixture.example'};
const sale=(db,p,action,data,request)=>db.query('SELECT keeptimer_phase3_command($1,$2,$3,$4,$5,$6) AS r',[p.id,p.session,request,action,'f'.repeat(64),JSON.stringify(data)]);

test('SOL1 regression: a different dependency owner rejects the whole migration',async t=>{
 const db=await phase6(t);await db.exec('ALTER FUNCTION keeptimer_phase3_require_actor(uuid,uuid,text) OWNER TO anon');
 await assert.rejects(db.exec(migration),/PHASE7_DEPENDENCY_OWNER_MISMATCH/);await db.exec('ROLLBACK');
 assert.equal((await db.query("SELECT to_regclass('keeptimer_auth_release') AS t")).rows[0].t,null);
});
for(const action of ['agent_create','customer_create','subscription_renew'])test(`SOL2 regression: ${action} final wrapper work expires MFA and all writes roll back`,async t=>{
 const db=await database(t);await enable(db);const p=await salesActor(db,action==='agent_create'?'superadmin':'agent');
 await db.exec('UPDATE keeptimer_sales_release SET enabled=true');
 let data;
 const expire=`UPDATE public.keeptimer_privileged_web_sessions SET verified_at=clock_timestamp()-interval '2 minutes',expires_at=clock_timestamp()-interval '1 second' WHERE session_id='${p.session}'::uuid;`;
 if(action==='subscription_renew'){
  const c=await customer(db);await ready(db,c.id);
  await db.exec(`ALTER FUNCTION public.keeptimer_auth_shape(uuid) RENAME TO fixture_saved_shape;
   CREATE FUNCTION public.keeptimer_auth_shape(p_user uuid) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path='' AS $$ BEGIN
    IF p_user='${c.id}'::uuid THEN ${expire} END IF;
    RETURN public.fixture_saved_shape(p_user); END; $$;`);
  data={customer_id:c.id,plan_code:'individual',term_months:1,amount_minor:10000,currency:'TRY'};
 }else{
  await db.exec(`CREATE FUNCTION public.fixture_expire_after_sale() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN ${expire} RETURN NEW; END; $$;
   CREATE TRIGGER fixture_expire_after_sale BEFORE INSERT ON keeptimer_auth_accounts FOR EACH ROW EXECUTE FUNCTION public.fixture_expire_after_sale();`);
  data={username:'late-wrapper',password_hash:fixtureHash,email:'late@example.test',...(action==='agent_create'?{mfa_email:'late@example.test'}:{plan_code:'individual',term_months:1,amount_minor:10000,currency:'TRY'})};
 }
 const before=(await db.query('SELECT (SELECT count(*) FROM users)::int AS users,(SELECT count(*) FROM subscriptions)::int AS subscriptions,(SELECT count(*) FROM admin_audit_log)::int AS audit')).rows[0];
 const request=randomUUID();await assert.rejects(sale(db,p,action,data,request),/PRIVILEGED_MFA_REQUIRED/);
 assert.deepEqual((await db.query('SELECT (SELECT count(*) FROM users)::int AS users,(SELECT count(*) FROM subscriptions)::int AS subscriptions,(SELECT count(*) FROM admin_audit_log)::int AS audit')).rows[0],before);
 assert.equal((await db.query('SELECT count(*)::int AS n FROM keeptimer_sales_requests WHERE request_id=$1',[request])).rows[0].n,0);
});
test('SOL3 regression: accepting a link never calls account lookup in the request path',async t=>{
 const db=await database(t);await enable(db);await customer(db);const adapter=rpcAdapter(db),seen=[];
 const core=createPasswordAuth({db:{rpc:async(name,args)=>{seen.push([name,args.p_action]);return adapter.rpc(name,args);}},tokens:{},env,
  mail:{configured:()=>true,send:async()=>({accepted:true})}});
 const first=await core.requestLink({email:'owner@example.test'},'127.0.0.1','activation');
 const other=await core.requestLink({email:'unknown@example.test'},'127.0.0.1','activation');
 assert.deepEqual(first,other);assert.equal(seen.filter(([_,a])=>a==='lookup'||a==='issue').length,0,'eligibility is not a pre-response operation');
});
test('SOL5 regression: recovery records authenticated DB operator separately from target',async t=>{
 const db=await database(t);await enable(db);const p=await privileged(db);await ready(db,p.id);
 const available=(await db.query("SELECT to_regprocedure('keeptimer_auth_recover_privileged(uuid,text,uuid)') AS fn")).rows[0].fn;
 if(available){
  const id=randomUUID();await db.query("INSERT INTO keeptimer_auth_recovery_cases(id,target_user_id,operator_login,reason,evidence_ref,expires_at) VALUES($1,$2,session_user,'Independent identity verification','fixture-case-evidence',clock_timestamp()+interval '1 hour')",[id,p.id]);
  await db.query('SELECT keeptimer_auth_recover_privileged($1,$2,$3)',[p.id,fixtureHash,id]);
 }else await db.query('SELECT keeptimer_auth_recover_privileged($1,$2)',[p.id,fixtureHash]);
 const forged=(await db.query("SELECT count(*)::int AS n FROM admin_audit_log WHERE action='password_reset' AND actor_user_id=target_user_id AND target_user_id=$1",[p.id])).rows[0].n;
 assert.equal(forged,0,'the target must not be logged as its own recovery operator');
 const audit=(await db.query('SELECT operator_login=session_user AS operator_ok,executing_owner=current_user AS owner_ok,target_user_id FROM keeptimer_auth_recovery_audit')).rows[0];
 assert.deepEqual(audit,{operator_ok:true,owner_ok:true,target_user_id:p.id});
});
test('SOL6 regression: executable bounded retention keeps live challenges and active budgets',async t=>{
 const db=await database(t);await enable(db);const c=await customer(db),d=await issued(db,c.id);
 await db.exec("INSERT INTO keeptimer_auth_limits SELECT lpad(to_hex(n),64,'0'),clock_timestamp()-interval '25 hours',1 FROM generate_series(1,100) n");
 for(let i=0;i<10;i++)await db.query("SELECT keeptimer_auth_limit('login',$1,$2)",['d'.repeat(64),'e'.repeat(64)]);
 const result=(await db.query('SELECT keeptimer_auth_maintain() AS r')).rows[0].r;assert.equal(result.limits,64);
 assert.equal((await db.query('SELECT consumed_at FROM keeptimer_auth_challenges WHERE id=$1',[d.challenge_id])).rows[0].consumed_at,null);
 assert.equal((await db.query("SELECT keeptimer_auth_limit('login',$1,$2) AS allowed",['d'.repeat(64),'e'.repeat(64)])).rows[0].allowed,false);
});
test('SOL7 regression: Individual login has no mail-provider dependency; privileged remains closed',async t=>{
 const db=await database(t);await enable(db);const c=await customer(db),p=await privileged(db);await ready(db,c.id);await ready(db,p.id);
 const tokens={generateAccessToken:()=> 'synthetic-access',generateRefreshToken:()=> 'synthetic-refresh',hashToken:()=> 'f'.repeat(64)};
 const core=createPasswordAuth({db:rpcAdapter(db),tokens,env:{AUTH_TOKEN_HMAC_KEY:env.AUTH_TOKEN_HMAC_KEY,AUTH_RATE_HMAC_KEY:env.AUTH_RATE_HMAC_KEY},mail:{configured:()=>false,send:()=>assert.fail('mail must not be sent')}});
 assert.equal((await core.passwordLogin({email:'owner@example.test',password:fixturePassword},'127.0.0.1','web')).user.id,c.id);
 await assert.rejects(core.passwordLogin({email:'admin@example.test',password:fixturePassword},'127.0.0.1','web'),e=>e.code==='AUTH_NOT_READY');
 assert.equal((await db.query('SELECT count(*)::int AS n FROM sessions WHERE user_id=$1',[p.id])).rows[0].n,0);
});
test('Invariant: at most one Superadmin total and one active Agent; duplicate preparation is atomic',async t=>{
 const db=await database(t),sa=await user(db,'superadmin');
 await assert.rejects(user(db,'superadmin'),/unique constraint/);
 await db.query('UPDATE users SET disabled_at=clock_timestamp() WHERE id=$1',[sa]);
 await assert.rejects(user(db,'superadmin'),/unique constraint/);
 const agent=await user(db,'agent',{credential_kind:'password',pin_hash:null,password_hash:fixtureHash});
 await assert.rejects(user(db,'agent',{credential_kind:'password',pin_hash:null,password_hash:fixtureHash}),/unique constraint/);
 await db.query('UPDATE users SET disabled_at=clock_timestamp() WHERE id=$1',[agent]);
 assert.ok(await user(db,'agent',{credential_kind:'password',pin_hash:null,password_hash:fixtureHash}));
});
test('Invariant: pre-existing duplicate Superadmin identities stop preparation without data repair',async t=>{
 const db=await phase6(t),first=await user(db,'superadmin');
 await db.query('UPDATE users SET disabled_at=clock_timestamp() WHERE id=$1',[first]);await user(db,'superadmin');
 await assert.rejects(db.exec(migration),/PHASE7_SUPERADMIN_CARDINALITY_MISMATCH/);await db.exec('ROLLBACK');
 assert.equal((await db.query("SELECT count(*)::int AS n FROM users WHERE role='superadmin'")).rows[0].n,2);
 assert.equal((await db.query("SELECT to_regclass('keeptimer_auth_release') AS t")).rows[0].t,null);
});
