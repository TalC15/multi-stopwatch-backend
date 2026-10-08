import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import bcrypt from 'bcrypt';
import { database,actor,enableIsolatedFixture,command,saleData,seededCustomer,user,asRole,resolve,
  fixtureHash,fixturePassword,migration } from './support/subscriptionPhase3.js';

const denied=(fn,code)=>assert.rejects(fn,e=>e.message===code);
const renewal=customer=>({customer_id:customer,plan_code:'individual',term_months:1,amount_minor:30000,currency:'TRY'});
const counts=async db=>(await db.query(`SELECT (SELECT count(*) FROM users)::int users,
 (SELECT count(*) FROM workspaces)::int workspaces,(SELECT count(*) FROM subscriptions)::int subscriptions,
 (SELECT count(*) FROM admin_audit_log)::int audit,(SELECT count(*) FROM keeptimer_sales_requests)::int requests,
 (SELECT count(*) FROM keeptimer_individual_customers)::int customers`)).rows[0];

test('Phase 3 MFA release and transaction authorization fail closed',async t=>{
  const db=await database(t),a=await actor(db),data=saleData();
  await t.test('default OFF even with a synthetic owner-provisioned proof',async()=>{
    await denied(()=>command(db,a,'customer_create',data),'PRIVILEGED_MFA_NOT_READY');
    await asRole(db,'service_role',async()=>{
      for(const table of ['keeptimer_sales_release','keeptimer_privileged_web_sessions','keeptimer_sales_requests','keeptimer_individual_customers']) {
        await assert.rejects(()=>db.exec(`SELECT * FROM ${table}`),e=>e.code==='42501');
        await assert.rejects(()=>db.exec(`DELETE FROM ${table}`),e=>e.code==='42501');
      }
      await assert.rejects(()=>db.exec('UPDATE keeptimer_sales_release SET enabled=true'),e=>e.code==='42501');
    });
    await enableIsolatedFixture(db);
  });
  await t.test('missing, mismatched, expired and future proof cannot authorize',async()=>{
    const second=randomUUID();await db.query('INSERT INTO sessions(id,user_id,refresh_token_hash) VALUES($1,$2,$3)',[second,a.id,'test-only']);
    await denied(()=>command(db,{...a,session:second},'customer_create',data),'PRIVILEGED_MFA_REQUIRED');
    await denied(()=>command(db,{...a,session:randomUUID()},'customer_create',data),'SALES_SESSION_INVALID');
    await db.query("UPDATE keeptimer_privileged_web_sessions SET verified_at=clock_timestamp()-interval '20 minutes',expires_at=clock_timestamp()-interval '10 minutes' WHERE session_id=$1",[a.session]);
    await denied(()=>command(db,a,'customer_create',data),'PRIVILEGED_MFA_REQUIRED');
    await db.query("UPDATE keeptimer_privileged_web_sessions SET verified_at=clock_timestamp()+interval '1 minute',expires_at=clock_timestamp()+interval '10 minutes' WHERE session_id=$1",[a.session]);
    await denied(()=>command(db,a,'customer_create',data),'PRIVILEGED_MFA_REQUIRED');
    await db.query("UPDATE keeptimer_privileged_web_sessions SET verified_at=clock_timestamp(),expires_at=clock_timestamp()+interval '10 minutes' WHERE session_id=$1",[a.session]);
  });
  await t.test('actor roles are reread, caller cannot promote itself or create privileged accounts',async()=>{
    for(const action of ['agent_create','agent_revoke','agent_password_reset']) await denied(()=>command(db,a,action,{}),'SALES_FORBIDDEN');
    await denied(()=>command(db,a,'superadmin_create',{}),'SALES_FORBIDDEN');
    const worker=await actor(db,'worker');
    await denied(()=>command(db,worker,'customer_create',data),'SALES_FORBIDDEN');
    await db.query('UPDATE users SET must_change_password=true WHERE id=$1',[a.id]);
    await denied(()=>command(db,a,'customer_create',data),'PASSWORD_CHANGE_REQUIRED');
    await db.query('UPDATE users SET must_change_password=false WHERE id=$1',[a.id]);
  });
  await t.test('untrusted SQL roles cannot execute privileged RPCs or mutate sales directly',async()=>{
    for(const role of ['anon','authenticated'])await asRole(db,role,async()=>{
      await assert.rejects(()=>command(db,a,'customer_create',data),e=>e.code==='42501');
      await assert.rejects(()=>db.query('SELECT keeptimer_phase3_access($1,$2,$3)',[a.id,a.session,'agent']),e=>e.code==='42501');
    });
    await asRole(db,'service_role',async()=>{
      await assert.rejects(()=>db.query("INSERT INTO admin_audit_log(actor_user_id,action) VALUES($1,'agent_created')",[a.id]),e=>e.code==='42501');
      await assert.rejects(()=>user(db,'agent'),e=>e.code==='42501');
      await assert.rejects(()=>db.query("UPDATE users SET role='superadmin' WHERE id=$1",[a.id]),e=>e.code==='42501');
      await assert.rejects(()=>db.query("SELECT keeptimer_phase3_add_months(clock_timestamp(),1)"),e=>e.code==='42501');
    });
  });
});

test('Phase 3 Superadmin agent lifecycle, password reset and revocation',async t=>{
  const db=await database(t),sa=await actor(db,'superadmin');await enableIsolatedFixture(db);
  let agent;
  await t.test('creates exactly one password-only agent and replays without another account/audit',async()=>{
    const request=randomUUID(),data={username:'agent_sales',password_hash:fixtureHash,mfa_email:'fixture@example.invalid'};
    await asRole(db,'service_role',async()=>{agent=await command(db,sa,'agent_create',data,request);
      assert.deepEqual(await command(db,sa,'agent_create',data,request),agent);});
    const row=(await db.query('SELECT role,pin_hash,password_hash,credential_kind,must_change_password FROM users WHERE id=$1',[agent.agentId])).rows[0];
    assert.equal(row.role,'agent');assert.equal(row.pin_hash,null);assert.equal(row.credential_kind,'password');
    assert.equal(row.must_change_password,true);assert.equal(await bcrypt.compare(fixturePassword,row.password_hash),true);
    await denied(()=>command(db,sa,'agent_create',{...data,username:'second_agent'}),'ACTIVE_AGENT_EXISTS');
    assert.equal((await db.query("SELECT count(*)::int n FROM admin_audit_log WHERE action='agent_created'")).rows[0].n,1);
    const session=randomUUID();await db.query('INSERT INTO sessions(id,user_id,refresh_token_hash) VALUES($1,$2,$3)',[session,agent.agentId,'synthetic']);
    agent={id:agent.agentId,session};
    await db.query("INSERT INTO keeptimer_privileged_web_sessions VALUES($1,$2,clock_timestamp(),clock_timestamp()+interval '10 minutes','email_otp')",[session,agent.id]);
    await denied(()=>command(db,agent,'customer_create',saleData()),'PASSWORD_CHANGE_REQUIRED');
  });
  await t.test('agent reset needs no old password; sessions and proof are invalidated',async()=>{
    const replacement=await bcrypt.hash('Different-Strong-Password-2026!',12);
    await command(db,sa,'agent_password_reset',{agent_id:agent.id,password_hash:replacement});
    const row=(await db.query('SELECT password_hash,must_change_password FROM users WHERE id=$1',[agent.id])).rows[0];
    assert.equal(await bcrypt.compare('Different-Strong-Password-2026!',row.password_hash),true);
    assert.equal(await bcrypt.compare(fixturePassword,row.password_hash),false);assert.equal(row.must_change_password,true);
    assert.notEqual((await db.query('SELECT revoked_at FROM sessions WHERE id=$1',[agent.session])).rows[0].revoked_at,null);
    assert.equal((await db.query('SELECT count(*)::int n FROM keeptimer_privileged_web_sessions WHERE user_id=$1',[agent.id])).rows[0].n,0);
  });
  await t.test('revoke is atomic and idempotent, old actor fails and replacement is possible',async()=>{
    const data={agent_id:agent.id};const result=await command(db,sa,'agent_revoke',data);
    assert.deepEqual(await command(db,sa,'agent_revoke',data),result);
    await denied(()=>command(db,agent,'customer_create',saleData()),'SALES_FORBIDDEN');
    assert.equal((await db.query("SELECT count(*)::int n FROM admin_audit_log WHERE action='agent_revoked'")).rows[0].n,1);
    const next=await command(db,sa,'agent_create',{username:'replacement_agent',password_hash:fixtureHash,mfa_email:'new@example.invalid'});
    assert.notEqual(next.agentId,agent.id);
    assert.equal((await db.query("SELECT count(*)::int n FROM users WHERE role='agent' AND disabled_at IS NULL")).rows[0].n,1);
  });
});

test('Phase 3 sales, private isolation, idempotency and history',async t=>{
  const db=await database(t),a=await actor(db);await enableIsolatedFixture(db);
  let created,customer;
  await t.test('new worker/private/subscription/two audits created together; repeated request is stable',async()=>{
    const data=saleData(),request=randomUUID();
    await asRole(db,'service_role',async()=>{created=await command(db,a,'customer_create',data,request);});
    customer=created.customerId;const before=await counts(db);
    assert.deepEqual(await command(db,a,'customer_create',data,request),created);assert.deepEqual(await counts(db),before);
    await denied(()=>command(db,a,'customer_create',{...data,amount_minor:1},request),'IDEMPOTENCY_CONFLICT');
    const row=(await db.query('SELECT u.role,u.pin_hash,u.password_hash,u.must_change_password,w.* FROM users u JOIN workspaces w ON w.id=u.workspace_id WHERE u.id=$1',[customer])).rows[0];
    assert.equal(row.role,'worker');assert.equal(row.owner_id,customer);assert.equal(row.kind,'individual_private');
    assert.equal(row.invite_code,null);assert.equal(row.shared_mode_enabled,false);assert.equal(row.pin_hash,null);
    assert.equal(await bcrypt.compare(fixturePassword,row.password_hash),true);assert.equal(created.loginReady,false);
    assert.equal(before.audit,2);assert.equal(created.subscription.amountMinor,'25000');
  });
  await t.test('team/enterprise, forged fields, invalid terms/amounts and disabled catalog fail atomically',async()=>{
    const before=await counts(db);
    for(const plan_code of ['team','enterprise'])await denied(()=>command(db,a,'customer_create',saleData({plan_code})),'PLAN_NOT_AVAILABLE');
    for(const extra of [{role:'superadmin'},{actor_user_id:a.id},{starts_at:'2000-01-01Z'},{term_months:13},{term_months:0},{amount_minor:-1},{amount_minor:0.5},{currency:'try'},{password_hash:'plaintext'}]) {
      await assert.rejects(()=>command(db,a,'customer_create',saleData(extra)));
    }
    await db.exec("UPDATE subscription_plans SET enabled=false WHERE code='individual'");
    await denied(()=>command(db,a,'customer_create',saleData()),'PLAN_NOT_AVAILABLE');
    await db.exec("UPDATE subscription_plans SET enabled=true WHERE code='individual'");
    assert.deepEqual(await counts(db),before);
  });
  await t.test('late audit failure rolls back customer, workspace, subscription, registry and request',async()=>{
    const before=await counts(db);
    await db.exec("CREATE FUNCTION test_phase3_audit_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='subscription_created' THEN RAISE EXCEPTION 'fixture rollback'; END IF; RETURN NEW; END $$; CREATE TRIGGER test_phase3_audit_failure BEFORE INSERT ON admin_audit_log FOR EACH ROW EXECUTE FUNCTION test_phase3_audit_failure()");
    try{await assert.rejects(()=>command(db,a,'customer_create',saleData()),/fixture rollback/);}finally{await db.exec('DROP TRIGGER test_phase3_audit_failure ON admin_audit_log; DROP FUNCTION test_phase3_audit_failure()');}
    assert.deepEqual(await counts(db),before);
  });
  await t.test('DB rejects outsider membership, owner departure, second workspace, conversions and shared timers',async()=>{
    const workspace=(await db.query('SELECT workspace_id FROM users WHERE id=$1',[customer])).rows[0].workspace_id;
    const outsider=await user(db);const team=(await db.query("INSERT INTO workspaces(name) VALUES('Legacy team') RETURNING id")).rows[0].id;
    for(const [sql,args] of [
      ['UPDATE users SET workspace_id=$1 WHERE id=$2',[workspace,outsider]],
      ['UPDATE users SET workspace_id=NULL WHERE id=$1',[customer]],
      ["UPDATE users SET role='manager' WHERE id=$1",[customer]],
      ["UPDATE workspaces SET kind='team' WHERE id=$1",[workspace]],
      ["UPDATE workspaces SET kind='individual_private',owner_id=$1,shared_mode_enabled=false WHERE id=$2",[customer,team]],
      ["UPDATE workspaces SET invite_code='INVITE' WHERE id=$1",[workspace]],
      ['UPDATE workspaces SET shared_mode_enabled=true WHERE id=$1',[workspace]],
      ['UPDATE workspaces SET owner_id=$1 WHERE id=$2',[outsider,workspace]],
      ["INSERT INTO workspaces(name,owner_id,kind,shared_mode_enabled) VALUES('Second',$1,'individual_private',false)",[customer]],
      ["INSERT INTO timers(user_id,workspace_id,name,type,target_minutes,is_shared) VALUES($1,$2,'Shared','up',1,true)",[customer,workspace]],
      ['SELECT keeptimer_close_company_worker($1,$2)',[a.id,customer]],
    ])await assert.rejects(()=>db.query(sql,args));
    const sa=await actor(db,'superadmin');
    await assert.rejects(()=>db.query('SELECT keeptimer_close_company_worker($1,$2)',[sa.id,customer]));
    assert.equal((await db.query('SELECT count(*)::int n FROM users WHERE workspace_id=$1',[workspace])).rows[0].n,1);
    const orphan=await user(db,'worker',{pin_hash:null,password_hash:fixtureHash,credential_kind:'password',plan_code:'individual'});
    await assert.rejects(()=>db.query("INSERT INTO workspaces(name,owner_id,kind,shared_mode_enabled) VALUES('Orphan',$1,'individual_private',false)",[orphan]),/PHASE3_PRIVATE_INCONSISTENT/);
  });
  await t.test('active renewal starts at exact prior end; pending period blocks a second sale',async()=>{
    const renewed=await command(db,a,'subscription_renew',renewal(customer));
    assert.equal(renewed.subscription.startsAt,created.subscription.endsAt);assert.equal(renewed.subscription.sequenceNo,2);
    await denied(()=>command(db,a,'subscription_renew',renewal(customer)),'PENDING_PERIOD_EXISTS');
    const cancel={customer_id:customer,subscription_id:renewed.subscription.id,reason:'customer_request'};
    const result=await command(db,a,'subscription_cancel',cancel);const before=await counts(db);
    assert.deepEqual(await command(db,a,'subscription_cancel',cancel),result);assert.deepEqual((await counts(db)).audit,before.audit);
    assert.equal((await resolve(db,customer)).status,'active');assert.equal((await resolve(db,customer)).startsAt,created.subscription.startsAt);
    const third=await command(db,a,'subscription_renew',renewal(customer));assert.equal(third.subscription.sequenceNo,3);
    await denied(()=>command(db,a,'subscription_cancel',{...cancel,customer_id:randomUUID()}),'CUSTOMER_NOT_FOUND');
    const other=await command(db,a,'customer_create',saleData());
    await denied(()=>command(db,a,'subscription_cancel',{...cancel,subscription_id:other.subscription.id}),'SUBSCRIPTION_NOT_FOUND');
  });
  await t.test('expired/cancelled-only sales use DB time and retain timer/history records',async()=>{
    for(const cancelled of [false,true]) {
      const old=await seededCustomer(db,a,{starts_at:'2000-01-01Z',ends_at:'2000-02-01Z'});
      await db.query("INSERT INTO timers(user_id,workspace_id,name,type,target_minutes,is_shared) VALUES($1,$2,'Retained','up',1,false)",[old.id,old.workspace]);
      if(cancelled)await command(db,a,'subscription_cancel',{customer_id:old.id,subscription_id:old.subscription.id,reason:'administrative'});
      const before=(await db.query('SELECT clock_timestamp() AS n')).rows[0].n;
      const next=await command(db,a,'subscription_renew',renewal(old.id));
      assert.ok(Date.parse(next.subscription.startsAt)>=new Date(before).getTime());assert.equal(next.subscription.sequenceNo,2);
      assert.equal((await db.query('SELECT count(*)::int n FROM timers WHERE user_id=$1',[old.id])).rows[0].n,1);
      assert.equal((await db.query('SELECT count(*)::int n FROM subscriptions WHERE user_id=$1',[old.id])).rows[0].n,2);
      assert.equal((await db.query('SELECT disabled_at FROM users WHERE id=$1',[old.id])).rows[0].disabled_at,null);
    }
  });
  await t.test('customer password reset invalidates sessions; cannot target legacy or privileged users',async()=>{
    const session=randomUUID();await db.query('INSERT INTO sessions(id,user_id,refresh_token_hash) VALUES($1,$2,$3)',[session,customer,'fixture']);
    await command(db,a,'customer_password_reset',{customer_id:customer,password_hash:fixtureHash});
    assert.notEqual((await db.query('SELECT revoked_at FROM sessions WHERE id=$1',[session])).rows[0].revoked_at,null);
    for(const target of [a.id,await user(db)]) await denied(()=>command(db,a,'customer_password_reset',{customer_id:target,password_hash:fixtureHash}),'CUSTOMER_NOT_FOUND');
  });
  await t.test('paginated customer/history views exclude legacy, company, agent and all credential fields',async()=>{
    const seen=[];let after=null;
    do {
      const result=(await db.query("SELECT keeptimer_phase3_list($1,$2,'customers',NULL,$3,2) r",[a.id,a.session,after])).rows[0].r;
      assert.ok(result.items.length<=2);seen.push(...result.items);after=result.nextCursor;
    }while(after);
    assert.equal(new Set(seen.map(x=>x.id)).size,seen.length);
    assert.equal(seen.length,(await db.query('SELECT count(*)::int n FROM keeptimer_individual_customers')).rows[0].n);
    assert.ok(seen.every(x=>Object.keys(x).sort().join(',')==='code,disabledAt,endsAt,id,isEntitled,status,username'));
    const history=(await db.query("SELECT keeptimer_phase3_list($1,$2,'history',$3,NULL,100) r",[a.id,a.session,customer])).rows[0].r;
    assert.equal(history.items.length,3);assert.ok(history.items.every(x=>typeof x.amountMinor==='string'&&x.createdBy===a.id));
    assert.deepEqual(history.items.map(x=>x.sequenceNo),[1,2,3]);
    const json=JSON.stringify((await db.query('SELECT metadata FROM admin_audit_log')).rows);
    assert.doesNotMatch(json,/password|pin|token|otp|email|\$2b/);
  });
  await t.test('replay preserves data and OFF/ON choice; legacy team PIN and personal sync schema remain intact',async()=>{
    const before=await counts(db);await db.exec(migration);assert.deepEqual(await counts(db),before);
    assert.equal((await db.query('SELECT enabled FROM keeptimer_sales_release')).rows[0].enabled,true);
    const manager=await user(db,'manager');
    const workspace=(await db.query("INSERT INTO workspaces(name,owner_id,invite_code) VALUES('Legacy',$1,'TEAM123') RETURNING id",[manager])).rows[0].id;
    await db.query('UPDATE users SET workspace_id=$1 WHERE id=$2',[workspace,manager]);
    const worker=await user(db,'worker',{workspace_id:workspace});
    assert.equal((await db.query('SELECT credential_kind FROM users WHERE id=$1',[worker])).rows[0].credential_kind,'pin');
    assert.equal((await resolve(db,worker)).requiresSubscription,false);
    const closed=(await db.query('SELECT keeptimer_close_company_worker($1,$2) r',[manager,worker])).rows[0].r;
    assert.ok(closed);
  });
});

test('Phase 3 calendar months are UTC, end-of-month and leap-year correct',async t=>{
  const db=await database(t);
  for(const [start,months,end] of [
    ['2026-01-31T12:13:14.123456Z',1,'2026-02-28T12:13:14.123456Z'],
    ['2024-01-31T12:13:14.123456Z',1,'2024-02-29T12:13:14.123456Z'],
    ['2024-02-29T00:00:00Z',12,'2025-02-28T00:00:00Z'],
    ['2026-01-31T00:00:00Z',2,'2026-03-31T00:00:00Z'],
  ])await t.test(start+' + '+months,async()=>{
    for(const zone of ['UTC','America/New_York','Asia/Kathmandu']) {
      await db.query("SELECT set_config('TimeZone',$1,false)",[zone]);
      assert.equal((await db.query('SELECT keeptimer_phase3_add_months($1,$2)=$3::timestamptz AS correct',[start,months,end])).rows[0].correct,true);
    }
  });
});

test('Phase 3 expired MFA after writes rolls back the entire command',async t=>{
  for(const [name,table,action] of [
    ['agent INSERT','users','agent_create'],['agent audit','admin_audit_log','agent_create'],
    ['agent idempotency','keeptimer_sales_requests','agent_create'],
    ['customer idempotency','keeptimer_sales_requests','customer_create'],
  ])await t.test(name,async()=>{
    const db=await database(t),who=await actor(db,action==='agent_create'?'superadmin':'agent');
    await enableIsolatedFixture(db);const before=await counts(db);
    // Owner-only fault injection into this isolated DB, never a production issuer.
    await db.exec(`CREATE FUNCTION public.test_expire_phase3_proof() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN
        UPDATE public.keeptimer_privileged_web_sessions SET expires_at=verified_at+interval '1 microsecond'
          WHERE session_id='${who.session}'::uuid;
        RETURN NEW;
      END; $$;
      CREATE TRIGGER test_expire_phase3_proof AFTER INSERT ON public.${table}
        FOR EACH ROW EXECUTE FUNCTION public.test_expire_phase3_proof();`);
    const data=action==='agent_create'?{username:'late_agent',password_hash:fixtureHash,mfa_email:'fixture@example.invalid'}:saleData();
    await denied(()=>command(db,who,action,data),'PRIVILEGED_MFA_REQUIRED');
    assert.deepEqual(await counts(db),before);
    assert.equal((await db.query('SELECT expires_at>clock_timestamp() AS valid FROM keeptimer_privileged_web_sessions WHERE session_id=$1',[who.session])).rows[0].valid,true);
  });
});
