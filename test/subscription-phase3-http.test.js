import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { randomUUID } from 'node:crypto';
import bcrypt from 'bcrypt';
import { createSalesCore } from '../src/subscriptionSales.js';
import { database,actor,enableIsolatedFixture,rpcAdapter,fixturePassword,user,fixtureHash } from './support/subscriptionPhase3.js';

test('Phase 3 real backend HTTP, synthetic DB proof, closed login and secret handling',async t=>{
  const db=await database(t),sa=await actor(db,'superadmin'),a=await actor(db),outsider=await actor(db,'worker');
  process.env.JWT_SECRET='phase3-test-only-jwt-secret';
  process.env.SUPABASE_URL='http://127.0.0.1:54321';process.env.SUPABASE_SERVICE_KEY='phase3-test-only-service';
  process.env.AUTH_ALLOWED_ORIGINS='https://fixture.example';process.env.PORT='0';
  process.env.SUBSCRIPTION_IDEMPOTENCY_HMAC_KEY='a'.repeat(64);
  const auth=await import('../src/auth.js'),adapter=rpcAdapter(db),originalFetch=globalThis.fetch;
  const json=(body,status=200)=>new Response(JSON.stringify(body),{status,headers:{'Content-Type':'application/json'}});
  let rpcFault=null,rpcOverride=null;const rpcPayloads=[];
  globalThis.fetch=async(request,options={})=>{
    const url=new URL(request.url??request);
    if(url.origin!=='http://127.0.0.1:54321') {assert.equal(url.hostname,'127.0.0.1');return originalFetch(request,options);}
    const table=url.pathname.split('/').at(-1),body=options.body?JSON.parse(options.body):null;
    const eq=k=>url.searchParams.get(k)?.replace(/^eq\./,'');
    if(table.startsWith('keeptimer_phase3_')) {
      rpcPayloads.push({table,body});
      if(rpcFault)return json(rpcFault,503);
      if(rpcOverride&&table!=='keeptimer_phase3_access')return json(rpcOverride);
      const response=await adapter.rpc(table,body);return response.error?json(response.error,400):json(response.data);
    }
    if(table==='keeptimer_resolve_entitlement')return json((await db.query('SELECT keeptimer_resolve_entitlement($1) r',[body.p_user_id])).rows[0].r);
    if(table==='users') {
      const row=(await db.query('SELECT * FROM users WHERE ($1::uuid IS NULL OR id=$1) AND ($2::text IS NULL OR role=$2) AND ($3::text IS NULL OR username=$3)',[eq('id')||null,eq('role')||null,eq('username')||null])).rows[0];
      return row?json(row):json({code:'PGRST116'},406);
    }
    if(table==='sessions') {
      if(options.method==='POST') {
        await db.query('INSERT INTO sessions(id,user_id,refresh_token_hash,user_agent) VALUES($1,$2,$3,$4)',[body.id,body.user_id,body.refresh_token_hash,body.user_agent]);return json(null,201);
      }
      const row=(await db.query('SELECT * FROM sessions WHERE id=$1 AND ($2::uuid IS NULL OR user_id=$2)',[eq('id'),eq('user_id')||null])).rows[0];
      return row?json(row):json({code:'PGRST116'},406);
    }
    if(table==='keeptimer_refresh_session')return json((await db.query('SELECT keeptimer_refresh_session($1,$2,$3) r',[body.p_user_id,body.p_session_id,body.p_token_hash])).rows[0].r);
    throw new Error('Unexpected resource call '+table);
  };
  const {httpServer}=await import('../src/server.js');if(!httpServer.listening)await once(httpServer,'listening');
  const base=`http://127.0.0.1:${httpServer.address().port}`;
  t.after(async()=>{globalThis.fetch=originalFetch;httpServer.closeAllConnections();await new Promise(done=>httpServer.close(done));});
  const tokens=new Map([sa,a,outsider].map(w=>[w.id,auth.generateAccessToken({id:w.id},w.session)]));
  const call=(who,path,body,key=randomUUID(),extra={})=>originalFetch(base+path,{method:body===undefined?'GET':'POST',
    headers:{Origin:'https://fixture.example',Authorization:`Bearer ${tokens.get(who.id)}`,'Content-Type':'application/json','X-KeepTimer-CSRF':'1','Idempotency-Key':key,...extra},
    ...(body===undefined?{}:{body:JSON.stringify(body)})});
  const data={username:'http_customer',password:fixturePassword,termMonths:1,amountMinor:25000,currency:'TRY'};
  let customer,subscription;
  await t.test('default gate rejects a valid session; no key/env can manufacture an MFA proof',async()=>{
    const closed=await call(a,'/agent/customers',data);assert.equal(closed.status,503);assert.equal((await closed.json()).code,'PRIVILEGED_MFA_NOT_READY');
    await enableIsolatedFixture(db);
    const absent=(await db.query('DELETE FROM keeptimer_privileged_web_sessions WHERE session_id=$1 RETURNING *',[a.session])).rows[0];
    const noProof=await call(a,'/agent/customers',data);assert.equal(noProof.status,403);assert.equal((await noProof.json()).code,'PRIVILEGED_MFA_REQUIRED');
    await db.query('INSERT INTO keeptimer_privileged_web_sessions VALUES($1,$2,$3,$4,$5)',[absent.session_id,absent.user_id,absent.verified_at,absent.expires_at,absent.method]);
  });
  await t.test('origin, CSRF, RBAC, plan and forged authority fields reject before mutation',async()=>{
    for(const [who,body,headers,status] of [
      [a,data,{Origin:'https://evil.example'},403],[a,data,{'X-KeepTimer-CSRF':'0'},400],
      [outsider,data,{},403],[a,{...data,planCode:'team'},{},403],[a,{...data,planCode:'enterprise'},{},403],
      [a,{...data,actor_user_id:sa.id},{},400],[a,{...data,starts_at:'2000-01-01Z'},{},400],
      [a,{...data,password:'short'},{},400],[a,{...data,password:'ş'.repeat(37)},{},400],
    ])assert.equal((await call(who,'/agent/customers',body,randomUUID(),headers)).status,status);
    assert.equal((await db.query('SELECT count(*)::int n FROM keeptimer_individual_customers')).rows[0].n,0);
    const preflight=await originalFetch(base+'/agent/customers',{method:'OPTIONS',headers:{Origin:'https://evil.example','Access-Control-Request-Method':'POST'}});
    assert.equal(preflight.status,403);assert.equal(preflight.headers.get('access-control-allow-origin'),null);
  });
  await t.test('password hashing, retry fingerprint and minimal returned data work through real routes',async()=>{
    const key=randomUUID(),response=await call(a,'/agent/customers',data,key);assert.equal(response.status,200);
    assert.equal(response.headers.get('cache-control'),'no-store');const created=await response.json();customer=created.customerId;subscription=created.subscription;
    assert.equal(created.loginReady,false);assert.equal(subscription.amountMinor,'25000');
    const repeat=await call(a,'/agent/customers',data,key);assert.equal(repeat.status,200);assert.deepEqual(await repeat.json(),created);
    const conflict=await call(a,'/agent/customers',{...data,amountMinor:99},key);assert.equal(conflict.status,409);assert.equal((await conflict.json()).code,'IDEMPOTENCY_CONFLICT');
    const hash=(await db.query('SELECT password_hash,pin_hash FROM users WHERE id=$1',[customer])).rows[0];
    assert.equal(hash.pin_hash,null);assert.equal(await bcrypt.compare(fixturePassword,hash.password_hash),true);
    assert.ok(rpcPayloads.every(x=>!JSON.stringify(x).includes(fixturePassword)));
    assert.doesNotMatch(JSON.stringify(created),/password|pin_hash|mfa_email|refresh_token/);
    assert.equal((await db.query('SELECT count(*)::int n FROM keeptimer_individual_customers')).rows[0].n,1);
  });
  await t.test('renewal/cancel/history use exact customer and do not open resource scope',async()=>{
    const res=await call(a,`/agent/customers/${customer}/subscriptions`,{termMonths:1,amountMinor:10000,currency:'TRY'});
    assert.equal(res.status,200);const renewal=await res.json();assert.equal(renewal.subscription.startsAt,subscription.endsAt);
    const cancel=await call(a,`/agent/customers/${customer}/subscriptions/${renewal.subscription.id}/cancel`,{reason:'customer_request'});
    assert.equal(cancel.status,200);
    const history=await call(a,`/agent/customers/${customer}/subscriptions?limit=1`);assert.equal(history.status,200);
    const page=await history.json();assert.equal(page.items.length,1);assert.match(page.nextCursor,/^[a-f0-9-]{36}$/);
    const session=randomUUID();await db.query('INSERT INTO sessions(id,user_id,refresh_token_hash) VALUES($1,$2,$3)',[session,customer,'fixture']);
    tokens.set(customer,auth.generateAccessToken({id:customer},session));
    const resource=await call({id:customer},'/timers/personal');assert.equal(resource.status,403);assert.equal((await resource.json()).code,'INDIVIDUAL_SCOPE_NOT_READY');
    const agentResource=await call(a,'/workspace');assert.equal(agentResource.status,403);assert.equal((await agentResource.json()).code,'AGENT_MANAGEMENT_ONLY');
  });
  await t.test('new customers and agents cannot use web/native PIN login or native refresh',async()=>{
    const agentName=(await db.query('SELECT username FROM users WHERE id=$1',[a.id])).rows[0].username;
    for(const path of ['/auth/login','/auth/native/login'])for(const username of [data.username,agentName]) {
      const headers={'Content-Type':'application/json',...(path==='/auth/login'?{Origin:'https://fixture.example','X-KeepTimer-CSRF':'1'}:{})};
      const response=await originalFetch(base+path,{method:'POST',headers,body:JSON.stringify({username,pin:fixturePassword})});assert.equal(response.status,401);
    }
    const refresh=auth.generateRefreshToken({id:a.id},a.session);
    await db.query('UPDATE sessions SET refresh_token_hash=$1 WHERE id=$2',[auth.hashToken(refresh),a.session]);
    const response=await originalFetch(base+'/auth/native/refresh',{method:'POST',headers:{'Content-Type':'application/json',Authorization:`Bearer ${refresh}`},body:JSON.stringify({sessionId:a.session})});
    assert.equal(response.status,401);assert.equal((await response.json()).code,'PASSWORD_LOGIN_NOT_READY');
  });
  await t.test('missing idempotency key and upstream errors fail safely without leaking request secrets',async()=>{
    assert.equal((await call(a,'/agent/customers',data,'')).status,400);
    rpcFault={code:'XX000',message:'PRIVATE-DATABASE-DETAIL-'+fixturePassword};
    try {
      const res=await call(a,'/agent/customers',data);assert.equal(res.status,503);assert.deepEqual(await res.json(),{code:'SALES_UNAVAILABLE',error:'İşlem tamamlanamadı'});
    }finally{rpcFault=null;}
  });
  await t.test('malformed subscription and customer RPC responses return HTTP 503 on real routes',async()=>{
    const unavailable=async response=>{
      assert.equal(response.status,503);
      assert.deepEqual(await response.json(),{code:'SALES_UNAVAILABLE',error:'İşlem tamamlanamadı'});
    };
    try {
      for(const patch of [
        {startsAt:'not-a-timestamp'},{endsAt:'2000-01-01T00:00:00Z'},
        {endsAt:subscription.startsAt},{cancelledAt:null,cancelledBy:a.id,cancellationReason:'administrative'},
      ]) {
        rpcOverride={items:[{...subscription,...patch}],nextCursor:null};
        await unavailable(await call(a,`/agent/customers/${customer}/subscriptions`));
        rpcOverride={customerId:customer,subscription:{...subscription,...patch},loginReady:false};
        await unavailable(await call(a,`/agent/customers/${customer}/subscriptions`,{termMonths:1,amountMinor:10000,currency:'TRY'}));
      }
      rpcOverride={items:[{id:customer,username:data.username,disabledAt:null,status:'active',
        endsAt:subscription.endsAt,isEntitled:true,code:'UNKNOWN_CODE'}],nextCursor:null};
      await unavailable(await call(a,'/agent/customers'));
    }finally{rpcOverride=null;}
  });
  await t.test('revoke invalidates the real old bearer session immediately',async()=>{
    const response=await call(sa,`/admin/agents/${a.id}/revoke`,{});assert.equal(response.status,200);
    const denied=await call(a,'/agent/customers');assert.equal(denied.status,401);
    assert.notEqual((await db.query('SELECT revoked_at FROM sessions WHERE id=$1',[a.session])).rows[0].revoked_at,null);
  });
});

test('Phase 3 password idempotency configuration is mandatory and malformed RPC fails closed',async()=>{
  const identity={id:randomUUID(),session:randomUUID()};
  const saved=process.env.SUBSCRIPTION_IDEMPOTENCY_HMAC_KEY;
  try {
    delete process.env.SUBSCRIPTION_IDEMPOTENCY_HMAC_KEY;
    let calls=0;
    const core=createSalesCore({rpc:async()=>{calls++;return {data:true,error:null};}});
    await assert.rejects(()=>core.command(identity.id,identity.session,randomUUID(),'customer_create',{password:fixturePassword}),e=>e.code==='SALES_UNAVAILABLE');
    assert.equal(calls,1);
    const malformed=createSalesCore({rpc:async()=>({data:'true',error:null})});
    await assert.rejects(()=>malformed.command(identity.id,identity.session,randomUUID(),'customer_create',{}),e=>e.code==='SALES_UNAVAILABLE');
  } finally {if(saved===undefined)delete process.env.SUBSCRIPTION_IDEMPOTENCY_HMAC_KEY;else process.env.SUBSCRIPTION_IDEMPOTENCY_HMAC_KEY=saved;}
});

test('Phase 3 response projection rejects malformed results and never exposes extra credential fields',async()=>{
  const who={id:randomUUID(),session:randomUUID()},target=randomUUID();
  let data={items:[{id:target,username:'customer',disabledAt:null,status:'active',endsAt:'2100-01-01T00:00:00Z',isEntitled:true,code:null,
    password_hash:'must-not-leak',mfa_email:'private@example.invalid'}],nextCursor:null,secret:'must-not-leak'};
  const core=createSalesCore({rpc:async()=>({data,error:null})});
  const result=await core.list(who.id,who.session,'customers',null,null,25);
  assert.doesNotMatch(JSON.stringify(result),/must-not-leak|password|mfa_email/);
  for(const broken of [{items:[null],nextCursor:null},{items:[{id:target}],nextCursor:null},{items:[],nextCursor:['bad']}]) {
    data=broken;await assert.rejects(()=>core.list(who.id,who.session,'customers',null,null,25),e=>e.code==='SALES_UNAVAILABLE');
  }
});

test('Phase 3 subscription responses preserve microseconds and reject malformed periods/cancellations',async t=>{
  const who={id:randomUUID(),session:randomUUID()},customer=randomUUID();
  const base={id:randomUUID(),customerId:customer,planCode:'individual',sequenceNo:1,
    startsAt:'2026-10-01T00:00:00.000001+00:00',endsAt:'2026-11-01T00:00:00.000002+00:00',
    termMonths:1,amountMinor:'25000',currency:'TRY',createdBy:who.id,
    cancelledAt:null,cancelledBy:null,cancellationReason:null};
  let item=base;
  const core=createSalesCore({rpc:async name=>({error:null,data:name==='keeptimer_phase3_access'?true:
    name==='keeptimer_phase3_command'?{customerId:customer,subscription:item,loginReady:false}:{items:[item],nextCursor:null}})});
  const saved=process.env.SUBSCRIPTION_IDEMPOTENCY_HMAC_KEY;
  process.env.SUBSCRIPTION_IDEMPOTENCY_HMAC_KEY='b'.repeat(64);
  const calls=()=>[
    ()=>core.list(who.id,who.session,'history',customer,null,25),
    ()=>core.command(who.id,who.session,randomUUID(),'subscription_renew',{}),
  ];
  try {
    for(const [name,patch] of [
      ['invalid start',{startsAt:'not-a-timestamp'}],['invalid end',{endsAt:'not-a-timestamp'}],
      ['invalid calendar',{startsAt:'2026-02-30T00:00:00Z'}],['non-leap February',{startsAt:'2026-02-29T00:00:00Z'}],
      ['missing timezone',{startsAt:'2026-10-01T00:00:00'}],['invalid offset hour',{startsAt:'2026-10-01T00:00:00+24:00'}],
      ['invalid offset minute',{startsAt:'2026-10-01T00:00:00-01:60'}],['invalid time',{startsAt:'2026-10-01T24:00:00Z'}],
      ['extra fraction precision',{startsAt:'2026-10-01T00:00:00.0000001Z'}],
      ['end before start',{endsAt:'2026-09-30T23:59:59Z'}],['equal microseconds',{endsAt:base.startsAt}],
      ['one microsecond earlier',{endsAt:'2026-10-01T00:00:00.000000Z'}],
      ['same instant different offsets',{endsAt:'2026-10-01T03:00:00.000001+03:00'}],
      ['lexical order hides earlier end',{startsAt:'2026-10-01T00:00:00-01:00',endsAt:'2026-10-01T01:30:00+01:00'}],
      ['invalid cancellation timestamp',{cancelledAt:'not-a-timestamp',cancelledBy:who.id,cancellationReason:'administrative'}],
      ['invalid cancellation calendar',{cancelledAt:'2026-02-30T00:00:00Z',cancelledBy:who.id,cancellationReason:'administrative'}],
      ['cancellation without actor',{cancelledAt:'2026-10-08T00:00:00Z',cancellationReason:'customer_request'}],
      ['actor without cancellation',{cancelledBy:who.id}],['reason without cancellation',{cancellationReason:'customer_request'}],
      ['actor/reason without cancellation',{cancelledBy:who.id,cancellationReason:'administrative'}],
      ['invalid cancellation actor',{cancelledAt:'2026-10-08T00:00:00Z',cancelledBy:'bad',cancellationReason:'administrative'}],
      ['unknown cancellation reason',{cancelledAt:'2026-10-08T00:00:00Z',cancelledBy:who.id,cancellationReason:'unknown'}],
    ])await t.test(name,async()=>{
      item={...base,...patch};
      for(const call of calls())await assert.rejects(call,e=>e.code==='SALES_UNAVAILABLE');
    });
    for(const [name,patch] of [
      ['active monthly period',{}],['pending period',{startsAt:'2026-11-01T00:00:00Z',endsAt:'2026-12-01T00:00:00Z'}],
      ['one microsecond valid',{endsAt:'2026-10-01T00:00:00.000002Z'}],
      ['different offsets, same millisecond',{startsAt:'2026-10-01T03:00:00.000001+03:00',endsAt:'2026-09-30T20:00:00.000002-04:00'}],
      ['PostgreSQL space/hour offset',{startsAt:'2026-10-01 05:45:00.1+05:45',endsAt:'2026-10-01 00:00:00.100001+00'}],
      ['compact negative offset',{startsAt:'2026-09-30T20:00:00.123456-0400',endsAt:'2026-10-01T00:00:00.123457Z'}],
      ['valid cancelled future period',{startsAt:'2026-11-01T00:00:00Z',endsAt:'2026-12-01T00:00:00Z',
        cancelledAt:'2026-10-08T03:00:00.123456+03:00',cancelledBy:who.id,cancellationReason:'customer_request'}],
      // SQL's existing cancellation contract permits an omitted business reason.
      ['cancelled with optional null reason',{cancelledAt:'2026-10-08T00:00:00Z',cancelledBy:who.id}],
    ])await t.test(name,async()=>{
      item={...base,...patch};
      assert.deepEqual((await calls()[0]()).items,[item]);
      assert.deepEqual((await calls()[1]()).subscription,item);
    });
  }finally{if(saved===undefined)delete process.env.SUBSCRIPTION_IDEMPOTENCY_HMAC_KEY;else process.env.SUBSCRIPTION_IDEMPOTENCY_HMAC_KEY=saved;}
});

test('Phase 3 customer status accepts only Phase 2 codes and valid timestamp formats',async t=>{
  const who={id:randomUUID(),session:randomUUID()};
  const base={id:randomUUID(),username:'customer',disabledAt:null,status:'active',
    endsAt:'2026-11-01T00:00:00.123456Z',isEntitled:true,code:null};
  let item=base;
  const core=createSalesCore({rpc:async()=>({data:{items:[item],nextCursor:null},error:null})});
  for(const [name,patch] of [
    ['unknown code',{code:'UNKNOWN_CODE'}],['coercible array code',{code:['ACCOUNT_DISABLED']}],
    ['object code',{code:{}}],['number code',{code:123}],['boolean code',{code:false}],
    ['invalid status end',{endsAt:'not-a-timestamp'}],['invalid status calendar',{endsAt:'2026-02-30T00:00:00Z'}],
    ['invalid status offset',{endsAt:'2026-11-01T00:00:00+01:60'}],
  ])await t.test(name,async()=>{
    item={...base,...patch};await assert.rejects(()=>core.list(who.id,who.session,'customers',null,null,25),e=>e.code==='SALES_UNAVAILABLE');
  });
  for(const [status,code,isEntitled] of [
    ['active',null,true],['pending','SUBSCRIPTION_PENDING',false],['expired','SUBSCRIPTION_EXPIRED',false],
    ['cancelled','SUBSCRIPTION_CANCELLED',false],[null,'SUBSCRIPTION_REQUIRED',false],
    ['active','PLAN_DISABLED',false],['expired','ACCOUNT_DISABLED',false],
    [null,'SUBSCRIPTION_FORBIDDEN',false],[null,'SUBSCRIPTION_CONFLICT',false],
    ['active','INDIVIDUAL_SCOPE_NOT_READY',false],[null,'SUBSCRIPTION_UNAVAILABLE',false],
  ])await t.test('valid '+(code??'active/null'),async()=>{
    item={...base,status,code,isEntitled,endsAt:status===null?null:base.endsAt};
    assert.deepEqual((await core.list(who.id,who.session,'customers',null,null,25)).items,[item]);
  });
});
