import test from 'node:test';
import assert from 'node:assert/strict';
import {once} from 'node:events';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import {createHash,randomUUID} from 'node:crypto';
import express from 'express';
import {mountPasswordAuth,createPasswordAuth,validateAuthPassword,normalizeAuthEmail} from '../src/passwordAuth.js';
import {createAuthEmail} from '../src/authEmail.js';
import {createWebAuthGuard,webAuthErrorHandler} from '../src/webAuth.js';
import {nativeAuthGuard} from '../src/nativeAuth.js';
import {customer,privileged,enable,ready,fixturePassword,fixtureHash} from './support/passwordAuth.js';
import {database as deviceDatabase,rpcAdapter} from './support/mfaDevice.js';
// The latest HTTP contract uses the additive MFA schema. No cutover SQL is
// executed: deviceDatabase provisions only isolated test gate state.
async function database(t){const db=await deviceDatabase(t);await db.exec('UPDATE keeptimer_auth_release SET enabled=false');return db;}
const origin='https://fixture.example';
const env={AUTH_TOKEN_HMAC_KEY:'a'.repeat(64),AUTH_RATE_HMAC_KEY:'b'.repeat(64),AUTH_PUBLIC_ORIGIN:origin,AUTH_ALLOWED_ORIGINS:origin};
const tokens={generateAccessToken:(u,s)=>jwt.sign({id:u.id,sessionId:s,type:'access'},'test-password-http-secret',{expiresIn:'15m'}),
 generateRefreshToken:(u,s)=>jwt.sign({id:u.id,sessionId:s,type:'refresh'},'test-password-http-secret',{expiresIn:'30d'}),
 hashToken:t=>createHash('sha256').update(t).digest('hex'),verifyToken:t=>jwt.verify(t,'test-password-http-secret')};
test('password HTTP: fail-closed rollout, pending login, generic errors, real session/cookie and MFA',async t=>{
 const db=await database(t),c=await customer(db),p=await privileged(db);const sent=[];
 const mail={configured:()=>true,send:async m=>{sent.push(m);return {accepted:true};}};
 const app=express();app.use('/auth',createWebAuthGuard(new Set([origin])));app.use(express.json());
 const core=mountPasswordAuth({app,db:rpcAdapter(db),tokens,mail,env,authenticate:(_req,res)=>res.sendStatus(401)});t.after(core.stopWorker);app.use(webAuthErrorHandler);
 const server=app.listen(0,'127.0.0.1');await once(server,'listening');t.after(async()=>{server.closeAllConnections();await new Promise(r=>server.close(r));});
 const base=`http://127.0.0.1:${server.address().port}`;
 const post=(path,body,headers={})=>fetch(base+'/auth/'+path,{method:'POST',headers:{Origin:origin,'Content-Type':'application/json','X-KeepTimer-CSRF':'1',...headers},body:JSON.stringify(body)});
 assert.equal((await post('password-login',{email:'owner@example.test',password:fixturePassword})).status,503);
 await enable(db);
 const bad1=await post('password-login',{email:'owner@example.test',password:fixturePassword});
 const bad2=await post('password-login',{email:'unknown@example.test',password:fixturePassword});
 assert.equal(bad1.status,401);assert.equal(bad2.status,401);assert.deepEqual(await bad1.json(),await bad2.json());
 assert.equal((await post('reset/request',{email:'owner@example.test'})).status,200);await core.drainLinks();assert.equal(sent.length,0);
 await ready(db,c.id);await ready(db,p.id);
 const login=await post('password-login',{email:'OWNER@example.test',password:fixturePassword}),body=await login.json();
 assert.equal(login.status,200);assert.equal(body.user.id,c.id);assert.ok(body.accessToken);assert.equal(body.refreshToken,undefined);
 assert.match(login.headers.get('set-cookie'),/HttpOnly/);assert.match(login.headers.get('set-cookie'),/Secure/);assert.match(login.headers.get('set-cookie'),/SameSite=Lax/);
 assert.equal((await post('password-login',{email:'admin@example.test',password:fixturePassword+'wrong'})).status,401);
 const bootstrap=await post('mfa/status',{}),device=bootstrap.headers.getSetCookie()[0].split(';')[0];
 const first=await post('password-login',{email:'admin@example.test',password:fixturePassword,operationId:randomUUID()},{Cookie:device});const challenge=await first.json();
 assert.equal(first.status,200);assert.equal(challenge.mfaRequired,true);
 const preauth=first.headers.getSetCookie().at(-1).split(';')[0],cookie=device+'; '+preauth;
 assert.match(preauth,/^__Secure-keeptimer-mfa=/);assert.doesNotMatch(first.headers.get('set-cookie'),/keeptimer-refresh/);
 for(const field of ['accessToken','refreshToken','sessionId','user'])assert.equal(challenge[field],undefined);
 assert.equal(sent.length,1);assert.match(sent[0].code,/^\d{8}$/);
 const verify={challengeId:challenge.challengeId,context:challenge.context,code:sent[0].code,operationId:randomUUID()};
 assert.equal((await post('mfa/verify',{...verify,mfaPassed:true},{Cookie:cookie})).status,400);
 assert.equal((await post('mfa/verify',verify)).status,409);
 assert.equal((await post('mfa/verify',verify,{Cookie:cookie+'; __Secure-keeptimer-refresh=new-account-session'})).status,409);
 const complete=await post('mfa/verify',verify,{Cookie:cookie});assert.equal(complete.status,200);const privilegedBody=await complete.json();assert.equal(privilegedBody.user.id,p.id);
 assert.notEqual(privilegedBody.sessionId,body.sessionId);assert.equal((await post('mfa/verify',verify,{Cookie:cookie})).status,409);
 for(const response of [login,first,complete,bad1])for(const header of ['Cache-Control','CDN-Cache-Control','Vercel-CDN-Cache-Control'])assert.equal(response.headers.get(header),'no-store');
 const cache=(await db.query('SELECT context_id,proof_digest FROM keeptimer_mfa_challenges')).rows[0];
 assert.ok(!JSON.stringify(cache).includes(sent[0].code));assert.ok(!JSON.stringify(cache).includes(challenge.context));
 const resetReady=await post('reset/request',{email:'admin@example.test'});assert.equal(resetReady.status,200);
 assert.equal((await post('reset/request',{email:'absent@example.test'})).status,200);
 for(const forged of [{userId:c.id},{mfaPassed:true},{role:'superadmin'},{workspace_id:c.workspace}])assert.equal((await post('password-login',{email:'owner@example.test',password:fixturePassword,...forged})).status,400);
 assert.equal((await post('password-login',{email:'owner@example.test',password:fixturePassword},{Origin:'https://evil.example'})).status,403);
 assert.equal((await fetch(base+'/auth/activation/complete',{headers:{Origin:origin}})).status,405);
});
test('email adapter: no fallback, fixed HTTPS/idempotency, sanitized provider failures',async()=>{
 const incomplete=createAuthEmail({},()=>assert.fail('no request without config'));assert.equal(incomplete.configured(),false);
 await assert.rejects(incomplete.send({}),/AUTH_NOT_READY/);
 const config={AUTH_EMAIL_PROVIDER:'resend',AUTH_EMAIL_FROM:'security@example.test',RESEND_API_KEY:'synthetic-send-key-only'};let calls=0;
 const mail=createAuthEmail(config,async(url,options)=>{
  calls++;assert.equal(url,'https://api.resend.com/emails');assert.equal(options.redirect,'error');assert.ok(options.signal);
  assert.match(options.headers['Idempotency-Key'],/^keeptimer-auth-/);const payload=JSON.parse(options.body);
  assert.match(payload.text,/12345678/);assert.equal(payload.password,undefined);return new Response(JSON.stringify({id:'test-provider-id'}));
 });
 assert.deepEqual(await mail.send({to:'owner@example.test',purpose:'mfa',code:'12345678',challengeId:'fixture',generation:1}),{accepted:true});assert.equal(calls,1);
 const broken=createAuthEmail(config,async()=>new Response('PRIVATE-PROVIDER-SECRET',{status:500}));
 await assert.rejects(broken.send({}),e=>e.message==='AUTH_EMAIL_UNAVAILABLE');
});
test('bcrypt12 byte boundary, deterministic ASCII email and no development fallback',async()=>{
 assert.equal(validateAuthPassword('😀'.repeat(16)),'😀'.repeat(16));
 for(const value of ['short','x'.repeat(73),'😀'.repeat(19),'123456789012345\n'])assert.throws(()=>validateAuthPassword(value));
 assert.equal(normalizeAuthEmail('  OWNER+tag@EXAMPLE.TEST '),'owner+tag@example.test');
 for(const value of ['a@b','a b@example.test','ü@example.test',null])assert.throws(()=>normalizeAuthEmail(value));
 const core=createPasswordAuth({db:{rpc:()=>assert.fail('no request without email config')},tokens,env:{...env,NODE_ENV:'development'}});
 await assert.rejects(core.requestLink({email:'a@example.test'},'127.0.0.1','activation'),e=>e.code==='AUTH_NOT_READY');
 const hash=await bcrypt.hash(fixturePassword,12);assert.match(hash,/^\$2b\$12\$/);assert.ok(!hash.includes(fixturePassword));
});
test('activated/expired Individual password login is provider-independent; native transport remains worker-only',async t=>{
 const db=await database(t),c=await customer(db,'expired@example.test',{starts_at:'2000-01-01Z',ends_at:'2001-01-01Z'}),p=await privileged(db);
 await enable(db);await ready(db,c.id);await ready(db,p.id);
 const mail={configured:()=>false,send:()=>assert.fail('mail is absent')};
 const core=createPasswordAuth({db:rpcAdapter(db),tokens,mail,env});
 const result=await core.passwordLogin({email:'expired@example.test',password:fixturePassword},'127.0.0.1','web');
 assert.equal(result.user.id,c.id);assert.ok(result.accessToken);
 assert.equal((await db.query('SELECT keeptimer_resolve_entitlement($1) AS e',[c.id])).rows[0].e.isEntitled,false);
 await assert.rejects(core.passwordLogin({email:'admin@example.test',password:fixturePassword},'127.0.0.1','web'),e=>e.code==='AUTH_NOT_READY');
 for(const purpose of ['activation','reset'])await assert.rejects(core.requestLink({email:'expired@example.test'},'127.0.0.1',purpose),e=>e.code==='AUTH_NOT_READY');
 const app=express();app.use('/auth/native',nativeAuthGuard);app.use(express.json());
 const mounted=mountPasswordAuth({app,db:rpcAdapter(db),tokens,mail,env,authenticate:(_req,res)=>res.sendStatus(401)});t.after(mounted.stopWorker);
 const server=app.listen(0,'127.0.0.1');await once(server,'listening');t.after(async()=>{server.closeAllConnections();await new Promise(r=>server.close(r));});
 const post=(email,extra={},password=fixturePassword)=>fetch(`http://127.0.0.1:${server.address().port}/auth/native/passwordLogin`,{method:'POST',headers:{'Content-Type':'application/json',...extra},body:JSON.stringify({email,password})});
 const native=await post('expired@example.test');assert.equal(native.status,200);assert.equal(native.headers.get('set-cookie'),null);
 const value=await native.json();assert.equal(value.user.id,c.id);assert.ok(value.refreshToken);assert.ok(value.accessToken);
 assert.equal((await post('expired@example.test',{},fixturePassword+'wrong')).status,401);
 assert.equal((await post('admin@example.test')).status,401);
 assert.equal((await post('expired@example.test',{Origin:origin})).status,403);
 const pending=await customer(db,'pending-native@example.test');
 assert.equal((await post('pending-native@example.test')).status,401);
 assert.equal((await db.query('SELECT activated_at FROM keeptimer_auth_accounts WHERE user_id=$1',[pending.id])).rows[0].activated_at,null);
});

test('link-request HTTP envelopes match every account state even while worker account lookup is blocked',async t=>{
 const db=await database(t);await enable(db);
 const active=await customer(db,'active@example.test');await ready(db,active.id);
 await customer(db,'pending@example.test');
 const expired=await customer(db,'expired@example.test',{starts_at:'2000-01-01Z',ends_at:'2001-01-01Z'});await ready(db,expired.id);
 // Phase 3 deliberately forbids disabling an Individual via a raw users update.
 // A disabled Agent exercises the auth eligibility path without bypassing that invariant.
 const disabled=(await db.query("SELECT id FROM users WHERE role='agent' AND disabled_at IS NULL")).rows[0];
 await db.query('SELECT keeptimer_auth_prepare($1,$2,$3)',[disabled.id,'disabled@example.test',fixtureHash]);await ready(db,disabled.id);
 await db.query('UPDATE users SET disabled_at=clock_timestamp() WHERE id=$1',[disabled.id]);
 const seen=[],adapter=rpcAdapter(db);let unblock;const gate=new Promise(r=>{unblock=r;});
 const wrapped={rpc:async(name,args)=>{seen.push([name,args.p_action]);if(name==='keeptimer_auth_command' && args.p_action==='lookup')await gate;return adapter.rpc(name,args);}};
 const mail={configured:()=>true,send:async()=>({accepted:true})};
 const app=express();app.use('/auth',createWebAuthGuard(new Set([origin])));app.use(express.json());
 const core=mountPasswordAuth({app,db:wrapped,tokens,mail,env,authenticate:(_req,res)=>res.sendStatus(401)});
 const server=app.listen(0,'127.0.0.1');await once(server,'listening');
 t.after(async()=>{unblock();await core.drainLinks();core.stopWorker();server.closeAllConnections();await new Promise(r=>server.close(r));});
 const envelopes=[],timings=[];
 for(const purpose of ['reset','activation'])for(const email of ['unknown@example.test','pending@example.test','active@example.test','expired@example.test','disabled@example.test']){
  const start=performance.now();
  const res=await fetch(`http://127.0.0.1:${server.address().port}/auth/${purpose}/request`,{method:'POST',signal:AbortSignal.timeout(3000),headers:{Origin:origin,'Content-Type':'application/json','X-KeepTimer-CSRF':'1'},body:JSON.stringify({email})});
  timings.push({purpose,state:email.split('@')[0],milliseconds:Number((performance.now()-start).toFixed(2))});
  envelopes.push({status:res.status,body:await res.json(),cache:res.headers.get('cache-control'),cdn:res.headers.get('cdn-cache-control'),cookie:res.headers.get('set-cookie'),retry:res.headers.get('retry-after')});
 }
 for(const value of envelopes)assert.deepEqual(value,envelopes[0]);assert.equal(envelopes[0].status,200);
 assert.equal(seen.filter(([name,action])=>name==='keeptimer_auth_link_queue_rpc' && action==='enqueue').length,10);
 // Request success before gate release proves response does not await eligibility.
 t.diagnostic('Informational latency samples (NOT proof of equal timing): '+JSON.stringify(timings));
 unblock();await core.drainLinks();
});
