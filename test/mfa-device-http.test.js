import test from 'node:test';
import assert from 'node:assert/strict';
import {once} from 'node:events';
import {createHash,randomUUID} from 'node:crypto';
import jwt from 'jsonwebtoken';
import express from 'express';
import {mountPasswordAuth,createPasswordAuth} from '../src/passwordAuth.js';
import {seededCustomer} from './support/subscriptionPhase3.js';
import {createAuthEmail} from '../src/authEmail.js';
import {createWebAuthGuard,webAuthErrorHandler} from '../src/webAuth.js';
import {database,privileged,rpcAdapter,fixturePassword} from './support/mfaDevice.js';
const origin='https://fixture.example',env={AUTH_TOKEN_HMAC_KEY:'a'.repeat(64),AUTH_RATE_HMAC_KEY:'b'.repeat(64),AUTH_PUBLIC_ORIGIN:origin,AUTH_ALLOWED_ORIGINS:origin};
const tokens={generateAccessToken:(u,s)=>jwt.sign({id:u.id,sessionId:s,type:'access'},'synthetic-mfa-test-only',{expiresIn:'15m'}),
 generateRefreshToken:(u,s)=>jwt.sign({id:u.id,sessionId:s,type:'refresh'},'synthetic-mfa-test-only',{expiresIn:'30d'}),
 hashToken:t=>createHash('sha256').update(t).digest('hex'),verifyToken:t=>jwt.verify(t,'synthetic-mfa-test-only')};
async function fixture(t){
 const db=await database(t),account=await privileged(db),messages=[];let behavior='accepted';
 const mail={configured:()=>true,send:async m=>{messages.push(m);if(behavior==='unknown')throw new Error('provider timeout');if(behavior==='rejected')throw Object.assign(new Error('provider rejection'),{delivery:'rejected'});return {accepted:true};}};
 const app=express();app.use('/auth',createWebAuthGuard(new Set([origin])));app.use(express.json());
 const core=mountPasswordAuth({app,db:rpcAdapter(db),tokens,mail,env,authenticate:(_req,res)=>res.sendStatus(401)});t.after(core.stopWorker);app.use(webAuthErrorHandler);
 const server=app.listen(0,'127.0.0.1');await once(server,'listening');t.after(async()=>{server.closeAllConnections();await new Promise(r=>server.close(r));});
 function browser(){const jar=new Map();return {jar,async post(path,body={},headers={}){
  const response=await fetch(`http://127.0.0.1:${server.address().port}/auth/${path}`,{method:'POST',headers:{Origin:origin,'Content-Type':'application/json','X-KeepTimer-CSRF':'1',Cookie:[...jar].map(([k,v])=>k+'='+v).join('; '),...headers},body:JSON.stringify(body)});
  for(const cookie of response.headers.getSetCookie()){const first=cookie.split(';')[0],i=first.indexOf('=');jar.set(first.slice(0,i),first.slice(i+1));}
  return {response,data:await response.json()};
 }};}
 return {db,account,messages,browser,mail,setBehavior:v=>{behavior=v;}};
}
const login=()=>({email:'admin@example.test',password:fixturePassword,operationId:randomUUID()});
test('HTTP bootstrap, HttpOnly signed context, lost first response resume, OTP session, tamper and CSRF',async t=>{
 const f=await fixture(t),b=f.browser();
 const noCookie=await b.post('password-login',login());assert.equal(noCookie.data.code,'MFA_CONTEXT_REQUIRED');assert.equal(f.messages.length,0);
 const init=await b.post('mfa/status');assert.equal(init.data.phase,'idle');
 const cookie=init.response.headers.getSetCookie()[0];for(const text of ['HttpOnly','Secure','SameSite=Lax','Path=/api/auth'])assert.ok(cookie.includes(text));
 const body=login(),first=await b.post('password-login',body);assert.equal(first.data.mfaRequired,true);assert.equal(first.data.delivery,'accepted');
 assert.equal(first.data.attemptsRemaining,6);assert.match(f.messages[0].code,/^\d{8}$/);
 const repeated=await b.post('password-login',body);assert.equal(repeated.data.challengeId,first.data.challengeId);assert.equal(f.messages.length,1);
 const state=await b.post('mfa/status');assert.equal(state.data.state.challengeId,first.data.challengeId);
 const {challengeId,context}=first.data,v={challengeId,context,code:f.messages[0].code,operationId:randomUUID()};
 assert.equal((await b.post('mfa/verify',{...v,deviceId:'forged'})).response.status,400);
 assert.equal((await b.post('mfa/verify',v,{Origin:'https://evil.example'})).response.status,403);
 const device=b.jar.get('__Secure-keeptimer-mfa-device');b.jar.set('__Secure-keeptimer-mfa-device',device.slice(0,-1)+(device.endsWith('A')?'B':'A'));
 assert.equal((await b.post('mfa/verify',v)).data.code,'MFA_CONTEXT_REQUIRED');b.jar.set('__Secure-keeptimer-mfa-device',device);
 const done=await b.post('mfa/verify',v);assert.equal(done.response.status,200);assert.equal(done.data.user.id,f.account.id);
 assert.equal(tokens.verifyToken(done.data.accessToken).id,f.account.id);assert.equal(done.data.refreshToken,undefined);
 assert.equal((await f.db.query('SELECT count(*)::int AS n FROM sessions')).rows[0].n,1);
 assert.notEqual((await b.post('mfa/verify',v)).response.status,200);
});
test('followup MFA HTTP resend: cooldown, clock-bound resend, old-code denial and one-session consume',async t=>{
 const f=await fixture(t),b=f.browser();await b.post('mfa/status');const first=(await b.post('password-login',login())).data;
 const body={challengeId:first.challengeId,context:first.context,operationId:randomUUID()},oldCode=f.messages[0].code;
 const tooSoon=await b.post('mfa/resend',body);assert.equal(tooSoon.response.status,429);assert.equal(tooSoon.data.code,'MFA_RESEND_COOLDOWN');assert.equal(f.messages.length,1);
 await f.db.exec("UPDATE keeptimer_mfa_sends SET created_at=clock_timestamp()-interval '61 seconds'");
 const resent=await b.post('mfa/resend',{...body,operationId:randomUUID()});assert.equal(resent.response.status,200);assert.equal(f.messages.length,2);
 const current={challengeId:first.challengeId,context:first.context,operationId:randomUUID()};
 assert.equal((await b.post('mfa/verify',{...current,code:oldCode})).response.status,401);
 assert.equal((await b.post('mfa/verify',{...current,operationId:randomUUID(),code:f.messages.at(-1).code})).response.status,200);
 assert.equal((await f.db.query('SELECT count(*)::int AS n FROM sessions')).rows[0].n,1);
});

test('HTTP sixth wrong returns precise lock/retry; new login same device stays locked, independent device succeeds',async t=>{
 const f=await fixture(t),a=f.browser(),b=f.browser();await a.post('mfa/status');await b.post('mfa/status');
 const first=(await a.post('password-login',login())).data;
 for(let n=1;n<=6;n++){
  const wrong=await a.post('mfa/verify',{challengeId:first.challengeId,context:first.context,code:'00000000'===f.messages[0].code?'11111111':'00000000',operationId:randomUUID()});
  assert.equal(wrong.data.state.attemptsRemaining,6-n);
  if(n===6){assert.equal(wrong.data.code,'MFA_ATTEMPTS_EXHAUSTED');assert.equal(wrong.response.headers.get('Retry-After'),'600');}
 }
 assert.equal((await a.post('password-login',login())).data.code,'MFA_DEVICE_LOCKED');
 assert.equal((await a.post('mfa/status')).data.code,'MFA_DEVICE_LOCKED');
 const other=(await b.post('password-login',login())).data;assert.equal(other.phase,'challenge');
 assert.equal((await b.post('mfa/verify',{challengeId:other.challengeId,context:other.context,code:f.messages.at(-1).code,operationId:randomUUID()})).response.status,200);
});
test('provider acceptance followed by lost HTTP is recoverable; unknown retries same email payload/key without new send',async t=>{
 const f=await fixture(t),b=f.browser();await b.post('mfa/status');f.setBehavior('unknown');
 const first=(await b.post('password-login',login())).data;assert.equal(first.delivery,'unknown');
 const original=f.messages[0];f.setBehavior('accepted');
 await f.db.exec("UPDATE keeptimer_mfa_sends SET lease_until=clock_timestamp()-interval '1 second'");
 // New core has no in-memory delivery/challenge state: process restart recovery.
 const restarted=createPasswordAuth({db:rpcAdapter(f.db),tokens,mail:f.mail,env});
 const recovered=await restarted.mfa.status({headers:{cookie:[...b.jar].map(([k,v])=>k+'='+v).join('; ')},ip:'127.0.0.1'},{cookie:()=>assert.fail('cookie already present')});
 assert.equal(recovered.state.delivery,'accepted');
 assert.deepEqual(f.messages[1],original);
 assert.equal((await f.db.query('SELECT count(*)::int AS n FROM keeptimer_mfa_sends')).rows[0].n,1);
});
test('Individual login remains mail-independent; privileged first factor fails closed without provider',async t=>{
 const db=await database(t),admin=await privileged(db),customer=await seededCustomer(db,admin);
 await db.query('SELECT keeptimer_auth_prepare($1,$2,$3)',[customer.id,'individual@example.test',(await db.query('SELECT password_hash FROM users WHERE id=$1',[customer.id])).rows[0].password_hash]);
 await db.query('UPDATE keeptimer_auth_accounts SET verified_at=clock_timestamp(),activated_at=clock_timestamp() WHERE user_id=$1',[customer.id]);
 await db.query('UPDATE users SET must_change_password=false WHERE id=$1',[customer.id]);
 const core=createPasswordAuth({db:rpcAdapter(db),tokens,env,mail:{configured:()=>false,send:()=>assert.fail('mail must not be used')}});
 const result=await core.passwordLogin({email:'individual@example.test',password:fixturePassword},'127.0.0.1','web');assert.equal(result.user.id,customer.id);
 await assert.rejects(core.passwordLogin(login(),'127.0.0.2','web'),e=>e.code==='AUTH_NOT_READY');
 assert.equal((await db.query('SELECT count(*)::int AS n FROM keeptimer_mfa_sends')).rows[0].n,0);
});
test('mail adapter distinguishes rejection/unknown, fixed payload/idempotency and absolute expiry',async()=>{
 const config={AUTH_EMAIL_PROVIDER:'resend',AUTH_EMAIL_FROM:'security@example.test',RESEND_API_KEY:'synthetic-provider-key-only'};
 const input={to:'recipient@example.test',purpose:'mfa',code:'12345678',challengeId:'fixture',generation:'operation',expiresAt:'2026-10-16T12:02:00Z'};
 const mail=createAuthEmail(config,async(_url,options)=>{assert.ok(JSON.parse(options.body).text.includes(input.expiresAt));assert.equal(options.headers['Idempotency-Key'],'keeptimer-auth-fixture-operation');return new Response('{"id":"fixture"}');});
 assert.deepEqual(await mail.send(input),{accepted:true});
 for(const [status,delivery] of [[403,'rejected'],[429,'unknown'],[500,'unknown'],[409,'unknown']])
  await assert.rejects(createAuthEmail(config,async()=>new Response('private provider data',{status})).send(input),e=>e.message==='AUTH_EMAIL_UNAVAILABLE' && e.delivery===delivery && !JSON.stringify(e).includes('private provider'));
 await assert.rejects(createAuthEmail(config,async()=>{throw Error('timeout');}).send(input),e=>e.delivery==='unknown');
});
