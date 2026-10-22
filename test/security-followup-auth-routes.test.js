import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import jwt from 'jsonwebtoken';
import {createHash,randomUUID} from 'node:crypto';
import {once} from 'node:events';
import {mountPasswordAuth} from '../src/passwordAuth.js';
import {mountSubscriptionSales} from '../src/subscriptionSales.js';
import {createWebAuthGuard,webAuthErrorHandler} from '../src/webAuth.js';
import {database,rpcAdapter,privileged,start,accept,verify,command} from './support/mfaDevice.js';
import {customer,fixturePassword,fixtureHash,ready,cutover} from './support/passwordAuth.js';
import {rpcAdapter as salesAdapter} from './support/subscriptionPhase3.js';
const origin='https://fixture.example',secret='followup-auth-routes-fixture-only';
const env={AUTH_PUBLIC_ORIGIN:origin,AUTH_ALLOWED_ORIGINS:origin,AUTH_TOKEN_HMAC_KEY:'a'.repeat(64),AUTH_RATE_HMAC_KEY:'b'.repeat(64)};
const tokens={generateAccessToken:(u,s)=>jwt.sign({id:u.id,sessionId:s,type:'access'},secret,{expiresIn:'15m'}),generateRefreshToken:(u,s)=>jwt.sign({id:u.id,sessionId:s,type:'refresh'},secret,{expiresIn:'30d'}),hashToken:t=>createHash('sha256').update(t).digest('hex'),verifyToken:t=>jwt.verify(t,secret)};
async function server(t,app){const s=app.listen(0,'127.0.0.1');await once(s,'listening');t.after(async()=>{s.closeAllConnections();await new Promise(r=>s.close(r));});return 'http://127.0.0.1:'+s.address().port;}
const authenticate=db=>async(req,res,next)=>{try{const d=jwt.verify(req.get('Authorization')?.replace(/^Bearer /,''),secret);if(d.type!=='access')return res.sendStatus(401);const good=(await db.query("SELECT public.keeptimer_auth_session($1,$2,'web',NULL) AS yes",[d.id,d.sessionId])).rows[0].yes;if(!good)return res.sendStatus(401);req.user=(await db.query('SELECT id,role,workspace_id FROM users WHERE id=$1',[d.id])).rows[0];req.sessionId=d.sessionId;next();}catch{return res.sendStatus(401);}};

test('followup auth HTTP: activation/reset consume, single-use, owned sessions and revoke-all have DB/side-effect proof',async t=>{
 const db=await database(t),c=await customer(db,'owner@example.test'),app=express(),sent=[];
 app.use('/auth',createWebAuthGuard(new Set([origin])));app.use(express.json());
 const core=mountPasswordAuth({app,db:rpcAdapter(db),tokens,env,authenticate:authenticate(db),mail:{configured:()=>true,send:async m=>{sent.push(m);return {accepted:true};}}});t.after(core.stopWorker);app.use(webAuthErrorHandler);const base=await server(t,app);
 const post=(p,body,access)=>fetch(base+'/auth/'+p,{method:'POST',headers:{Origin:origin,'Content-Type':'application/json','X-KeepTimer-CSRF':'1',...(access?{Authorization:'Bearer '+access}:{})},body:JSON.stringify(body)});
 assert.equal((await post('activation/request',{email:'owner@example.test'})).status,200);await core.drainLinks();
 const link=()=>{const u=new URL(sent.at(-1).url),q=new URLSearchParams(u.hash.slice(1));assert.equal(u.origin,origin);return {challengeId:q.get('id'),context:q.get('token'),password:fixturePassword};};
 const activation=link(),done=await post('activation/complete',activation);assert.equal(done.status,200);const result=await done.json();assert.equal(result.loginReady,true);assert.equal(result.accessToken,undefined);assert.equal(result.userId,c.id);assert.equal((await post('activation/complete',activation)).status,401);
 let login=await post('password-login',{email:'owner@example.test',password:fixturePassword});assert.equal(login.status,200);let session=await login.json();
 const listed=await post('sessions/list',{},session.accessToken);assert.equal(listed.status,200);assert.ok((await listed.json()).sessions.some(x=>x.id===session.sessionId||x.sessionId===session.sessionId));
 assert.equal((await post('reset/request',{email:'owner@example.test'})).status,200);await core.drainLinks();const reset={...link(),password:'Reset-Synthetic-Password-2026!'};assert.equal((await post('reset/complete',reset)).status,200);assert.equal((await post('reset/complete',reset)).status,401);assert.equal((await post('sessions/list',{},session.accessToken)).status,401);
 assert.equal((await db.query('SELECT revoked_at IS NOT NULL AS revoked FROM sessions WHERE id=$1',[session.sessionId])).rows[0].revoked,true);
 login=await post('password-login',{email:'owner@example.test',password:reset.password});assert.equal(login.status,200);session=await login.json();assert.equal((await post('sessions/revoke-all',{},session.accessToken)).status,200);assert.equal((await post('sessions/list',{},session.accessToken)).status,401);
 assert.equal((await db.query('SELECT count(*)::int AS n FROM sessions WHERE user_id=$1 AND revoked_at IS NULL',[c.id])).rows[0].n,0);assert.equal(sent.length,2);
});

test('followup sales HTTP: exact Superadmin Agent lifecycle routes reject lower role and keep secrets outside responses',async t=>{
 // Full isolated installation: the preparation-only device fixture deliberately
 // omits the cutover sales wrapper that accepts the current email contract.
 // Run the unchanged guarded migration with closed fixture gates, before users.
 const db=await database(t,{enabled:false});await db.exec("SET keeptimer.phase7_cutover='confirmed-maintenance'");await db.exec(cutover);await db.exec('UPDATE keeptimer_auth_release SET enabled=true');
 const sa=await privileged(db),pending=await start(db,sa);await accept(db,pending.args);const factor=verify(pending.args);assert.equal((await command(db,'verify',factor)).ok,true);sa.session=factor.session_id;await db.exec('UPDATE keeptimer_sales_release SET enabled=true');
 process.env.SUBSCRIPTION_IDEMPOTENCY_HMAC_KEY='a'.repeat(64);
 const app=express();app.use(express.json());const adapter=salesAdapter(db);mountSubscriptionSales({app,authenticate:authenticate(db),db:adapter,origins:new Set([origin])});const base=await server(t,app),access=tokens.generateAccessToken({id:sa.id},sa.session);
 const call=(path,body)=>fetch(base+path,{method:body===undefined?'GET':'POST',headers:{Origin:origin,'Content-Type':'application/json','X-KeepTimer-CSRF':'1','Idempotency-Key':randomUUID(),Authorization:'Bearer '+access},...(body===undefined?{}:{body:JSON.stringify(body)})});
 const made=await call('/admin/agents',{username:'followup_agent',mfaEmail:'agent@example.test'});const agent=await made.json();assert.equal(made.status,200,JSON.stringify(agent));assert.equal(agent.loginReady,false);assert.equal(agent.mustChangePassword,true);assert.ok(agent.agentId);
 const list=await call('/admin/agents');assert.equal(list.status,200);assert.ok((await list.json()).items.some(x=>x.id===agent.agentId));
 // Controlled isolated second factor, not a real provider/MFA acceptance claim.
 await db.query('UPDATE users SET password_hash=$1 WHERE id=$2',[fixtureHash,agent.agentId]);await ready(db,agent.agentId);
 const second=await start(db,{id:agent.agentId});await accept(db,second.args);const agentFactor=verify(second.args);assert.equal((await command(db,'verify',agentFactor)).ok,true);
 const agentAccess=tokens.generateAccessToken({id:agent.agentId},agentFactor.session_id);
 const before=(await db.query('SELECT (SELECT count(*) FROM users)::int AS users,(SELECT count(*) FROM admin_audit_log)::int AS audit,(SELECT count(*) FROM keeptimer_sales_requests)::int AS receipts')).rows;
 for(const [path,body] of [['/admin/agents',undefined],['/admin/agents',{username:'forged_agent',mfaEmail:'forged@example.test'}],['/admin/agents/'+agent.agentId+'/revoke',{}]]){
  const denied=await fetch(base+path,{method:body===undefined?'GET':'POST',headers:{Origin:origin,'Content-Type':'application/json','X-KeepTimer-CSRF':'1','Idempotency-Key':randomUUID(),Authorization:'Bearer '+agentAccess},...(body===undefined?{}:{body:JSON.stringify(body)})});assert.equal(denied.status,403);assert.doesNotMatch(await denied.text(),/password_hash|pin_hash|refresh_token/);
 }
 assert.deepEqual((await db.query('SELECT (SELECT count(*) FROM users)::int AS users,(SELECT count(*) FROM admin_audit_log)::int AS audit,(SELECT count(*) FROM keeptimer_sales_requests)::int AS receipts')).rows,before);
 for(const p of ['/admin/agents/'+agent.agentId+'/password-reset','/agent/customers/'+agent.agentId+'/password-reset']){const r=await call(p,{});assert.equal(r.status,403);assert.doesNotMatch(await r.text(),/password_hash|pin_hash|refresh_token/);}
 const revoke=await call('/admin/agents/'+agent.agentId+'/revoke',{});assert.equal(revoke.status,200);assert.equal((await db.query('SELECT disabled_at IS NOT NULL AS disabled FROM users WHERE id=$1',[agent.agentId])).rows[0].disabled,true);
});
