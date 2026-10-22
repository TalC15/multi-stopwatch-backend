import test from 'node:test';
import assert from 'node:assert/strict';
import {once} from 'node:events';
import {randomUUID} from 'node:crypto';
import express from 'express';
import {mountSharedTimers} from '../src/sharedTimers.js';
import {mountSubscriptionSales} from '../src/subscriptionSales.js';
import {mountPasswordAuth} from '../src/passwordAuth.js';
import {createWebAuthGuard,webAuthErrorHandler} from '../src/webAuth.js';
import {database,rpcAdapter} from './support/mfaDevice.js';
import {customer,ready,privileged} from './support/passwordAuth.js';
const origin='https://fixture.example';
const env={AUTH_PUBLIC_ORIGIN:origin,AUTH_ALLOWED_ORIGINS:origin,AUTH_TOKEN_HMAC_KEY:'a'.repeat(64),AUTH_RATE_HMAC_KEY:'b'.repeat(64)};
async function serve(t,app){const server=app.listen(0,'127.0.0.1');await once(server,'listening');t.after(async()=>{server.closeAllConnections();await new Promise(r=>server.close(r));});return 'http://127.0.0.1:'+server.address().port;}

test('followup input: duplicate query grammar, nested/null/array/large JSON fail without RPC, broadcast or provider effects',async t=>{
 const calls=[],effects=[],app=express();app.use(express.json());
 const db={rpc:async()=>{calls.push('rpc');assert.fail('invalid input must not reach DB');}};
 const auth=(req,_res,next)=>{req.user={id:randomUUID(),workspace_id:randomUUID(),role:'agent'};req.sessionId=randomUUID();next();};
 mountSubscriptionSales({app,authenticate:auth,db,origins:new Set([origin])});
 const shared=mountSharedTimers({app,authenticate:auth,db,io:{to:()=>({emit:()=>effects.push('broadcast')})},sendTelegramMessage:()=>effects.push('provider')});t.after(shared.dispose);
 app.use(webAuthErrorHandler);const base=await serve(t,app);
 const headers={Origin:origin,'Content-Type':'application/json','X-KeepTimer-CSRF':'1','Idempotency-Key':randomUUID()};
 for(const query of ['limit=1&limit=100','limit[]=1','limit[gt]=1','after=x&after=y','limit=100000000000000000000']){
  const r=await fetch(base+'/agent/customers?'+query,{headers});assert.equal(r.status,400);assert.doesNotMatch(await r.text(),/SELECT|stack|password_hash/);
 }
 const good={protocol:5,command:'create',timerId:randomUUID(),mutationId:randomUUID(),expectedRevision:'0',name:'Valid',type:'up',targetMinutes:1};
 let nested={};for(let i=0;i<128;i++)nested={child:nested};
 for(const value of [null,[],{...good,name:null},{...good,name:['array']},{...good,targetMinutes:{value:1}},{...good,actor:nested},{...good,...Object.fromEntries(Array.from({length:256},(_,i)=>['extra'+i,i]))},{...good,name:'x'.repeat(4096)}]){
  const r=await fetch(base+'/timers/shared/commands',{method:'POST',headers,body:JSON.stringify(value)});assert.equal(r.status,400);
 }
 const over=await fetch(base+'/timers/shared/commands',{method:'POST',headers,body:JSON.stringify({...good,name:'x'.repeat(128*1024)})});assert.equal(over.status,413);
 assert.deepEqual(calls,[]);assert.deepEqual(effects,[]);assert.equal({}.polluted,undefined);
});

test('followup mail: hostile Host/forwarded URL cannot poison activation link; repeated account-state envelopes have equal status/body/length',async t=>{
 const db=await database(t),pending=await customer(db,'pending@example.test'),active=await customer(db,'active@example.test'),expired=await customer(db,'expired@example.test',{starts_at:'2000-01-01Z',ends_at:'2001-01-01Z'}),disabled=await privileged(db,'disabled@example.test');
 await ready(db,active.id);await ready(db,expired.id);await db.query('UPDATE users SET disabled_at=clock_timestamp() WHERE id=$1',[disabled.id]);
 const app=express();app.use('/auth',createWebAuthGuard(new Set([origin])));app.use(express.json());const sent=[];
 const adapter=rpcAdapter(db);let release,lookupStarted=false;const held=new Promise(r=>{release=r;});
 const controlled={rpc:async(name,args)=>{if(name==='keeptimer_auth_command'&&args.p_action==='lookup'){lookupStarted=true;await held;}return adapter.rpc(name,args);}};
 const core=mountPasswordAuth({app,db:controlled,env,tokens:{},authenticate:(_req,res)=>res.sendStatus(401),mail:{configured:()=>true,send:async m=>{sent.push(m);return {accepted:true};}}});t.after(()=>{release();core.stopWorker();});app.use(webAuthErrorHandler);const base=await serve(t,app);
 const states=['unknown@example.test','pending@example.test','active@example.test','expired@example.test','disabled@example.test'];const timing=[];let expectedText;
 for(let round=0;round<4;round++)for(const email of states){
  const start=performance.now(),r=await fetch(base+'/auth/activation/request',{method:'POST',headers:{Origin:origin,'Content-Type':'application/json','X-KeepTimer-CSRF':'1',Host:'attacker.invalid','X-Forwarded-Host':'attacker.invalid','X-Forwarded-Proto':'http'},body:JSON.stringify({email})});
  const text=await r.text();timing.push({state:states.indexOf(email),ms:performance.now()-start});assert.equal(r.status,200);const body=JSON.parse(text);assert.equal(body.accepted,true);assert.deepEqual(Object.keys(body).sort(),['accepted','message']);expectedText??=text;assert.equal(text,expectedText);assert.equal(Buffer.byteLength(text),Buffer.byteLength(expectedText));assert.equal(r.headers.get('cache-control'),'no-store');
 }
 assert.ok(lookupStarted,'eligibility lookup is held while every HTTP request already finished');release();await core.drainLinks();assert.ok(sent.length>0);
 for(const m of sent){const u=new URL(m.url);assert.equal(u.origin,origin);assert.equal(u.pathname,'/account/activate');assert.ok(u.hash.startsWith('#id='));assert.ok(!m.url.includes('attacker'));}
 assert.equal((await db.query('SELECT activated_at FROM keeptimer_auth_accounts WHERE user_id=$1',[pending.id])).rows[0].activated_at,null);
 assert.equal(timing.length,20);assert.ok(timing.every(x=>Number.isFinite(x.ms)));
 // Four samples/state are exploratory, not a statistical constant-time claim.
});
