import test from 'node:test';
import assert from 'node:assert/strict';
import {once} from 'node:events';
import {randomUUID} from 'node:crypto';
import express from 'express';
import bcrypt from 'bcrypt';
import {mountPrivilegedManagement} from '../src/privilegedManagement.js';
import {database,enable,salesActor,customer,rpcAdapter,user} from './support/passwordAuth.js';

test('management HTTP uses real JWT/session middleware and MFA SQL; company PIN fallback and sales-closed administration work',async t=>{
 const db=await database(t);await enable(db);const sa=await salesActor(db,'superadmin'),agent=await salesActor(db);
 const company={id:await user(db,'worker'),session:randomUUID()};
 await db.query('INSERT INTO sessions(id,user_id,refresh_token_hash) VALUES($1,$2,$3)',[company.session,company.id,'company-fixture']);
 process.env.JWT_SECRET='management-http-fixture-only';process.env.SUPABASE_URL='http://127.0.0.1:54321';process.env.SUPABASE_SERVICE_KEY='management-fixture-only';
 const originalFetch=globalThis.fetch,adapter=rpcAdapter(db),origin='https://fixture.example';
 const json=(body,status=200)=>new Response(JSON.stringify(body),{status,headers:{'Content-Type':'application/json'}});
 globalThis.fetch=async(request,options={})=>{
  const url=new URL(request.url??request);assert.equal(url.origin,'http://127.0.0.1:54321');
  const table=url.pathname.split('/').at(-1),eq=k=>url.searchParams.get(k)?.replace(/^eq\./,'');
  if(table.startsWith('keeptimer_auth_')){const reply=await adapter.rpc(table,JSON.parse(options.body));return reply.error?json(reply.error,400):json(reply.data);}
  assert.ok(['users','sessions'].includes(table));
  const row=(await db.query(`SELECT * FROM ${table} WHERE id=$1`,[eq('id')])).rows[0];
  if(table==='sessions' && row && eq('user_id'))assert.equal(row.user_id,eq('user_id'));
  return row?json(row):json({code:'PGRST116'},406);
 };
 t.after(()=>{globalThis.fetch=originalFetch;});
 const auth=await import('../src/auth.js'),app=express(),revoked=[];app.use(express.json());
 mountPrivilegedManagement({app,authenticate:auth.authenticate,db:adapter,origins:new Set([origin]),onRevoke:id=>revoked.push(id)});
 app.get('/users',(_req,res)=>res.json({companyFallback:true}));
 const server=app.listen(0,'127.0.0.1');await once(server,'listening');
 t.after(async()=>{server.closeAllConnections();await new Promise(r=>server.close(r));});
 const call=(who,path,method='GET',body,headers={})=>originalFetch(`http://127.0.0.1:${server.address().port}${path}`,{
  method,headers:{Origin:origin,Authorization:`Bearer ${auth.generateAccessToken({id:who.id},who.session)}`,'Content-Type':'application/json','X-KeepTimer-CSRF':'1',...headers},
  ...(body===undefined?{}:{body:JSON.stringify(body)})});
 for(const path of ['/users','/admin/users','/admin/workspaces']){
  const r=await call(sa,path);assert.equal(r.status,200);assert.equal(r.headers.get('cache-control'),'no-store');
  assert.doesNotMatch(JSON.stringify(await r.json()),/password_hash|pin_hash|refresh_token|mfa_email/);
 }
 assert.deepEqual(await (await call(company,'/users')).json(),{companyFallback:true});
 assert.equal((await call(agent,'/users')).status,403);
 assert.equal((await call(sa,'/users','GET',undefined,{Origin:''})).status,403);
 assert.equal((await call(sa,'/users?actor_user_id='+agent.id)).status,400);
 assert.equal((await call(sa,'/workspace/create','POST',{name:'Company'},{'X-KeepTimer-CSRF':'0'})).status,403);
 const made=await call(sa,'/workspace/create','POST',{name:'Managed company'});assert.equal(made.status,200);
 const ws=(await made.json()).workspace.id;
 assert.equal((await call(sa,'/workspace')).status,200);
 assert.equal((await call(sa,'/users/create','POST',{username:'forged-admin',pin:'123456',role:'superadmin',workspace_id:ws})).status,400);
 const madeUser=await call(sa,'/users/create','POST',{username:'http-company-worker',pin:'fixture-company-pin',role:'worker',workspace_id:ws});
 assert.equal(madeUser.status,200);const worker=(await madeUser.json()).user;
 assert.equal(await bcrypt.compare('fixture-company-pin',(await db.query('SELECT pin_hash FROM users WHERE id=$1',[worker.id])).rows[0].pin_hash),true);
 assert.ok((await (await call(sa,`/admin/workspaces/${ws}`)).json()).members.some(x=>x.id===worker.id));
 assert.equal((await call(sa,`/admin/users/${worker.id}`,'PATCH',{username:'http-renamed-worker',role:'worker',workspace_id:ws})).status,200);
 const session=randomUUID();await db.query('INSERT INTO sessions(id,user_id,refresh_token_hash) VALUES($1,$2,$3)',[session,worker.id,'fixture']);
 assert.equal((await call(sa,`/users/${worker.id}/force-logout`,'POST',{})).status,200);
 assert.equal((await db.query('SELECT revoked_at IS NOT NULL AS revoked FROM sessions WHERE id=$1',[session])).rows[0].revoked,true);
 assert.equal((await (await call(sa,'/workspace/toggle-shared','POST',{})).json()).shared_mode_enabled,true);
 const invite=(await (await call(sa,'/workspace/refresh-invite','POST',{})).json()).invite_code;
 assert.match(invite,/^[A-F0-9]{24}$/);assert.equal((await call(sa,'/workspace/leave','POST',{})).status,200);
 assert.equal((await call(sa,'/workspace/join','POST',{inviteCode:invite})).status,200);
 const privateAccount=await customer(db);assert.equal((await call(sa,`/admin/workspaces/${privateAccount.workspace}`)).status,404);
 assert.equal((await call(sa,`/admin/users/${privateAccount.id}`,'PATCH',{username:'private-owner',role:'manager',workspace_id:ws})).status,403);
 assert.equal((await call(sa,`/users/${worker.id}`,'DELETE',{})).status,200);
 assert.deepEqual(revoked,[worker.id,worker.id]);
 assert.equal((await db.query('SELECT disabled_at IS NOT NULL AS disabled FROM users WHERE id=$1',[worker.id])).rows[0].disabled,true);
 assert.equal((await db.query('SELECT enabled FROM keeptimer_sales_release')).rows[0].enabled,false);
 await db.query("UPDATE keeptimer_privileged_web_sessions SET verified_at=clock_timestamp()-interval '2 minutes',expires_at=clock_timestamp()-interval '1 second' WHERE session_id=$1",[sa.session]);
 assert.equal((await call(sa,'/users')).status,401);
 await db.exec('UPDATE keeptimer_auth_release SET enabled=false');
 assert.equal((await call(agent,'/users')).status,401);
});
