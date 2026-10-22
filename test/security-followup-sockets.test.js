// Actual server/Engine.IO/Socket.IO + disposable PGlite RPCs. No live network.
import test from 'node:test';
import assert from 'node:assert/strict';
import {once} from 'node:events';
import {randomUUID} from 'node:crypto';
import jwt from 'jsonwebtoken';
import {database,user,resolve} from './support/subscriptionPhase2.js';

test('followup real sockets: hostile rooms/events, expired/revoked sessions, bounded frames and canonical recipient isolation', {timeout:45000},async t=>{
 const db=await database(t);process.env.JWT_SECRET='followup-socket-fixture-only';process.env.SUPABASE_URL='http://127.0.0.1:54321';process.env.SUPABASE_SERVICE_KEY='followup-fixture-only';process.env.PORT='0';process.env.AUTH_ALLOWED_ORIGINS='https://fixture.example';
 await user(db,'superadmin');const workspaces=[];
 for(const name of ['A','B'])workspaces.push((await db.query('INSERT INTO workspaces(name,shared_mode_enabled) VALUES($1,true) RETURNING id',[name])).rows[0].id);
 const auth=await import('../src/auth.js'),actors={};
 for(const [name,w] of [['a',0],['peer',0],['b',1],['guarded',0],['disabled',0]]){
  const id=await user(db,'worker',{workspace_id:workspaces[w]}),session=randomUUID(),refresh=auth.generateRefreshToken({id},session);
  await db.query('INSERT INTO sessions(id,user_id,refresh_token_hash) VALUES($1,$2,$3)',[session,id,auth.hashToken(refresh)]);actors[name]={id,session,token:auth.generateAccessToken({id},session),workspace:workspaces[w]};
 }
 const original=globalThis.fetch,engines=[],calls=[];let scopeFailure=null;
 const json=(x,status=200)=>new Response(JSON.stringify(x),{status,headers:{'Content-Type':'application/json'}});
 globalThis.fetch=async(request,options={})=>{
  const url=new URL(request.url??request),body=options.body?JSON.parse(options.body):null;
  if(url.origin!=='http://127.0.0.1:54321'){assert.equal(url.hostname,'127.0.0.1','No external network');return original(request,options);}
  const table=url.pathname.split('/').at(-1),eq=k=>url.searchParams.get(k)?.replace(/^eq\./,'');
  if(table==='keeptimer_resolve_entitlement')return body.p_user_id===scopeFailure?json({code:'UNAVAILABLE'},503):json(await resolve(db,body.p_user_id));
  if(table==='keeptimer_auth_session')return json(false);
  if(table==='keeptimer_shared_request'){
   calls.push(body);try{return json((await db.query('SELECT public.keeptimer_shared_request($1,$2::jsonb) AS r',[body.p_actor_id,JSON.stringify(body.p_request)])).rows[0].r);}catch(e){return json({code:e.code,message:e.message},400);}
  }
  assert.ok(['users','sessions','timers'].includes(table));
  const where=[],args=[];for(const k of ['id','user_id','role','username'])if(eq(k))where.push(k+'=$'+args.push(eq(k)));
  const row=(await db.query('SELECT * FROM public.'+table+(where.length?' WHERE '+where.join(' AND '):''),args)).rows[0];return row?json(row):json({code:'PGRST116'},406);
 };
 const {httpServer}=await import('../src/server.js');if(!httpServer.listening)await once(httpServer,'listening');const base='http://127.0.0.1:'+httpServer.address().port;
 t.after(async()=>{for(const endpoint of engines)await original(endpoint,{method:'POST',body:'1'}).catch(()=>{});globalThis.fetch=original;httpServer.closeAllConnections();await new Promise(r=>httpServer.close(r));});
 const connect=async(actor,token=actor.token)=>{
  const opened=await original(base+'/socket.io/?EIO=4&transport=polling',{headers:{Origin:'https://hostile.invalid'}});const sid=JSON.parse((await opened.text()).slice(1)).sid;
  const endpoint=base+'/socket.io/?EIO=4&transport=polling&sid='+sid;engines.push(endpoint);
  await original(endpoint,{method:'POST',body:'40'+JSON.stringify({token,workspaceId:workspaces[1],actorId:actors.b.id})});
  const first=await(await original(endpoint,{signal:AbortSignal.timeout(2500)})).text();assert.match(first,/^40/);return {endpoint};
 };
 const publish=async(actor,name)=>{const body={protocol:5,command:'create',timerId:randomUUID(),mutationId:randomUUID(),expectedRevision:'0',name,type:'up',targetMinutes:1};
  const r=await original(base+'/timers/shared/commands',{method:'POST',headers:{Authorization:'Bearer '+actor.token,'Content-Type':'application/json'},body:JSON.stringify(body)});assert.equal(r.status,200);return r.json();};
 const read=async(socket,marker)=>{
  const names=[];for(let i=0;i<4;i++){
   const r=await original(socket.endpoint,{signal:AbortSignal.timeout(2500)});if(r.status===400)return {names,closed:true};
   const packet=await r.text();for(const part of packet.split('\x1e')){
    if(part==='1'||part.startsWith('41'))return {names,closed:true,namespaceDisconnect:part.startsWith('41')};
    if(part==='2'){await original(socket.endpoint,{method:'POST',body:'3'});continue;}
    if(part.startsWith('42')){const [event,data]=JSON.parse(part.slice(2));if(event==='timer-event')names.push(data.data.timer.name);}
   }
   if(names.includes(marker))return {names,closed:false};
  }throw Error('No fence packet');
 };
 await t.test('followup rooms: two company sockets cannot forge joins, actor scope or server broadcasts',async()=>{
  const a=await connect(actors.a),b=await connect(actors.b),before=calls.length;
  for(const s of [a,b])for(const event of [['join',{room:'workspace-'+workspaces[1]}],['join-room','workspace-'+workspaces[0]],['timer-event',{data:{timer:{name:'FORGED'}}}],['command',{actorId:actors.a.id,workspaceId:workspaces[0]}]])await original(s.endpoint,{method:'POST',body:'42'+JSON.stringify(event)});
  assert.equal(calls.length,before);
  await publish(actors.b,'B-private');await publish(actors.a,'A-fence');await publish(actors.b,'B-fence');
  const ar=await read(a,'A-fence'),br=await read(b,'B-fence');assert.deepEqual(ar.names,['A-fence']);assert.deepEqual(br.names,['B-private','B-fence']);
  assert.equal((await db.query("SELECT count(*)::int AS n FROM timers WHERE name='FORGED'")).rows[0].n,0);
 });
 await t.test('followup personal cancel: authenticated own timer has no DB mutation or provider effect',async()=>{
  const id=randomUUID();await db.query("INSERT INTO timers(id,user_id,created_by,workspace_id,name,type,target_minutes,status,record_status,is_shared) VALUES($1,$2,$2,$3,'Personal','up',1,'idle','active',false)",[id,actors.peer.id,workspaces[0]]);
  const before=(await db.query('SELECT * FROM timers WHERE id=$1',[id])).rows[0],count=calls.length;
  const r=await original(base+'/timer/cancel',{method:'POST',headers:{Authorization:'Bearer '+actors.peer.token,'Content-Type':'application/json'},body:JSON.stringify({timerId:id})});assert.equal(r.status,200);assert.equal((await r.json()).success,true);
  assert.deepEqual((await db.query('SELECT * FROM timers WHERE id=$1',[id])).rows[0],before);assert.equal(calls.length,count);
 });
 await t.test('followup revoked socket: committed other-instance revocation prevents the next private broadcast',async()=>{
  const socket=await connect(actors.a);await db.query('UPDATE sessions SET revoked_at=clock_timestamp() WHERE id=$1',[actors.a.session]);
  const denied=await original(base+'/account/security',{headers:{Authorization:'Bearer '+actors.a.token}});assert.equal(denied.status,401);
  const peer=await connect(actors.peer);await publish(actors.peer,'AFTER-REVOKE');assert.ok((await read(peer,'AFTER-REVOKE')).names.includes('AFTER-REVOKE'));
  const observed=await read(socket,'AFTER-REVOKE');assert.ok(!observed.names.includes('AFTER-REVOKE'),'revoked session received private workspace timer after DB commit');
 });
 await t.test('followup expired socket: expired access token cannot receive later private workspace data',async()=>{
  const claims={id:actors.b.id,sessionId:actors.b.session,type:'access'},expiry=Math.floor(Date.now()/1000)+1;
  const token=jwt.sign({...claims,exp:expiry},process.env.JWT_SECRET),socket=await connect(actors.b,token);
  await new Promise(r=>setTimeout(r,Math.max(0,expiry*1000-Date.now()+20)));assert.equal(auth.verifyToken(token),null);
  const denied=await original(base+'/account/security',{headers:{Authorization:'Bearer '+token}});assert.equal(denied.status,401);
  await publish(actors.b,'AFTER-EXPIRY');const observed=await read(socket,'AFTER-EXPIRY');assert.ok(!observed.names.includes('AFTER-EXPIRY'),'expired access token received new private timer');
 });
 await t.test('followup scope: company workspace transfer is rejected by DB and reconnect always rechecks revoked session',async()=>{
  await assert.rejects(db.query('UPDATE users SET workspace_id=$1 WHERE id=$2',[workspaces[1],actors.peer.id]),/COMPANY_WORKSPACE_IMMUTABLE/);
  const o=await original(base+'/socket.io/?EIO=4&transport=polling');const sid=JSON.parse((await o.text()).slice(1)).sid;const endpoint=base+'/socket.io/?EIO=4&transport=polling&sid='+sid;engines.push(endpoint);await original(endpoint,{method:'POST',body:'40'+JSON.stringify({token:actors.a.token})});assert.match(await(await original(endpoint,{signal:AbortSignal.timeout(2500)})).text(),/^44/);
 });
 await t.test('followup live recipient: disabled user cannot receive the next committed workspace event',async()=>{
  const socket=await connect(actors.disabled);await db.query('UPDATE users SET disabled_at=clock_timestamp() WHERE id=$1',[actors.disabled.id]);
  const peer=await connect(actors.peer);await publish(actors.peer,'AFTER-DISABLE');assert.ok((await read(peer,'AFTER-DISABLE')).names.includes('AFTER-DISABLE'));
  assert.ok(!(await read(socket,'AFTER-DISABLE')).names.includes('AFTER-DISABLE'));
 });
 await t.test('followup live recipient: unavailable authority fails closed without suppressing healthy peers or retrying commands',async()=>{
  const socket=await connect(actors.guarded),peer=await connect(actors.peer);scopeFailure=actors.guarded.id;const before=calls.length;
  try{await publish(actors.peer,'AUTHORITY-UNAVAILABLE');assert.ok((await read(peer,'AUTHORITY-UNAVAILABLE')).names.includes('AUTHORITY-UNAVAILABLE'));const observed=await read(socket,'AUTHORITY-UNAVAILABLE');assert.ok(!observed.names.includes('AUTHORITY-UNAVAILABLE'));assert.equal(observed.closed,true);assert.notEqual(observed.namespaceDisconnect,true,'Namespace disconnect would disable automatic recovery');assert.equal(calls.length,before+1);}
  finally{scopeFailure=null;}
  // A fresh handshake after recovery uses the live same-account session.
  const recovered=await connect(actors.guarded);await publish(actors.peer,'AFTER-AUTHORITY-RECOVERY');assert.ok((await read(recovered,'AFTER-AUTHORITY-RECOVERY')).names.includes('AFTER-AUTHORITY-RECOVERY'));
 });
});
