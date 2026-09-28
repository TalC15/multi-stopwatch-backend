import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import { once } from 'node:events';
import { mountSharedTimers, validSharedCommand } from '../src/sharedTimers.js';
import { ids } from './support/database.js';
const body=extra=>({protocol:5,command:'pause',timerId:ids.shared,mutationId:ids.deleted,expectedRevision:'1',...extra});
const timer=extra=>({id:ids.shared,user_id:ids.worker,workspace_id:ids.company,is_shared:true,
 shared_revision:'2',record_status:'active',status:'paused',name:'Canonical',type:'up',target_minutes:1,is_pay:false,accumulated_ms:2000,...extra});
const frame=extra=>({protocol:5,workspaceId:ids.company,generation:'2',serverNow:'2026-09-28T00:00:00Z',success:true,...extra});
async function fixture(t){
 const calls=[],sockets=[],scheduled=[],cancelled=[],sent=[];let result=frame({timer:timer(),mutationId:ids.deleted}),error=null;
 const db={rpc:async(name,args)=>{calls.push({name,args});return {data:result,error};},from(){return {select(){return this;},eq(){return this;},is(){return this;},async not(){return{data:[{telegram_chat_id:'one'},{telegram_chat_id:'one'}]};}};}};
 const app=express();app.use(express.json());
 const auth=(req,res,next)=>{if(req.headers.authorization!=='fixture')return res.sendStatus(401);req.user={id:ids.worker,workspace_id:ids.company};next();};
 const service=mountSharedTimers({app,authenticate:auth,db,io:{to:room=>({emit:(event,data)=>sockets.push({room,event,data})})},
  sendTelegramMessage:async(...args)=>sent.push(args),now:()=>Date.parse('2026-09-28T00:00:00Z'),
  setTimeout:(callback,delay)=>{const item={callback,delay};scheduled.push(item);return item;},clearTimeout:item=>cancelled.push(item)});
 const server=app.listen(0,'127.0.0.1');await once(server,'listening');
 t.after(async()=>{service.dispose();server.closeAllConnections();await new Promise(r=>server.close(r));});
 const request=(payload,path='/timers/shared/commands',authHeader='fixture')=>fetch(`http://127.0.0.1:${server.address().port}${path}`,
  {method:payload?'POST':'GET',headers:{authorization:authHeader,'Content-Type':'application/json'},...(payload?{body:JSON.stringify(payload)}:{})});
 return{calls,sockets,scheduled,cancelled,sent,request,set(data,err=null){result=data;error=err;}};
}
test('shared HTTP requires auth and rejects client clock/identity fields before RPC',async t=>{
 const f=await fixture(t);assert.equal((await f.request(body(),undefined,'bad')).status,401);
 for(const extra of [{ends_at:'2030-01-01'},{accumulated_ms:10},{paused_count:1},{workspaceId:ids.otherCompany},{userId:ids.manager},{status:'running'},{expectedRevision:1},{expectedRevision:'9223372036854775808'},{command:'complete'}]){
  assert.equal((await f.request(body(extra))).status,400);
 }
 assert.equal(f.calls.length,0);assert.equal(f.sockets.length,0);
});
test('shared command RPC uses authenticated actor and socket publishes only canonical DB data',async t=>{
 const f=await fixture(t);const response=await f.request(body());assert.equal(response.status,200);
 assert.deepEqual(f.calls[0],{name:'keeptimer_shared_request',args:{p_actor_id:ids.worker,p_request:body()}});
 assert.deepEqual(f.sockets[0].data.data.timer,(await response.json()).timer);
 assert.equal(f.sockets[0].room,`workspace-${ids.company}`);assert.equal(f.scheduled.length,0);
});
for(const [message,status] of [['SHARED_FORBIDDEN',403],['SHARED_ACCOUNT_DISABLED',401],['SHARED_CONFLICT',409],['SHARED_DELETED',409],['SHARED_NOT_FOUND',404],['SHARED_INVALID',400],['connection lost',503]])test(`shared RPC ${message} -> ${status}, no event/job`,async t=>{
 const f=await fixture(t);f.set(null,{message});assert.equal((await f.request(body())).status,status);assert.equal(f.sockets.length,0);assert.equal(f.scheduled.length,0);
});
test('one scalar snapshot delivers 1005 rows with explicit completeness and authenticated scope',async t=>{
 const f=await fixture(t);const timers=Array.from({length:1005},(_,i)=>timer({id:`10000000-0000-4000-8000-${String(i+1).padStart(12,'0')}`}));
 f.set(frame({complete:true,timers}));const response=await f.request(null,'/timers/shared?protocol=5');const data=await response.json();
 assert.equal(response.status,200);assert.equal(data.timers.length,1005);assert.equal(data.complete,true);
 assert.deepEqual(f.calls[0].args,{p_actor_id:ids.worker,p_request:{protocol:5,command:'snapshot'}});
});
test('incomplete RPC snapshot is a 503, never an empty successful snapshot',async t=>{
 const f=await fixture(t);f.set(frame({timers:[]}));assert.equal((await f.request(null,'/timers/shared?protocol=5')).status,503);
});
for(const success of [false,'missing']) test(`RPC snapshot success=${success} returns 503 even with complete empty rows`,async t=>{
 const f=await fixture(t);const result=frame({complete:true,timers:[],success});
 if(success==='missing') delete result.success;
 f.set(result);assert.equal((await f.request(null,'/timers/shared?protocol=5')).status,503);
 assert.equal(f.scheduled.length,0);assert.equal(f.sockets.length,0);
});
for(const success of [false,'missing']) test(`RPC command success=${success} cannot publish canonical ACK`,async t=>{
 const f=await fixture(t);const result=frame({timer:timer(),mutationId:ids.deleted,success});
 if(success==='missing') delete result.success;
 f.set(result);assert.equal((await f.request(body())).status,503);
 assert.equal(f.sockets.length,0);assert.equal(f.scheduled.length,0);
});
test('Telegram job rejects late older ACK after cancellation; claim deduplicates workspace recipients',async t=>{
 const f=await fixture(t);const running=timer({status:'running',shared_run_id:ids.session,ends_at:'2026-09-28T00:00:00Z',shared_revision:'2'});
 f.set(frame({timer:running,mutationId:ids.deleted}));await f.request(body());assert.equal(f.scheduled.length,1);
 f.set(frame({timer:timer({shared_revision:'3'}),mutationId:ids.deleted}));await f.request(body());
 f.set(frame({timer:running,mutationId:ids.deleted}));await f.request(body());assert.equal(f.scheduled.length,1);
 const before=f.calls.length;f.scheduled[0].callback();await new Promise(r=>setImmediate(r));assert.equal(f.calls.length,before);
 assert.equal(f.sent.length,0); // A's canonical cancellation never causes a Telegram send.
 const next={...running,shared_revision:'4'};f.set(frame({timer:next,mutationId:ids.deleted}));await f.request(body());
 f.set(frame({timer:{...next,shared_revision:'5',shared_alarm_claimed:true}}));f.scheduled.at(-1).callback();await new Promise(r=>setImmediate(r));
 assert.equal(f.calls.at(-1).name,'keeptimer_shared_due');assert.equal(f.sent.length,1);
 assert.deepEqual(f.calls.at(-1).args,{p_id:ids.shared,p_run:ids.session,p_ends:running.ends_at});
});
for(const success of [false,'missing']) test(`due success=${success} cannot publish or send Telegram`,async t=>{
 const f=await fixture(t);const running=timer({status:'running',shared_run_id:ids.session,
  ends_at:'2026-09-28T00:00:00Z',shared_revision:'2'});
 f.set(frame({timer:running,mutationId:ids.deleted}));await f.request(body());
 assert.equal(f.scheduled.length,1);const published=f.sockets.length;
 const claimed=frame({timer:{...running,shared_revision:'3',shared_alarm_claimed:true},success});
 if(success==='missing') delete claimed.success;
 f.set(claimed);f.scheduled[0].callback();await new Promise(r=>setImmediate(r));
 assert.equal(f.calls.at(-1).name,'keeptimer_shared_due');
 assert.equal(f.sockets.length,published);assert.equal(f.sent.length,0);
});
test('due success=true with an unverifiable timer cannot publish or send Telegram',async t=>{
 const f=await fixture(t);const running=timer({status:'running',shared_run_id:ids.session,
  ends_at:'2026-09-28T00:00:00Z',shared_revision:'2'});
 f.set(frame({timer:running,mutationId:ids.deleted}));await f.request(body());
 const published=f.sockets.length;
 f.set(frame({timer:{...running,id:ids.deleted,shared_alarm_claimed:true}}));
 f.scheduled[0].callback();await new Promise(r=>setImmediate(r));
 assert.equal(f.sockets.length,published);assert.equal(f.sent.length,0);
});
test('create validator preserves positive target, name length and narrow operation schema',()=>{
 const create=body({command:'create',expectedRevision:'0',name:'Work',type:'down',targetMinutes:1});assert.equal(validSharedCommand(create),true);
 assert.equal(validSharedCommand({...create,targetMinutes:1/60000}),true);
 for(const extra of [{name:'x'.repeat(36)},{targetMinutes:0},{targetMinutes:-1},{targetMinutes:1e-12},
  {targetMinutes:0.000016666666666666},{type:'bad'},{name:'   '},{targetMinutes:Infinity},{value:true}]) assert.equal(validSharedCommand({...create,...extra}),false);
});
test('shared HTTP rejects a positive zero-ms target before RPC and accepts a one-ms target',async t=>{
 const f=await fixture(t);const create=body({command:'create',expectedRevision:'0',name:'Boundary',type:'down',targetMinutes:1e-12});
 assert.equal((await f.request(create)).status,400);assert.equal(f.calls.length,0);
 assert.equal((await f.request({...create,targetMinutes:1/60000})).status,200);
 assert.equal(f.calls.length,1);
});
