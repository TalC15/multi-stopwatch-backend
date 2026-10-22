// Rebuilt from current shared HTTP contract. Prepared, NOT RUN.
// RPC denial is synthetic: this is HTTP validation/side-effect evidence only.
import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import {once} from 'node:events';
import {mountSharedTimers} from '../src/sharedTimers.js';
import {ids} from './support/database.js';

const base=()=>({protocol:5,command:'create',timerId:ids.shared,mutationId:ids.deleted,
  expectedRevision:'0',name:"O'Brien İstanbul",type:'up',targetMinutes:5});
async function fixture(t){
  const rpc=[],effects=[];
  const app=express();app.use(express.json());
  const service=mountSharedTimers({app,authenticate:(req,_res,next)=>{req.user={id:ids.worker,workspace_id:ids.company};next();},
    db:{rpc:async(name,args)=>{rpc.push({name,args});return{data:null,error:{code:'P0001',message:'SHARED_FORBIDDEN PRIVATE_SQL_SENTINEL'}};},
      from:()=>{effects.push('table');assert.fail('no table side effect');}},
    io:{to:()=>({emit:()=>effects.push('broadcast')})},sendTelegramMessage:async()=>effects.push('provider'),
    setTimeout:()=>{effects.push('job');return null;},clearTimeout:()=>effects.push('cancel-job')});
  const server=app.listen(0,'127.0.0.1');await once(server,'listening');
  t.after(async()=>{service.dispose();server.closeAllConnections();await new Promise(resolve=>server.close(resolve));});
  return {rpc,effects,post:body=>fetch(`http://127.0.0.1:${server.address().port}/timers/shared/commands`,{
    method:'POST',headers:{'Content-Type':'application/json'},body:typeof body==='string'?body:JSON.stringify(body)})};
}
test('shared: legitimate apostrophe/Unicode reaches actor-bound RPC, denial hides SQL and emits nothing',async t=>{
  const f=await fixture(t),body=base(),response=await f.post(body);
  assert.equal(response.status,403);assert.deepEqual(f.rpc,[{name:'keeptimer_shared_request',args:{p_actor_id:ids.worker,p_request:body}}]);
  const result=await response.text();assert.ok(!result.includes('PRIVATE_SQL_SENTINEL'));assert.ok(!result.includes('SHARED_FORBIDDEN'));
  assert.deepEqual(f.effects,[]);
});
test('shared: identity/property/filter/prototype payloads fail before RPC and any side effect',async t=>{
  const f=await fixture(t);
  const extras=[{userId:ids.outsider},{workspaceId:ids.otherCompany},{actor:{id:ids.superadmin,role:'superadmin'}},
    {role:'manager'},{plan:'enterprise'},{entitlement:true},{revision:'9'},{ends_at:'2030-01-01T00:00:00Z'},
    {table:'users'},{filter:'id.neq.null'},{name:['array']},{targetMinutes:{valueOf:1}},{constructor:{prototype:{polluted:true}}}];
  for(const extra of extras){const r=await f.post({...base(),...extra});assert.equal(r.status,400);}
  const prototypeBody=JSON.stringify(base()).replace(/}$/,',"__proto__":{"polluted":true}}');
  assert.equal((await f.post(prototypeBody)).status,400);
  assert.equal({}.polluted,undefined);assert.deepEqual(f.rpc,[]);assert.deepEqual(f.effects,[]);
});
