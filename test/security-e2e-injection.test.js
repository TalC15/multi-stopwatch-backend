// Synthetic disposable DB only. Added for hosted CI; never imports server.js.
import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {fixture,applyPersonalSyncMigration,ids} from './support/database.js';
const state=extra=>({name:'Valid',type:'up',target_minutes:1,is_pay:false,status:'idle',
 ends_at:null,ended_at:null,duration_ms:null,accumulated_ms:0,paused_count:0,...extra});
const put=async(db,actor,id,mutation,value)=>(await db.query(
 'SELECT public.keeptimer_sync_personal($1,$2,$3,$4,$5::jsonb) AS result',
 [actor,id,mutation,0,JSON.stringify(value)])).rows[0].result;
const rows=async db=>(await db.query('SELECT to_jsonb(t) AS row FROM public.timers t ORDER BY id')).rows;
const catalog=async db=>(await db.query(`SELECT n.nspname,c.relname,c.relkind,c.relrowsecurity,
 c.relowner::text,c.relacl::text FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n
 ON n.oid=c.relnamespace WHERE n.nspname='public' ORDER BY c.relname,c.relkind`)).rows;

test('security injection: SQL/filter syntax stays literal data; catalog/ACL/owners and other rows do not change',async t=>{
 const db=await fixture(t);await applyPersonalSyncMigration(db);
 const before=await catalog(db),other=await rows(db);
 const payloads=["O'Brien İstanbul", "' OR '1'='1", '" UNION SELECT NULL--',
  '; SELECT pg_sleep(0.01); --', 'id.neq.null),or=(id.gt.0', '%27%20OR%201%3D1--', '\uFF07;--'];
 const own=[];
 for(const name of payloads){
  const id=randomUUID(),result=await put(db,ids.worker,id,randomUUID(),state({name}));own.push(id);
  assert.equal(result.timer.name,name);assert.equal(result.timer.user_id,ids.worker);
  assert.equal(result.timer.workspace_id,ids.company);assert.equal(result.timer.is_shared,false);
 }
 const after=await rows(db);assert.equal(after.length,other.length+payloads.length);
 assert.deepEqual(after.filter(x=>!own.includes(x.row.id)),other);
 assert.deepEqual(await catalog(db),before,'data values cannot change relation/owner/RLS/ACL metadata');
});

test('security injection: same-company and other-company actor reuse cannot widen scope or leave partial state',async t=>{
 const db=await fixture(t);await applyPersonalSyncMigration(db);
 const second=randomUUID();await db.query("INSERT INTO users(id,username,pin_hash,role,workspace_id) VALUES($1,$2,'synthetic','worker',$3)",[second,'second-worker',ids.company]);
 const id=randomUUID();await put(db,ids.worker,id,randomUUID(),state({name:'Owner record'}));
 const before=await rows(db);
 for(const actor of [second,ids.manager,ids.outsider]){
  await assert.rejects(put(db,actor,id,randomUUID(),state({name:"' OR true --",user_id:actor,
   workspace_id:ids.otherCompany,actor:{role:'superadmin'},entitlement:true})),/KEEPTIMER_TIMER_FORBIDDEN/);
  assert.deepEqual(await rows(db),before);
 }
});

test('security injection: nested authority fields never control bindings and malformed scalar values roll back',async t=>{
 const db=await fixture(t);await applyPersonalSyncMigration(db);
 const result=await put(db,ids.worker,randomUUID(),randomUUID(),state({user_id:ids.outsider,
  workspace_id:ids.otherCompany,actor:{id:ids.superadmin},role:'superadmin',is_shared:true,
  sync_revision:999,plan:'enterprise',endsAt:'2100-01-01'}));
 assert.equal(result.timer.user_id,ids.worker);assert.equal(result.timer.created_by,ids.worker);
 assert.equal(result.timer.workspace_id,ids.company);assert.equal(result.timer.is_shared,false);
 assert.equal(Number(result.timer.sync_revision),1);assert.equal(result.timer.ends_at,null);
 const before=await rows(db);
 for(const extra of [{target_minutes:[]},{target_minutes:{or:'1=1'}},{is_pay:{value:true}},
  {paused_count:'1; DROP TABLE users;--'},{accumulated_ms:'0 UNION SELECT 1'}]){
  await assert.rejects(put(db,ids.worker,randomUUID(),randomUUID(),state(extra)));
  assert.deepEqual(await rows(db),before,'failed cast/validation cannot leave partial rows');
 }
});
