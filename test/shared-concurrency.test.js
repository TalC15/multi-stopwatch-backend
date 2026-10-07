import test from 'node:test';
import assert from 'node:assert/strict';
import pg from 'pg';
import { readFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { ids, schema } from './support/database.js';

// DESTRUCTIVE TEST FIXTURE. No proposed migration is run without explicit
// approval naming this disposable local database. Never point at a restore DB.
const url=process.env.TEST_DATABASE_URL;
const approved=process.env.PHASE5_DISPOSABLE_DB_APPROVED;
const enabled=Boolean(url && approved);
const options={skip:enabled?false:'Requires explicit approval of a disposable local *_keeptimer_test DB'};
async function setup(t) {
  const parsed=new URL(url), name=decodeURIComponent(parsed.pathname.slice(1));
  assert.ok(['localhost','127.0.0.1','[::1]'].includes(parsed.hostname));
  assert.match(name,/^[a-zA-Z0-9_]+_keeptimer_test$/);
  assert.equal(approved,name,'Approval must name the exact disposable DB');
  const clients=[];
  t.after(async()=>{await Promise.all(clients.map(c=>c.end()));});
  for(let i=0;i<3;i++){const client=new pg.Client({connectionString:url});await client.connect();clients.push(client);}
  const [admin,a,b]=clients;
  // This is the only schema reset in this new suite, after both safety checks.
  await admin.query('DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public');
  for(const role of ['anon','authenticated','service_role']) {
    if(!(await admin.query('SELECT 1 FROM pg_roles WHERE rolname=$1',[role])).rowCount) await admin.query(`CREATE ROLE ${role}`);
  }
  await admin.query(schema.replace(/CREATE ROLE (anon|authenticated|service_role);/g,''));
  // Match the relevant live metadata additions absent from the historical fixture.
  await admin.query("ALTER TABLE timers ADD COLUMN created_at timestamptz DEFAULT now(), ALTER COLUMN name SET NOT NULL, ALTER COLUMN type SET NOT NULL");
  for(const name of ['20260925_company_account_deactivation.sql','20260925_personal_sync_api.sql','20260928_shared_authority.sql','20261007_subscription_phase1.sql']) {
    await admin.query(await readFile(new URL(`../db/migrations/${name}`,import.meta.url),'utf8'));
  }
  await admin.query("INSERT INTO workspaces(id,name) VALUES($1,'A'),($2,'B')",[ids.company,ids.otherCompany]);
  for(const [id,name,role,workspace] of [[ids.worker,'worker','worker',ids.company],[ids.manager,'manager','manager',ids.company],
    [ids.outsider,'outsider','manager',ids.otherCompany],[ids.superadmin,'superadmin','superadmin',null]]) {
    await admin.query("INSERT INTO users(id,username,pin_hash,role,workspace_id) VALUES($1,$2,'test',$3,$4)",[id,name,role,workspace]);
  }
  await admin.query('UPDATE workspaces SET owner_id=$1 WHERE id=$2',[ids.manager,ids.company]);
  for(const client of clients) await client.query("SET lock_timeout='250ms'");
  return{admin,a,b};
}
const command=(command,extra={})=>({protocol:5,command,timerId:ids.shared,mutationId:randomUUID(),expectedRevision:'0',...extra});
const create=(extra={})=>command('create',{name:'Shared',type:'up',targetMinutes:1,...extra});
async function rpc(db,body,actor=ids.worker) {
  return (await db.query('SELECT public.keeptimer_shared_request($1,$2::jsonb) AS result',[actor,JSON.stringify(body)])).rows[0].result;
}
const snapshot=db=>rpc(db,{protocol:5,command:'snapshot'});
const due=(db,row)=>db.query('SELECT public.keeptimer_shared_due($1,$2,$3) AS result',[row.id,row.shared_run_id,row.ends_at]);

test('shared PG: concurrent starts serialize and stale revision cannot reset server deadline',options,async t=>{
  const{admin,a,b}=await setup(t);await rpc(admin,create());
  const start=command('start',{expectedRevision:'1'});
  await a.query('BEGIN');
  const first=await rpc(a,start);
  await assert.rejects(()=>rpc(b,command('start',{expectedRevision:'1'})),e=>e.code==='55P03');
  await a.query('COMMIT');
  await assert.rejects(()=>rpc(b,command('start',{expectedRevision:'1'})),/SHARED_CONFLICT/);
  const latest=(await snapshot(admin)).timers[0];assert.equal(latest.ends_at,first.timer.ends_at);assert.equal(latest.shared_revision,'2');
  assert.equal(Date.parse(first.timer.ends_at)-Date.parse(first.serverNow),60000);
});
test('shared PG: pause-pause increments once, pause-delete CAS and terminal resurrection protection',options,async t=>{
  const{admin,a,b}=await setup(t);await rpc(admin,create());await rpc(admin,command('start',{expectedRevision:'1'}));
  await a.query('BEGIN');const paused=await rpc(a,command('pause',{expectedRevision:'2'}));
  await assert.rejects(()=>rpc(b,command('pause',{expectedRevision:'2'})),e=>e.code==='55P03');await a.query('COMMIT');
  await assert.rejects(()=>rpc(b,command('delete',{expectedRevision:'2'})),/SHARED_CONFLICT/);
  assert.equal(paused.timer.paused_count,1);const del=command('delete',{expectedRevision:'3'});
  const deleted=await rpc(b,del);assert.equal(deleted.timer.record_status,'deleted');
  assert.equal((await rpc(b,del)).timer.shared_revision,'4');
  await assert.rejects(()=>rpc(admin,command('start',{expectedRevision:'4'})),/SHARED_DELETED/);
});
test('shared PG: lost ACK duplicate create/start/pause is idempotent; reused mutation payload fails',options,async t=>{
  const{admin}=await setup(t);const first=create();assert.equal((await rpc(admin,first)).timer.shared_revision,'1');
  assert.equal((await rpc(admin,first)).timer.shared_revision,'1');
  const start=command('start',{expectedRevision:'1'});const running=await rpc(admin,start);
  assert.deepEqual((await rpc(admin,start)).timer,running.timer);
  const pause=command('pause',{expectedRevision:'2'});await rpc(admin,pause);
  assert.equal((await rpc(admin,pause)).timer.paused_count,1);
  await assert.rejects(()=>rpc(admin,{...pause,command:'set-pay',value:true}),/SHARED_CONFLICT/);
  await assert.rejects(()=>rpc(admin,start),/SHARED_CONFLICT/);
});
test('shared PG: scopes, superadmin, UUID ownership and personal revision isolation',options,async t=>{
  const{admin}=await setup(t);const first=create();await rpc(admin,first);
  await assert.rejects(()=>rpc(admin,first,ids.outsider),/SHARED_FORBIDDEN/);
  await assert.rejects(()=>rpc(admin,command('start',{expectedRevision:'1'}),ids.outsider),/SHARED_FORBIDDEN/);
  const changed=await rpc(admin,command('set-pay',{expectedRevision:'1',value:true}),ids.superadmin);
  assert.equal(changed.timer.is_pay,true);assert.equal(changed.timer.sync_revision,0);
  assert.equal(changed.timer.user_id,ids.worker);assert.equal(changed.timer.workspace_id,ids.company);
});
test('shared PG: legacy RPC and direct INSERT cannot bypass command authority',options,async t=>{
  const{admin}=await setup(t);await rpc(admin,create());
  await assert.rejects(()=>admin.query("SELECT public.keeptimer_change_timer($1,$2,'{\"status\":\"paused\",\"accumulated_ms\":0}'::jsonb,false)",[ids.worker,ids.shared]),/SHARED_PROTOCOL_REQUIRED/);
  await assert.rejects(()=>admin.query("SELECT public.keeptimer_change_timer($1,$2,'{}'::jsonb,true)",[ids.worker,ids.shared]),/SHARED_PROTOCOL_REQUIRED/);
  await assert.rejects(()=>admin.query("INSERT INTO timers(id,user_id,created_by,workspace_id,name,type,target_minutes,is_shared) VALUES($1,$2,$2,$3,'Legacy','up',1,true)",[ids.deleted,ids.worker,ids.company]),/SHARED_PROTOCOL_REQUIRED/);
  assert.equal((await snapshot(admin)).timers[0].status,'idle');
});
test('shared PG: Count-Up target remains running; Countdown completes from DB deadline',options,async t=>{
  const{admin}=await setup(t);
  for(const [type,id] of [['up',ids.shared],['down',ids.personal]]) {
    await rpc(admin,create({timerId:id,type,targetMinutes:0.0001}));
    await rpc(admin,command('start',{timerId:id,expectedRevision:'1'}));
  }
  await admin.query('SELECT pg_sleep(0.02)');
  const rows=(await snapshot(admin)).timers;
  assert.equal(rows.find(r=>r.type==='up').status,'running');
  const down=rows.find(r=>r.type==='down');assert.equal(down.status,'completed');assert.equal(down.ended_at,down.ends_at);assert.equal(down.duration_ms,6);
});
test('shared PG: atomic Telegram claim across processes, stale deadline and delete cancellation',options,async t=>{
  const{admin,a,b}=await setup(t);await rpc(admin,create({targetMinutes:0.0001}));
  const running=(await rpc(admin,command('start',{expectedRevision:'1'}))).timer;await admin.query('SELECT pg_sleep(0.02)');
  await a.query('BEGIN');
  const claim=(await due(a,running)).rows[0].result;
  assert.equal(claim.success,true);
  assert.equal(claim.protocol,5);
  assert.equal(claim.timer.id,running.id);
  assert.equal(claim.timer.shared_alarm_claimed,true);
  assert.equal(claim.timer.shared_run_id,running.shared_run_id);
  await assert.rejects(()=>due(b,running),e=>e.code==='55P03');await a.query('COMMIT');
  assert.equal((await due(b,running)).rows[0].result,null);
  const current=(await snapshot(admin)).timers[0];assert.equal(current.status,'running');
  await rpc(admin,command('delete',{expectedRevision:current.shared_revision}));assert.equal((await due(b,running)).rows[0].result,null);
});
test('shared PG: pause/resume invalidates old run and old Telegram deadline',options,async t=>{
  const{admin}=await setup(t);await rpc(admin,create());const old=(await rpc(admin,command('start',{expectedRevision:'1'}))).timer;
  await rpc(admin,command('pause',{expectedRevision:'2'}));const current=(await rpc(admin,command('start',{expectedRevision:'3'}))).timer;
  assert.notEqual(current.shared_run_id,old.shared_run_id);assert.equal((await due(admin,old)).rows[0].result,null);
});
test('shared PG: complete scalar snapshot covers 1005 records including tombstones',options,async t=>{
  const{admin}=await setup(t);
  await admin.query(`SELECT public.keeptimer_shared_request($1,jsonb_build_object('protocol',5,'command','create',
    'timerId',('10000000-0000-4000-8000-'||lpad(i::text,12,'0')),'mutationId',gen_random_uuid()::text,
    'expectedRevision','0','name','Row','type','up','targetMinutes',1)) FROM generate_series(1,1005) i`,[ids.worker]);
  const response=await snapshot(admin);assert.equal(response.complete,true);assert.equal(response.timers.length,1005);
  const id=response.timers[0].id;await rpc(admin,command('delete',{timerId:id,expectedRevision:'1'}));
  const next=await snapshot(admin);assert.equal(next.timers.length,1005);assert.equal(next.timers[0].record_status,'deleted');
  assert.ok(BigInt(next.generation)>BigInt(response.generation));
});
test('shared PG: command holds actor before timer; closure wins then late command fails',options,async t=>{
  const{admin,a,b}=await setup(t);await rpc(admin,create());await a.query('BEGIN');
  await rpc(a,command('start',{expectedRevision:'1'}));
  const close=()=>b.query('SELECT public.keeptimer_close_company_worker($1,$2)',[ids.manager,ids.worker]);
  await assert.rejects(close,e=>e.code==='55P03');await a.query('COMMIT');await close();
  await assert.rejects(()=>rpc(admin,command('pause',{expectedRevision:'2'})),/SHARED_ACCOUNT_DISABLED/);
  const saved=await admin.query('SELECT status,archived_at FROM timers WHERE id=$1',[ids.shared]);
  assert.equal(saved.rows[0].status,'running');assert.equal(saved.rows[0].archived_at,null);
});
test('shared PG: DB rejects client clocks, unknown fields, invalid names and paid values',options,async t=>{
  const{admin}=await setup(t);
  for(const extra of [{ends_at:'2030-01-01'},{name:'x'.repeat(36)},{targetMinutes:0},
    {targetMinutes:1e-12},{targetMinutes:0.000016666666666666}]) await assert.rejects(()=>rpc(admin,create(extra)),/SHARED_INVALID/);
  const oneMs=await rpc(admin,create({targetMinutes:1/60000}));
  assert.equal(oneMs.timer.shared_revision,'1');
  await assert.rejects(()=>rpc(admin,command('set-pay',{expectedRevision:'1',value:'true'})),/SHARED_INVALID/);
  const invalidDeadline=new Date(Date.now()-1000).toISOString();
  await admin.query('BEGIN');
  await admin.query("SELECT set_config('keeptimer.shared_protocol','5',true)");
  await admin.query("UPDATE timers SET target_minutes=$1,status='running',ends_at=$2,shared_run_id=$3 WHERE id=$4",
    [1e-12,invalidDeadline,ids.session,ids.shared]);
  await admin.query('COMMIT');
  await assert.rejects(()=>rpc(admin,command('start',{expectedRevision:'2'})),/SHARED_INVALID_STATE/);
  assert.equal((await due(admin,{id:ids.shared,shared_run_id:ids.session,ends_at:invalidDeadline})).rows[0].result,null);
});
test('shared PG: v5 RPCs are service-role only and creation respects workspace shared mode',options,async t=>{
  const{admin}=await setup(t);
  const allowed=await admin.query("SELECT has_function_privilege('authenticated','public.keeptimer_shared_request(uuid,jsonb)','EXECUTE') AS a, has_function_privilege('service_role','public.keeptimer_shared_request(uuid,jsonb)','EXECUTE') AS s");
  assert.equal(allowed.rows[0].a,false);assert.equal(allowed.rows[0].s,true);
  await admin.query('UPDATE workspaces SET shared_mode_enabled=false WHERE id=$1',[ids.company]);
  await assert.rejects(()=>rpc(admin,create()),/SHARED_MODE_DISABLED/);
});
