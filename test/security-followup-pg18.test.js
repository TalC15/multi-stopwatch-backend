import test from 'node:test';
import assert from 'node:assert/strict';
import {fork} from 'node:child_process';
import {once} from 'node:events';
import {database,localTestUrl} from './support/mfaDevice.js';
import {asRole} from './support/subscriptionDatabase.js';
const options={skip:localTestUrl()?false:'Guarded real PG18 required, no PGlite substitute'};
async function setup(t){const db=await database(t);assert.equal(Math.floor(Number((await db.query('SHOW server_version_num')).rows[0].server_version_num)/10000),18);return db;}

test('followup PG18: hostile temp objects/search_path cannot shadow qualified auth objects or redirect writes',options,async t=>{
 const db=await setup(t),before=(await db.query('SELECT count(*)::int AS n FROM public.keeptimer_auth_limits')).rows[0].n;
 await db.exec('CREATE TEMP TABLE users(poisoned text);CREATE TEMP TABLE sessions(poisoned text);CREATE TEMP TABLE keeptimer_auth_limits(poisoned text);CREATE TEMP TABLE keeptimer_auth_release(poisoned text)');
 await db.exec("SET search_path=pg_temp,public");
 const result=await asRole(db,'service_role',()=>db.query("SELECT public.keeptimer_auth_limit('pin',$1,$2) AS allowed",['c'.repeat(64),'d'.repeat(64)]));assert.equal(result.rows[0].allowed,true);
 assert.equal((await db.query('SELECT count(*)::int AS n FROM public.keeptimer_auth_limits')).rows[0].n,before+2);
 for(const table of ['users','sessions','keeptimer_auth_limits','keeptimer_auth_release'])assert.equal((await db.query('SELECT count(*)::int AS n FROM pg_temp.'+table)).rows[0].n,0);
 assert.deepEqual((await db.query('SELECT enabled FROM public.keeptimer_sales_release')).rows[0],{enabled:false});
 await db.exec('SET search_path=public,pg_catalog');
});

test('followup PG18: all sensitive column ACLs, public EXECUTE inheritance, overloads and sequences have explicit catalog evidence',options,async t=>{
 const db=await setup(t);
 const tables=(await db.query("SELECT c.oid::text AS oid,c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind='r' AND (c.relname LIKE 'keeptimer_auth_%' OR c.relname LIKE 'keeptimer_mfa_%' OR c.relname='keeptimer_privileged_web_sessions') ORDER BY c.relname")).rows;
 assert.ok(tables.length>=15);
 for(const table of tables)for(const role of ['anon','authenticated','service_role'])for(const privilege of ['SELECT','INSERT','UPDATE','REFERENCES'])assert.equal((await db.query('SELECT has_any_column_privilege($1,$2::oid,$3) AS allowed',[role,table.oid,privilege])).rows[0].allowed,false,role+' '+privilege+' '+table.relname);
 const functions=(await db.query("SELECT p.oid::text AS oid,p.oid::regprocedure::text AS signature,p.prorettype='trigger'::regtype AS trigger,p.prosecdef,has_function_privilege('anon',p.oid,'EXECUTE') AS anon,has_function_privilege('authenticated',p.oid,'EXECUTE') AS authenticated FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.proname LIKE 'keeptimer_%' ORDER BY signature")).rows;
 assert.ok(functions.length>20);
 for(const f of functions.filter(x=>x.prosecdef&&!x.trigger)){assert.equal(f.anon,false,f.signature);assert.equal(f.authenticated,false,f.signature);}
 const publicGrants=(await db.query("SELECT p.oid::regprocedure::text AS signature FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE n.nspname='public' AND p.proname LIKE 'keeptimer_%' AND p.prosecdef AND p.prorettype<>'trigger'::regtype AND a.grantee=0 AND a.privilege_type='EXECUTE'")).rows;assert.deepEqual(publicGrants,[]);
 const sequences=(await db.query("SELECT c.oid::text AS oid,c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind='S'")).rows;
 for(const s of sequences)for(const role of ['anon','authenticated'])for(const privilege of ['SELECT','USAGE','UPDATE'])assert.equal((await db.query('SELECT has_sequence_privilege($1,$2::oid,$3) AS allowed',[role,s.oid,privilege])).rows[0].allowed,false);
 // Count-only catalog evidence is synthetic, contains no user/credential rows.
 console.log('FOLLOWUP_CATALOG '+JSON.stringify({sensitiveTables:tables.length,functions:functions.length,sequences:sequences.length,publicUnsafeExecute:publicGrants.length}));
});

test('followup PG18: independent HTTP auth processes and restart cannot reset shared account budget',options,async t=>{
 const db=await setup(t),children=new Set();
 const start=async()=>{const child=fork(new URL('./support/followupAuthInstance.js',import.meta.url),[],{stdio:['ignore','ignore','ignore','ipc'],env:{...process.env}});children.add(child);const message=await Promise.race([once(child,'message').then(x=>x[0]),once(child,'exit').then(()=>{throw Error('auth child exited before ready');}),new Promise((_,reject)=>{const timer=setTimeout(()=>reject(Error('auth child startup timed out')),10000);timer.unref();})]);return {child,base:'http://127.0.0.1:'+message.port};};
 const stop=async a=>{if(a.child.exitCode===null){const exited=once(a.child,'exit');a.child.kill('SIGTERM');await exited;}children.delete(a.child);};
 t.after(async()=>{for(const child of children){if(child.exitCode===null){const end=once(child,'exit');child.kill('SIGTERM');await end;}}});
 let a=await start();const b=await start();const call=async instance=>fetch(instance.base+'/auth/password-login',{method:'POST',headers:{Origin:'https://fixture.example','Content-Type':'application/json','X-KeepTimer-CSRF':'1'},body:JSON.stringify({email:'unknown@example.test',password:'Synthetic-only-password-2026!'})});
 for(let i=0;i<4;i++)assert.equal((await call(a)).status,401);
 for(let i=0;i<4;i++)assert.equal((await call(b)).status,401);
 await stop(a);a=await start();
 assert.equal((await call(a)).status,401);assert.equal((await call(b)).status,401);
 const rejected=await Promise.all([call(a),call(b)]);assert.ok(rejected.every(x=>x.status===429));
 const counts=(await db.query('SELECT count(*)::int AS rows,max(count)::int AS maximum FROM public.keeptimer_auth_limits')).rows[0];assert.equal(counts.rows,2);assert.ok(counts.maximum>=10);
 assert.equal((await db.query('SELECT count(*)::int AS n FROM public.sessions')).rows[0].n,0);
 await stop(a);await stop(b);
});
