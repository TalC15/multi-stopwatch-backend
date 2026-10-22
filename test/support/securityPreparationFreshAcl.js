// Reconstructed support, never an application migration runner.
// database() retains original loopback/cluster/inventory/role safety gates.
import {readFile} from 'node:fs/promises';
import assert from 'node:assert/strict';
import {database,asRole} from './subscriptionDatabase.js';
const ordered=[
 '20261007_subscription_phase1.sql','20261008_subscription_entitlement_core.sql','20261008_subscription_sales.sql',
 '20261008_subscription_workspace_private_access.sql','20261009_subscription_lifecycle.sql',
 '20261009_password_mfa_activation.sql','20261009_password_mfa_management.sql','20261016_mfa_device_context.sql',
];
const privateTables=['keeptimer_auth_release','keeptimer_auth_accounts','keeptimer_auth_challenges',
 'keeptimer_auth_sessions','keeptimer_auth_limits','keeptimer_auth_recovery_cases','keeptimer_auth_recovery_audit',
 'keeptimer_auth_link_queue','keeptimer_mfa_contexts','keeptimer_mfa_challenges','keeptimer_mfa_sends',
 'keeptimer_mfa_verifications','keeptimer_mfa_risk_audit','keeptimer_mfa_revocations'];
export async function verifyFreshAcl(t,{realPg18=false}={}){
 const db=await database(t,{migrate:false});
 if(realPg18){const version=Number((await db.query('SHOW server_version_num')).rows[0].server_version_num);assert.ok(version>=180000&&version<190000);}
 // Undo ONLY fixture default grants for future tables, before creating new tables.
 // Existing base-table backend grants and production migration files are untouched.
 await db.exec('ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM anon,authenticated,service_role');
 for(const name of ordered)await db.exec(await readFile(new URL('../../db/migrations/'+name,import.meta.url),'utf8'));
 // No cutover migration or release-enable statement is run by this test.
 for(const table of privateTables){
  const row=(await db.query('SELECT relrowsecurity FROM pg_catalog.pg_class WHERE oid=$1::regclass',['public.'+table])).rows[0];
  assert.equal(row?.relrowsecurity,true,`${table} RLS`);
  for(const role of ['anon','authenticated','service_role'])for(const privilege of ['SELECT','INSERT','UPDATE','DELETE']){
   const allowed=(await db.query('SELECT has_table_privilege($1,$2,$3) AS allowed',[role,'public.'+table,privilege])).rows[0].allowed;
   assert.equal(allowed,false,`${role} ${privilege} ${table}`);
  }
  for(const role of ['anon','authenticated','service_role'])await assert.rejects(asRole(db,role,()=>db.query(`SELECT * FROM public.${table}`)),/permission denied/i);
 }
 for(const signature of ['public.keeptimer_auth_limit(text,text,text)','public.keeptimer_mfa_command(text,jsonb)']){
  for(const role of ['anon','authenticated'])assert.equal((await db.query('SELECT has_function_privilege($1,$2,$3) AS allowed',[role,signature,'EXECUTE'])).rows[0].allowed,false);
  assert.equal((await db.query('SELECT has_function_privilege($1,$2,$3) AS allowed',['service_role',signature,'EXECUTE'])).rows[0].allowed,true);
 }
 const result=await asRole(db,'service_role',()=>db.query('SELECT public.keeptimer_auth_limit($1,$2,$3) AS allowed',['pin','a'.repeat(64),'b'.repeat(64)]));
 assert.equal(result.rows[0].allowed,true);
 const count=(await db.query('SELECT count(*)::int AS n FROM public.keeptimer_auth_limits')).rows[0].n;
 assert.equal(count,2,'only the RPC writes its two HMAC-key budget rows');
 const release=(await db.query('SELECT enabled,cutover FROM public.keeptimer_auth_release')).rows[0];
 assert.equal(release.enabled,false);assert.equal(release.cutover,false);
}
