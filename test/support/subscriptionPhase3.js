import { readFile } from 'node:fs/promises';
import { randomUUID, createHash } from 'node:crypto';
import bcrypt from 'bcrypt';
import { database as previousDatabase, user, subscription } from './subscriptionPhase2.js';
export { user, subscription, asRole, connect, localTestUrl, resolve } from './subscriptionPhase2.js';
export const migration = await readFile(new URL('../../db/migrations/20261008_subscription_sales.sql', import.meta.url),'utf8');
export const fixturePassword = 'Synthetic-Test-Password-2026!';
export const fixtureHash = await bcrypt.hash(fixturePassword,12);
export async function database(t) {
  const db=await previousDatabase(t); await db.exec(migration); return db;
}
// ONLY isolated-test DB owner can provision these synthetic proofs. No HTTP,
// environment flag, service-role grant or production proof issuer exists.
export async function actor(db, role='agent') {
  const id=await user(db,role, role==='agent' ? { pin_hash:null,password_hash:fixtureHash,credential_kind:'password' } : {});
  const session=randomUUID();
  await db.query('INSERT INTO sessions(id,user_id,refresh_token_hash) VALUES($1,$2,$3)',[session,id,'synthetic-fixture-hash']);
  await db.query("INSERT INTO keeptimer_privileged_web_sessions VALUES($1,$2,clock_timestamp(),clock_timestamp()+interval '10 minutes','email_otp')",[session,id]);
  return {id,session};
}
export async function enableIsolatedFixture(db) { await db.exec('UPDATE keeptimer_sales_release SET enabled=true'); }
export async function command(db, who, action, data, request=randomUUID(), fingerprint) {
  const hash=fingerprint || createHash('sha256').update(JSON.stringify({action,data})).digest('hex');
  return (await db.query('SELECT keeptimer_phase3_command($1,$2,$3,$4,$5,$6) AS result',
    [who.id,who.session,request,action,hash,JSON.stringify(data)])).rows[0].result;
}
export const saleData = extra => ({ username:'customer_'+randomUUID().slice(0,8),password_hash:fixtureHash,
  plan_code:'individual',term_months:1,amount_minor:25000,currency:'TRY',...extra });
export async function seededCustomer(db,who,period={}) {
  await db.exec('BEGIN');
  try {
    const id=await user(db,'worker',{pin_hash:null,password_hash:fixtureHash,credential_kind:'password',plan_code:'individual'});
    const workspace=(await db.query("INSERT INTO workspaces(name,owner_id,kind,shared_mode_enabled) VALUES('Fixture',$1,'individual_private',false) RETURNING id",[id])).rows[0].id;
    await db.query('UPDATE users SET workspace_id=$1 WHERE id=$2',[workspace,id]);
    await db.query('INSERT INTO keeptimer_individual_customers(user_id,workspace_id,created_by_user_id) VALUES($1,$2,$3)',[id,workspace,who.id]);
    const row=await subscription(db,{user_id:id,created_by_user_id:who.id,...period});
    await db.exec('COMMIT'); return {id,workspace,subscription:row};
  } catch(e) {await db.exec('ROLLBACK');throw e;}
}
export function rpcAdapter(db) {
  return { rpc:async (name,args) => {
    const functions={
      keeptimer_phase3_access:['p_actor','p_session','p_role'],
      keeptimer_phase3_command:['p_actor','p_session','p_request','p_action','p_fingerprint','p_data'],
      keeptimer_phase3_list:['p_actor','p_session','p_kind','p_customer','p_after','p_limit'],
    };
    const fields=functions[name];
    if(!fields)throw new Error('Unexpected RPC');
    try {return {data:(await db.query(`SELECT public.${name}(${fields.map((_,i)=>'$'+(i+1)).join(',')}) AS result`,
      fields.map(f=>f==='p_data'?JSON.stringify(args[f]):args[f]))).rows[0].result,error:null};}
    catch(e){return {data:null,error:{code:e.code,message:e.message}};}
  }};
}
