import { readFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { database as previous, user } from './subscriptionPhase6.js';
import { fixtureHash, seededCustomer } from './subscriptionPhase3.js';
export { fixtureHash, fixturePassword } from './subscriptionPhase3.js';
export { asRole, connect, localTestUrl, user } from './subscriptionPhase6.js';
export const migration=await readFile(new URL('../../db/migrations/20261009_password_mfa_activation.sql',import.meta.url),'utf8');
export const management=await readFile(new URL('../../db/migrations/20261009_password_mfa_management.sql',import.meta.url),'utf8');
export const cutover=await readFile(new URL('../../db/migrations/20261009_password_mfa_cutover.sql',import.meta.url),'utf8');
export async function database(t) {const db=await previous(t);await db.exec(migration);await db.exec(management);
 await db.exec("SET keeptimer.phase7_cutover='confirmed-maintenance'");await db.exec(cutover);return db;}
export async function customer(db,email='owner@example.test',period={}) {
 const who=(await db.query("SELECT id FROM users WHERE role='agent' AND disabled_at IS NULL")).rows[0]?.id || await user(db,'agent',{pin_hash:null,password_hash:fixtureHash,credential_kind:'password'});
 const target=await seededCustomer(db,{id:who},period);
 await db.query('SELECT keeptimer_auth_prepare($1,$2,$3)',[target.id,email,fixtureHash]);return target;
}
export async function privileged(db,email='admin@example.test',role='superadmin') {
 const id=await user(db,role);
 await db.query('SELECT keeptimer_auth_prepare($1,$2,$3)',[id,email,fixtureHash]);return {id};
}
export async function enable(db) { await db.exec('UPDATE keeptimer_auth_release SET enabled=true'); }
export async function ready(db,id) {
 await db.query('UPDATE keeptimer_auth_accounts SET verified_at=clock_timestamp(),activated_at=clock_timestamp() WHERE user_id=$1',[id]);
 await db.query('UPDATE users SET must_change_password=false WHERE id=$1',[id]);
}
export async function command(db,action,data) {
 return (await db.query('SELECT keeptimer_auth_command($1,$2) AS result',[action,JSON.stringify(data)])).rows[0].result;
}
export const challengeData=(id,purpose='activation',extra={})=>({user_id:id,purpose,transport:'web',challenge_id:randomUUID(),context_digest:'a'.repeat(64),proof_digest:'b'.repeat(64),binding_digest:'d'.repeat(64),...extra});
export async function issued(db,id,purpose='activation') {
 const data=challengeData(id,purpose,purpose==='mfa'?{expected_hash:fixtureHash}:{});
 const row=await command(db,'issue',data); if(!row.ok) throw new Error('fixture issue failed');
 await command(db,'delivery',{challenge_id:data.challenge_id,proof_digest:data.proof_digest,accepted:true});return data;
}
export const consumeData=d=>({challenge_id:d.challenge_id,context_digest:d.context_digest,proof_digest:d.proof_digest,binding_digest:d.binding_digest,purpose:d.purpose,transport:d.transport,password_hash:fixtureHash,
 session_id:randomUUID(),refresh_hash:'c'.repeat(64)});
export function rpcAdapter(db) {
 return {rpc:async(name,args)=>{
  const fields={keeptimer_auth_command:['p_action','p_data'],keeptimer_auth_limit:['p_kind','p_account','p_ip'],
   keeptimer_auth_session:['p_user','p_session','p_transport','p_refresh'],keeptimer_auth_link_queue_rpc:['p_action','p_data'],keeptimer_auth_maintain:[],
   keeptimer_auth_management:['p_actor','p_session','p_action','p_data']}[name];
  if(!fields)throw new Error('unexpected test RPC');
  try{return {data:(await db.query(`SELECT public.${name}(${fields.map((_,i)=>'$'+(i+1)).join(',')}) AS result`,fields.map(k=>k==='p_data'?JSON.stringify(args[k]):args[k]))).rows[0].result,error:null};}
  catch(e){return {data:null,error:{code:e.code,message:e.message}};}
 }};
}

export async function salesActor(db,role='agent') {
 const p=await privileged(db,`${role}@example.test`,role);await ready(db,p.id);
 const d=await issued(db,p.id,'mfa'),v=consumeData(d);await command(db,'consume',v);return {id:p.id,session:v.session_id};
}
