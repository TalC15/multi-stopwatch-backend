import {readFile} from 'node:fs/promises';
import {randomUUID} from 'node:crypto';
import {database as phase6,user} from './subscriptionPhase6.js';
export {connect,localTestUrl} from './subscriptionPhase6.js';
export {fixtureHash,fixturePassword} from './subscriptionPhase3.js';
import {fixtureHash} from './subscriptionPhase3.js';
export const migration=await readFile(new URL('../../db/migrations/20261016_mfa_device_context.sql',import.meta.url),'utf8');
export async function database(t,{enabled=true}={}){
 const db=await phase6(t);
 // Deliberately do NOT read or execute the prohibited cutover migration.
 for(const name of ['20261009_password_mfa_activation.sql','20261009_password_mfa_management.sql'])
  await db.exec(await readFile(new URL('../../db/migrations/'+name,import.meta.url),'utf8'));
 await db.exec(migration);
 // Isolated fixture state only, never a rollout or cutover execution.
 if(enabled)await db.exec('UPDATE keeptimer_auth_release SET cutover=true,enabled=true');
 return db;
}
export async function privileged(db,email='admin@example.test'){
 const id=await user(db,'superadmin');await db.query('SELECT keeptimer_auth_prepare($1,$2,$3)',[id,email,fixtureHash]);
 await db.query('UPDATE keeptimer_auth_accounts SET verified_at=clock_timestamp(),activated_at=clock_timestamp() WHERE user_id=$1',[id]);
 await db.query('UPDATE users SET must_change_password=false WHERE id=$1',[id]);return {id};
}
export const scope=(n='a')=>({context_id:n.repeat(64),device_digest:n.repeat(64),binding_digest:'d'.repeat(64)});
export const command=async(db,action,data)=>(await db.query('SELECT keeptimer_mfa_command($1,$2) AS r',[action,JSON.stringify(data)])).rows[0].r;
export async function start(db,p,s=scope()){
 const args={...s,user_id:p.id,expected_hash:fixtureHash,operation_id:randomUUID(),new_challenge_id:randomUUID(),nonce:'b'.repeat(64),proof_digest:'c'.repeat(64)};
 const r=await command(db,'start',args);return {args,result:r};
}
export async function accept(db,args){
 const c=await command(db,'claim',{...args,challenge_id:args.new_challenge_id});
 return command(db,'delivery',{...args,challenge_id:args.new_challenge_id,operation_id:c.job.id,lease:c.job.lease,delivery:'accepted'});
}
export const verify=(args,extra={})=>({...args,challenge_id:args.new_challenge_id,operation_id:randomUUID(),session_id:randomUUID(),refresh_hash:'f'.repeat(64),...extra});
export function rpcAdapter(db){return {rpc:async(name,args={})=>{
 const fields={keeptimer_auth_command:['p_action','p_data'],keeptimer_auth_limit:['p_kind','p_account','p_ip'],keeptimer_mfa_command:['p_action','p_data'],keeptimer_mfa_maintain:[],keeptimer_auth_maintain:[],keeptimer_auth_link_queue_rpc:['p_action','p_data']}[name];
 if(!fields)throw Error('Unknown fixture RPC');
 try{return {data:(await db.query(`SELECT public.${name}(${fields.map((_,i)=>'$'+(i+1)).join(',')}) AS r`,fields.map(k=>k==='p_data'?JSON.stringify(args[k]):args[k]))).rows[0].r,error:null};}
 catch(e){return {error:{code:e.code,message:e.message},data:null};}
 }};}
