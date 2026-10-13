import crypto from 'node:crypto';
import bcrypt from 'bcrypt';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const invalid=()=>Object.assign(new Error('AUTH_INPUT_INVALID'),{code:'AUTH_INPUT_INVALID'});
const exact=(data,keys)=>{
 if(!data || Array.isArray(data) || typeof data!=='object' || Object.keys(data).length!==keys.length || keys.some(k=>!Object.hasOwn(data,k)))throw invalid();
};
const id=value=>{if(typeof value!=='string' || !uuid.test(value))throw invalid();return value;};
const name=value=>{if(typeof value!=='string' || !/^[A-Za-z0-9_.-]{3,25}$/.test(value))throw invalid();return value;};
const workspace=value=>value===null?null:id(value);
const empty=req=>{exact(req.body ?? {},[]);return {};};
const routes=[
 ['get','/users','users',()=>({})],['get','/admin/users','users',()=>({})],
 ['get','/admin/workspaces','workspaces',()=>({})],
 ['get','/admin/workspaces/:id','workspace_detail',req=>({id:id(req.params.id)})],
 ['get','/workspace','workspace',()=>({})],
 ['post','/users/create','user_create',async req=>{
  exact(req.body,['username','pin','role','workspace_id']);
  if(!['worker','manager'].includes(req.body.role) || typeof req.body.pin!=='string' || req.body.pin.length<1 || req.body.pin.length>25 || Buffer.byteLength(req.body.pin)>72)throw invalid();
  return {username:name(req.body.username),role:req.body.role,workspace_id:workspace(req.body.workspace_id),pin_hash:await bcrypt.hash(req.body.pin,12)};
 }],
 ['patch','/admin/users/:id','user_update',req=>{
  exact(req.body,['username','role','workspace_id']);
  if(!['worker','manager','superadmin','agent'].includes(req.body.role))throw invalid();
  return {id:id(req.params.id),username:name(req.body.username),role:req.body.role,workspace_id:workspace(req.body.workspace_id)};
 }],
 ...['/users/:id','/admin/users/:id'].map(path=>['delete',path,'user_disable',req=>{empty(req);return {id:id(req.params.id)};}]),
 ['post','/users/:id/force-logout','force_logout',req=>{empty(req);return {id:id(req.params.id)};}],
 ['post','/workspace/create','workspace_create',req=>{exact(req.body,['name']);if(typeof req.body.name!=='string' || !req.body.name.trim() || req.body.name.length>100)throw invalid();return {name:req.body.name,invite_code:crypto.randomBytes(12).toString('hex').toUpperCase()};}],
 ['post','/workspace/join','workspace_join',req=>{exact(req.body,['inviteCode']);if(typeof req.body.inviteCode!=='string' || !req.body.inviteCode || req.body.inviteCode.length>64)throw invalid();return req.body;}],
 ['post','/workspace/leave','workspace_leave',empty],['post','/workspace/toggle-shared','workspace_toggle',empty],
 ['post','/workspace/refresh-invite','workspace_invite',req=>{empty(req);return {invite_code:crypto.randomBytes(12).toString('hex').toUpperCase()};}],
];
export function mountPrivilegedManagement({app,authenticate,db,origins,onRevoke=()=>{}}) {
 const webCors=cors({origin:(origin,done)=>done(null,origins.has(origin)),methods:['GET','POST','PATCH','DELETE'],allowedHeaders:['Authorization','Content-Type','X-KeepTimer-CSRF']});
 const limiter=rateLimit({windowMs:60_000,limit:60,standardHeaders:true,legacyHeaders:false});
 const deny=(res,status,code)=>res.status(status).json({code,error:'Yönetim işlemi tamamlanamadı.'});
 for(const [method,path,action,parse] of routes)app[method](path,authenticate,(req,res,next)=>{
  if(!['agent','superadmin'].includes(req.user.role))return next('route');
  res.set({'Cache-Control':'no-store','CDN-Cache-Control':'no-store'});res.vary('Origin');
  if(req.user.role!=='superadmin')return deny(res,403,'AUTH_FORBIDDEN');
  if(!origins.size)return deny(res,503,'AUTH_NOT_READY');
  if(!origins.has(req.get('Origin')))return deny(res,403,'AUTH_FORBIDDEN');
  if(method!=='get' && (!req.is('application/json') || req.get('X-KeepTimer-CSRF')!=='1'))return deny(res,403,'AUTH_FORBIDDEN');
  return webCors(req,res,()=>limiter(req,res,async()=>{
   try {
    exact(req.query,[]);const data=await parse(req);
    const reply=await db.rpc('keeptimer_auth_management',{p_actor:req.user.id,p_session:req.sessionId,p_action:action,p_data:data});
    if(reply.error) {
     const code=reply.error.code==='P0001'?reply.error.message:'AUTH_UNAVAILABLE';
     const status=code==='AUTH_RESOURCE_NOT_FOUND'?404:code==='AUTH_INPUT_INVALID'?400:code==='AUTH_FORBIDDEN'?403:code?.startsWith('KEEPTIMER_')?409:503;
     return deny(res,status,['AUTH_RESOURCE_NOT_FOUND','AUTH_INPUT_INVALID','AUTH_FORBIDDEN','AUTH_NOT_READY'].includes(code)?code:status===409?'AUTH_CONFLICT':'AUTH_UNAVAILABLE');
    }
    if(!reply.data || typeof reply.data!=='object')return deny(res,503,'AUTH_UNAVAILABLE');
    if(['force_logout','user_disable'].includes(action))onRevoke(data.id);
    return res.json(reply.data);
   } catch(error){return deny(res,error.code==='AUTH_INPUT_INVALID'?400:503,error.code==='AUTH_INPUT_INVALID'?'AUTH_INPUT_INVALID':'AUTH_UNAVAILABLE');}
  }));
 });
}
