import crypto from 'node:crypto';
import {readRefreshCookie,readMfaCookie,setMfaCookie,REFRESH_COOKIE_OPTIONS} from './webAuth.js';

export const MFA_DEVICE_COOKIE='__Secure-keeptimer-mfa-device';
const tokenPattern=/^[A-Za-z0-9_-]{43}$/;
const uuid=/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
export const mfaMessages={
 MFA_INVALID_CODE:'Doğrulama kodu hatalı. Kalan hakkınızı kontrol edip tekrar deneyin.',
 MFA_CODE_EXPIRED:'Kodun süresi doldu. Yeni bir giriş doğrulaması başlatın.',
 MFA_ATTEMPTS_EXHAUSTED:'Doğrulama kodu 6 kez hatalı girildi. Güvenliğiniz için bu cihazdaki giriş işlemi 10 dakika durduruldu.',
 MFA_DEVICE_LOCKED:'Bu cihazdaki giriş işlemi geçici olarak durduruldu. Kalan sürenin bitmesini bekleyin.',
 MFA_RESEND_COOLDOWN:'Yeni kod istemeden önce belirtilen sürenin bitmesini bekleyin.',
 MFA_SEND_LIMIT_REACHED:'Bu giriş bağlamında 15 dakika içinde 3 kod istendi. Son geçerli kodu kullanabilir veya yeni gönderim için bekleyebilirsiniz.',
 MFA_CHALLENGE_INVALID:'Doğrulama işlemi artık geçerli değil. Girişi yeniden başlatın.',
 MFA_CONTEXT_REQUIRED:'Güvenli giriş bağlamı hazırlanıyor. Girişinizi tekrar deneyin.',
 EMAIL_DELIVERY_UNAVAILABLE:'E-posta gönderimi doğrulanamadı. Durumu tekrar kontrol edin; giriş yetkisi verilmedi.',
 NETWORK_OR_SERVER_ERROR:'İşlem sonucu doğrulanamadı. İnternet bağlantınızı kontrol edip durumu tekrar sorgulayın.',
};
export function createMfaDeviceAuth({rpc,hmac,mail,session,resultSession,limit}) {
 const command=(action,data)=>rpc('keeptimer_mfa_command',{p_action:action,p_data:data});
 const signed=nonce=>nonce+'.'+Buffer.from(hmac('AUTH_TOKEN_HMAC_KEY',['mfa-device-cookie-v1',nonce]),'hex').toString('base64url');
 function device(req,res,create=false){
  const values=(req.headers.cookie || '').split(';').map(v=>v.trim()).filter(v=>v.startsWith(MFA_DEVICE_COOKIE+'='));
  let raw=values.length===1?values[0].slice(MFA_DEVICE_COOKIE.length+1):'';
  const parts=raw.split('.');
  if(parts.length!==2 || !tokenPattern.test(parts[0]) || !tokenPattern.test(parts[1]) ||
    !crypto.timingSafeEqual(Buffer.from(raw),Buffer.from(signed(parts[0])))) {
   if(!create)return null;
   raw=signed(crypto.randomBytes(32).toString('base64url'));
   res.cookie(MFA_DEVICE_COOKIE,raw,{...REFRESH_COOKIE_OPTIONS,maxAge:30*86400_000});
  }
  return raw.split('.')[0];
 }
 function scope(req,res,candidate=null){
  const nonce=device(req,res,false);
  if(!nonce)throw Object.assign(new Error('MFA_CONTEXT_REQUIRED'),{code:'MFA_CONTEXT_REQUIRED'});
  const context=candidate?Buffer.from(hmac('AUTH_TOKEN_HMAC_KEY',['mfa-device-account-v1',nonce,candidate.id]),'hex').toString('base64url'):readMfaCookie(req);
  if(!context)return null;
  if(candidate)setMfaCookie(res,context);
  return {context_id:hmac('AUTH_TOKEN_HMAC_KEY',['mfa-context-id-v1',context]),
   device_digest:hmac('AUTH_TOKEN_HMAC_KEY',['mfa-device-id-v1',nonce]),
   binding_digest:hmac('AUTH_TOKEN_HMAC_KEY',['mfa-binding-v1',nonce,readRefreshCookie(req)||'anonymous'])};
 }
 const challengeContext=(s,id)=>Buffer.from(hmac('AUTH_TOKEN_HMAC_KEY',['mfa-challenge-context-v1',s.context_id,id]),'hex').toString('base64url');
 const proof=(s,id,code)=>hmac('AUTH_TOKEN_HMAC_KEY',['mfa-proof-v1',s.context_id,id,code]);
 const codeFor=nonce=>(BigInt('0x'+hmac('AUTH_TOKEN_HMAC_KEY',['mfa-otp-prf-v1',nonce]))%100_000_000n).toString().padStart(8,'0');
 const validOperation=id=>{if(!uuid.test(id || ''))throw Object.assign(new Error('AUTH_INPUT_INVALID'),{code:'AUTH_INPUT_INVALID'});return id;};
 function publicState(result,s){
  const state=result?.state;
  const safe=state?{...state,...(state.challengeId?{context:challengeContext(s,state.challengeId)}:{})}:undefined;
  if(result?.ok!==true)throw Object.assign(new Error(result?.code || 'MFA_CHALLENGE_INVALID'),{code:result?.code || 'MFA_CHALLENGE_INVALID',state:safe});
  return safe;
 }
 async function sendCurrent(s,state){
  if(state?.phase!=='challenge' || !['pending','unknown'].includes(state.delivery))return state;
  const claimed=await command('claim',{...s,challenge_id:state.challengeId});
  const job=claimed?.job;
  if(!job)return publicState(await command('status',s),s);
  let delivery='unknown';
  try {
   const result=await mail.send({to:job.email,purpose:'mfa',code:codeFor(job.nonce),
    challengeId:job.challengeId,generation:job.id,expiresAt:job.expiresAt});
   delivery=result?.accepted===true?'accepted':result?.delivery==='rejected'?'rejected':'unknown';
  } catch(error){delivery=error?.delivery==='rejected'?'rejected':'unknown';}
  return publicState(await command('delivery',{...s,challenge_id:job.challengeId,operation_id:job.id,lease:job.lease,delivery}),s);
 }
 async function status(req,res){
  // Bootstrap precedes password submission; no mail or account lookup here.
  if(!device(req,res,false)){device(req,res,true);return {phase:'idle'};}
  const s=scope(req,res);if(!s)return {phase:'idle'};
  await limit('verify','mfa-state:'+s.context_id,req.ip);
  return {state:await sendCurrent(s,publicState(await command('status',s),s))};
 }
 async function start(candidate,body,req,res){
  const s=scope(req,res,candidate),operation=validOperation(body.operationId);
  await limit('send','mfa-device:'+s.context_id,req.ip);
  const id=crypto.randomUUID(),nonce=crypto.randomBytes(32).toString('hex');
  const state=publicState(await command('start',{...s,user_id:candidate.id,expected_hash:candidate.hash,
   operation_id:operation,new_challenge_id:id,nonce,proof_digest:proof(s,id,codeFor(nonce))}),s);
  const latest=await sendCurrent(s,state);
  return {mfaRequired:true,...latest};
 }
 function validate(req,res,keys){
  const body=req.body;
  if(!body || typeof body!=='object' || Array.isArray(body) || Object.keys(body).length!==keys.length || keys.some(k=>!Object.hasOwn(body,k)))
   throw Object.assign(new Error('AUTH_INPUT_INVALID'),{code:'AUTH_INPUT_INVALID'});
  validOperation(body.operationId);
  const s=scope(req,res);
  if(!s || !uuid.test(body.challengeId || '') || !tokenPattern.test(body.context || '') ||
   !crypto.timingSafeEqual(Buffer.from(body.context),Buffer.from(challengeContext(s,body.challengeId))))
   throw Object.assign(new Error('MFA_CHALLENGE_INVALID'),{code:'MFA_CHALLENGE_INVALID'});
  return s;
 }
 async function resend(req,res){
  const s=validate(req,res,['challengeId','context','operationId']),body=req.body;
  await limit('send','mfa-device:'+s.context_id,req.ip);
  const nonce=crypto.randomBytes(32).toString('hex');
  const state=publicState(await command('resend',{...s,challenge_id:body.challengeId,operation_id:body.operationId,
   nonce,proof_digest:proof(s,body.challengeId,codeFor(nonce))}),s);
  const latest=await sendCurrent(s,state);
  return {accepted:latest.delivery==='accepted',...latest};
 }
 async function verify(req,res){
  const s=validate(req,res,['challengeId','context','code','operationId']),body=req.body;
  if(!/^\d{8}$/.test(body.code || ''))throw Object.assign(new Error('AUTH_INPUT_INVALID'),{code:'AUTH_INPUT_INVALID'});
  await limit('verify','mfa-device:'+s.context_id,req.ip);
  // Inspection only identifies the target server-side; it never grants a session.
  const check=await command('status',s);publicState(check,s);
  const issued=session(check.id);
  const result=await command('verify',{...s,challenge_id:body.challengeId,operation_id:body.operationId,
   proof_digest:proof(s,body.challengeId,body.code),session_id:issued.sessionId,refresh_hash:issued.refresh_hash});
  publicState(result,s);
  // JWTs must be minted for the locked, verified DB identity, not a body userId.
  return resultSession(result,issued);
 }
 return {start,status,resend,verify};
}
