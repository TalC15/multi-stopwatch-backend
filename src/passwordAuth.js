import crypto from 'node:crypto';
import bcrypt from 'bcrypt';
import { createAuthEmail } from './authEmail.js';
import { setRefreshCookie, readRefreshCookie, readMfaCookie, setMfaCookie, clearMfaCookie } from './webAuth.js';

const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const secret = /^[A-Za-z0-9_-]{43}$/;
const errors = { AUTH_INPUT_INVALID: 400, AUTH_INVALID: 401, AUTH_FORBIDDEN: 403,
  AUTH_RATE_LIMITED: 429, AUTH_NOT_READY: 503, AUTH_UNAVAILABLE: 503, AUTH_EMAIL_UNAVAILABLE: 503 };
const fail = code => Object.assign(new Error(code), { code });
export const normalizeAuthEmail = value => {
  // ASCII canonicalization only; no provider-specific dot/plus rewriting.
  if (typeof value !== 'string') throw fail('AUTH_INPUT_INVALID');
  const email = value.trim().toLowerCase();
  if (email.length > 254 || !/^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9.-]+\.[a-z]{2,}$/.test(email)) throw fail('AUTH_INPUT_INVALID');
  return email;
};
export function validateAuthPassword(value) {
  // eslint-disable-next-line no-control-regex -- bcrypt's byte bound and control rejection are API policy.
  if (typeof value !== 'string' || !value.isWellFormed() || [...value].length < 16 || Buffer.byteLength(value, 'utf8') > 72 || /[\u0000-\u001f\u007f]/.test(value)) throw fail('AUTH_INPUT_INVALID');
  return value;
}
const exact = (body, keys) => {
  if (!body || typeof body !== 'object' || Array.isArray(body) || Object.keys(body).length !== keys.length || keys.some(k => !Object.hasOwn(body,k))) throw fail('AUTH_INPUT_INVALID');
};
// Cost12 dummy compare runs for unknown/unready accounts as for known accounts.
const dummyHash = bcrypt.hash(crypto.randomBytes(32).toString('base64url'), 12);
export function createPasswordAuth({ db, tokens, mail = createAuthEmail(), env = process.env }) {
  const hmac = (keyName, values) => {
    const key = env[keyName];
    if (typeof key !== 'string' || key.length!==64 || !/^[a-f0-9]{64}$/i.test(key)) throw fail('AUTH_NOT_READY');
    return crypto.createHmac('sha256',Buffer.from(key,'hex')).update(JSON.stringify(values)).digest('hex');
  };
  async function rpc(name,args) {
    let response;
    try { response = await db.rpc(name,args); } catch { throw fail('AUTH_UNAVAILABLE'); }
    if (response?.error) {
      const code = response.error.code==='P0001' && Object.hasOwn(errors,response.error.message) ? response.error.message : 'AUTH_UNAVAILABLE';
      throw fail(code);
    }
    return response?.data;
  }
  const command = (action,data) => rpc('keeptimer_auth_command',{p_action:action,p_data:data});
  function cryptoConfigured() {
    hmac('AUTH_TOKEN_HMAC_KEY',['configuration']); hmac('AUTH_RATE_HMAC_KEY',['configuration']);
  }
  function mailConfigured() {
    cryptoConfigured();
    let url;
    try { url = new URL(env.AUTH_PUBLIC_ORIGIN); } catch { throw fail('AUTH_NOT_READY'); }
    if (url.protocol!=='https:' || url.username || url.password || url.pathname!=='/' || url.search || url.hash ||
        !(env.AUTH_ALLOWED_ORIGINS || '').split(',').map(s=>s.trim()).includes(url.origin) || !mail.configured()) throw fail('AUTH_NOT_READY');
    return url.origin;
  }
  async function limit(kind,account,ip) {
    if (typeof ip!=='string' || !ip) throw fail('AUTH_UNAVAILABLE');
    const data=await rpc('keeptimer_auth_limit',{p_kind:kind,
      p_account:hmac('AUTH_RATE_HMAC_KEY',[kind,'account',account]),p_ip:hmac('AUTH_RATE_HMAC_KEY',[kind,'ip',ip])});
    if(data!==true) throw fail('AUTH_RATE_LIMITED');
  }
  const digest = (purpose,id,context,proof) => ({
    context_digest:hmac('AUTH_TOKEN_HMAC_KEY',['context',purpose,id,context]),
    proof_digest:hmac('AUTH_TOKEN_HMAC_KEY',['proof',purpose,id,context,proof]),
  });
  function context(body,purpose) {
    if(typeof body.challengeId!=='string' || !uuid.test(body.challengeId) || typeof body.context!=='string' || !secret.test(body.context)) throw fail('AUTH_INPUT_INVALID');
    const id=body.challengeId.toLowerCase();
    return {challenge_id:id,purpose,...digest(purpose,id,body.context,purpose==='mfa'?body.code:body.context)};
  }
  function session(id) {
    const sessionId=crypto.randomUUID(), user={id};
    const accessToken=tokens.generateAccessToken(user,sessionId),refreshToken=tokens.generateRefreshToken(user,sessionId);
    return { id,sessionId,accessToken,refreshToken,refresh_hash:tokens.hashToken(refreshToken) };
  }
  function resultSession(data, issued) {
    if(data?.ok!==true || data.user?.id!==issued.id || !uuid.test(data.user?.id || '') || !['worker','superadmin','agent'].includes(data.user?.role)) throw fail('AUTH_INVALID');
    return { accessToken:issued.accessToken,refreshToken:issued.refreshToken,sessionId:issued.sessionId,user:data.user };
  }
  async function deliver(row,purpose,id,contextValue,proof,proofDigest,origin,generation=1) {
    let accepted=false;
    try {
      accepted=(await mail.send({to:row.email,purpose,code:purpose==='mfa'?proof:undefined,
        url:purpose==='mfa'?undefined:`${origin}/account/${purpose==='activation'?'activate':'reset'}#id=${id}&token=${contextValue}`,
        challengeId:id,generation})).accepted===true;
    } catch { /* No exception/provider/request/OTP logging. */ }
    const confirmed=await command('delivery',{challenge_id:id,proof_digest:proofDigest,accepted});
    if(!accepted || confirmed?.ok!==true) throw fail('AUTH_EMAIL_UNAVAILABLE');
  }
  async function issue(candidate,purpose,transport,origin,browserContext='') {
    const id=crypto.randomUUID(),ctx=crypto.randomBytes(32).toString('base64url');
    const proof=purpose==='mfa'?String(crypto.randomInt(0,100_000_000)).padStart(8,'0'):ctx;
    const hashes=digest(purpose,id,ctx,proof);
    const row=await command('issue',{user_id:candidate.id,purpose,transport,challenge_id:id,...hashes,
      ...(purpose==='mfa'?{expected_hash:candidate.hash,binding_digest:hmac('AUTH_TOKEN_HMAC_KEY',['browser',browserContext])}:{})});
    if(row?.ok!==true) throw fail(row?.code==='AUTH_RATE_LIMITED'?'AUTH_RATE_LIMITED':'AUTH_INVALID');
    await deliver(row,purpose,id,ctx,proof,hashes.proof_digest,origin);
    return {mfaRequired:true,challengeId:id,context:ctx,retryAfter:60,expiresIn:600};
  }
  async function passwordLogin(body,ip,transport,browserContext='') {
    exact(body,['email','password']); const email=normalizeAuthEmail(body.email); validateAuthPassword(body.password);
    cryptoConfigured(); await limit('login',email,ip);
    const candidate=await command('lookup',{email});
    const matches=await bcrypt.compare(body.password,candidate?.hash || await dummyHash);
    if(!matches || candidate?.ready!==true || transport==='native' && candidate.role!=='worker') throw fail('AUTH_INVALID');
    if(['superadmin','agent'].includes(candidate.role)) {
      const origin=mailConfigured();
      await limit('send',email,ip); return issue(candidate,'mfa',transport,origin,browserContext);
    }
    const issued=session(candidate.id);
    return resultSession(await command('login',{user_id:candidate.id,expected_hash:candidate.hash,transport,session_id:issued.sessionId,refresh_hash:issued.refresh_hash}),issued);
  }
  async function verifyMfa(body,ip,browserContext='') {
    exact(body,['challengeId','context','code']);
    if(typeof body.code!=='string' || !/^\d{8}$/.test(body.code)) throw fail('AUTH_INPUT_INVALID');
    mailConfigured(); const data={...context(body,'mfa'),transport:'web',binding_digest:hmac('AUTH_TOKEN_HMAC_KEY',['browser',browserContext])};
    await limit('verify',body.challengeId,ip);
    const inspected=await command('inspect',data);
    if(inspected?.ok!==true || !uuid.test(inspected.id || '')) throw fail('AUTH_INVALID');
    const issued=session(inspected.id);
    return resultSession(await command('consume',{...data,session_id:issued.sessionId,refresh_hash:issued.refresh_hash}),issued);
  }
  async function resendMfa(body,ip,browserContext='') {
    exact(body,['challengeId','context']); const origin=mailConfigured();
    const data={...context(body,'mfa'),transport:'web',binding_digest:hmac('AUTH_TOKEN_HMAC_KEY',['browser',browserContext])};
    await limit('send',body.challengeId,ip);
    const proof=String(crypto.randomInt(0,100_000_000)).padStart(8,'0');
    const hashes=digest('mfa',data.challenge_id,body.context,proof);
    const row=await command('resend',{...data,proof_digest:hashes.proof_digest});
    if(row?.ok!==true) throw fail(row?.code==='AUTH_RATE_LIMITED'?'AUTH_RATE_LIMITED':'AUTH_INVALID');
    // Unique generation keyed to the replacement proof, no raw OTP in headers.
    await deliver(row,'mfa',data.challenge_id,body.context,proof,hashes.proof_digest,origin,hashes.proof_digest);
    return {accepted:true,retryAfter:60};
  }
  async function requestLink(body,ip,purpose) {
    exact(body,['email']); const email=normalizeAuthEmail(body.email);mailConfigured();
    await limit('send',email,ip);
    const accepted=await rpc('keeptimer_auth_link_queue_rpc',{p_action:'enqueue',p_data:{id:crypto.randomUUID(),email,purpose}});
    if(accepted?.ok!==true)throw fail('AUTH_UNAVAILABLE');
    return {accepted:true,message:'İstek alındı. Hesap uygunsa e-posta işlemi başlatılır. Teslimat garanti edilmez.'};
  }
  // Bounded worker: eligibility and network delivery never run in requestLink.
  // Separate DB claims/leases allow multiple instances and restart recovery.
  let drainPromise=null;
  async function drainLinks() {
    if(drainPromise)return drainPromise;
    drainPromise=(async()=>{
    try {
      await rpc('keeptimer_auth_maintain',{});
      const origin=mailConfigured();
      for(let count=0;count<5;count++) {
        const job=await rpc('keeptimer_auth_link_queue_rpc',{p_action:'claim',p_data:{}});
        if(!job)break;
        try {
          const candidate=await command('lookup',{email:job.email});
          if(candidate && (job.purpose==='activation'?candidate.ready!==true:candidate.ready===true && candidate.role==='worker')) {
            await issue(candidate,job.purpose,'web',origin);
          }
        } catch { /* Failed delivery stays unusable; never log account/token/provider. */ }
        await rpc('keeptimer_auth_link_queue_rpc',{p_action:'done',p_data:{id:job.id,lease:job.lease}});
      }
    } catch { /* Closed gate/unavailable DB/config never enables fake delivery. */ }
    })().finally(()=>{drainPromise=null;});
    return drainPromise;
  }
  async function consumeLink(body,ip,purpose) {
    exact(body,['challengeId','context','password']); cryptoConfigured(); validateAuthPassword(body.password);
    const data={...context(body,purpose),transport:'web'}; await limit('verify',body.challengeId,ip);
    const hash=await bcrypt.hash(body.password,12);
    const result=await command('consume',{...data,password_hash:hash});
    if(result?.ok!==true || result.loginReady!==true || !uuid.test(result.userId || '')) throw fail('AUTH_INVALID');
    return {success:true,loginReady:true,userId:result.userId}; // Does not log in or create MFA evidence.
  }
  async function changePassword(body,ip,user,sessionId,transport) {
    exact(body,['email','currentPassword','password']); cryptoConfigured(); const email=normalizeAuthEmail(body.email);
    validateAuthPassword(body.currentPassword); validateAuthPassword(body.password); await limit('login',email,ip);
    const candidate=await command('lookup',{email});
    const matches=await bcrypt.compare(body.currentPassword,candidate?.hash || await dummyHash);
    if(!matches || candidate?.id!==user.id || candidate?.ready!==true) throw fail('AUTH_INVALID');
    const hash=await bcrypt.hash(body.password,12);
    const result=await command('change',{user_id:user.id,session_id:sessionId,transport,expected_hash:candidate.hash,password_hash:hash});
    if(result?.ok!==true) throw fail('AUTH_INVALID');
    return {success:true,requiresLogin:true};
  }
  async function sessions(body,user,sessionId,revoke=false) {
    exact(body,[]); cryptoConfigured();
    const result=await command(revoke?'revoke_sessions':'sessions',{user_id:user.id,session_id:sessionId,transport:'web'});
    if(result?.ok!==true || !revoke && !Array.isArray(result.sessions)) throw fail('AUTH_INVALID');
    return revoke?{success:true,requiresLogin:true}:{sessions:result.sessions};
  }
  return {passwordLogin,verifyMfa,resendMfa,requestLink,consumeLink,changePassword,sessions,drainLinks};
}
export function mountPasswordAuth({app,db,tokens,authenticate,mail,env=process.env}) {
  const core=createPasswordAuth({db,tokens,mail,env});
  const worker=setInterval(()=>void core.drainLinks(),5000);worker.unref();
  // Not an auth session: a short-lived HttpOnly pre-auth browser nonce, additionally
  // bound to the current refresh cookie. Account switch/PIN login/logout clears it.
  const browserContext=(req,nonce=readMfaCookie(req))=>{
    if(!nonce)throw fail('AUTH_INVALID');
    return nonce+':'+(readRefreshCookie(req)?tokens.hashToken(readRefreshCookie(req)):'anonymous');
  };
  const route=(path,fn,session=false)=>app.post(path,...(session?[authenticate]:[]),async(req,res)=>{
    try {
      if(req.path==='/auth/password-login')clearMfaCookie(res);
      const data=await fn(req);
      if(data.mfaRequired && req.mfaNonce)setMfaCookie(res,req.mfaNonce);
      if(data.accessToken) {
        const {refreshToken,...publicData}=data;
        if(!req.nativeAuth) setRefreshCookie(res,refreshToken,tokens.verifyToken(refreshToken).exp);
        return res.json({...publicData,...(req.nativeAuth?{refreshToken}:{})});
      }
      // Revocation makes the old cookie unusable. Do not clear a cookie that
      // may belong to a newer tab login racing this password change.
      return res.json(data);
    } catch(error) {
      const code=Object.hasOwn(errors,error?.code || '')?error.code:'AUTH_UNAVAILABLE';
      if(code==='AUTH_RATE_LIMITED') res.set('Retry-After','900');
      return res.status(errors[code]).json({code,error:code==='AUTH_RATE_LIMITED'?'Çok fazla deneme. Daha sonra tekrar deneyin.':
        code==='AUTH_INVALID'?'Bilgiler doğrulanamadı.':'İşlem şu anda tamamlanamadı.'});
    }
  });
  route(['/auth/password-login','/auth/native/passwordLogin'],req=>{
    req.mfaNonce=crypto.randomBytes(32).toString('base64url');
    return core.passwordLogin(req.body,req.ip,req.nativeAuth?'native':'web',browserContext(req,req.mfaNonce));
  });
  route('/auth/mfa/verify',req=>core.verifyMfa(req.body,req.ip,browserContext(req)));
  route('/auth/mfa/resend',req=>core.resendMfa(req.body,req.ip,browserContext(req)));
  for(const [path,purpose] of [['activation','activation'],['reset','reset']]) {
    route(`/auth/${path}/request`,async req=>{
      const accepted=await core.requestLink(req.body,req.ip,purpose);
      req.res.once('finish',()=>setImmediate(()=>void core.drainLinks()));
      return accepted;
    });
    route(`/auth/${path}/complete`,req=>core.consumeLink(req.body,req.ip,purpose));
  }
  route('/auth/sessions/list',req=>core.sessions(req.body,req.user,req.sessionId),true);
  route('/auth/sessions/revoke-all',req=>core.sessions(req.body,req.user,req.sessionId,true),true);
  route('/auth/password/change',req=>core.changePassword(req.body,req.ip,req.user,req.sessionId,'web'),true);
  return {...core,stopWorker:()=>clearInterval(worker)};
}
