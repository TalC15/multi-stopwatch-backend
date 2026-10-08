import bcrypt from 'bcrypt';
import { createHmac } from 'node:crypto';
import cors from 'cors';
import rateLimit from 'express-rate-limit';

const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const statuses = Object.freeze({
  PRIVILEGED_MFA_NOT_READY: 503, PRIVILEGED_MFA_REQUIRED: 403, PASSWORD_CHANGE_REQUIRED: 403,
  SALES_SESSION_INVALID: 401, SALES_FORBIDDEN: 403, SALES_INPUT_INVALID: 400,
  PLAN_NOT_AVAILABLE: 403, ACTIVE_AGENT_EXISTS: 409, IDEMPOTENCY_CONFLICT: 409,
  SUBSCRIPTION_CONFLICT: 409, PENDING_PERIOD_EXISTS: 409,
  CUSTOMER_NOT_FOUND: 404, AGENT_NOT_FOUND: 404, SUBSCRIPTION_NOT_FOUND: 404,
  SALES_IDENTITY_CONFLICT: 409, SALES_UNAVAILABLE: 503,
});
const fail = code => Object.assign(new Error(code), { code });
const sendError = (res, error) => {
  const code = typeof error?.code === 'string' && Object.hasOwn(statuses, error.code) ? error.code : 'SALES_UNAVAILABLE';
  return res.status(statuses[code]).json({ code, error: 'İşlem tamamlanamadı' });
};
const exact = (body, required, optional = []) => {
  if (!body || typeof body !== 'object' || Array.isArray(body) || required.some(k => !Object.hasOwn(body, k)) ||
      Object.keys(body).some(k => ![...required, ...optional].includes(k))) throw fail('SALES_INPUT_INVALID');
};
const id = value => { if (typeof value !== 'string' || !uuid.test(value)) throw fail('SALES_INPUT_INVALID'); return value.toLowerCase(); };
const project = (value, fields) => {
  if (!value || typeof value !== 'object' || Array.isArray(value) || fields.some(k => !Object.hasOwn(value,k))) throw fail('SALES_UNAVAILABLE');
  return Object.fromEntries(fields.map(k=>[k,value[k]]));
};
// Keep the Phase 2 RPC timestamp contract without changing its core: validate
// the calendar in UTC, convert whole seconds, then add integer microseconds.
function timestampMicros(value) {
  if (typeof value !== 'string') return null;
  const match = /^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:\.(\d{1,6}))?(Z|[+-]\d{2}(?::?\d{2})?)$/.exec(value);
  if (!match || match[0] !== value) return null;
  const local = `${match[1]}T${match[2]}`;
  const localMs = Date.parse(`${local}Z`);
  if (!Number.isFinite(localMs) || new Date(localMs).toISOString().slice(0, 19) !== local) return null;
  const zone = match[4].length === 3 ? `${match[4]}:00` : match[4];
  const milliseconds = Date.parse(`${local}${zone}`);
  if (!Number.isFinite(milliseconds)) return null;
  return BigInt(milliseconds) * 1000n + BigInt((match[3] || '').padEnd(6, '0'));
}
const entitlementCodes = new Set([
  'ACCOUNT_DISABLED', 'SUBSCRIPTION_REQUIRED', 'SUBSCRIPTION_PENDING', 'SUBSCRIPTION_EXPIRED',
  'SUBSCRIPTION_CANCELLED', 'PLAN_DISABLED', 'SUBSCRIPTION_FORBIDDEN', 'SUBSCRIPTION_CONFLICT',
  'INDIVIDUAL_SCOPE_NOT_READY', 'SUBSCRIPTION_UNAVAILABLE',
]);
function subscriptionResult(value) {
  const item=project(value,['id','customerId','planCode','sequenceNo','startsAt','endsAt','termMonths','amountMinor','currency',
    'createdBy','cancelledAt','cancelledBy','cancellationReason']);
  if (!['id','customerId','createdBy'].every(k=>typeof item[k]==='string'&&uuid.test(item[k])) || item.planCode!=='individual' ||
    !Number.isInteger(item.sequenceNo) || item.sequenceNo<1 || !Number.isInteger(item.termMonths) || item.termMonths<1 || item.termMonths>12 ||
    typeof item.startsAt!=='string' || typeof item.endsAt!=='string' || typeof item.amountMinor!=='string' || !/^\d+$/.test(item.amountMinor) ||
    typeof item.currency!=='string' || !/^[A-Z]{3}$/.test(item.currency) ||
    !(item.cancelledAt===null||typeof item.cancelledAt==='string') ||
    !(item.cancelledBy===null||typeof item.cancelledBy==='string'&&uuid.test(item.cancelledBy)) ||
    !(item.cancellationReason===null||['customer_request','payment_record_correction','administrative'].includes(item.cancellationReason))) throw fail('SALES_UNAVAILABLE');
  const startsAt=timestampMicros(item.startsAt),endsAt=timestampMicros(item.endsAt);
  if (startsAt===null || endsAt===null || endsAt<=startsAt ||
      (item.cancelledAt===null ? item.cancelledBy!==null || item.cancellationReason!==null :
        timestampMicros(item.cancelledAt)===null || item.cancelledBy===null)) throw fail('SALES_UNAVAILABLE');
  return item;
}
function commandResult(action,value) {
  if (action==='customer_create'||action==='subscription_renew'||action==='subscription_cancel') {
    const result=project(value,action==='subscription_cancel'?['customerId','subscription']:['customerId','subscription','loginReady']);
    result.subscription=subscriptionResult(result.subscription);
    if (result.customerId!==result.subscription.customerId || action!=='subscription_cancel'&&result.loginReady!==false) throw fail('SALES_UNAVAILABLE');
    return result;
  }
  const fields=action==='agent_create'?['agentId','mustChangePassword','loginReady']:
    action==='agent_revoke'?['agentId','disabled']:['userId','mustChangePassword','loginReady'];
  const result=project(value,fields),target=result.agentId??result.userId;
  if(typeof target!=='string'||!uuid.test(target)||
    (action==='agent_revoke'?result.disabled!==true:result.mustChangePassword!==true||result.loginReady!==false)) throw fail('SALES_UNAVAILABLE');
  return result;
}
function password(value) {
  if (typeof value !== 'string' || [...value].length < 16 || Buffer.byteLength(value, 'utf8') > 72 || /[\u0000-\u001f\u007f]/.test(value)) {
    throw fail('SALES_INPUT_INVALID');
  }
  return value;
}
function sale(body) {
  if (body.planCode !== undefined && body.planCode !== 'individual') throw fail('PLAN_NOT_AVAILABLE');
  if (!Number.isInteger(body.termMonths) || body.termMonths < 1 || body.termMonths > 12 ||
    !Number.isSafeInteger(body.amountMinor) || body.amountMinor < 0 ||
    typeof body.currency !== 'string' || !/^[A-Z]{3}$/.test(body.currency)) throw fail('SALES_INPUT_INVALID');
  return { plan_code: 'individual', term_months: body.termMonths, amount_minor: body.amountMinor, currency: body.currency };
}
function account(body) {
  if (typeof body.username !== 'string' || !/^[A-Za-z0-9_.-]{3,25}$/.test(body.username)) throw fail('SALES_INPUT_INVALID');
  return { username: body.username, password: password(body.password) };
}

// Password-bearing bodies are never stored, returned, or logged. The HMAC key
// is separate from JWT/service credentials and stable across retries/restarts.
export function createSalesCore(db) {
  async function rpc(name, args) {
    let response;
    try { response = await db.rpc(name, args); } catch { throw fail('SALES_UNAVAILABLE'); }
    if (response?.error) {
      const message = response.error.message;
      if (response.error.code === 'P0001' && typeof message === 'string' && Object.hasOwn(statuses, message)) throw fail(message);
      if (response.error.code === '23505') throw fail('SALES_IDENTITY_CONFLICT');
      if (['22P02','22003','23514'].includes(response.error.code)) throw fail('SALES_INPUT_INVALID');
      throw fail('SALES_UNAVAILABLE');
    }
    return response?.data;
  }
  async function access(actor, session, role) {
    if (await rpc('keeptimer_phase3_access', { p_actor: id(actor), p_session: id(session), p_role: role }) !== true) throw fail('SALES_UNAVAILABLE');
  }
  async function command(actor, session, request, action, data) {
    const role = action.startsWith('agent_') ? 'superadmin' : 'agent';
    await access(actor, session, role); // Reject before expensive password work.
    const key = process.env.SUBSCRIPTION_IDEMPOTENCY_HMAC_KEY;
    if (typeof key !== 'string' || !/^(?:[a-f0-9]{2}){32,64}$/i.test(key)) throw fail('SALES_UNAVAILABLE');
    const fingerprint = createHmac('sha256', Buffer.from(key, 'hex')).update(JSON.stringify({ action, data })).digest('hex');
    const payload = { ...data };
    if (Object.hasOwn(payload, 'password')) {
      payload.password_hash = await bcrypt.hash(password(payload.password), 12);
      delete payload.password;
    }
    const result = await rpc('keeptimer_phase3_command', {
      p_actor: id(actor), p_session: id(session), p_request: id(request), p_action: action,
      p_fingerprint: fingerprint, p_data: payload,
    });
    return commandResult(action,result);
  }
  async function list(actor, session, kind, customer, after, limit) {
    const result = await rpc('keeptimer_phase3_list', { p_actor: id(actor), p_session: id(session), p_kind: kind,
      p_customer: customer ? id(customer) : null, p_after: after ? id(after) : null, p_limit: limit });
    if (!result || !Array.isArray(result.items) || result.items.length > limit ||
        !(result.nextCursor === null || typeof result.nextCursor === 'string' && uuid.test(result.nextCursor))) throw fail('SALES_UNAVAILABLE');
    const items=result.items.map(value=>{
      if(kind==='history')return subscriptionResult(value);
      const row=project(value,kind==='agents'?['id','username','disabledAt','mustChangePassword']:
        ['id','username','disabledAt','status','endsAt','isEntitled','code']);
      if(typeof row.id!=='string'||!uuid.test(row.id)||typeof row.username!=='string'||
        !(row.disabledAt===null||typeof row.disabledAt==='string'))throw fail('SALES_UNAVAILABLE');
      if(kind==='agents' ? typeof row.mustChangePassword!=='boolean' :
        ![null,'pending','active','expired','cancelled'].includes(row.status)||typeof row.isEntitled!=='boolean'||
        !(row.endsAt===null||timestampMicros(row.endsAt)!==null)||
        !(row.code===null||typeof row.code==='string'&&entitlementCodes.has(row.code)))throw fail('SALES_UNAVAILABLE');
      return row;
    });
    return {items,nextCursor:result.nextCursor};
  }
  return { command, list };
}

export function mountSubscriptionSales({ app, authenticate, db, origins }) {
  const core = createSalesCore(db);
  const webCors = cors({ origin: (origin, done) => done(null, origins.has(origin)),
    methods: ['GET','POST'], allowedHeaders: ['Authorization','Content-Type','X-KeepTimer-CSRF','Idempotency-Key'] });
  const limiter = rateLimit({ windowMs: 60_000, limit: 30, standardHeaders: true, legacyHeaders: false,
    handler: (_req,res) => res.status(429).json({code:'SALES_RATE_LIMITED',error:'Çok fazla istek'}) });
  app.use(['/admin/agents','/agent/customers'], (req, res, next) => {
    req.webAuth = true;
    res.set('Cache-Control','no-store'); res.vary('Origin');
    if (!origins.size) return sendError(res, fail('PRIVILEGED_MFA_NOT_READY'));
    if (!origins.has(req.get('Origin'))) return sendError(res, fail('SALES_FORBIDDEN'));
    return webCors(req, res, () => {
      if (!['GET','POST'].includes(req.method)) return res.status(405).set('Allow','GET, POST').json({ code:'SALES_METHOD_INVALID' });
      if (req.method==='POST' && (!req.is('application/json') || req.get('X-KeepTimer-CSRF')!=='1')) return sendError(res, fail('SALES_INPUT_INVALID'));
      next();
    });
  }, limiter, authenticate);
  const write = (path, role, action, parse) => app.post(path, async (req, res) => {
    try {
      if (req.user.role !== role) throw fail('SALES_FORBIDDEN');
      const request = id(req.get('Idempotency-Key'));
      const data = parse(req.body, req.params);
      res.json(await core.command(req.user.id, req.sessionId, request, action, data));
    } catch (error) { sendError(res,error); }
  });
  write('/admin/agents','superadmin','agent_create', body => {
    exact(body,['username','password','mfaEmail']);
    if (typeof body.mfaEmail!=='string' || body.mfaEmail.length>254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(body.mfaEmail)) throw fail('SALES_INPUT_INVALID');
    return { ...account(body), mfa_email: body.mfaEmail.toLowerCase() };
  });
  write('/admin/agents/:id/revoke','superadmin','agent_revoke', (body,params) => { exact(body,[]); return { agent_id:id(params.id) }; });
  write('/agent/customers','agent','customer_create', body => {
    exact(body,['username','password','termMonths','amountMinor','currency'],['planCode']);
    return { ...account(body), ...sale(body) };
  });
  write('/agent/customers/:id/subscriptions','agent','subscription_renew', (body,params) => {
    exact(body,['termMonths','amountMinor','currency'],['planCode']);
    return { customer_id:id(params.id), ...sale(body) };
  });
  write('/agent/customers/:id/subscriptions/:subscriptionId/cancel','agent','subscription_cancel', (body,params) => {
    exact(body,['reason']);
    if (!['customer_request','payment_record_correction','administrative'].includes(body.reason)) throw fail('SALES_INPUT_INVALID');
    return { customer_id:id(params.id), subscription_id:id(params.subscriptionId), reason:body.reason };
  });
  for (const [base,role,action,key] of [['/admin/agents','superadmin','agent_password_reset','agent_id'],
    ['/agent/customers','agent','customer_password_reset','customer_id']]) {
    write(base+'/:id/password-reset',role,action,(body,params) => { exact(body,['password']); return { [key]:id(params.id), password:password(body.password) }; });
  }
  for (const [path,role,kind] of [['/admin/agents','superadmin','agents'],['/agent/customers','agent','customers'],
    ['/agent/customers/:id/subscriptions','agent','history']]) app.get(path, async (req,res) => {
    try {
      if (req.user.role!==role) throw fail('SALES_FORBIDDEN');
      exact(req.query,[],['after','limit']);
      if (req.query.limit!==undefined && (typeof req.query.limit!=='string' || !/^[1-9][0-9]?$|^100$/.test(req.query.limit))) throw fail('SALES_INPUT_INVALID');
      const limit=req.query.limit===undefined?25:Number(req.query.limit);
      res.json(await core.list(req.user.id,req.sessionId,kind,req.params.id,req.query.after,limit));
    } catch(error) { sendError(res,error); }
  });
}
