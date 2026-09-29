// Shared v5: commands and snapshots are authorized and serialized by DB RPCs.
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const revision = /^(0|[1-9][0-9]{0,18})$/;
export function validSharedCommand(body) {
  if (!body || Array.isArray(body) || body.protocol !== 5 || !uuid.test(body.timerId) || !uuid.test(body.mutationId) ||
      typeof body.expectedRevision !== 'string' || !revision.test(body.expectedRevision) || BigInt(body.expectedRevision)>9223372036854775807n) return false;
  const base = ['protocol','command','timerId','mutationId','expectedRevision'];
  const extra = body.command === 'create' ? ['name','type','targetMinutes'] : body.command === 'set-pay' ? ['value'] : [];
  if (!['create','start','pause','set-pay','delete'].includes(body.command) || Object.keys(body).some(k=>![...base,...extra].includes(k))) return false;
  if (body.command === 'create') return body.expectedRevision === '0' && typeof body.name === 'string' &&
    body.name.trim().length>0 && [...body.name].length<=35 && ['up','down'].includes(body.type) &&
    Number.isFinite(body.targetMinutes) && Math.trunc(body.targetMinutes*60000)>=1 && body.targetMinutes<=1440;
  return body.command !== 'set-pay' || typeof body.value === 'boolean';
}
export function sharedError(error) {
  const text = error?.message ?? '';
  if (text.includes('ACCOUNT_DISABLED')) return [401,'Oturum geçerli değil'];
  if (/FORBIDDEN|SHARED_MODE_DISABLED/.test(text)) return [403,'Bu ortak işlem için izin yok'];
  if (/CONFLICT|TRANSITION|DELETED/.test(text)) return [409,'Ortak sayaç değişti; güncel durum alınmalı'];
  if (/NOT_FOUND/.test(text)) return [404,'Ortak sayaç bulunamadı'];
  if (/INVALID|TARGET_REQUIRED/.test(text) || ['22P02','22003','22007'].includes(error?.code)) return [400,'Geçersiz ortak sayaç komutu'];
  return [503,'Ortak sayaç sunucusuna erişilemiyor'];
}
export function mountSharedTimers({ app, authenticate, db, io, sendTelegramMessage,
  setTimeout: later = globalThis.setTimeout, clearTimeout: clear = globalThis.clearTimeout, now = Date.now }) {
  const jobs = new Map();
  function publish(envelope) {
    if (!envelope?.timer) return;
    io.to(`workspace-${envelope.workspaceId}`).emit('timer-event', {
      event: envelope.timer.record_status === 'deleted' ? 'deleted' : 'updated', data: envelope,
    });
  }
  async function fire(row) {
    try {
      const { data, error } = await db.rpc('keeptimer_shared_due', { p_id: row.id, p_run: row.shared_run_id, p_ends: row.ends_at });
      const timer = data?.timer;
      if (error || data?.protocol!==5 || data?.success!==true || data.workspaceId!==row.workspace_id ||
          typeof data.generation!=='string' || !revision.test(data.generation) ||
          !Number.isFinite(Date.parse(data.serverNow)) || !timer || timer.id!==row.id ||
          timer.workspace_id!==data.workspaceId || !uuid.test(timer.user_id) || timer.is_shared!==true ||
          timer.record_status!=='active' || timer.shared_alarm_claimed!==true ||
          timer.shared_run_id!==row.shared_run_id || timer.ends_at!==row.ends_at ||
          typeof timer.shared_revision!=='string' || !revision.test(timer.shared_revision) ||
          BigInt(timer.shared_revision)<=BigInt(row.shared_revision) ||
          typeof timer.name!=='string' || !timer.name.trim() || typeof timer.is_pay!=='boolean' ||
          !Number.isFinite(Number(timer.target_minutes)) || Math.trunc(Number(timer.target_minutes)*60000)<1 ||
          !((timer.type==='up' && timer.status==='running') || (timer.type==='down' && timer.status==='completed'))) return;
      publish(data);
      const members = await db.from('users').select('telegram_chat_id').eq('workspace_id',data.workspaceId)
        .is('disabled_at',null).not('telegram_chat_id','is',null);
      if (members.error) return;
      const ids = [...new Set((members.data ?? []).map(m=>m.telegram_chat_id).filter(Boolean))];
      await Promise.allSettled(ids.map(chat=>sendTelegramMessage(chat,`${timer.name} bitti! ${timer.is_pay ? 'ODENDI' : 'ODENMEDI'}`)));
    } catch { /* Claim may already be committed: do not blindly retry delivery. */ }
  }
  function reconcileJob(row) {
    const previous = jobs.get(row.id);
    if (previous && BigInt(previous.revision)>BigInt(row.shared_revision)) return;
    if (previous) clear(previous.handle);
    // Retain revision even when cancelled so a late HTTP ACK cannot re-arm it.
    const entry = { revision: row.shared_revision, handle: null }; jobs.set(row.id,entry);
    if (row.record_status!=='active' || row.archived_at || row.shared_alarm_claimed || !row.shared_run_id || !row.ends_at ||
        !['running','completed'].includes(row.status)) return;
    const wake = () => {
      if (jobs.get(row.id)!==entry) return;
      const delay = Date.parse(row.ends_at)-now();
      if (delay>0) { entry.handle=later(wake,Math.min(delay,2147483647)); entry.handle?.unref?.(); }
      else { entry.handle=null; void fire(row); }
    };
    // Defer even a passed deadline so HTTP ACK cannot wait for Telegram.
    entry.handle=later(wake,Math.max(0,Math.min(Date.parse(row.ends_at)-now(),2147483647))); entry.handle?.unref?.();
  }
  app.post('/timers/shared/commands',authenticate,async (req,res)=>{
    if (!validSharedCommand(req.body)) return res.status(400).json({error:'Geçersiz ortak sayaç komutu'});
    try {
      const {data,error}=await db.rpc('keeptimer_shared_request',{p_actor_id:req.user.id,p_request:req.body});
      if (error || data?.success!==true || !data?.timer) { const [status,message]=sharedError(error); return res.status(status).json({error:message}); }
      publish(data); reconcileJob(data.timer); return res.json(data);
    } catch { return res.status(503).json({error:'Ortak işlem sonucu doğrulanamadı'}); }
  });
  app.get('/timers/shared',authenticate,async (req,res,next)=>{
    if (req.query.protocol!=='5') return next();
    try {
      const {data,error}=await db.rpc('keeptimer_shared_request',{p_actor_id:req.user.id,p_request:{protocol:5,command:'snapshot'}});
      if (error || data?.success!==true || data?.complete!==true || !Array.isArray(data.timers)) {
        const [status,message]=sharedError(error); return res.status(status).json({error:message});
      }
      data.timers.forEach(reconcileJob);
      return res.json(data);
    } catch { return res.status(503).json({error:'Ortak sayaçlar alınamadı'}); }
  });
  return { dispose() { for(const job of jobs.values()) clear(job.handle); jobs.clear(); } };
}
