// The only subscription authority is the DB RPC, never req.body/JWT/client time.
const failures = Object.freeze({
  ACCOUNT_DISABLED: [401, 'Hesap kullanılamıyor'],
  SUBSCRIPTION_REQUIRED: [403, 'Abonelik gerekli'],
  SUBSCRIPTION_PENDING: [403, 'Abonelik henüz başlamadı'],
  SUBSCRIPTION_EXPIRED: [403, 'Abonelik süresi doldu'],
  SUBSCRIPTION_CANCELLED: [403, 'Abonelik iptal edildi'],
  PLAN_DISABLED: [403, 'Paket kullanıma kapalı'],
  SUBSCRIPTION_FORBIDDEN: [403, 'Bu hesap bireysel erişime uygun değil'],
  SUBSCRIPTION_CONFLICT: [409, 'Abonelik dönemleri çakışıyor'],
  INDIVIDUAL_SCOPE_NOT_READY: [403, 'Bireysel hesap kapsamı henüz kullanıma açık değil'],
  SUBSCRIPTION_UNAVAILABLE: [503, 'Abonelik doğrulanamadı'],
});

export function subscriptionFailure(code) {
  const [status, error] = failures[code] || failures.SUBSCRIPTION_UNAVAILABLE;
  return { status, body: { error, code: Object.hasOwn(failures, code) ? code : 'SUBSCRIPTION_UNAVAILABLE' } };
}
const failure = subscriptionFailure;

// PostgreSQL JSON timestamps carry up to six fractional digits. Parse whole
// seconds separately, then add the fraction as integer microseconds after UTC
// offset conversion. Reject calendar normalization and timezone-free values.
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

export function validSubscriptionEntitlement(result) {
  if (!result || typeof result !== 'object' || Array.isArray(result) ||
      typeof result.isEntitled !== 'boolean' || typeof result.requiresSubscription !== 'boolean' ||
      !(result.code === null || (typeof result.code === 'string' && Object.hasOwn(failures, result.code))) ||
      ![null, 'individual', 'team', 'enterprise'].includes(result.planCode) ||
      ![null, 'cancelled', 'pending', 'active', 'expired'].includes(result.status)) return false;
  if (result.planCode === null) {
    if (result.status !== null || result.startsAt !== null || result.endsAt !== null) return false;
  } else {
    const startsAt = timestampMicros(result.startsAt), endsAt = timestampMicros(result.endsAt);
    if (startsAt === null || endsAt === null || endsAt <= startsAt || result.status === null) return false;
  }
  if (result.isEntitled) return result.planCode === 'individual' && result.status === 'active' &&
    result.requiresSubscription && result.code === null;
  if (result.code === null) return false;
  // Only an explicit empty legacy account may bypass the paid-scope guard.
  return result.requiresSubscription || (result.code === 'SUBSCRIPTION_REQUIRED' && result.planCode === null);
}

export function createSubscriptionCore(db) {
  async function resolveSubscriptionEntitlement(userId) {
    if (typeof userId !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(userId)) {
      throw failure('SUBSCRIPTION_UNAVAILABLE');
    }
    let response;
    try { response = await db.rpc('keeptimer_resolve_entitlement', { p_user_id: userId }); }
    catch { throw failure('SUBSCRIPTION_UNAVAILABLE'); }
    if (response?.error || !validSubscriptionEntitlement(response?.data)) throw failure('SUBSCRIPTION_UNAVAILABLE');
    return response.data;
  }

  // Existing group/standalone routes must not become an accidental paid fallback.
  // Phase 5 opens only separately guarded personal routes; this company/shared
  // and Socket.IO guard still keeps private accounts out.
  async function currentAccountScopeError(userId) {
    try {
      const result = await resolveSubscriptionEntitlement(userId);
      if (!result.requiresSubscription) return null;
      return failure(result.isEntitled ? 'INDIVIDUAL_SCOPE_NOT_READY' : result.code);
    } catch { return failure('SUBSCRIPTION_UNAVAILABLE'); }
  }

  const guardCurrentAccountScope = async (req, res, next) => {
    const denied = await currentAccountScopeError(req.user?.id);
    if (denied) return res.status(denied.status).json(denied.body);
    next();
  };

  // Read/route preflight only. Mutation RPCs MUST also call the SQL assertion in
  // the same transaction. No current private resource is opened by this helper.
  const requireIndividualEntitlement = async (req, res, next) => {
    try {
      const result = await resolveSubscriptionEntitlement(req.user?.id);
      if (!result.isEntitled) throw failure(result.code);
      next();
    } catch (error) {
      const denied = error?.body?.code ? error : failure('SUBSCRIPTION_UNAVAILABLE');
      return res.status(denied.status).json(denied.body);
    }
  };

  const getSubscription = async (req, res) => {
    res.set('Cache-Control', 'no-store');
    try {
      const result = await resolveSubscriptionEntitlement(req.user?.id);
      if (['ACCOUNT_DISABLED', 'SUBSCRIPTION_CONFLICT', 'SUBSCRIPTION_UNAVAILABLE'].includes(result.code)) {
        const denied = failure(result.code); return res.status(denied.status).json(denied.body);
      }
      // Deliberate projection: no history IDs, actor IDs, amount, sequence, email,
      // credential fields, private workspace details or internal scope flag.
      return res.json({ subscription: {
        planCode: result.planCode, status: result.status,
        startsAt: result.startsAt, endsAt: result.endsAt, isEntitled: result.isEntitled,
      }, code: result.code });
    } catch {
      const denied = failure('SUBSCRIPTION_UNAVAILABLE');
      return res.status(denied.status).json(denied.body);
    }
  };
  return { resolveSubscriptionEntitlement, currentAccountScopeError,
    guardCurrentAccountScope, requireIndividualEntitlement, getSubscription };
}
