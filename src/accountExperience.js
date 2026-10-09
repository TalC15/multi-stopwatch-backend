import { subscriptionFailure as failure, validSubscriptionEntitlement } from './subscriptions.js';

const uuid = value => typeof value === 'string' && /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(value);
const sameId = (a, b) => uuid(a) && uuid(b) && a.toLowerCase() === b.toLowerCase();
const fatal = new Set(['ACCOUNT_DISABLED', 'SUBSCRIPTION_CONFLICT', 'SUBSCRIPTION_UNAVAILABLE']);
const sqlCodes = ['ACCOUNT_DISABLED', 'SUBSCRIPTION_REQUIRED', 'SUBSCRIPTION_PENDING',
  'SUBSCRIPTION_EXPIRED', 'SUBSCRIPTION_CANCELLED', 'PLAN_DISABLED',
  'SUBSCRIPTION_FORBIDDEN', 'SUBSCRIPTION_CONFLICT', 'INDIVIDUAL_SCOPE_NOT_READY'];

export function privateScopeFailure(error) {
  const code = sqlCodes.find(code => error?.message === code);
  return failure(code || 'SUBSCRIPTION_UNAVAILABLE');
}

// Only these personal/feature routes may use private scope. All company routes
// and Socket.IO continue to use Phase 2's closed paid-account guard.
export function createAccountExperience(db, subscriptions) {
  async function scope(user, write = false) {
    const entitlement = await subscriptions.resolveSubscriptionEntitlement(user?.id);
    if (!entitlement.requiresSubscription) {
      return { kind: 'company', userId: user.id, workspaceId: user.workspace_id ?? null, entitlement };
    }
    if (fatal.has(entitlement.code)) throw failure(entitlement.code);
    // Do not turn unprovisioned paid history into a legacy fallback.
    if (!uuid(user.workspace_id)) throw failure(entitlement.isEntitled ? 'INDIVIDUAL_SCOPE_NOT_READY' : entitlement.code);
    let response;
    try { response = await db.rpc('keeptimer_phase5_scope', { p_actor: user.id, p_write: write }); }
    catch { throw failure('SUBSCRIPTION_UNAVAILABLE'); }
    if (response?.error) throw privateScopeFailure(response.error);
    const row = response?.data;
    if (row?.kind !== 'individual' || !sameId(row.userId, user.id) || !sameId(row.workspaceId, user.workspace_id) ||
        user.role !== 'worker' || !validSubscriptionEntitlement(row.entitlement) ||
        !row.entitlement.requiresSubscription || fatal.has(row.entitlement.code) ||
        (write && !row.entitlement.isEntitled)) throw failure('SUBSCRIPTION_UNAVAILABLE');
    return row;
  }
  const guard = write => async (req, res, next) => {
    try {
      req.accountScope = await scope(req.user, write);
      next();
    } catch (error) {
      const denied = error?.body ? error : failure('SUBSCRIPTION_UNAVAILABLE');
      res.status(denied.status).json(denied.body);
    }
  };
  const getExperience = async (req, res) => {
    res.set('Cache-Control', 'no-store');
    if (req.user.role === 'agent') return res.status(403).json({ code: 'AGENT_MANAGEMENT_ONLY', error: 'Yalnız web yönetim işlemleri kullanılabilir' });
    try {
      const current = await scope(req.user), e = current.entitlement;
      const paid = current.kind === 'company' || e.isEntitled;
      res.json({ account: { kind: current.kind, userId: current.userId, workspaceId: current.workspaceId },
        subscription: { planCode: e.planCode, status: e.status, startsAt: e.startsAt, endsAt: e.endsAt, isEntitled: e.isEntitled },
        code: e.code, features: { tts: paid, telegram: paid, presets: paid },
        personal: { readable: Boolean(current.workspaceId), writable: Boolean(current.workspaceId) && paid },
        shared: current.kind === 'company', loginReady: false });
    } catch (error) {
      const denied = error?.body ? error : failure('SUBSCRIPTION_UNAVAILABLE');
      res.status(denied.status).json(denied.body);
    }
  };
  return { scope, guard, getExperience };
}
