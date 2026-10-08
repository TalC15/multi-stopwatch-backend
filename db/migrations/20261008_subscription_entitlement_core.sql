-- Phase 2, forward-only: server-authoritative subscription core. No data rewrite.
BEGIN;
SET LOCAL lock_timeout = '5s';

-- Pure internal helper permits exact, non-flaky boundary tests. Not a client RPC.
CREATE OR REPLACE FUNCTION public.keeptimer_subscription_state(
  p_cancelled_at timestamptz, p_starts_at timestamptz,
  p_ends_at timestamptz, p_now timestamptz
) RETURNS text LANGUAGE sql IMMUTABLE SET search_path = '' AS $$
  SELECT CASE WHEN p_cancelled_at IS NOT NULL THEN 'cancelled'
    WHEN p_now < p_starts_at THEN 'pending'
    WHEN p_now >= p_ends_at THEN 'expired'
    WHEN p_starts_at <= p_now AND p_now < p_ends_at THEN 'active'
    ELSE NULL END;
$$;

-- INSERT cannot introduce an unseen history row while an entitlement decision
-- holds the user's SHARE lock. No subscription row is rewritten by this trigger.
CREATE OR REPLACE FUNCTION public.keeptimer_lock_subscription_insert()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
BEGIN
  PERFORM 1 FROM public.users WHERE id = NEW.user_id FOR UPDATE;
  RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS keeptimer_subscription_insert_lock ON public.subscriptions;
CREATE TRIGGER keeptimer_subscription_insert_lock BEFORE INSERT ON public.subscriptions
FOR EACH ROW EXECUTE FUNCTION public.keeptimer_lock_subscription_insert();

CREATE OR REPLACE FUNCTION public.keeptimer_resolve_entitlement(p_user_id uuid)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = '' AS $$
DECLARE
  u record;
  s public.subscriptions%ROWTYPE;
  n timestamptz;
  active_count integer;
  has_history boolean;
  paid_scope boolean;
  state text;
  denial text;
  enabled boolean;
BEGIN
  -- READ COMMITTED is required by future mutation RPCs too. A long-running RR
  -- snapshot could miss a newly committed INSERT even after waiting on its user.
  IF pg_catalog.current_setting('transaction_isolation') <> 'read committed' THEN
    RAISE EXCEPTION 'SUBSCRIPTION_ISOLATION_UNSUPPORTED' USING ERRCODE = 'P0001';
  END IF;
  SELECT id, role, plan_code, disabled_at, workspace_id INTO u
    FROM public.users WHERE id = p_user_id FOR SHARE;
  IF NOT FOUND THEN
    RETURN pg_catalog.jsonb_build_object('planCode',NULL,'status',NULL,
      'startsAt',NULL,'endsAt',NULL,'isEntitled',false,
      'requiresSubscription',true,'code','ACCOUNT_DISABLED');
  END IF;
  -- Tiny three-row catalog, stable ordering. Locks prevent plan toggles and
  -- cancellation during a same-transaction authorized mutation.
  PERFORM code FROM public.subscription_plans ORDER BY code FOR SHARE;
  PERFORM id FROM public.subscriptions WHERE user_id=p_user_id ORDER BY sequence_no FOR SHARE;
  -- Real clock AFTER lock waits; transaction-start now() is not an expiry clock.
  n := pg_catalog.clock_timestamp();
  SELECT EXISTS(SELECT 1 FROM public.subscriptions WHERE user_id=p_user_id) INTO has_history;
  paid_scope := u.plan_code IS NOT NULL OR has_history OR EXISTS (
    SELECT 1 FROM public.workspaces WHERE id=u.workspace_id AND kind='individual_private'
  );
  SELECT count(*) INTO active_count FROM public.subscriptions
    WHERE user_id=p_user_id AND cancelled_at IS NULL AND starts_at<=n AND n<ends_at;
  IF active_count > 1 THEN
    denial := 'SUBSCRIPTION_CONFLICT';
  ELSE
    -- Any current active row precedes all future renewals. Cancellation is per
    -- period: a cancelled newest row does not cancel an older valid active row.
    SELECT * INTO s FROM public.subscriptions WHERE user_id=p_user_id
      ORDER BY CASE
        WHEN cancelled_at IS NULL AND starts_at<=n AND n<ends_at THEN 0
        WHEN cancelled_at IS NULL AND n<starts_at THEN 1 ELSE 2 END,
        CASE WHEN cancelled_at IS NULL AND n<starts_at THEN starts_at END ASC,
        sequence_no DESC
      LIMIT 1;
    IF NOT FOUND THEN
      denial := 'SUBSCRIPTION_REQUIRED';
    ELSE
      state := public.keeptimer_subscription_state(s.cancelled_at,s.starts_at,s.ends_at,n);
      SELECT p.enabled INTO enabled FROM public.subscription_plans p WHERE p.code=s.plan_code;
      IF enabled IS DISTINCT FROM true OR s.plan_code IS DISTINCT FROM 'individual' THEN
        denial := 'PLAN_DISABLED';
      ELSIF state='pending' THEN denial := 'SUBSCRIPTION_PENDING';
      ELSIF state='cancelled' THEN denial := 'SUBSCRIPTION_CANCELLED';
      ELSIF state='expired' THEN denial := 'SUBSCRIPTION_EXPIRED';
      ELSIF state IS DISTINCT FROM 'active' THEN denial := 'SUBSCRIPTION_UNAVAILABLE';
      END IF;
    END IF;
  END IF;
  IF u.disabled_at IS NOT NULL THEN
    denial := 'ACCOUNT_DISABLED';
    paid_scope := true; -- never allow legacy bypass after a concurrent disable
  ELSIF has_history AND u.role IS DISTINCT FROM 'worker' THEN denial := 'SUBSCRIPTION_FORBIDDEN';
  END IF;
  RETURN pg_catalog.jsonb_build_object(
    'planCode',s.plan_code,'status',state,'startsAt',s.starts_at,'endsAt',s.ends_at,
    'isEntitled',denial IS NULL,'requiresSubscription',paid_scope,'code',denial);
END;
$$;

-- Future paid mutations must call this INSIDE the same DB transaction, before
-- locking/writing their resource rows. An earlier HTTP check is not sufficient.
CREATE OR REPLACE FUNCTION public.keeptimer_require_individual_entitlement(p_user_id uuid)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = '' AS $$
DECLARE result jsonb;
BEGIN
  result := public.keeptimer_resolve_entitlement(p_user_id);
  IF (result->>'isEntitled')::boolean IS DISTINCT FROM true THEN
    RAISE EXCEPTION '%', result->>'code' USING ERRCODE = 'P0001';
  END IF;
  RETURN result;
END;
$$;

REVOKE ALL ON FUNCTION public.keeptimer_subscription_state(timestamptz,timestamptz,timestamptz,timestamptz)
  FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION public.keeptimer_lock_subscription_insert()
  FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION public.keeptimer_resolve_entitlement(uuid)
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.keeptimer_require_individual_entitlement(uuid)
  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.keeptimer_resolve_entitlement(uuid),
  public.keeptimer_require_individual_entitlement(uuid) TO service_role;

COMMENT ON FUNCTION public.keeptimer_resolve_entitlement(uuid) IS
  'Phase 2: DB clock, locked history/catalog, active then earliest pending then latest sequence; overlapping active rows deny. Actor must come from validated server authentication.';
COMMENT ON FUNCTION public.keeptimer_require_individual_entitlement(uuid) IS
  'Call inside the paid mutation transaction at READ COMMITTED, user/catalog/history before resource locks. Does not provision or authorize private workspace membership.';
NOTIFY pgrst, 'reload schema';
COMMIT;
