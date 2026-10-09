-- Phase 5: AFTER Phase 1, entitlement core and subscription_sales (including
-- their reviewed revisions). No timer rewrite, provisioning or release toggle.
BEGIN;
SET LOCAL lock_timeout = '5s';

CREATE OR REPLACE FUNCTION public.keeptimer_phase5_scope(p_actor uuid, p_write boolean DEFAULT false)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path='' AS $$
DECLARE u public.users%ROWTYPE; w public.workspaces%ROWTYPE; e jsonb;
BEGIN
  -- Resolver locks user -> catalog -> history, then uses the real clock.
  e := public.keeptimer_resolve_entitlement(p_actor);
  IF e->>'code' IN ('ACCOUNT_DISABLED','SUBSCRIPTION_CONFLICT','SUBSCRIPTION_UNAVAILABLE') THEN
    RAISE EXCEPTION '%',e->>'code' USING ERRCODE='P0001';
  END IF;
  SELECT * INTO u FROM public.users WHERE id=p_actor FOR SHARE;
  IF NOT FOUND OR u.disabled_at IS NOT NULL THEN
    RAISE EXCEPTION 'ACCOUNT_DISABLED' USING ERRCODE='P0001';
  END IF;
  IF u.role='agent' THEN RAISE EXCEPTION 'SUBSCRIPTION_FORBIDDEN' USING ERRCODE='P0001'; END IF;
  IF (e->>'requiresSubscription')::boolean IS DISTINCT FROM true THEN
    RETURN pg_catalog.jsonb_build_object('kind','company','userId',u.id,'workspaceId',u.workspace_id,'entitlement',e);
  END IF;
  SELECT * INTO w FROM public.workspaces WHERE id=u.workspace_id FOR SHARE;
  IF NOT FOUND OR w.kind IS DISTINCT FROM 'individual_private' OR w.owner_id IS DISTINCT FROM u.id
    OR u.role IS DISTINCT FROM 'worker' OR u.plan_code IS DISTINCT FROM 'individual'
    OR u.credential_kind IS DISTINCT FROM 'password' OR w.invite_code IS NOT NULL
    OR w.shared_mode_enabled IS DISTINCT FROM false
    OR EXISTS(SELECT 1 FROM public.users WHERE workspace_id=w.id AND id<>u.id) THEN
    RAISE EXCEPTION 'INDIVIDUAL_SCOPE_NOT_READY' USING ERRCODE='P0001';
  END IF;
  -- Expired/pending/cancelled private data remains readable, never erased.
  IF p_write IS DISTINCT FROM false AND (e->>'isEntitled')::boolean IS DISTINCT FROM true THEN
    RAISE EXCEPTION '%',e->>'code' USING ERRCODE='P0001';
  END IF;
  RETURN pg_catalog.jsonb_build_object('kind','individual','userId',u.id,'workspaceId',w.id,'entitlement',e);
END; $$;

-- Preserve the existing revision/idempotency/conflict implementation. Its
-- unchecked entry points become owner-only, unreachable by PostgREST roles.
DO $$ BEGIN
  IF pg_catalog.to_regprocedure('public.keeptimer_phase5_sync_personal_internal(uuid,uuid,uuid,bigint,jsonb)') IS NULL THEN
    ALTER FUNCTION public.keeptimer_sync_personal(uuid,uuid,uuid,bigint,jsonb) RENAME TO keeptimer_phase5_sync_personal_internal;
    ALTER FUNCTION public.keeptimer_delete_personal(uuid,uuid,uuid,bigint) RENAME TO keeptimer_phase5_delete_personal_internal;
    ALTER FUNCTION public.keeptimer_change_timer(uuid,uuid,jsonb,boolean) RENAME TO keeptimer_phase5_change_timer_internal;
    ALTER FUNCTION public.keeptimer_shared_request(uuid,jsonb) RENAME TO keeptimer_phase5_shared_request_internal;
  END IF;
END; $$;

CREATE OR REPLACE FUNCTION public.keeptimer_phase5_require_session(p_actor uuid,p_session uuid)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path='' AS $$
BEGIN
  PERFORM 1 FROM public.sessions WHERE id=p_session AND user_id=p_actor AND revoked_at IS NULL FOR SHARE;
  IF NOT FOUND THEN RAISE EXCEPTION 'AUTH_SESSION_INVALID' USING ERRCODE='P0001'; END IF;
END; $$;
REVOKE ALL ON FUNCTION public.keeptimer_phase5_require_session(uuid,uuid) FROM PUBLIC,anon,authenticated,service_role;

CREATE OR REPLACE FUNCTION public.keeptimer_sync_personal(p_actor_id uuid,p_timer_id uuid,p_mutation_id uuid,p_expected_revision bigint,p_state jsonb,p_session_id uuid DEFAULT NULL)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path='' AS $$
DECLARE result jsonb;
BEGIN
  IF public.keeptimer_phase5_scope(p_actor_id,true)->>'kind'='individual' THEN
    PERFORM public.keeptimer_phase5_require_session(p_actor_id,p_session_id);
  END IF;
  result := public.keeptimer_phase5_sync_personal_internal(p_actor_id,p_timer_id,p_mutation_id,p_expected_revision,p_state);
  -- INSERT unique checks or row locks can wait past subscription expiry.
  -- Failure here rolls back the timer and its duplicate marker together.
  IF public.keeptimer_phase5_scope(p_actor_id,true)->>'kind'='individual' THEN
    PERFORM public.keeptimer_phase5_require_session(p_actor_id,p_session_id);
  END IF;
  RETURN result;
END; $$;
CREATE OR REPLACE FUNCTION public.keeptimer_delete_personal(p_actor_id uuid,p_timer_id uuid,p_mutation_id uuid,p_expected_revision bigint,p_session_id uuid DEFAULT NULL)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path='' AS $$
DECLARE result jsonb;
BEGIN
  IF public.keeptimer_phase5_scope(p_actor_id,true)->>'kind'='individual' THEN
    PERFORM public.keeptimer_phase5_require_session(p_actor_id,p_session_id);
  END IF;
  result := public.keeptimer_phase5_delete_personal_internal(p_actor_id,p_timer_id,p_mutation_id,p_expected_revision);
  IF public.keeptimer_phase5_scope(p_actor_id,true)->>'kind'='individual' THEN
    PERFORM public.keeptimer_phase5_require_session(p_actor_id,p_session_id);
  END IF;
  RETURN result;
END; $$;

CREATE OR REPLACE FUNCTION public.keeptimer_change_timer(p_actor_id uuid,p_timer_id uuid,p_updates jsonb,p_delete boolean)
RETURNS public.timers LANGUAGE plpgsql SECURITY DEFINER SET search_path='' AS $$
DECLARE scope jsonb; result public.timers;
BEGIN
  scope := public.keeptimer_phase5_scope(p_actor_id,false);
  IF scope->>'kind'='individual' OR EXISTS(SELECT 1 FROM public.timers t JOIN public.workspaces w ON w.id=t.workspace_id
    WHERE t.id=p_timer_id AND w.kind='individual_private') THEN
    RAISE EXCEPTION 'INDIVIDUAL_SCOPE_NOT_READY' USING ERRCODE='P0001';
  END IF;
  result := public.keeptimer_phase5_change_timer_internal(p_actor_id,p_timer_id,p_updates,p_delete);
  RETURN result;
END; $$;
CREATE OR REPLACE FUNCTION public.keeptimer_shared_request(p_actor_id uuid,p_request jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path='' AS $$
BEGIN
  IF public.keeptimer_phase5_scope(p_actor_id,false)->>'kind'='individual' THEN
    RAISE EXCEPTION 'INDIVIDUAL_SCOPE_NOT_READY' USING ERRCODE='P0001';
  END IF;
  RETURN public.keeptimer_phase5_shared_request_internal(p_actor_id,p_request);
END; $$;

CREATE OR REPLACE FUNCTION public.keeptimer_phase5_private_timer_guard()
RETURNS trigger LANGUAGE plpgsql SET search_path='' AS $$
DECLARE private_old boolean := false; private_new boolean := false;
BEGIN
  IF TG_OP<>'INSERT' THEN
    SELECT EXISTS(SELECT 1 FROM public.workspaces WHERE id=OLD.workspace_id AND kind='individual_private') INTO private_old;
  END IF;
  IF TG_OP<>'DELETE' THEN
    SELECT EXISTS(SELECT 1 FROM public.workspaces WHERE id=NEW.workspace_id AND kind='individual_private') INTO private_new;
  END IF;
  IF (private_old OR private_new) AND current_user IN ('anon','authenticated','service_role') THEN
    RAISE EXCEPTION 'PHASE5_PRIVATE_RPC_REQUIRED' USING ERRCODE='42501';
  END IF;
  IF private_old AND TG_OP='UPDATE' AND (NEW.user_id IS DISTINCT FROM OLD.user_id
    OR NEW.workspace_id IS DISTINCT FROM OLD.workspace_id OR NEW.created_by IS DISTINCT FROM OLD.created_by
    OR NEW.is_shared IS DISTINCT FROM false) THEN
    RAISE EXCEPTION 'PHASE5_PRIVATE_TIMER_IMMUTABLE' USING ERRCODE='23514';
  END IF;
  IF TG_OP='DELETE' THEN RETURN OLD; END IF;
  RETURN NEW;
END; $$;
DROP TRIGGER IF EXISTS keeptimer_phase5_private_timer_guard ON public.timers;
CREATE TRIGGER keeptimer_phase5_private_timer_guard BEFORE INSERT OR UPDATE OR DELETE ON public.timers
FOR EACH ROW EXECUTE FUNCTION public.keeptimer_phase5_private_timer_guard();

-- Connection removal remains available after expiry; attaching a new chat
-- requires current paid rights. No client user ID or plan claim is accepted.
CREATE OR REPLACE FUNCTION public.keeptimer_phase5_telegram(p_actor uuid,p_chat_id text,p_session_id uuid DEFAULT NULL)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path='' AS $$
BEGIN
  IF p_chat_id IS NOT NULL AND p_chat_id !~ '^-?[0-9]{1,20}$' THEN
    RAISE EXCEPTION 'SUBSCRIPTION_FORBIDDEN' USING ERRCODE='P0001';
  END IF;
  -- Serialize only this actor before the resolver takes user/catalog/history
  -- locks: concurrent SHARE-to-UPDATE upgrades on this row can deadlock.
  PERFORM 1 FROM public.users WHERE id=p_actor FOR UPDATE;
  IF public.keeptimer_phase5_scope(p_actor,p_chat_id IS NOT NULL)->>'kind'='individual' THEN
    PERFORM public.keeptimer_phase5_require_session(p_actor,p_session_id);
  END IF;
  UPDATE public.users SET telegram_chat_id=p_chat_id WHERE id=p_actor;
  IF public.keeptimer_phase5_scope(p_actor,p_chat_id IS NOT NULL)->>'kind'='individual' THEN
    PERFORM public.keeptimer_phase5_require_session(p_actor,p_session_id);
  END IF;
  RETURN true;
END; $$;
REVOKE ALL ON FUNCTION public.keeptimer_phase5_telegram(uuid,text,uuid) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.keeptimer_phase5_telegram(uuid,text,uuid) TO service_role;

-- Private records have no browser-DB path, even if an older permissive policy
-- exists. Company policies remain intact. Backend uses scoped service-role RPCs.
CREATE OR REPLACE FUNCTION public.keeptimer_phase5_private_workspace(p_workspace uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path='' AS $$
  SELECT EXISTS(SELECT 1 FROM public.workspaces WHERE id=p_workspace AND kind='individual_private');
$$;
ALTER TABLE public.workspaces ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.timers ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS keeptimer_phase5_no_private ON public.workspaces;
CREATE POLICY keeptimer_phase5_no_private ON public.workspaces AS RESTRICTIVE TO anon,authenticated
  USING(kind<>'individual_private') WITH CHECK(kind<>'individual_private');
DROP POLICY IF EXISTS keeptimer_phase5_no_private ON public.users;
CREATE POLICY keeptimer_phase5_no_private ON public.users AS RESTRICTIVE TO anon,authenticated
  USING(NOT public.keeptimer_phase5_private_workspace(workspace_id)) WITH CHECK(NOT public.keeptimer_phase5_private_workspace(workspace_id));
DROP POLICY IF EXISTS keeptimer_phase5_no_private ON public.timers;
CREATE POLICY keeptimer_phase5_no_private ON public.timers AS RESTRICTIVE TO anon,authenticated
  USING(NOT public.keeptimer_phase5_private_workspace(workspace_id)) WITH CHECK(NOT public.keeptimer_phase5_private_workspace(workspace_id));

REVOKE ALL ON FUNCTION public.keeptimer_phase5_scope(uuid,boolean),
  public.keeptimer_sync_personal(uuid,uuid,uuid,bigint,jsonb,uuid), public.keeptimer_delete_personal(uuid,uuid,uuid,bigint,uuid),
  public.keeptimer_change_timer(uuid,uuid,jsonb,boolean), public.keeptimer_shared_request(uuid,jsonb)
  FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.keeptimer_phase5_scope(uuid,boolean),
  public.keeptimer_sync_personal(uuid,uuid,uuid,bigint,jsonb,uuid), public.keeptimer_delete_personal(uuid,uuid,uuid,bigint,uuid),
  public.keeptimer_change_timer(uuid,uuid,jsonb,boolean), public.keeptimer_shared_request(uuid,jsonb) TO service_role;
REVOKE ALL ON FUNCTION public.keeptimer_phase5_sync_personal_internal(uuid,uuid,uuid,bigint,jsonb),
  public.keeptimer_phase5_delete_personal_internal(uuid,uuid,uuid,bigint),
  public.keeptimer_phase5_change_timer_internal(uuid,uuid,jsonb,boolean),
  public.keeptimer_phase5_shared_request_internal(uuid,jsonb),public.keeptimer_phase5_private_timer_guard()
  FROM PUBLIC,anon,authenticated,service_role;
REVOKE ALL ON FUNCTION public.keeptimer_phase5_private_workspace(uuid) FROM PUBLIC,service_role;
GRANT EXECUTE ON FUNCTION public.keeptimer_phase5_private_workspace(uuid) TO anon,authenticated;
NOTIFY pgrst,'reload schema';
COMMIT;
