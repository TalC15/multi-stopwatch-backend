-- CUTOVER only in a confirmed maintenance window, after preparation and deployments.
BEGIN;
SET LOCAL lock_timeout='5s';
SELECT public.keeptimer_auth_assert_owner();
DO $$ BEGIN
 IF pg_catalog.to_regprocedure('public.keeptimer_auth_management(uuid,uuid,text,jsonb)') IS NULL THEN RAISE EXCEPTION 'PHASE7_MANAGEMENT_PREPARATION_REQUIRED'; END IF;
 IF current_setting('keeptimer.phase7_cutover',true) IS DISTINCT FROM 'confirmed-maintenance' THEN RAISE EXCEPTION 'PHASE7_MAINTENANCE_CONFIRMATION_REQUIRED'; END IF;
 IF EXISTS(SELECT 1 FROM public.keeptimer_auth_release WHERE cutover OR enabled) OR
    EXISTS(SELECT 1 FROM public.keeptimer_sales_release WHERE enabled) THEN RAISE EXCEPTION 'PHASE7_CUTOVER_STATE_INVALID'; END IF;
END; $$;
CREATE OR REPLACE FUNCTION public.keeptimer_auth_user_guard() RETURNS trigger LANGUAGE plpgsql SET search_path='' AS $$ BEGIN
 IF current_user::text IN ('anon','authenticated','service_role') AND OLD.credential_kind='password' AND
  (NEW.password_hash IS DISTINCT FROM OLD.password_hash OR NEW.credential_kind IS DISTINCT FROM OLD.credential_kind OR
   NEW.must_change_password IS DISTINCT FROM OLD.must_change_password OR NEW.mfa_email IS DISTINCT FROM OLD.mfa_email) THEN RAISE EXCEPTION 'AUTH_FORBIDDEN'; END IF;
 RETURN NEW;
END; $$;
CREATE TRIGGER keeptimer_auth_user_guard BEFORE UPDATE ON public.users FOR EACH ROW EXECUTE FUNCTION public.keeptimer_auth_user_guard();
-- Blocks an old backend from issuing privileged/password sessions, even rollback.
CREATE FUNCTION public.keeptimer_auth_session_guard() RETURNS trigger LANGUAGE plpgsql SET search_path='' AS $$ DECLARE u record; BEGIN
 -- Revocation cannot create authority. Do not take a user lock after the
 -- UPDATE already locked its session: that would reverse actor -> session.
 IF TG_OP='UPDATE' AND NEW.revoked_at IS NOT NULL THEN RETURN NEW; END IF;
 SELECT role,credential_kind INTO u FROM public.users WHERE id=NEW.user_id FOR SHARE;
 IF current_user::text IN ('anon','authenticated','service_role') AND (u.role IN ('superadmin','agent') OR u.credential_kind='password') AND
  (TG_OP='INSERT' OR NEW.revoked_at IS NULL) THEN RAISE EXCEPTION 'AUTH_FORBIDDEN'; END IF;
 RETURN NEW;
END; $$;
CREATE TRIGGER keeptimer_auth_session_guard BEFORE INSERT OR UPDATE ON public.sessions FOR EACH ROW EXECUTE FUNCTION public.keeptimer_auth_session_guard();
-- Invalidate pre-MFA privileged and pre-activation password sessions, no data loss.
UPDATE public.sessions s SET revoked_at=clock_timestamp() FROM public.users u WHERE u.id=s.user_id AND s.revoked_at IS NULL
 AND (u.role IN ('superadmin','agent') OR u.credential_kind='password');
DELETE FROM public.keeptimer_privileged_web_sessions;

-- Closing rollout atomically revokes every password/privileged session and
-- outstanding challenge. An old backend cannot reuse these sessions on rollback.
CREATE FUNCTION public.keeptimer_auth_close_release() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path='' AS $$
DECLARE target uuid; BEGIN
 IF OLD.enabled AND NOT NEW.enabled THEN
  FOR target IN SELECT id FROM public.users WHERE credential_kind='password' OR role IN ('superadmin','agent') ORDER BY id LOOP
   PERFORM 1 FROM public.users WHERE id=target FOR UPDATE;
   UPDATE public.sessions SET revoked_at=clock_timestamp() WHERE user_id=target AND revoked_at IS NULL;
  END LOOP;
  UPDATE public.keeptimer_auth_challenges SET consumed_at=clock_timestamp() WHERE consumed_at IS NULL;
  DELETE FROM public.keeptimer_auth_link_queue;
  DELETE FROM public.keeptimer_privileged_web_sessions;
 END IF;
 RETURN NEW;
END; $$;
CREATE TRIGGER keeptimer_auth_close_release AFTER UPDATE ON public.keeptimer_auth_release FOR EACH ROW EXECUTE FUNCTION public.keeptimer_auth_close_release();
REVOKE ALL ON FUNCTION public.keeptimer_auth_close_release() FROM PUBLIC,anon,authenticated,service_role;

-- Wrap the existing actor guard: Phase 3 sales release, audit/idempotency and
-- Phase 6 lifecycle stay untouched, now additionally require Phase 7 evidence.
ALTER FUNCTION public.keeptimer_phase3_require_actor(uuid,uuid,text) RENAME TO keeptimer_phase7_previous_actor;
CREATE FUNCTION public.keeptimer_phase3_require_actor(p_actor uuid,p_session uuid,p_role text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path='' AS $$ BEGIN
 PERFORM public.keeptimer_auth_ready_gate(); -- Always lock rollout before actor.
 PERFORM public.keeptimer_phase7_previous_actor(p_actor,p_session,p_role);
 IF NOT public.keeptimer_auth_session(p_actor,p_session,'web') THEN RAISE EXCEPTION 'PRIVILEGED_MFA_REQUIRED'; END IF;
END; $$;
ALTER FUNCTION public.keeptimer_phase3_command(uuid,uuid,uuid,text,text,jsonb) RENAME TO keeptimer_phase7_previous_sale;
CREATE FUNCTION public.keeptimer_phase3_command(p_actor uuid,p_session uuid,p_request uuid,p_action text,p_fingerprint text,p_data jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path='' AS $$ DECLARE result jsonb; target uuid; email text; BEGIN
 IF p_action IN ('agent_password_reset','customer_password_reset') THEN RAISE EXCEPTION 'SALES_FORBIDDEN'; END IF;
 IF p_action IN ('agent_create','customer_create') THEN
  email:=p_data->>'email';
  IF email IS NULL THEN RAISE EXCEPTION 'SALES_INPUT_INVALID'; END IF;
  result:=public.keeptimer_phase7_previous_sale(p_actor,p_session,p_request,p_action,p_fingerprint,p_data-'email');
  target:=coalesce(result->>'agentId',result->>'customerId')::uuid;
  IF EXISTS(SELECT 1 FROM public.users WHERE id<>target AND lower(btrim(mfa_email))=email) THEN RAISE EXCEPTION 'SALES_IDENTITY_CONFLICT'; END IF;
  INSERT INTO public.keeptimer_auth_accounts(user_id,email) VALUES(target,email) ON CONFLICT(user_id) DO NOTHING;
  IF (SELECT a.email FROM public.keeptimer_auth_accounts a WHERE a.user_id=target) IS DISTINCT FROM email THEN RAISE EXCEPTION 'IDEMPOTENCY_CONFLICT'; END IF;
  PERFORM public.keeptimer_phase3_require_actor(p_actor,p_session,CASE WHEN p_action='agent_create' THEN 'superadmin' ELSE 'agent' END);
  RETURN result; -- final check after ALL new wrapper writes/lock waits.
 END IF;
 result:=public.keeptimer_phase7_previous_sale(p_actor,p_session,p_request,p_action,p_fingerprint,p_data);
 IF p_action='subscription_renew' THEN
  -- Readiness is an auth fact; renewing entitlement neither grants nor removes it.
  target:=(result->>'customerId')::uuid;
  result:=jsonb_set(result,'{loginReady}',to_jsonb(EXISTS(SELECT 1 FROM public.keeptimer_auth_accounts a
   JOIN public.users u ON u.id=a.user_id WHERE a.user_id=target AND a.verified_at IS NOT NULL AND a.activated_at IS NOT NULL
    AND NOT u.must_change_password AND u.disabled_at IS NULL AND public.keeptimer_auth_shape(target))));
 END IF;
 PERFORM public.keeptimer_phase3_require_actor(p_actor,p_session,CASE WHEN p_action IN ('agent_create','agent_revoke') THEN 'superadmin' ELSE 'agent' END);
 RETURN result;
END; $$;
REVOKE ALL ON FUNCTION public.keeptimer_phase7_previous_actor(uuid,uuid,text),public.keeptimer_phase7_previous_sale(uuid,uuid,uuid,text,text,jsonb)
 FROM PUBLIC,anon,authenticated,service_role;
REVOKE ALL ON FUNCTION public.keeptimer_phase3_require_actor(uuid,uuid,text) FROM PUBLIC,anon,authenticated,service_role;
REVOKE ALL ON FUNCTION public.keeptimer_phase3_command(uuid,uuid,uuid,text,text,jsonb) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.keeptimer_phase3_command(uuid,uuid,uuid,text,text,jsonb) TO service_role;
REVOKE ALL ON FUNCTION public.keeptimer_auth_ready_gate(),public.keeptimer_auth_shape(uuid),public.keeptimer_auth_new_session(uuid,uuid,text,text),
 public.keeptimer_auth_prepare(uuid,text,text),public.keeptimer_auth_user_guard(),public.keeptimer_auth_session_guard(),
 public.keeptimer_auth_limit(text,text,text),public.keeptimer_auth_session(uuid,uuid,text,text),public.keeptimer_auth_command(text,jsonb) FROM PUBLIC,anon,authenticated,service_role;
GRANT EXECUTE ON FUNCTION public.keeptimer_auth_limit(text,text,text),public.keeptimer_auth_session(uuid,uuid,text,text),public.keeptimer_auth_command(text,jsonb) TO service_role;
UPDATE public.keeptimer_auth_release SET cutover=true; -- enabled stays false
NOTIFY pgrst, 'reload schema';
COMMIT;
