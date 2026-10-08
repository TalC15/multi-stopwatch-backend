-- Phase 3: apply AFTER subscription_entitlement_core. No production enablement.
BEGIN;
SET LOCAL lock_timeout = '5s';
DO $$ BEGIN
  IF current_user IN ('anon','authenticated','service_role') THEN RAISE EXCEPTION 'PHASE3_OWNER_MIGRATION_REQUIRED'; END IF;
END; $$;
LOCK TABLE public.users, public.workspaces IN ACCESS EXCLUSIVE MODE;

ALTER TABLE public.users ADD COLUMN IF NOT EXISTS credential_kind text NOT NULL DEFAULT 'pin';
ALTER TABLE public.users ALTER COLUMN pin_hash DROP NOT NULL;
ALTER TABLE public.users DROP CONSTRAINT IF EXISTS users_credential_kind_check;
ALTER TABLE public.users ADD CONSTRAINT users_credential_kind_check CHECK (
  (credential_kind='pin' AND pin_hash IS NOT NULL) OR
  (credential_kind='password' AND pin_hash IS NULL AND password_hash IS NOT NULL
   AND password_hash ~ '^\$2[aby]\$12\$[./A-Za-z0-9]{53}$')
);

-- No application grant, setting, environment variable or proof-issuing RPC can
-- enable these controls. Phase 7 must supply a reviewed real web MFA issuer.
CREATE TABLE IF NOT EXISTS public.keeptimer_sales_release (
  singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
  enabled boolean NOT NULL DEFAULT false
);
INSERT INTO public.keeptimer_sales_release VALUES(true,false) ON CONFLICT DO NOTHING;
CREATE TABLE IF NOT EXISTS public.keeptimer_privileged_web_sessions (
  session_id uuid PRIMARY KEY REFERENCES public.sessions(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
  verified_at timestamptz NOT NULL CHECK(isfinite(verified_at)),
  expires_at timestamptz NOT NULL CHECK(isfinite(expires_at)),
  method text NOT NULL CHECK(method='email_otp'),
  CHECK(expires_at>verified_at AND expires_at<=verified_at+interval '15 minutes')
);
CREATE TABLE IF NOT EXISTS public.keeptimer_individual_customers (
  user_id uuid PRIMARY KEY REFERENCES public.users(id) ON DELETE RESTRICT,
  workspace_id uuid NOT NULL UNIQUE REFERENCES public.workspaces(id) ON DELETE RESTRICT,
  created_by_user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE IF NOT EXISTS public.keeptimer_sales_requests (
  actor_id uuid NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
  request_id uuid NOT NULL,
  action text NOT NULL,
  fingerprint text NOT NULL CHECK(fingerprint ~ '^[a-f0-9]{64}$'),
  result jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(actor_id,request_id)
);
ALTER TABLE public.keeptimer_sales_release ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.keeptimer_privileged_web_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.keeptimer_individual_customers ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.keeptimer_sales_requests ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.keeptimer_sales_release, public.keeptimer_privileged_web_sessions,
  public.keeptimer_individual_customers, public.keeptimer_sales_requests FROM PUBLIC,anon,authenticated,service_role;
-- Existing Phase 1 tables become writeable only by checked owner-executed RPCs.
REVOKE INSERT, UPDATE ON public.subscriptions, public.admin_audit_log FROM service_role;
REVOKE UPDATE(cancelled_at,cancelled_by_user_id,cancellation_reason) ON public.subscriptions FROM service_role;
CREATE INDEX IF NOT EXISTS users_phase3_workspace_members_idx ON public.users(workspace_id) WHERE workspace_id IS NOT NULL;

CREATE OR REPLACE FUNCTION public.keeptimer_phase3_user_guard()
RETURNS trigger LANGUAGE plpgsql SET search_path='' AS $$
DECLARE w record; sensitive boolean;
BEGIN
  sensitive := (TG_OP<>'DELETE' AND (NEW.role='agent' OR NEW.credential_kind='password'))
    OR (TG_OP<>'INSERT' AND (OLD.role='agent' OR OLD.credential_kind='password'));
  IF sensitive AND current_user IN ('anon','authenticated','service_role') THEN
    RAISE EXCEPTION 'PHASE3_RPC_REQUIRED' USING ERRCODE='42501';
  END IF;
  IF TG_OP<>'INSERT' THEN
    IF OLD.role='agent' AND (TG_OP='DELETE' OR NEW.role IS DISTINCT FROM OLD.role) THEN
      RAISE EXCEPTION 'PHASE3_AGENT_IMMUTABLE' USING ERRCODE='23514';
    END IF;
    IF OLD.credential_kind='password' AND
       (TG_OP='DELETE' OR NEW.credential_kind IS DISTINCT FROM OLD.credential_kind OR NEW.role IS DISTINCT FROM OLD.role) THEN
      RAISE EXCEPTION 'PHASE3_CREDENTIAL_IMMUTABLE' USING ERRCODE='23514';
    END IF;
    SELECT * INTO w FROM public.workspaces WHERE id=OLD.workspace_id;
    IF w.kind='individual_private' AND (TG_OP='DELETE' OR NEW.workspace_id IS DISTINCT FROM OLD.workspace_id
      OR NEW.role IS DISTINCT FROM 'worker' OR NEW.plan_code IS DISTINCT FROM 'individual'
      OR NEW.disabled_at IS DISTINCT FROM OLD.disabled_at) THEN
      RAISE EXCEPTION 'PHASE3_PRIVATE_MEMBERSHIP_IMMUTABLE' USING ERRCODE='23514';
    END IF;
  END IF;
  IF TG_OP<>'DELETE' AND NEW.workspace_id IS NOT NULL THEN
    SELECT * INTO w FROM public.workspaces WHERE id=NEW.workspace_id FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION 'PHASE3_WORKSPACE_NOT_FOUND' USING ERRCODE='23503'; END IF;
    IF w.kind='individual_private' AND (NEW.id IS DISTINCT FROM w.owner_id OR NEW.role IS DISTINCT FROM 'worker'
      OR NEW.plan_code IS DISTINCT FROM 'individual' OR NEW.credential_kind IS DISTINCT FROM 'password') THEN
      RAISE EXCEPTION 'PHASE3_PRIVATE_OWNER_ONLY' USING ERRCODE='23514';
    END IF;
  END IF;
  IF TG_OP='DELETE' THEN RETURN OLD; END IF;
  RETURN NEW;
END; $$;
DROP TRIGGER IF EXISTS keeptimer_phase3_user_guard ON public.users;
CREATE TRIGGER keeptimer_phase3_user_guard BEFORE INSERT OR UPDATE OR DELETE ON public.users
FOR EACH ROW EXECUTE FUNCTION public.keeptimer_phase3_user_guard();

CREATE OR REPLACE FUNCTION public.keeptimer_phase3_workspace_guard()
RETURNS trigger LANGUAGE plpgsql SET search_path='' AS $$
DECLARE u record;
BEGIN
  IF TG_OP<>'INSERT' AND (TG_OP='DELETE' AND OLD.kind='individual_private' OR
    TG_OP='UPDATE' AND (NEW.kind IS DISTINCT FROM OLD.kind OR
      OLD.kind='individual_private' AND NEW.owner_id IS DISTINCT FROM OLD.owner_id)) THEN
    RAISE EXCEPTION 'PHASE3_PRIVATE_WORKSPACE_IMMUTABLE' USING ERRCODE='23514';
  END IF;
  IF TG_OP<>'DELETE' AND NEW.kind='individual_private' THEN
    IF current_user IN ('anon','authenticated','service_role') THEN
      RAISE EXCEPTION 'PHASE3_RPC_REQUIRED' USING ERRCODE='42501';
    END IF;
    IF TG_OP='INSERT' THEN
      SELECT * INTO u FROM public.users WHERE id=NEW.owner_id FOR UPDATE;
      IF NOT FOUND OR u.role<>'worker' OR u.plan_code IS DISTINCT FROM 'individual' OR
        u.credential_kind<>'password' OR u.workspace_id IS NOT NULL THEN
        RAISE EXCEPTION 'PHASE3_PRIVATE_OWNER_ONLY' USING ERRCODE='23514';
      END IF;
    END IF;
  END IF;
  IF TG_OP='DELETE' THEN RETURN OLD; END IF;
  RETURN NEW;
END; $$;
DROP TRIGGER IF EXISTS keeptimer_phase3_workspace_guard ON public.workspaces;
CREATE TRIGGER keeptimer_phase3_workspace_guard BEFORE INSERT OR UPDATE OR DELETE ON public.workspaces
FOR EACH ROW EXECUTE FUNCTION public.keeptimer_phase3_workspace_guard();

-- Deferred because the owner and workspace reference each other. At commit the
-- owner MUST be its sole member. Existing invalid private rows fail preflight.
CREATE OR REPLACE FUNCTION public.keeptimer_phase3_private_consistency()
RETURNS trigger LANGUAGE plpgsql SET search_path='' AS $$
DECLARE workspace_ids uuid[]; owner_ids uuid[];
BEGIN
  IF TG_TABLE_NAME='workspaces' THEN
    workspace_ids:=ARRAY[NEW.id,OLD.id]; owner_ids:=ARRAY[]::uuid[];
  ELSE
    workspace_ids:=ARRAY[NEW.workspace_id,OLD.workspace_id]; owner_ids:=ARRAY[NEW.id,OLD.id];
  END IF;
  IF EXISTS (SELECT 1 FROM public.workspaces w LEFT JOIN public.users u ON u.id=w.owner_id
    WHERE w.kind='individual_private' AND (w.id=ANY(workspace_ids) OR w.owner_id=ANY(owner_ids))
      AND (u.id IS NULL OR u.workspace_id IS DISTINCT FROM w.id
      OR u.role IS DISTINCT FROM 'worker' OR u.plan_code IS DISTINCT FROM 'individual'
      OR u.credential_kind IS DISTINCT FROM 'password'
      OR EXISTS(SELECT 1 FROM public.users other WHERE other.workspace_id=w.id AND other.id<>w.owner_id))) THEN
    RAISE EXCEPTION 'PHASE3_PRIVATE_INCONSISTENT' USING ERRCODE='23514';
  END IF;
  RETURN NULL;
END; $$;
DROP TRIGGER IF EXISTS keeptimer_phase3_private_user_check ON public.users;
CREATE CONSTRAINT TRIGGER keeptimer_phase3_private_user_check AFTER INSERT OR UPDATE OR DELETE ON public.users
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.keeptimer_phase3_private_consistency();
DROP TRIGGER IF EXISTS keeptimer_phase3_private_workspace_check ON public.workspaces;
CREATE CONSTRAINT TRIGGER keeptimer_phase3_private_workspace_check AFTER INSERT OR UPDATE OR DELETE ON public.workspaces
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.keeptimer_phase3_private_consistency();
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM public.workspaces w LEFT JOIN public.users u ON u.id=w.owner_id
    WHERE w.kind='individual_private' AND (u.id IS NULL OR u.workspace_id IS DISTINCT FROM w.id
      OR u.role IS DISTINCT FROM 'worker' OR u.plan_code IS DISTINCT FROM 'individual'
      OR u.credential_kind IS DISTINCT FROM 'password'
      OR EXISTS(SELECT 1 FROM public.users other WHERE other.workspace_id=w.id AND other.id<>w.owner_id))) THEN
    RAISE EXCEPTION 'PHASE3_PRIVATE_PREFLIGHT_FAILED';
  END IF;
END; $$;

CREATE OR REPLACE FUNCTION public.keeptimer_phase3_timer_guard()
RETURNS trigger LANGUAGE plpgsql SET search_path='' AS $$
DECLARE w record;
BEGIN
  SELECT * INTO w FROM public.workspaces WHERE id=NEW.workspace_id FOR SHARE;
  IF w.kind='individual_private' AND (NEW.user_id IS DISTINCT FROM w.owner_id OR NEW.is_shared IS DISTINCT FROM false) THEN
    RAISE EXCEPTION 'PHASE3_PRIVATE_TIMER_FORBIDDEN' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END; $$;
DROP TRIGGER IF EXISTS keeptimer_phase3_timer_guard ON public.timers;
CREATE TRIGGER keeptimer_phase3_timer_guard BEFORE INSERT OR UPDATE ON public.timers
FOR EACH ROW EXECUTE FUNCTION public.keeptimer_phase3_timer_guard();

CREATE OR REPLACE FUNCTION public.keeptimer_phase3_require_actor(p_actor uuid,p_session uuid,p_role text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path='' AS $$
DECLARE u record; s record; m record; n timestamptz;
BEGIN
  IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION 'SALES_UNAVAILABLE'; END IF;
  IF p_role NOT IN ('superadmin','agent') OR p_role IS NULL THEN RAISE EXCEPTION 'SALES_FORBIDDEN'; END IF;
  PERFORM 1 FROM public.keeptimer_sales_release WHERE singleton AND enabled FOR SHARE;
  IF NOT FOUND THEN RAISE EXCEPTION 'PRIVILEGED_MFA_NOT_READY'; END IF;
  SELECT * INTO u FROM public.users WHERE id=p_actor FOR UPDATE;
  IF NOT FOUND OR u.disabled_at IS NOT NULL OR u.role<>p_role THEN RAISE EXCEPTION 'SALES_FORBIDDEN'; END IF;
  IF u.must_change_password THEN RAISE EXCEPTION 'PASSWORD_CHANGE_REQUIRED'; END IF;
  SELECT * INTO s FROM public.sessions WHERE id=p_session AND user_id=p_actor FOR SHARE;
  IF NOT FOUND OR s.revoked_at IS NOT NULL THEN RAISE EXCEPTION 'SALES_SESSION_INVALID'; END IF;
  SELECT * INTO m FROM public.keeptimer_privileged_web_sessions WHERE session_id=p_session AND user_id=p_actor FOR SHARE;
  n:=clock_timestamp();
  IF NOT FOUND OR m.verified_at>n OR m.expires_at<=n OR m.method<>'email_otp' THEN RAISE EXCEPTION 'PRIVILEGED_MFA_REQUIRED'; END IF;
END; $$;

CREATE OR REPLACE FUNCTION public.keeptimer_phase3_access(p_actor uuid,p_session uuid,p_role text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path='' AS $$
BEGIN
  PERFORM public.keeptimer_phase3_require_actor(p_actor,p_session,p_role);
  RETURN true;
END; $$;

CREATE OR REPLACE FUNCTION public.keeptimer_phase3_add_months(p_start timestamptz,p_months integer)
RETURNS timestamptz LANGUAGE plpgsql IMMUTABLE SET search_path='' AS $$
BEGIN
  IF p_start IS NULL OR NOT isfinite(p_start) OR p_months IS NULL OR p_months NOT BETWEEN 1 AND 12 THEN
    RAISE EXCEPTION 'SALES_INPUT_INVALID';
  END IF;
  RETURN ((p_start AT TIME ZONE 'UTC') + make_interval(months=>p_months)) AT TIME ZONE 'UTC';
END; $$;

CREATE OR REPLACE FUNCTION public.keeptimer_phase3_subscription_json(p_id uuid)
RETURNS jsonb LANGUAGE sql STABLE SET search_path='' AS $$
  SELECT jsonb_build_object('id',s.id,'customerId',s.user_id,'planCode',s.plan_code,
    'sequenceNo',s.sequence_no,'startsAt',s.starts_at,'endsAt',s.ends_at,'termMonths',s.term_months,
    'amountMinor',s.amount_minor::text,'currency',s.currency,'createdBy',s.created_by_user_id,
    'cancelledAt',s.cancelled_at,'cancelledBy',s.cancelled_by_user_id,'cancellationReason',s.cancellation_reason)
  FROM public.subscriptions s WHERE s.id=p_id;
$$;

CREATE OR REPLACE FUNCTION public.keeptimer_phase3_command(
  p_actor uuid,p_session uuid,p_request uuid,p_action text,p_fingerprint text,p_data jsonb
) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path='' AS $$
DECLARE required_role text; allowed text[]; old_request record; target public.users%ROWTYPE;
  customer uuid; workspace uuid; sub public.subscriptions%ROWTYPE; n timestamptz; start_at timestamptz;
  seq integer; active_count integer; result jsonb; audit_action text;
BEGIN
  required_role:=CASE WHEN p_action IN ('agent_create','agent_revoke','agent_password_reset') THEN 'superadmin'
    WHEN p_action IN ('customer_create','subscription_renew','subscription_cancel','customer_password_reset') THEN 'agent' END;
  PERFORM public.keeptimer_phase3_require_actor(p_actor,p_session,required_role);
  IF p_request IS NULL OR p_fingerprint IS NULL OR p_fingerprint !~ '^[a-f0-9]{64}$' OR
     jsonb_typeof(p_data) IS DISTINCT FROM 'object' THEN RAISE EXCEPTION 'SALES_INPUT_INVALID'; END IF;
  SELECT * INTO old_request FROM public.keeptimer_sales_requests WHERE actor_id=p_actor AND request_id=p_request;
  IF FOUND THEN
    IF old_request.action IS DISTINCT FROM p_action OR old_request.fingerprint IS DISTINCT FROM p_fingerprint THEN
      RAISE EXCEPTION 'IDEMPOTENCY_CONFLICT';
    END IF;
    PERFORM public.keeptimer_phase3_require_actor(p_actor,p_session,required_role);
    RETURN old_request.result;
  END IF;
  allowed:=CASE p_action
    WHEN 'agent_create' THEN ARRAY['username','password_hash','mfa_email']
    WHEN 'customer_create' THEN ARRAY['username','password_hash','plan_code','term_months','amount_minor','currency']
    WHEN 'subscription_renew' THEN ARRAY['customer_id','plan_code','term_months','amount_minor','currency']
    WHEN 'subscription_cancel' THEN ARRAY['customer_id','subscription_id','reason']
    WHEN 'agent_revoke' THEN ARRAY['agent_id']
    WHEN 'agent_password_reset' THEN ARRAY['agent_id','password_hash']
    WHEN 'customer_password_reset' THEN ARRAY['customer_id','password_hash'] END;
  IF p_data-allowed<>'{}'::jsonb OR NOT(p_data ?& allowed) THEN RAISE EXCEPTION 'SALES_INPUT_INVALID'; END IF;
  IF p_action IN ('agent_create','customer_create','agent_password_reset','customer_password_reset') THEN
    IF jsonb_typeof(p_data->'password_hash') IS DISTINCT FROM 'string' OR
      (p_data->>'password_hash') !~ '^\$2[aby]\$12\$[./A-Za-z0-9]{53}$' THEN RAISE EXCEPTION 'SALES_INPUT_INVALID'; END IF;
  END IF;
  IF p_action IN ('agent_create','customer_create') AND (jsonb_typeof(p_data->'username') IS DISTINCT FROM 'string'
    OR (p_data->>'username') !~ '^[A-Za-z0-9_.-]{3,25}$') THEN RAISE EXCEPTION 'SALES_INPUT_INVALID'; END IF;
  IF p_action='agent_create' THEN
    IF jsonb_typeof(p_data->'mfa_email') IS DISTINCT FROM 'string' OR length(p_data->>'mfa_email')>254
      OR (p_data->>'mfa_email') !~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$' THEN RAISE EXCEPTION 'SALES_INPUT_INVALID'; END IF;
    IF EXISTS(SELECT 1 FROM public.users WHERE role='agent' AND disabled_at IS NULL) THEN RAISE EXCEPTION 'ACTIVE_AGENT_EXISTS'; END IF;
    INSERT INTO public.users(username,role,pin_hash,password_hash,credential_kind,must_change_password,mfa_email)
      VALUES(p_data->>'username','agent',NULL,p_data->>'password_hash','password',true,p_data->>'mfa_email') RETURNING id INTO customer;
    -- Unique checks/triggers may have waited past the initial MFA deadline.
    PERFORM public.keeptimer_phase3_require_actor(p_actor,p_session,required_role);
    INSERT INTO public.admin_audit_log(actor_user_id,action,target_user_id) VALUES(p_actor,'agent_created',customer);
    result:=jsonb_build_object('agentId',customer,'mustChangePassword',true,'loginReady',false);
  ELSIF p_action='customer_create' OR p_action='subscription_renew' THEN
    IF p_data->>'plan_code' IS DISTINCT FROM 'individual' THEN RAISE EXCEPTION 'PLAN_NOT_AVAILABLE'; END IF;
    IF jsonb_typeof(p_data->'term_months') IS DISTINCT FROM 'number' OR (p_data->>'term_months') !~ '^[0-9]{1,2}$'
      OR (p_data->>'term_months')::integer NOT BETWEEN 1 AND 12 OR
      jsonb_typeof(p_data->'amount_minor') IS DISTINCT FROM 'number' OR (p_data->>'amount_minor') !~ '^[0-9]{1,16}$'
      OR (p_data->>'amount_minor')::numeric>9007199254740991 OR
      jsonb_typeof(p_data->'currency') IS DISTINCT FROM 'string' OR (p_data->>'currency') !~ '^[A-Z]{3}$'
      THEN RAISE EXCEPTION 'SALES_INPUT_INVALID'; END IF;
    IF p_action='customer_create' THEN
      INSERT INTO public.users(username,role,pin_hash,password_hash,credential_kind,must_change_password,plan_code)
        VALUES(p_data->>'username','worker',NULL,p_data->>'password_hash','password',true,'individual') RETURNING id INTO customer;
    ELSE
      customer:=(p_data->>'customer_id')::uuid;
      SELECT * INTO target FROM public.users WHERE id=customer FOR UPDATE;
      IF NOT FOUND OR target.role<>'worker' OR target.disabled_at IS NOT NULL OR target.plan_code IS DISTINCT FROM 'individual'
        OR NOT EXISTS(SELECT 1 FROM public.keeptimer_individual_customers c WHERE c.user_id=customer AND c.workspace_id=target.workspace_id)
        THEN RAISE EXCEPTION 'CUSTOMER_NOT_FOUND'; END IF;
    END IF;
    PERFORM code FROM public.subscription_plans ORDER BY code FOR SHARE;
    IF NOT EXISTS(SELECT 1 FROM public.subscription_plans WHERE code='individual' AND enabled) THEN RAISE EXCEPTION 'PLAN_NOT_AVAILABLE'; END IF;
    PERFORM id FROM public.subscriptions WHERE user_id=customer ORDER BY sequence_no FOR UPDATE;
    PERFORM public.keeptimer_phase3_require_actor(p_actor,p_session,required_role);
    n:=clock_timestamp();
    SELECT count(*) INTO active_count FROM public.subscriptions WHERE user_id=customer AND cancelled_at IS NULL AND starts_at<=n AND ends_at>n;
    IF active_count>1 THEN RAISE EXCEPTION 'SUBSCRIPTION_CONFLICT'; END IF;
    IF EXISTS(SELECT 1 FROM public.subscriptions WHERE user_id=customer AND cancelled_at IS NULL AND starts_at>n) THEN
      RAISE EXCEPTION 'PENDING_PERIOD_EXISTS';
    END IF;
    SELECT ends_at INTO start_at FROM public.subscriptions WHERE user_id=customer AND cancelled_at IS NULL AND starts_at<=n AND ends_at>n;
    start_at:=coalesce(start_at,n);
    SELECT coalesce(max(sequence_no),0)+1 INTO seq FROM public.subscriptions WHERE user_id=customer;
    IF p_action='customer_create' THEN
      INSERT INTO public.workspaces(name,owner_id,kind,invite_code,shared_mode_enabled)
        VALUES('Individual',customer,'individual_private',NULL,false) RETURNING id INTO workspace;
      UPDATE public.users SET workspace_id=workspace WHERE id=customer;
      INSERT INTO public.keeptimer_individual_customers(user_id,workspace_id,created_by_user_id) VALUES(customer,workspace,p_actor);
      INSERT INTO public.admin_audit_log(actor_user_id,action,target_user_id) VALUES(p_actor,'customer_created',customer);
    END IF;
    INSERT INTO public.subscriptions(user_id,plan_code,sequence_no,starts_at,ends_at,term_months,amount_minor,currency,created_by_user_id)
      VALUES(customer,'individual',seq,start_at,public.keeptimer_phase3_add_months(start_at,(p_data->>'term_months')::integer),
        (p_data->>'term_months')::smallint,(p_data->>'amount_minor')::bigint,p_data->>'currency',p_actor) RETURNING * INTO sub;
    audit_action:=CASE WHEN p_action='customer_create' THEN 'subscription_created' ELSE 'subscription_renewed' END;
    INSERT INTO public.admin_audit_log(actor_user_id,action,target_user_id,metadata) VALUES(p_actor,audit_action,customer,
      jsonb_build_object('subscription_id',sub.id,'sequence_no',sub.sequence_no,'plan_code','individual'));
    result:=jsonb_build_object('customerId',customer,'subscription',public.keeptimer_phase3_subscription_json(sub.id),'loginReady',false);
  ELSE
    customer:=coalesce(p_data->>'customer_id',p_data->>'agent_id')::uuid;
    SELECT * INTO target FROM public.users WHERE id=customer FOR UPDATE;
    IF required_role='superadmin' THEN
      IF NOT FOUND OR target.role<>'agent' THEN RAISE EXCEPTION 'AGENT_NOT_FOUND'; END IF;
    ELSE
      IF NOT FOUND OR target.role<>'worker' OR target.plan_code IS DISTINCT FROM 'individual' OR target.disabled_at IS NOT NULL
        OR NOT EXISTS(SELECT 1 FROM public.keeptimer_individual_customers c WHERE c.user_id=customer AND c.workspace_id=target.workspace_id)
        THEN RAISE EXCEPTION 'CUSTOMER_NOT_FOUND'; END IF;
    END IF;
    IF p_action='subscription_cancel' THEN
      IF p_data->>'reason' IS NULL OR p_data->>'reason' NOT IN ('customer_request','payment_record_correction','administrative') THEN
        RAISE EXCEPTION 'SALES_INPUT_INVALID'; END IF;
      PERFORM code FROM public.subscription_plans ORDER BY code FOR SHARE;
      PERFORM id FROM public.subscriptions WHERE user_id=customer ORDER BY sequence_no FOR UPDATE;
      SELECT * INTO sub FROM public.subscriptions WHERE id=(p_data->>'subscription_id')::uuid AND user_id=customer;
      IF NOT FOUND THEN RAISE EXCEPTION 'SUBSCRIPTION_NOT_FOUND'; END IF;
      PERFORM public.keeptimer_phase3_require_actor(p_actor,p_session,required_role);
      IF sub.cancelled_at IS NULL THEN
        UPDATE public.subscriptions SET cancelled_at=clock_timestamp(),cancelled_by_user_id=p_actor,cancellation_reason=p_data->>'reason' WHERE id=sub.id;
        INSERT INTO public.admin_audit_log(actor_user_id,action,target_user_id,metadata) VALUES(p_actor,'subscription_cancelled',customer,
          jsonb_build_object('subscription_id',sub.id,'sequence_no',sub.sequence_no,'plan_code',sub.plan_code));
      END IF;
      result:=jsonb_build_object('customerId',customer,'subscription',public.keeptimer_phase3_subscription_json(sub.id));
    ELSE
      PERFORM public.keeptimer_phase3_require_actor(p_actor,p_session,required_role);
      IF p_action='agent_revoke' THEN
        IF target.disabled_at IS NULL THEN
          UPDATE public.users SET disabled_at=clock_timestamp() WHERE id=customer;
          INSERT INTO public.admin_audit_log(actor_user_id,action,target_user_id) VALUES(p_actor,'agent_revoked',customer);
        END IF;
        result:=jsonb_build_object('agentId',customer,'disabled',true);
      ELSE
        IF target.disabled_at IS NOT NULL OR target.credential_kind<>'password' THEN RAISE EXCEPTION 'SALES_FORBIDDEN'; END IF;
        UPDATE public.users SET password_hash=p_data->>'password_hash',must_change_password=true WHERE id=customer;
        INSERT INTO public.admin_audit_log(actor_user_id,action,target_user_id) VALUES(p_actor,'password_reset',customer);
        result:=jsonb_build_object('userId',customer,'mustChangePassword',true,'loginReady',false);
      END IF;
      UPDATE public.sessions SET revoked_at=coalesce(revoked_at,clock_timestamp()) WHERE user_id=customer;
      DELETE FROM public.keeptimer_privileged_web_sessions WHERE user_id=customer;
    END IF;
  END IF;
  INSERT INTO public.keeptimer_sales_requests(actor_id,request_id,action,fingerprint,result)
    VALUES(p_actor,p_request,p_action,p_fingerprint,result);
  -- Every command must recheck AFTER all writes, including audit/idempotency
  -- lock waits. Failure rolls back the entire RPC, including these records.
  PERFORM public.keeptimer_phase3_require_actor(p_actor,p_session,required_role);
  RETURN result;
END; $$;

CREATE OR REPLACE FUNCTION public.keeptimer_phase3_list(
  p_actor uuid,p_session uuid,p_kind text,p_customer uuid DEFAULT NULL,p_after uuid DEFAULT NULL,p_limit integer DEFAULT 25
) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path='' AS $$
DECLARE result jsonb; required_role text;
BEGIN
  required_role:=CASE WHEN p_kind='agents' THEN 'superadmin' WHEN p_kind IN ('customers','history') THEN 'agent' END;
  PERFORM public.keeptimer_phase3_require_actor(p_actor,p_session,required_role);
  IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 100 THEN RAISE EXCEPTION 'SALES_INPUT_INVALID'; END IF;
  IF p_kind='agents' THEN
    SELECT coalesce(jsonb_agg(q.item ORDER BY q.id),'[]'::jsonb) INTO result FROM (
      SELECT id,jsonb_build_object('id',id,'username',username,'disabledAt',disabled_at,'mustChangePassword',must_change_password) item
      FROM public.users WHERE role='agent' AND (p_after IS NULL OR id>p_after) ORDER BY id LIMIT p_limit+1
    ) q;
  ELSIF p_kind='customers' THEN
    WITH page AS MATERIALIZED (
      SELECT u.id,u.username,u.disabled_at FROM public.keeptimer_individual_customers c JOIN public.users u ON u.id=c.user_id
      WHERE u.role='worker' AND u.plan_code='individual' AND (p_after IS NULL OR u.id>p_after)
      ORDER BY u.id LIMIT p_limit+1
    ), states AS MATERIALIZED (SELECT page.*,public.keeptimer_resolve_entitlement(page.id) e FROM page)
    SELECT coalesce(jsonb_agg(q.item ORDER BY q.id),'[]'::jsonb) INTO result FROM (
      SELECT u.id,jsonb_build_object('id',u.id,'username',u.username,'disabledAt',u.disabled_at,
        'status',u.e->'status','endsAt',u.e->'endsAt','isEntitled',u.e->'isEntitled','code',u.e->'code') item
      FROM states u
      ORDER BY u.id
    ) q;
  ELSE
    IF NOT EXISTS(SELECT 1 FROM public.keeptimer_individual_customers c JOIN public.users u ON u.id=c.user_id
      WHERE u.id=p_customer AND u.role='worker' AND u.plan_code='individual') THEN RAISE EXCEPTION 'CUSTOMER_NOT_FOUND'; END IF;
    IF p_after IS NOT NULL AND NOT EXISTS(SELECT 1 FROM public.subscriptions WHERE user_id=p_customer AND id=p_after) THEN
      RAISE EXCEPTION 'SALES_INPUT_INVALID';
    END IF;
    SELECT coalesce(jsonb_agg(q.item ORDER BY q.sequence_no),'[]'::jsonb) INTO result FROM (
      SELECT s.sequence_no,public.keeptimer_phase3_subscription_json(s.id) item FROM public.subscriptions s
      WHERE s.user_id=p_customer AND (p_after IS NULL OR s.sequence_no>(SELECT sequence_no FROM public.subscriptions WHERE id=p_after AND user_id=p_customer))
      ORDER BY s.sequence_no LIMIT p_limit+1
    ) q;
  END IF;
  PERFORM public.keeptimer_phase3_require_actor(p_actor,p_session,required_role);
  RETURN jsonb_build_object('items',CASE WHEN jsonb_array_length(result)>p_limit THEN result-p_limit ELSE result END,
    'nextCursor',CASE WHEN jsonb_array_length(result)>p_limit THEN result->(p_limit-1)->>'id' ELSE NULL END);
END; $$;

-- Revoke PUBLIC's default EXECUTE on EVERY helper in this migration.
DO $$ DECLARE f record; BEGIN
  FOR f IN SELECT p.oid::regprocedure AS signature FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
    WHERE n.nspname='public' AND p.proname LIKE 'keeptimer_phase3_%' LOOP
    EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC,anon,authenticated,service_role',f.signature);
  END LOOP;
END; $$;
GRANT EXECUTE ON FUNCTION public.keeptimer_phase3_access(uuid,uuid,text),
  public.keeptimer_phase3_command(uuid,uuid,uuid,text,text,jsonb),
  public.keeptimer_phase3_list(uuid,uuid,text,uuid,uuid,integer) TO service_role;
COMMENT ON TABLE public.keeptimer_privileged_web_sessions IS
  'No issuer in Phase 3. Only future reviewed Phase 7 web MFA may create short-lived session-bound proofs. No application DML grants.';
COMMENT ON TABLE public.keeptimer_sales_release IS
  'Default OFF. Phase 7 reviewed release migration required, together with real MFA proof issuance. Not an environment/test bypass.';
COMMENT ON TABLE public.keeptimer_sales_requests IS
  'Durable actor-scoped idempotency. Fingerprint is backend HMAC, never a raw body/password/hash. Do not expire keys and permit double sales.';
NOTIFY pgrst,'reload schema';
COMMIT;
