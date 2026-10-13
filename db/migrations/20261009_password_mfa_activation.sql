-- Phase 7 PREPARATION, once after Phase 6 as the verified existing owner.
-- No legacy guard/function replacement or existing-session revocation here.
-- No release flag is enabled, no mailbox enrolled and no email is sent here.
BEGIN;
CREATE FUNCTION public.keeptimer_auth_assert_owner() RETURNS void
LANGUAGE plpgsql SECURITY INVOKER SET search_path='' AS $$
DECLARE owner_oid oid; dependency record; signature text;
BEGIN
 SELECT oid INTO owner_oid FROM pg_catalog.pg_roles WHERE rolname=current_user;
 IF current_user::text IN ('anon','authenticated','service_role') THEN RAISE EXCEPTION 'PHASE7_TRUSTED_OWNER_REQUIRED'; END IF;
 FOREACH signature IN ARRAY ARRAY[
  'public.keeptimer_phase3_command(uuid,uuid,uuid,text,text,jsonb)',
  'public.keeptimer_phase3_require_actor(uuid,uuid,text)',
  'public.keeptimer_phase3_list(uuid,uuid,text,uuid,uuid,integer)',
  'public.keeptimer_resolve_entitlement(uuid)',
  'public.keeptimer_close_company_worker(uuid,uuid)'] LOOP
  IF pg_catalog.to_regprocedure(signature) IS NULL THEN RAISE EXCEPTION 'PHASE7_DEPENDENCY_MISSING'; END IF;
 END LOOP;
 FOR dependency IN
  SELECT p.proowner AS owner FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
   WHERE n.nspname='public' AND p.proname LIKE 'keeptimer_%'
  UNION ALL
  SELECT c.relowner FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
   WHERE n.nspname='public' AND (c.relname LIKE 'keeptimer_%' OR c.relname IN ('users','sessions','workspaces','timers','subscriptions','subscription_plans','admin_audit_log'))
 LOOP
  IF dependency.owner<>owner_oid THEN RAISE EXCEPTION 'PHASE7_DEPENDENCY_OWNER_MISMATCH'; END IF;
 END LOOP;
 IF EXISTS(SELECT 1 FROM pg_catalog.pg_roles r WHERE r.rolname IN ('anon','authenticated','service_role')
  AND (r.rolsuper OR pg_catalog.pg_has_role(r.oid,owner_oid,'MEMBER'))) THEN RAISE EXCEPTION 'PHASE7_UNSAFE_OWNER_MEMBERSHIP'; END IF;
END; $$;
REVOKE ALL ON FUNCTION public.keeptimer_auth_assert_owner() FROM PUBLIC,anon,authenticated,service_role;
SELECT public.keeptimer_auth_assert_owner();
DO $$ BEGIN
 IF current_user::text IN ('anon','authenticated','service_role') THEN RAISE EXCEPTION 'PHASE7_TRUSTED_OWNER_REQUIRED'; END IF;
 IF EXISTS(SELECT 1 FROM public.keeptimer_sales_release WHERE enabled) THEN RAISE EXCEPTION 'PHASE7_SALES_GATE_MUST_BE_CLOSED'; END IF;
END; $$;
-- Phase 1 already limits ACTIVE privileged accounts. Phase 7 also enforces the
-- requested single Superadmin identity, including disabled history. Never
-- delete/merge accounts to make this preflight pass.
DO $$ BEGIN
 IF (SELECT count(*) FROM public.users WHERE role='superadmin')>1 THEN
  RAISE EXCEPTION 'PHASE7_SUPERADMIN_CARDINALITY_MISMATCH';
 END IF;
END; $$;
CREATE UNIQUE INDEX keeptimer_auth_one_superadmin_identity ON public.users(role) WHERE role='superadmin';
CREATE TABLE public.keeptimer_auth_release (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton), enabled boolean NOT NULL DEFAULT false,
 cutover boolean NOT NULL DEFAULT false, CHECK(NOT enabled OR cutover)
);
INSERT INTO public.keeptimer_auth_release VALUES(true,false,false);
CREATE TABLE public.keeptimer_auth_accounts (
 user_id uuid PRIMARY KEY REFERENCES public.users(id),
 email text NOT NULL UNIQUE CHECK(length(email)<=254 AND email=lower(email) AND email ~ '^[a-z0-9.!#$%&''*+/=?^_`{|}~-]+@[a-z0-9.-]+\.[a-z]{2,}$'),
 verified_at timestamptz, activated_at timestamptz,
 version bigint NOT NULL DEFAULT 1 CHECK(version>0),
 CHECK((verified_at IS NULL)=(activated_at IS NULL))
);
CREATE TABLE public.keeptimer_auth_challenges (
 id uuid PRIMARY KEY, user_id uuid NOT NULL REFERENCES public.keeptimer_auth_accounts(user_id),
 purpose text NOT NULL CHECK(purpose IN ('mfa','activation','reset')),
 context_digest text NOT NULL CHECK(context_digest ~ '^[a-f0-9]{64}$'),
 proof_digest text NOT NULL CHECK(proof_digest ~ '^[a-f0-9]{64}$'),
 binding_digest text CHECK(binding_digest ~ '^[a-f0-9]{64}$'),
 version bigint NOT NULL, transport text NOT NULL CHECK(transport IN ('web','native')),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(), expires_at timestamptz NOT NULL,
 last_sent_at timestamptz NOT NULL DEFAULT clock_timestamp(), sends integer NOT NULL DEFAULT 1 CHECK(sends BETWEEN 1 AND 3),
 attempts integer NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 5),
 delivery text NOT NULL DEFAULT 'pending' CHECK(delivery IN ('pending','accepted','failed')),
 consumed_at timestamptz, CHECK(expires_at>created_at AND expires_at<=created_at+interval '30 minutes')
);
CREATE INDEX keeptimer_auth_challenges_user ON public.keeptimer_auth_challenges(user_id,purpose);
CREATE INDEX keeptimer_auth_challenges_recent ON public.keeptimer_auth_challenges(user_id,created_at DESC);
CREATE INDEX keeptimer_auth_challenges_expiry ON public.keeptimer_auth_challenges(expires_at,id);
CREATE TABLE public.keeptimer_auth_sessions (
 session_id uuid PRIMARY KEY REFERENCES public.sessions(id), user_id uuid NOT NULL REFERENCES public.keeptimer_auth_accounts(user_id),
 version bigint NOT NULL, transport text NOT NULL CHECK(transport IN ('web','native')),
 expires_at timestamptz NOT NULL
);
CREATE TABLE public.keeptimer_auth_limits (
 key text PRIMARY KEY CHECK(key ~ '^[a-f0-9]{64}$'), started_at timestamptz NOT NULL, count integer NOT NULL CHECK(count>0)
);
CREATE INDEX keeptimer_auth_limits_expiry ON public.keeptimer_auth_limits(started_at,key);
-- Default privileges may grant every newly created table to browser roles.
ALTER TABLE public.keeptimer_auth_release ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.keeptimer_auth_accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.keeptimer_auth_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.keeptimer_auth_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.keeptimer_auth_limits ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.keeptimer_auth_release,public.keeptimer_auth_accounts,public.keeptimer_auth_challenges,
 public.keeptimer_auth_sessions,public.keeptimer_auth_limits FROM PUBLIC,anon,authenticated,service_role;

CREATE FUNCTION public.keeptimer_auth_ready_gate() RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path='' AS $$ BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION 'AUTH_UNAVAILABLE'; END IF;
 PERFORM 1 FROM public.keeptimer_auth_release WHERE singleton AND enabled AND cutover FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'AUTH_NOT_READY'; END IF;
END; $$;
-- Fixed backend budgets, not caller-supplied limits. Increment includes successful
-- attempts: stricter than failed-only and cannot race a counter reset.
CREATE FUNCTION public.keeptimer_auth_limit(p_kind text,p_account text,p_ip text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path='' AS $$
DECLARE k text; n integer; maximum integer; budget integer;
BEGIN
 IF p_kind NOT IN ('login','send','verify','pin') OR p_kind IS NULL OR
    p_account IS NULL OR p_ip IS NULL OR p_account !~ '^[a-f0-9]{64}$' OR p_ip !~ '^[a-f0-9]{64}$' OR p_account=p_ip
 THEN RAISE EXCEPTION 'AUTH_INPUT_INVALID'; END IF;
 IF p_kind<>'pin' THEN PERFORM public.keeptimer_auth_ready_gate(); END IF;
 -- Every call locks its domain-separated IP key before its account key.
 -- A denied IP cannot create an unbounded number of account rows.
 FOR k IN SELECT unnest(ARRAY[p_ip,p_account]) LOOP
  maximum:=CASE p_kind WHEN 'send' THEN 5 WHEN 'verify' THEN 30 ELSE 10 END;
  budget:=CASE WHEN k=p_ip THEN maximum*5 ELSE maximum END;
  INSERT INTO public.keeptimer_auth_limits AS r(key,started_at,count) VALUES(k,clock_timestamp(),1)
   ON CONFLICT(key) DO UPDATE SET
    count=CASE WHEN r.started_at<=clock_timestamp()-interval '15 minutes' THEN 1 ELSE least(r.count+1,1000000) END,
    started_at=CASE WHEN r.started_at<=clock_timestamp()-interval '15 minutes' THEN clock_timestamp() ELSE r.started_at END
   RETURNING count INTO n;
  IF n>budget THEN RETURN false; END IF;
 END LOOP;
 RETURN true; -- returning, rather than raising, commits denied-attempt counters.
END; $$;

CREATE FUNCTION public.keeptimer_auth_shape(p_user uuid) RETURNS boolean
LANGUAGE sql SECURITY DEFINER SET search_path='' AS $$
 SELECT EXISTS(SELECT 1 FROM public.users u WHERE u.id=p_user AND u.disabled_at IS NULL AND u.credential_kind='password'
  AND (u.role IN ('superadmin','agent') OR (u.role='worker' AND u.plan_code='individual' AND EXISTS(
   SELECT 1 FROM public.keeptimer_individual_customers c JOIN public.workspaces w ON w.id=c.workspace_id
    WHERE c.user_id=u.id AND c.workspace_id=u.workspace_id AND w.owner_id=u.id AND w.kind='individual_private' AND NOT coalesce(w.shared_mode_enabled,false) FOR SHARE OF w,c))))
$$;

CREATE FUNCTION public.keeptimer_auth_session(p_user uuid,p_session uuid,p_transport text DEFAULT NULL,p_refresh text DEFAULT NULL)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path='' AS $$
DECLARE u record; a record; s record; q record; m record; n timestamptz;
BEGIN
 PERFORM public.keeptimer_auth_ready_gate();
 SELECT * INTO u FROM public.users WHERE id=p_user FOR SHARE;
 IF NOT FOUND OR u.disabled_at IS NOT NULL OR u.must_change_password OR NOT public.keeptimer_auth_shape(p_user) THEN RETURN false; END IF;
 SELECT * INTO a FROM public.keeptimer_auth_accounts WHERE user_id=p_user FOR SHARE;
 IF NOT FOUND OR a.verified_at IS NULL OR a.activated_at IS NULL THEN RETURN false; END IF;
 SELECT * INTO s FROM public.sessions WHERE id=p_session AND user_id=p_user FOR SHARE;
 IF NOT FOUND OR s.revoked_at IS NOT NULL OR (p_refresh IS NOT NULL AND s.refresh_token_hash IS DISTINCT FROM p_refresh) THEN RETURN false; END IF;
 SELECT * INTO q FROM public.keeptimer_auth_sessions WHERE session_id=p_session AND user_id=p_user FOR SHARE;
 n:=clock_timestamp();
 IF NOT FOUND OR q.version<>a.version OR q.expires_at<=n OR
    (p_transport IS NOT NULL AND q.transport<>p_transport) THEN RETURN false; END IF;
 IF u.role IN ('superadmin','agent') THEN
  IF q.transport<>'web' THEN RETURN false; END IF;
  SELECT * INTO m FROM public.keeptimer_privileged_web_sessions WHERE session_id=p_session AND user_id=p_user FOR SHARE;
  n:=clock_timestamp();
  IF NOT FOUND OR m.method<>'email_otp' OR m.verified_at>n OR m.expires_at<=n OR q.expires_at<=n THEN RETURN false; END IF;
 END IF;
 RETURN true;
END; $$;

CREATE FUNCTION public.keeptimer_auth_new_session(p_user uuid,p_session uuid,p_hash text,p_transport text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path='' AS $$
DECLARE u record; a record; n timestamptz; finish timestamptz;
BEGIN
 SELECT * INTO u FROM public.users WHERE id=p_user FOR UPDATE;
 SELECT * INTO a FROM public.keeptimer_auth_accounts WHERE user_id=p_user FOR UPDATE;
 IF NOT public.keeptimer_auth_shape(p_user) OR u.must_change_password OR a.activated_at IS NULL OR a.verified_at IS NULL OR
  p_transport NOT IN ('web','native') OR p_transport IS NULL OR p_session IS NULL OR p_hash IS NULL OR p_hash !~ '^[a-f0-9]{64}$' OR
  (u.role IN ('superadmin','agent') AND p_transport<>'web') THEN RAISE EXCEPTION 'AUTH_INVALID'; END IF;
 n:=clock_timestamp(); finish:=n+CASE WHEN u.role IN ('superadmin','agent') THEN interval '15 minutes' ELSE interval '30 days' END;
 INSERT INTO public.sessions(id,user_id,refresh_token_hash) VALUES(p_session,p_user,p_hash);
 INSERT INTO public.keeptimer_auth_sessions VALUES(p_session,p_user,a.version,p_transport,finish);
 IF u.role IN ('superadmin','agent') THEN
  INSERT INTO public.keeptimer_privileged_web_sessions VALUES(p_session,p_user,n,finish,'email_otp');
 END IF;
 RETURN jsonb_build_object('id',u.id,'username',u.username,'role',u.role,'workspace_id',u.workspace_id);
END; $$;

-- Single trusted backend RPC. Browser roles have NO EXECUTE. Password comparison
-- happens with bcrypt in backend; expected_hash is rechecked after taking user lock.
CREATE FUNCTION public.keeptimer_auth_command(p_action text,p_data jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path='' AS $$
DECLARE u record; a record; c record; target uuid; challenge uuid; ctx text; proof text; n timestamptz; transport text;
BEGIN
 PERFORM public.keeptimer_auth_ready_gate();
 IF jsonb_typeof(p_data) IS DISTINCT FROM 'object' THEN RAISE EXCEPTION 'AUTH_INPUT_INVALID'; END IF;
 IF p_action='lookup' THEN
  SELECT * INTO a FROM public.keeptimer_auth_accounts WHERE email=p_data->>'email';
  IF NOT FOUND THEN RETURN NULL; END IF;
  SELECT * INTO u FROM public.users WHERE id=a.user_id;
  IF NOT public.keeptimer_auth_shape(u.id) THEN RETURN NULL; END IF;
  RETURN jsonb_build_object('id',u.id,'email',a.email,'hash',u.password_hash,'role',u.role,
   'ready',a.verified_at IS NOT NULL AND a.activated_at IS NOT NULL AND NOT u.must_change_password);
 END IF;
 IF p_action IN ('delivery','consume','resend','inspect') THEN
  challenge:=(p_data->>'challenge_id')::uuid;
  SELECT user_id INTO target FROM public.keeptimer_auth_challenges WHERE id=challenge;
 ELSE target:=(p_data->>'user_id')::uuid; END IF;
 SELECT * INTO u FROM public.users WHERE id=target FOR UPDATE;
 IF NOT FOUND OR NOT public.keeptimer_auth_shape(target) THEN RETURN jsonb_build_object('ok',false); END IF;
 SELECT * INTO a FROM public.keeptimer_auth_accounts WHERE user_id=target FOR UPDATE;
 IF NOT FOUND THEN RETURN jsonb_build_object('ok',false); END IF;
 transport:=p_data->>'transport';
 IF p_action IN ('issue','login') THEN
  IF p_data->>'purpose'='mfa' OR p_action='login' THEN
   IF u.password_hash IS DISTINCT FROM p_data->>'expected_hash' OR a.activated_at IS NULL OR a.verified_at IS NULL OR u.must_change_password THEN
    RETURN jsonb_build_object('ok',false); END IF;
   IF p_action='login' THEN
    IF u.role<>'worker' THEN RETURN jsonb_build_object('ok',false); END IF;
    RETURN jsonb_build_object('ok',true,'user',public.keeptimer_auth_new_session(target,(p_data->>'session_id')::uuid,p_data->>'refresh_hash',transport));
   END IF;
   IF p_data->>'binding_digest' IS NULL OR p_data->>'binding_digest' !~ '^[a-f0-9]{64}$' THEN RAISE EXCEPTION 'AUTH_INPUT_INVALID'; END IF;
   IF u.role NOT IN ('superadmin','agent') OR transport<>'web' THEN RETURN jsonb_build_object('ok',false); END IF;
  ELSIF p_data->>'purpose'='activation' THEN
   IF a.activated_at IS NOT NULL OR a.verified_at IS NOT NULL THEN RETURN jsonb_build_object('ok',false); END IF;
  ELSIF p_data->>'purpose'='reset' THEN
   IF u.role<>'worker' OR a.activated_at IS NULL OR a.verified_at IS NULL THEN RETURN jsonb_build_object('ok',false); END IF;
  ELSE RAISE EXCEPTION 'AUTH_INPUT_INVALID'; END IF;
  -- Account cooldown and issue-count survive process restart and multiple IPs.
  SELECT * INTO c FROM public.keeptimer_auth_challenges WHERE user_id=target AND purpose=p_data->>'purpose'
   ORDER BY created_at DESC LIMIT 1;
  IF FOUND AND c.last_sent_at>clock_timestamp()-interval '60 seconds' THEN RETURN jsonb_build_object('ok',false,'code','AUTH_RATE_LIMITED'); END IF;
  IF (SELECT count(*) FROM public.keeptimer_auth_challenges WHERE user_id=target AND created_at>clock_timestamp()-interval '15 minutes')>=5 THEN
   RETURN jsonb_build_object('ok',false,'code','AUTH_RATE_LIMITED'); END IF;
  UPDATE public.keeptimer_auth_challenges SET consumed_at=clock_timestamp() WHERE user_id=target AND purpose=p_data->>'purpose' AND consumed_at IS NULL;
  n:=clock_timestamp(); challenge:=(p_data->>'challenge_id')::uuid;
  INSERT INTO public.keeptimer_auth_challenges(id,user_id,purpose,context_digest,proof_digest,binding_digest,version,transport,created_at,expires_at,last_sent_at)
   VALUES(challenge,target,p_data->>'purpose',p_data->>'context_digest',p_data->>'proof_digest',p_data->>'binding_digest',a.version,transport,n,
    n+CASE WHEN p_data->>'purpose'='mfa' THEN interval '10 minutes' ELSE interval '30 minutes' END,n);
  RETURN jsonb_build_object('ok',true,'email',a.email,'challengeId',challenge,'retryAfter',60);
 END IF;
 IF p_action IN ('delivery','consume','resend','inspect') THEN
  SELECT * INTO c FROM public.keeptimer_auth_challenges WHERE id=challenge AND user_id=target FOR UPDATE;
  n:=clock_timestamp();
  IF NOT FOUND OR c.version<>a.version OR c.consumed_at IS NOT NULL OR c.expires_at<=n THEN RETURN jsonb_build_object('ok',false); END IF;
  IF p_action='delivery' THEN
   IF c.delivery<>'pending' OR c.proof_digest IS DISTINCT FROM p_data->>'proof_digest' THEN RETURN jsonb_build_object('ok',false); END IF;
   UPDATE public.keeptimer_auth_challenges SET delivery=CASE WHEN p_data->>'accepted'='true' THEN 'accepted' ELSE 'failed' END,
    consumed_at=CASE WHEN p_data->>'accepted'='true' THEN NULL ELSE n END WHERE id=challenge;
   RETURN jsonb_build_object('ok',p_data->>'accepted'='true');
  END IF;
  IF c.context_digest IS DISTINCT FROM p_data->>'context_digest' OR c.transport IS DISTINCT FROM transport OR
     c.purpose IS DISTINCT FROM p_data->>'purpose' THEN RETURN jsonb_build_object('ok',false); END IF;
  IF c.delivery<>'accepted' OR c.attempts>=5 THEN RETURN jsonb_build_object('ok',false); END IF;
  IF c.purpose='mfa' AND c.binding_digest IS DISTINCT FROM p_data->>'binding_digest' THEN RETURN jsonb_build_object('ok',false); END IF;
  IF c.purpose='mfa' AND (u.role NOT IN ('superadmin','agent') OR a.activated_at IS NULL OR u.must_change_password) THEN RETURN jsonb_build_object('ok',false); END IF;
  IF p_action='inspect' THEN RETURN jsonb_build_object('ok',true,'id',target); END IF;
  IF p_action='resend' THEN
   IF c.purpose<>'mfa' OR c.sends>=3 OR c.last_sent_at>n-interval '60 seconds' THEN RETURN jsonb_build_object('ok',false,'code','AUTH_RATE_LIMITED'); END IF;
   UPDATE public.keeptimer_auth_challenges SET proof_digest=p_data->>'proof_digest',delivery='pending',last_sent_at=n,sends=sends+1 WHERE id=challenge;
   RETURN jsonb_build_object('ok',true,'email',a.email,'retryAfter',60);
  END IF;
  UPDATE public.keeptimer_auth_challenges SET attempts=attempts+1 WHERE id=challenge;
  IF c.proof_digest IS DISTINCT FROM p_data->>'proof_digest' THEN RETURN jsonb_build_object('ok',false); END IF;
  IF c.purpose='reset' AND u.role<>'worker' THEN RETURN jsonb_build_object('ok',false); END IF;
  IF c.purpose IN ('activation','reset') THEN
   IF (c.purpose='activation' AND a.activated_at IS NOT NULL) OR (c.purpose='reset' AND a.activated_at IS NULL) THEN RETURN jsonb_build_object('ok',false); END IF;
   IF p_data->>'password_hash' IS NULL OR p_data->>'password_hash' !~ '^\$2[aby]\$12\$[./A-Za-z0-9]{53}$' THEN RAISE EXCEPTION 'AUTH_INPUT_INVALID'; END IF;
   UPDATE public.users SET password_hash=p_data->>'password_hash',must_change_password=false WHERE id=target;
   UPDATE public.keeptimer_auth_accounts SET verified_at=coalesce(verified_at,n),activated_at=coalesce(activated_at,n),version=version+1 WHERE user_id=target;
   UPDATE public.sessions SET revoked_at=n WHERE user_id=target AND revoked_at IS NULL;
   UPDATE public.keeptimer_auth_challenges SET consumed_at=n WHERE user_id=target AND consumed_at IS NULL;
   DELETE FROM public.keeptimer_privileged_web_sessions WHERE user_id=target;
   RETURN jsonb_build_object('ok',true,'loginReady',true,'userId',target);
  END IF;
  UPDATE public.keeptimer_auth_challenges SET consumed_at=n WHERE id=challenge;
  RETURN jsonb_build_object('ok',true,'user',public.keeptimer_auth_new_session(target,(p_data->>'session_id')::uuid,p_data->>'refresh_hash',transport));
 END IF;
 IF p_action='status' THEN RETURN jsonb_build_object('ok',true,'loginReady',a.verified_at IS NOT NULL AND a.activated_at IS NOT NULL AND NOT u.must_change_password); END IF;
 IF p_action IN ('sessions','revoke_sessions') THEN
  IF NOT public.keeptimer_auth_session(target,(p_data->>'session_id')::uuid,transport) THEN RETURN jsonb_build_object('ok',false); END IF;
  IF p_action='sessions' THEN RETURN jsonb_build_object('ok',true,'sessions',coalesce((SELECT jsonb_agg(jsonb_build_object(
   'id',s.id,'createdAt',s.created_at,'revoked',s.revoked_at IS NOT NULL,'expiresAt',q.expires_at) ORDER BY s.created_at DESC)
   FROM public.sessions s JOIN public.keeptimer_auth_sessions q ON q.session_id=s.id WHERE s.user_id=target),'[]'::jsonb)); END IF;
  UPDATE public.sessions SET revoked_at=clock_timestamp() WHERE user_id=target AND revoked_at IS NULL;
  DELETE FROM public.keeptimer_privileged_web_sessions WHERE user_id=target;
  UPDATE public.keeptimer_auth_challenges SET consumed_at=clock_timestamp() WHERE user_id=target AND consumed_at IS NULL;
  RETURN jsonb_build_object('ok',true);
 END IF;
 IF p_action='change' THEN
  IF NOT public.keeptimer_auth_session(target,(p_data->>'session_id')::uuid,transport) OR u.password_hash IS DISTINCT FROM p_data->>'expected_hash' THEN
   RETURN jsonb_build_object('ok',false); END IF;
  IF p_data->>'password_hash' IS NULL OR p_data->>'password_hash' !~ '^\$2[aby]\$12\$[./A-Za-z0-9]{53}$' THEN RAISE EXCEPTION 'AUTH_INPUT_INVALID'; END IF;
  UPDATE public.users SET password_hash=p_data->>'password_hash',must_change_password=false WHERE id=target;
  UPDATE public.keeptimer_auth_accounts SET version=version+1 WHERE user_id=target;
  UPDATE public.sessions SET revoked_at=clock_timestamp() WHERE user_id=target AND revoked_at IS NULL;
  UPDATE public.keeptimer_auth_challenges SET consumed_at=clock_timestamp() WHERE user_id=target AND consumed_at IS NULL;
  DELETE FROM public.keeptimer_privileged_web_sessions WHERE user_id=target;
  RETURN jsonb_build_object('ok',true);
 END IF;
 RAISE EXCEPTION 'AUTH_INPUT_INVALID';
END; $$;

-- Trusted owner enrollment, never service_role/browser: no automatic migration.
-- Supply an unknown random bcrypt12 placeholder; user chooses password by link.
CREATE FUNCTION public.keeptimer_auth_prepare(p_user uuid,p_email text,p_placeholder text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path='' AS $$ DECLARE u record; BEGIN
 IF NOT EXISTS(SELECT 1 FROM public.keeptimer_auth_release WHERE cutover) THEN RAISE EXCEPTION 'AUTH_NOT_READY'; END IF;
 SELECT * INTO u FROM public.users WHERE id=p_user FOR UPDATE;
 IF NOT FOUND OR u.role NOT IN ('superadmin','agent','worker') OR u.disabled_at IS NOT NULL OR
  EXISTS(SELECT 1 FROM public.keeptimer_auth_accounts WHERE user_id=p_user) OR
  p_placeholder IS NULL OR p_placeholder !~ '^\$2[aby]\$12\$[./A-Za-z0-9]{53}$' THEN RAISE EXCEPTION 'AUTH_INPUT_INVALID'; END IF;
 IF u.role='worker' AND (u.credential_kind<>'password' OR NOT public.keeptimer_auth_shape(p_user)) THEN RAISE EXCEPTION 'AUTH_INVALID'; END IF;
 UPDATE public.users SET credential_kind='password',pin_hash=NULL,password_hash=p_placeholder,must_change_password=true,
  mfa_email=CASE WHEN role IN ('agent','superadmin') THEN p_email ELSE mfa_email END WHERE id=p_user;
 IF EXISTS(SELECT 1 FROM public.users WHERE id<>p_user AND lower(btrim(mfa_email))=p_email) THEN RAISE EXCEPTION 'AUTH_INPUT_INVALID'; END IF;
 INSERT INTO public.keeptimer_auth_accounts(user_id,email) VALUES(p_user,p_email);
 UPDATE public.sessions SET revoked_at=clock_timestamp() WHERE user_id=p_user AND revoked_at IS NULL;
 DELETE FROM public.keeptimer_privileged_web_sessions WHERE user_id=p_user;
END; $$;

-- Owner-created case AFTER independent identity verification. session_user is
-- the authenticated database login, not an HTTP actor or the function definer.
CREATE TABLE public.keeptimer_auth_recovery_cases(
 id uuid PRIMARY KEY, target_user_id uuid NOT NULL REFERENCES public.users(id),
 operator_login name NOT NULL, reason text NOT NULL CHECK(length(reason) BETWEEN 10 AND 500),
 evidence_ref text NOT NULL CHECK(length(evidence_ref) BETWEEN 8 AND 200),
 verified_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 expires_at timestamptz NOT NULL CHECK(expires_at>verified_at AND expires_at<=verified_at+interval '1 day'),
 used_at timestamptz
);
CREATE TABLE public.keeptimer_auth_recovery_audit(
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), case_id uuid NOT NULL UNIQUE REFERENCES public.keeptimer_auth_recovery_cases(id),
 target_user_id uuid NOT NULL REFERENCES public.users(id), operator_login name NOT NULL, executing_owner name NOT NULL,
 reason text NOT NULL, evidence_ref text NOT NULL, occurred_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
ALTER TABLE public.keeptimer_auth_recovery_cases ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.keeptimer_auth_recovery_audit ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.keeptimer_auth_recovery_cases,public.keeptimer_auth_recovery_audit FROM PUBLIC,anon,authenticated,service_role;
CREATE FUNCTION public.keeptimer_auth_recover_privileged(p_user uuid,p_placeholder text,p_case uuid) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path='' AS $$ DECLARE u record; c record; BEGIN
 IF NOT EXISTS(SELECT 1 FROM public.keeptimer_auth_release WHERE cutover) THEN RAISE EXCEPTION 'AUTH_NOT_READY'; END IF;
 IF session_user::text IN ('anon','authenticated','service_role','authenticator') THEN RAISE EXCEPTION 'AUTH_FORBIDDEN'; END IF;
 SELECT * INTO u FROM public.users WHERE id=p_user FOR UPDATE;
 IF NOT FOUND OR u.role NOT IN ('superadmin','agent') OR u.disabled_at IS NOT NULL OR
  p_placeholder IS NULL OR p_placeholder !~ '^\$2[aby]\$12\$[./A-Za-z0-9]{53}$' OR
  NOT EXISTS(SELECT 1 FROM public.keeptimer_auth_accounts WHERE user_id=p_user) THEN RAISE EXCEPTION 'AUTH_INVALID'; END IF;
 SELECT * INTO c FROM public.keeptimer_auth_recovery_cases WHERE id=p_case FOR UPDATE;
 IF NOT FOUND OR c.target_user_id<>p_user OR c.operator_login<>session_user OR c.used_at IS NOT NULL OR
  c.verified_at>clock_timestamp() OR c.expires_at<=clock_timestamp() THEN RAISE EXCEPTION 'AUTH_FORBIDDEN'; END IF;
 UPDATE public.users SET password_hash=p_placeholder,must_change_password=true WHERE id=p_user;
 UPDATE public.keeptimer_auth_accounts SET version=version+1,verified_at=NULL,activated_at=NULL WHERE user_id=p_user;
 UPDATE public.sessions SET revoked_at=clock_timestamp() WHERE user_id=p_user AND revoked_at IS NULL;
 UPDATE public.keeptimer_auth_challenges SET consumed_at=clock_timestamp() WHERE user_id=p_user AND consumed_at IS NULL;
 DELETE FROM public.keeptimer_privileged_web_sessions WHERE user_id=p_user;
 INSERT INTO public.keeptimer_auth_recovery_audit(case_id,target_user_id,operator_login,executing_owner,reason,evidence_ref)
 VALUES(p_case,p_user,session_user,current_user,c.reason,c.evidence_ref);
 UPDATE public.keeptimer_auth_recovery_cases SET used_at=clock_timestamp() WHERE id=p_case;
END; $$;
REVOKE ALL ON FUNCTION public.keeptimer_auth_recover_privileged(uuid,text,uuid) FROM PUBLIC,anon,authenticated,service_role;

REVOKE ALL ON FUNCTION public.keeptimer_auth_ready_gate(),public.keeptimer_auth_shape(uuid),public.keeptimer_auth_new_session(uuid,uuid,text,text),
 public.keeptimer_auth_prepare(uuid,text,text),
 public.keeptimer_auth_limit(text,text,text),public.keeptimer_auth_session(uuid,uuid,text,text),public.keeptimer_auth_command(text,jsonb) FROM PUBLIC,anon,authenticated,service_role;
GRANT EXECUTE ON FUNCTION public.keeptimer_auth_limit(text,text,text),public.keeptimer_auth_session(uuid,uuid,text,text),public.keeptimer_auth_command(text,jsonb) TO service_role;

-- Bounded, private queue: enqueue NEVER looks up account readiness/existence.
-- No raw OTP/link/password is persisted. Email is private PII, as in accounts.
CREATE TABLE public.keeptimer_auth_link_queue(
 id uuid PRIMARY KEY, email text NOT NULL CHECK(length(email) BETWEEN 3 AND 254),
 purpose text NOT NULL CHECK(purpose IN ('activation','reset')),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 expires_at timestamptz NOT NULL DEFAULT clock_timestamp()+interval '15 minutes',
 lease_id uuid, lease_until timestamptz
);
CREATE INDEX keeptimer_auth_queue_expiry ON public.keeptimer_auth_link_queue(expires_at,id);
CREATE INDEX keeptimer_auth_queue_claim ON public.keeptimer_auth_link_queue(created_at,id);
ALTER TABLE public.keeptimer_auth_link_queue ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.keeptimer_auth_link_queue FROM PUBLIC,anon,authenticated,service_role;
CREATE FUNCTION public.keeptimer_auth_link_queue_rpc(p_action text,p_data jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path='' AS $$ DECLARE job record; lease uuid; BEGIN
 PERFORM public.keeptimer_auth_ready_gate();
 IF p_action='enqueue' THEN
  IF p_data->>'purpose' NOT IN ('activation','reset') OR p_data->>'purpose' IS NULL OR
   p_data->>'email' IS NULL OR length(p_data->>'email') NOT BETWEEN 3 AND 254 THEN RAISE EXCEPTION 'AUTH_INPUT_INVALID'; END IF;
  -- Serialize capacity checks only, not account lookups or delivery. A busy/full
  -- global queue is the same 503 for all account states. No per-account FK/index.
  IF NOT pg_catalog.pg_try_advisory_xact_lock(7107,1) THEN RAISE EXCEPTION 'AUTH_UNAVAILABLE'; END IF;
  IF (SELECT count(*) FROM public.keeptimer_auth_link_queue)>=200 THEN RAISE EXCEPTION 'AUTH_UNAVAILABLE'; END IF;
  INSERT INTO public.keeptimer_auth_link_queue(id,email,purpose) VALUES((p_data->>'id')::uuid,p_data->>'email',p_data->>'purpose');
  RETURN jsonb_build_object('ok',true);
 ELSIF p_action='claim' THEN
  SELECT * INTO job FROM public.keeptimer_auth_link_queue WHERE expires_at>clock_timestamp()
   AND (lease_until IS NULL OR lease_until<=clock_timestamp()) ORDER BY created_at,id LIMIT 1 FOR UPDATE SKIP LOCKED;
  IF NOT FOUND THEN RETURN NULL; END IF;
  lease:=gen_random_uuid();
  UPDATE public.keeptimer_auth_link_queue SET lease_id=lease,lease_until=clock_timestamp()+interval '60 seconds' WHERE id=job.id;
  RETURN jsonb_build_object('id',job.id,'lease',lease,'email',job.email,'purpose',job.purpose);
 ELSIF p_action='done' THEN
  DELETE FROM public.keeptimer_auth_link_queue WHERE id=(p_data->>'id')::uuid AND lease_id=(p_data->>'lease')::uuid;
  RETURN jsonb_build_object('ok',true);
 END IF;
 RAISE EXCEPTION 'AUTH_INPUT_INVALID';
END; $$;
-- Fixed 64-row indexed batches, separate from auth transactions. SKIP LOCKED
-- never steals a live challenge/counter lock. Counters retained >=24h, well
-- beyond their 15m window; every challenge retained 7d AFTER expiration.
CREATE FUNCTION public.keeptimer_auth_maintain() RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path='' AS $$
DECLARE limits_n integer; challenges_n integer; queue_n integer;
 n timestamptz:=clock_timestamp(); limits_before timestamptz:=n-interval '24 hours'; challenges_before timestamptz:=n-interval '7 days';
BEGIN
 IF NOT pg_catalog.pg_try_advisory_xact_lock(7107,2) THEN RETURN jsonb_build_object('busy',true); END IF;
 -- Capture the volatile clock once: parameter cutoffs permit index range scans.
 WITH expired AS (SELECT key FROM public.keeptimer_auth_limits WHERE started_at<limits_before
  ORDER BY started_at,key LIMIT 64 FOR UPDATE SKIP LOCKED)
 DELETE FROM public.keeptimer_auth_limits r USING expired e WHERE r.key=e.key AND r.started_at<limits_before;
 GET DIAGNOSTICS limits_n=ROW_COUNT;
 WITH expired AS (SELECT id FROM public.keeptimer_auth_challenges WHERE expires_at<challenges_before
  ORDER BY expires_at,id LIMIT 64 FOR UPDATE SKIP LOCKED)
 DELETE FROM public.keeptimer_auth_challenges c USING expired e WHERE c.id=e.id AND c.expires_at<challenges_before;
 GET DIAGNOSTICS challenges_n=ROW_COUNT;
 WITH expired AS (SELECT id FROM public.keeptimer_auth_link_queue WHERE expires_at<=n
  AND (lease_until IS NULL OR lease_until<n) ORDER BY expires_at,id LIMIT 64 FOR UPDATE SKIP LOCKED)
 DELETE FROM public.keeptimer_auth_link_queue q USING expired e WHERE q.id=e.id;
 GET DIAGNOSTICS queue_n=ROW_COUNT;
 RETURN jsonb_build_object('limits',limits_n,'challenges',challenges_n,'queue',queue_n);
END; $$;
REVOKE ALL ON FUNCTION public.keeptimer_auth_link_queue_rpc(text,jsonb),public.keeptimer_auth_maintain() FROM PUBLIC,anon,authenticated,service_role;
GRANT EXECUTE ON FUNCTION public.keeptimer_auth_link_queue_rpc(text,jsonb),public.keeptimer_auth_maintain() TO service_role;
NOTIFY pgrst, 'reload schema';
COMMIT;
