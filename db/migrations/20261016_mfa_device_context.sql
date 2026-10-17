-- Additive preparation only. Run ONCE as the verified existing owner, before cutover.
-- Does not enable auth/sales, execute cutover, alter PINs, or rewrite older migrations.
BEGIN;
SET LOCAL lock_timeout='5s';
SELECT public.keeptimer_auth_assert_owner();
DO $$ BEGIN
 -- Hold both gate rows until COMMIT: an operator cannot race preparation by
 -- opening a gate between the preflight read and function installation.
 PERFORM 1 FROM public.keeptimer_auth_release FOR UPDATE;
 PERFORM 1 FROM public.keeptimer_sales_release FOR UPDATE;
 IF EXISTS(SELECT 1 FROM public.keeptimer_auth_release WHERE enabled OR cutover)
 OR EXISTS(SELECT 1 FROM public.keeptimer_sales_release WHERE enabled) THEN
  RAISE EXCEPTION 'MFA_PREPARATION_REQUIRES_CLOSED_GATES';
 END IF;
END; $$;
CREATE TABLE public.keeptimer_mfa_contexts (
 id text PRIMARY KEY CHECK(id ~ '^[a-f0-9]{64}$'),
 device_digest text NOT NULL CHECK(device_digest ~ '^[a-f0-9]{64}$'),
 user_id uuid NOT NULL REFERENCES public.users(id), version bigint NOT NULL,
 binding_digest text NOT NULL CHECK(binding_digest ~ '^[a-f0-9]{64}$'),
 verified_at timestamptz NOT NULL, locked_until timestamptz, risk_until timestamptz,
 attempts integer NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 6),
 current_challenge uuid, trusted_at timestamptz, revocation_version bigint NOT NULL DEFAULT 0,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(), updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(device_digest,user_id)
);
CREATE TABLE public.keeptimer_mfa_challenges (
 id uuid PRIMARY KEY, context_id text NOT NULL REFERENCES public.keeptimer_mfa_contexts(id) ON DELETE RESTRICT,
 created_at timestamptz NOT NULL, expires_at timestamptz NOT NULL,
 consumed_at timestamptz, current_send uuid NOT NULL,
 proof_digest text NOT NULL CHECK(proof_digest ~ '^[a-f0-9]{64}$')
);
CREATE TABLE public.keeptimer_mfa_sends (
 id uuid PRIMARY KEY, context_id text NOT NULL REFERENCES public.keeptimer_mfa_contexts(id) ON DELETE RESTRICT,
 challenge_id uuid NOT NULL REFERENCES public.keeptimer_mfa_challenges(id) ON DELETE RESTRICT,
 action text NOT NULL CHECK(action IN ('start','resend')), created_at timestamptz NOT NULL,
 -- Random server nonce permits a domain-separated keyed PRF to reconstruct the
 -- SAME OTP after a process crash; no plaintext code or token is stored.
 nonce text NOT NULL CHECK(nonce ~ '^[a-f0-9]{64}$'), expires_at timestamptz NOT NULL,
 delivery text NOT NULL DEFAULT 'pending' CHECK(delivery IN ('pending','accepted','rejected','unknown')),
 lease uuid, lease_until timestamptz
);
CREATE INDEX keeptimer_mfa_challenge_retention ON public.keeptimer_mfa_challenges(expires_at);
CREATE INDEX keeptimer_mfa_challenge_context ON public.keeptimer_mfa_challenges(context_id,expires_at);
CREATE INDEX keeptimer_mfa_sends_window ON public.keeptimer_mfa_sends(context_id,created_at);
CREATE INDEX keeptimer_mfa_contexts_user ON public.keeptimer_mfa_contexts(user_id);
CREATE INDEX keeptimer_mfa_contexts_retention ON public.keeptimer_mfa_contexts(updated_at);
CREATE TABLE public.keeptimer_mfa_verifications (
 id uuid PRIMARY KEY, context_id text NOT NULL REFERENCES public.keeptimer_mfa_contexts(id) ON DELETE RESTRICT,
 challenge_id uuid NOT NULL REFERENCES public.keeptimer_mfa_challenges(id) ON DELETE RESTRICT,
 proof_digest text NOT NULL, result jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX keeptimer_mfa_sends_challenge ON public.keeptimer_mfa_sends(challenge_id,id);
CREATE INDEX keeptimer_mfa_verifications_challenge ON public.keeptimer_mfa_verifications(challenge_id,id);
CREATE INDEX keeptimer_mfa_verifications_context ON public.keeptimer_mfa_verifications(context_id);
CREATE TABLE public.keeptimer_mfa_risk_audit (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, user_id uuid NOT NULL REFERENCES public.users(id),
 context_id text NOT NULL, event text NOT NULL CHECK(event IN ('device_locked','unfamiliar_context_delay')),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX keeptimer_mfa_audit_retention ON public.keeptimer_mfa_risk_audit(created_at);
ALTER TABLE public.keeptimer_mfa_contexts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.keeptimer_mfa_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.keeptimer_mfa_sends ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.keeptimer_mfa_verifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.keeptimer_mfa_risk_audit ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.keeptimer_mfa_contexts,public.keeptimer_mfa_challenges,public.keeptimer_mfa_sends,
 public.keeptimer_mfa_verifications,public.keeptimer_mfa_risk_audit FROM PUBLIC,anon,authenticated,service_role;
REVOKE ALL ON SEQUENCE public.keeptimer_mfa_risk_audit_id_seq FROM PUBLIC,anon,authenticated,service_role;

-- One persistent generation per user; deliberately no parent FK. Session-row
-- revocation must NOT acquire user/account/context locks in reverse order.
CREATE TABLE public.keeptimer_mfa_revocations(user_id uuid PRIMARY KEY, version bigint NOT NULL);
ALTER TABLE public.keeptimer_mfa_revocations ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.keeptimer_mfa_revocations FROM PUBLIC,anon,authenticated,service_role;
CREATE FUNCTION public.keeptimer_mfa_session_revoked() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path='' AS $$ BEGIN
 IF (TG_OP='DELETE' AND OLD.revoked_at IS NULL) OR
    (TG_OP='UPDATE' AND OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL) THEN
  INSERT INTO public.keeptimer_mfa_revocations VALUES(OLD.user_id,1)
   ON CONFLICT(user_id) DO UPDATE SET version=keeptimer_mfa_revocations.version+1;
 END IF;
 IF TG_OP='DELETE' THEN RETURN OLD; END IF; RETURN NEW;
END; $$;
CREATE TRIGGER keeptimer_mfa_session_revoked AFTER UPDATE OF revoked_at OR DELETE ON public.sessions
 FOR EACH ROW EXECUTE FUNCTION public.keeptimer_mfa_session_revoked();
REVOKE ALL ON FUNCTION public.keeptimer_mfa_session_revoked() FROM PUBLIC,anon,authenticated,service_role;
-- Callers already own the user or account row. Never acquire it from a child.
CREATE FUNCTION public.keeptimer_mfa_invalidate(p_user uuid) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path='' AS $$ DECLARE d record; BEGIN
 FOR d IN SELECT id FROM public.keeptimer_mfa_contexts WHERE user_id=p_user ORDER BY id FOR UPDATE LOOP
  UPDATE public.keeptimer_mfa_contexts SET verified_at='epoch',updated_at=clock_timestamp() WHERE id=d.id;
  UPDATE public.keeptimer_mfa_challenges SET consumed_at=clock_timestamp() WHERE context_id=d.id AND consumed_at IS NULL;
 END LOOP;
END; $$;
REVOKE ALL ON FUNCTION public.keeptimer_mfa_invalidate(uuid) FROM PUBLIC,anon,authenticated,service_role;
CREATE FUNCTION public.keeptimer_mfa_identity_changed() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path='' AS $$ BEGIN
 IF TG_TABLE_NAME='users' THEN
  IF ROW(OLD.password_hash,OLD.credential_kind,OLD.must_change_password,OLD.disabled_at,OLD.role)
   IS DISTINCT FROM ROW(NEW.password_hash,NEW.credential_kind,NEW.must_change_password,NEW.disabled_at,NEW.role) THEN
   PERFORM public.keeptimer_mfa_invalidate(NEW.id);
  END IF;
 ELSE
  IF ROW(OLD.version,OLD.email,OLD.verified_at,OLD.activated_at) IS DISTINCT FROM ROW(NEW.version,NEW.email,NEW.verified_at,NEW.activated_at) THEN
   PERFORM public.keeptimer_mfa_invalidate(NEW.user_id);
  END IF;
 END IF;
 RETURN NEW;
END; $$;
CREATE TRIGGER keeptimer_mfa_identity_changed AFTER UPDATE ON public.users
 FOR EACH ROW EXECUTE FUNCTION public.keeptimer_mfa_identity_changed();
CREATE TRIGGER keeptimer_mfa_identity_changed AFTER UPDATE ON public.keeptimer_auth_accounts
 FOR EACH ROW EXECUTE FUNCTION public.keeptimer_mfa_identity_changed();
REVOKE ALL ON FUNCTION public.keeptimer_mfa_identity_changed() FROM PUBLIC,anon,authenticated,service_role;

-- Disable the legacy MFA entry points, preserving activation/reset/Individual
-- and management contracts byte-for-byte in the former implementation.
ALTER FUNCTION public.keeptimer_auth_command(text,jsonb) RENAME TO keeptimer_auth_command_pre_device;
REVOKE ALL ON FUNCTION public.keeptimer_auth_command_pre_device(text,jsonb) FROM PUBLIC,anon,authenticated,service_role;
CREATE FUNCTION public.keeptimer_auth_command(p_action text,p_data jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path='' AS $$ DECLARE result jsonb; BEGIN
 IF p_data->>'purpose'='mfa' OR (p_action IN ('inspect','delivery','consume','resend') AND EXISTS(
  SELECT 1 FROM public.keeptimer_auth_challenges WHERE id=(p_data->>'challenge_id')::uuid AND purpose='mfa')) THEN
  RAISE EXCEPTION 'AUTH_NOT_READY';
 END IF;
 result:=public.keeptimer_auth_command_pre_device(p_action,p_data);
 IF p_action='revoke_sessions' AND result->>'ok'='true' THEN
  PERFORM public.keeptimer_mfa_invalidate((p_data->>'user_id')::uuid);
 END IF;
 RETURN result;
END; $$;
REVOKE ALL ON FUNCTION public.keeptimer_auth_command(text,jsonb) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.keeptimer_auth_command(text,jsonb) TO service_role;

ALTER FUNCTION public.keeptimer_auth_management(uuid,uuid,text,jsonb) RENAME TO keeptimer_auth_management_pre_device;
REVOKE ALL ON FUNCTION public.keeptimer_auth_management_pre_device(uuid,uuid,text,jsonb) FROM PUBLIC,anon,authenticated,service_role;
CREATE FUNCTION public.keeptimer_auth_management(p_actor uuid,p_session uuid,p_action text,p_data jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path='' AS $$ DECLARE result jsonb; BEGIN
 result:=public.keeptimer_auth_management_pre_device(p_actor,p_session,p_action,p_data);
 IF p_action IN ('force_logout','user_disable') AND result->>'success'='true' THEN
  PERFORM public.keeptimer_mfa_invalidate((p_data->>'id')::uuid);
  -- Include any new invalidation lock waits in the final actor/MFA check.
  PERFORM public.keeptimer_auth_require_admin(p_actor,p_session);
 END IF;
 RETURN result;
END; $$;
REVOKE ALL ON FUNCTION public.keeptimer_auth_management(uuid,uuid,text,jsonb) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.keeptimer_auth_management(uuid,uuid,text,jsonb) TO service_role;

CREATE FUNCTION public.keeptimer_mfa_state(p_context text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path='' AS $$
DECLARE d record; c record; s record; n timestamptz:=clock_timestamp(); quota timestamptz; last_send timestamptz; phase text;
BEGIN
 SELECT * INTO d FROM public.keeptimer_mfa_contexts WHERE id=p_context;
 IF NOT FOUND THEN RETURN jsonb_build_object('phase','idle','serverNow',n); END IF;
 SELECT * INTO c FROM public.keeptimer_mfa_challenges WHERE id=d.current_challenge;
 SELECT * INTO s FROM public.keeptimer_mfa_sends WHERE id=c.current_send;
 SELECT max(created_at) INTO last_send FROM public.keeptimer_mfa_sends WHERE context_id=d.id;
 SELECT CASE WHEN count(*)>=3 THEN min(created_at)+interval '15 minutes' END INTO quota
  FROM public.keeptimer_mfa_sends WHERE context_id=d.id AND delivery<>'rejected' AND created_at>n-interval '15 minutes';
 phase:=CASE WHEN d.locked_until>n THEN 'locked' WHEN d.risk_until>n THEN 'risk_wait'
  WHEN c.id IS NULL THEN 'idle' WHEN c.consumed_at IS NOT NULL THEN 'consumed'
  WHEN c.expires_at<=n THEN 'expired' ELSE 'challenge' END;
 RETURN jsonb_build_object('phase',phase,'serverNow',n,'challengeId',c.id,'expiresAt',c.expires_at,
  'resendAvailableAt',last_send+interval '60 seconds','sendLimitAvailableAt',quota,'lockedUntil',d.locked_until,
  'riskUntil',d.risk_until,'attemptsRemaining',greatest(0,6-d.attempts),'delivery',s.delivery);
END; $$;
REVOKE ALL ON FUNCTION public.keeptimer_mfa_state(text) FROM PUBLIC,anon,authenticated,service_role;

CREATE FUNCTION public.keeptimer_mfa_command(p_action text,p_data jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path='' AS $$
DECLARE d record; u record; a record; c record; s record; v record; target uuid; ctx text:=p_data->>'context_id';
 n timestamptz; operation uuid; challenge uuid; last_send timestamptz; outcome jsonb; code text; new_user jsonb;
BEGIN
 PERFORM public.keeptimer_auth_ready_gate();
 IF jsonb_typeof(p_data) IS DISTINCT FROM 'object' OR ctx IS NULL OR ctx !~ '^[a-f0-9]{64}$'
 OR p_data->>'device_digest' IS NULL OR p_data->>'binding_digest' IS NULL THEN RAISE EXCEPTION 'AUTH_INPUT_INVALID'; END IF;
 IF p_action='start' THEN target:=(p_data->>'user_id')::uuid;
 ELSE SELECT user_id INTO target FROM public.keeptimer_mfa_contexts WHERE id=ctx; END IF;
 -- All account changes and MFA transactions use user -> account -> context -> challenge.
 SELECT * INTO u FROM public.users WHERE id=target FOR UPDATE;
 SELECT * INTO a FROM public.keeptimer_auth_accounts WHERE user_id=target FOR UPDATE;
 IF u.id IS NULL OR a.user_id IS NULL OR u.disabled_at IS NOT NULL OR u.must_change_password
 OR u.credential_kind<>'password' OR u.role NOT IN ('superadmin','agent') OR a.activated_at IS NULL OR a.verified_at IS NULL THEN
  RETURN jsonb_build_object('ok',false,'code','MFA_CHALLENGE_INVALID');
 END IF;
 IF p_action='start' AND u.password_hash IS DISTINCT FROM p_data->>'expected_hash' THEN
  RETURN jsonb_build_object('ok',false,'code','MFA_CHALLENGE_INVALID'); END IF;
 n:=clock_timestamp();
 IF p_action='start' THEN
  INSERT INTO public.keeptimer_mfa_contexts(id,device_digest,user_id,version,binding_digest,verified_at)
   VALUES(ctx,p_data->>'device_digest',target,a.version,p_data->>'binding_digest',n) ON CONFLICT(id) DO NOTHING;
 END IF;
 SELECT * INTO d FROM public.keeptimer_mfa_contexts WHERE id=ctx FOR UPDATE;
 IF NOT FOUND OR d.user_id<>target OR d.device_digest IS DISTINCT FROM p_data->>'device_digest' THEN
  RETURN jsonb_build_object('ok',false,'code','MFA_CHALLENGE_INVALID'); END IF;
 n:=clock_timestamp();
 IF p_action<>'start' AND (d.binding_digest IS DISTINCT FROM p_data->>'binding_digest' OR d.version<>a.version OR d.revocation_version<>coalesce((SELECT version FROM public.keeptimer_mfa_revocations WHERE user_id=target),0) OR d.verified_at<=n-interval '15 minutes') THEN
  RETURN jsonb_build_object('ok',false,'code','MFA_CHALLENGE_INVALID'); END IF;
 IF d.locked_until>n THEN RETURN jsonb_build_object('ok',false,'code','MFA_DEVICE_LOCKED','state',public.keeptimer_mfa_state(ctx)); END IF;
 IF d.locked_until IS NOT NULL THEN
  UPDATE public.keeptimer_mfa_contexts SET locked_until=NULL,attempts=0 WHERE id=ctx;d.attempts:=0;
 END IF;
 IF p_action='start' THEN
  IF d.binding_digest IS DISTINCT FROM p_data->>'binding_digest' OR d.version<>a.version OR
   d.revocation_version<>coalesce((SELECT version FROM public.keeptimer_mfa_revocations WHERE user_id=target),0) THEN
   UPDATE public.keeptimer_mfa_challenges SET consumed_at=n WHERE context_id=ctx AND consumed_at IS NULL;
  END IF;
  UPDATE public.keeptimer_mfa_contexts SET binding_digest=p_data->>'binding_digest',version=a.version,verified_at=n,updated_at=n,
   revocation_version=coalesce((SELECT version FROM public.keeptimer_mfa_revocations WHERE user_id=target),0) WHERE id=ctx;
  -- No account-wide MFA lock/quota: only a new unfamiliar context waits once.
  -- Existing proven contexts and another context's attempts are not locked.
  IF d.current_challenge IS NULL AND d.risk_until IS NULL AND d.trusted_at IS NULL AND
    (SELECT count(*) FROM public.keeptimer_mfa_sends x JOIN public.keeptimer_mfa_contexts y ON y.id=x.context_id
      WHERE y.user_id=target AND x.created_at>n-interval '15 minutes')>=6 THEN
   UPDATE public.keeptimer_mfa_contexts SET risk_until=n+interval '60 seconds' WHERE id=ctx;
   d.risk_until:=n+interval '60 seconds';
   INSERT INTO public.keeptimer_mfa_risk_audit(user_id,context_id,event) VALUES(target,ctx,'unfamiliar_context_delay');
  END IF;
 END IF;
 IF d.risk_until>n THEN RETURN jsonb_build_object('ok',false,'code','MFA_RESEND_COOLDOWN','state',public.keeptimer_mfa_state(ctx)); END IF;
 SELECT * INTO c FROM public.keeptimer_mfa_challenges WHERE id=d.current_challenge FOR UPDATE;
 n:=clock_timestamp();
 IF p_action='status' THEN RETURN jsonb_build_object('ok',true,'id',target,'state',public.keeptimer_mfa_state(ctx)); END IF;
 IF p_action IN ('start','resend') THEN
  operation:=(p_data->>'operation_id')::uuid;
  IF operation IS NULL THEN RAISE EXCEPTION 'AUTH_INPUT_INVALID'; END IF;
  SELECT * INTO s FROM public.keeptimer_mfa_sends WHERE id=operation;
  IF FOUND THEN
   IF s.context_id<>ctx OR s.action<>p_action OR (p_action='resend' AND s.challenge_id IS DISTINCT FROM (p_data->>'challenge_id')::uuid) THEN
    RETURN jsonb_build_object('ok',false,'code','MFA_CHALLENGE_INVALID'); END IF;
   RETURN jsonb_build_object('ok',true,'state',public.keeptimer_mfa_state(ctx));
  END IF;
  IF p_action='start' AND c.id IS NOT NULL AND c.consumed_at IS NULL AND c.expires_at>n THEN
   RETURN jsonb_build_object('ok',true,'state',public.keeptimer_mfa_state(ctx)); END IF;
  IF p_action='resend' AND (c.id IS NULL OR c.id IS DISTINCT FROM (p_data->>'challenge_id')::uuid OR c.consumed_at IS NOT NULL) THEN
   RETURN jsonb_build_object('ok',false,'code','MFA_CHALLENGE_INVALID'); END IF;
  IF p_action='resend' AND c.expires_at<=n THEN RETURN jsonb_build_object('ok',false,'code','MFA_CODE_EXPIRED','state',public.keeptimer_mfa_state(ctx)); END IF;
  SELECT max(created_at) INTO last_send FROM public.keeptimer_mfa_sends WHERE context_id=ctx;
  IF last_send>n-interval '60 seconds' THEN RETURN jsonb_build_object('ok',false,'code','MFA_RESEND_COOLDOWN','state',public.keeptimer_mfa_state(ctx)); END IF;
  IF (SELECT count(*) FROM public.keeptimer_mfa_sends WHERE context_id=ctx AND delivery<>'rejected' AND created_at>n-interval '15 minutes')>=3 THEN
   RETURN jsonb_build_object('ok',false,'code','MFA_SEND_LIMIT_REACHED','state',public.keeptimer_mfa_state(ctx)); END IF;
  -- Even a rare 8-digit random collision must not keep the previous OTP valid.
  -- No send/quota/expiry mutation occurs; a retry generates a fresh server nonce.
  IF p_action='resend' AND c.proof_digest IS NOT DISTINCT FROM p_data->>'proof_digest' THEN RAISE EXCEPTION 'AUTH_UNAVAILABLE'; END IF;
  challenge:=CASE WHEN p_action='start' THEN (p_data->>'new_challenge_id')::uuid ELSE c.id END;
  IF p_action='start' THEN
   INSERT INTO public.keeptimer_mfa_challenges(id,context_id,created_at,expires_at,current_send,proof_digest)
    VALUES(challenge,ctx,n,n+interval '120 seconds',operation,p_data->>'proof_digest');
   UPDATE public.keeptimer_mfa_contexts SET current_challenge=challenge WHERE id=ctx;
  ELSE
   -- The context+challenge locks make cooldown and the +30 atomic.
   UPDATE public.keeptimer_mfa_challenges SET expires_at=expires_at+interval '30 seconds',current_send=operation,
    proof_digest=p_data->>'proof_digest' WHERE id=challenge;
  END IF;
  INSERT INTO public.keeptimer_mfa_sends(id,context_id,challenge_id,action,created_at,nonce,expires_at)
   SELECT operation,ctx,challenge,p_action,n,p_data->>'nonce',expires_at FROM public.keeptimer_mfa_challenges WHERE id=challenge;
  UPDATE public.keeptimer_mfa_contexts SET updated_at=n WHERE id=ctx;
  IF p_action='resend' AND c.expires_at<=clock_timestamp() THEN RAISE EXCEPTION 'MFA_CODE_EXPIRED'; END IF;
  RETURN jsonb_build_object('ok',true,'state',public.keeptimer_mfa_state(ctx));
 END IF;
 IF c.id IS NULL OR c.consumed_at IS NOT NULL OR c.id IS DISTINCT FROM (p_data->>'challenge_id')::uuid THEN
  RETURN jsonb_build_object('ok',false,'code','MFA_CHALLENGE_INVALID'); END IF;
 n:=clock_timestamp();
 IF c.expires_at<=n THEN RETURN jsonb_build_object('ok',false,'code','MFA_CODE_EXPIRED','state',public.keeptimer_mfa_state(ctx)); END IF;
 SELECT * INTO s FROM public.keeptimer_mfa_sends WHERE id=c.current_send FOR UPDATE;
 n:=clock_timestamp();
 IF c.expires_at<=n THEN RETURN jsonb_build_object('ok',false,'code','MFA_CODE_EXPIRED','state',public.keeptimer_mfa_state(ctx)); END IF;
 IF p_action='claim' THEN
  IF s.delivery NOT IN ('pending','unknown') OR s.lease_until>n THEN RETURN jsonb_build_object('ok',true); END IF;
  UPDATE public.keeptimer_mfa_sends SET lease=gen_random_uuid(),lease_until=n+interval '20 seconds' WHERE id=s.id RETURNING * INTO s;
  RETURN jsonb_build_object('ok',true,'job',jsonb_build_object('id',s.id,'challengeId',c.id,'nonce',s.nonce,'lease',s.lease,'email',a.email,'expiresAt',s.expires_at));
 END IF;
 IF p_action='delivery' THEN
  IF s.id IS DISTINCT FROM (p_data->>'operation_id')::uuid OR s.lease IS DISTINCT FROM (p_data->>'lease')::uuid THEN
   RETURN jsonb_build_object('ok',false,'code','MFA_CHALLENGE_INVALID'); END IF;
  IF p_data->>'delivery' NOT IN ('accepted','rejected','unknown') OR p_data->>'delivery' IS NULL THEN RAISE EXCEPTION 'AUTH_INPUT_INVALID'; END IF;
  IF s.delivery IN ('accepted','rejected') THEN RETURN jsonb_build_object('ok',true,'state',public.keeptimer_mfa_state(ctx)); END IF;
  UPDATE public.keeptimer_mfa_sends SET delivery=p_data->>'delivery',lease_until=CASE WHEN p_data->>'delivery'='unknown' THEN n+interval '5 seconds' END WHERE id=s.id;
  RETURN jsonb_build_object('ok',true,'state',public.keeptimer_mfa_state(ctx));
 END IF;
 IF p_action='verify' THEN
  operation:=(p_data->>'operation_id')::uuid;
  IF operation IS NULL OR p_data->>'proof_digest' IS NULL THEN RAISE EXCEPTION 'AUTH_INPUT_INVALID'; END IF;
  SELECT * INTO v FROM public.keeptimer_mfa_verifications WHERE id=operation;
  IF FOUND THEN
   IF v.context_id<>ctx OR v.challenge_id<>c.id OR v.proof_digest IS DISTINCT FROM p_data->>'proof_digest' THEN
    RETURN jsonb_build_object('ok',false,'code','MFA_CHALLENGE_INVALID'); END IF;
   RETURN v.result || jsonb_build_object('state',public.keeptimer_mfa_state(ctx));
  END IF;
  IF s.delivery<>'accepted' THEN RETURN jsonb_build_object('ok',false,'code','EMAIL_DELIVERY_UNAVAILABLE','state',public.keeptimer_mfa_state(ctx)); END IF;
  IF c.proof_digest IS DISTINCT FROM p_data->>'proof_digest' THEN
   UPDATE public.keeptimer_mfa_contexts SET attempts=attempts+1,updated_at=n,
    locked_until=CASE WHEN attempts+1>=6 THEN n+interval '10 minutes' END WHERE id=ctx RETURNING * INTO d;
   code:=CASE WHEN d.attempts>=6 THEN 'MFA_ATTEMPTS_EXHAUSTED' ELSE 'MFA_INVALID_CODE' END;
   IF d.attempts>=6 THEN
    UPDATE public.keeptimer_mfa_challenges SET consumed_at=n WHERE id=c.id;
    INSERT INTO public.keeptimer_mfa_risk_audit(user_id,context_id,event) VALUES(target,ctx,'device_locked');
   END IF;
   outcome:=jsonb_build_object('ok',false,'code',code,'state',public.keeptimer_mfa_state(ctx));
   INSERT INTO public.keeptimer_mfa_verifications(id,context_id,challenge_id,proof_digest,result) VALUES(operation,ctx,c.id,p_data->>'proof_digest',outcome-'state');
   RETURN outcome;
  END IF;
  UPDATE public.keeptimer_mfa_challenges SET consumed_at=n WHERE id=c.id;
  new_user:=public.keeptimer_auth_new_session(target,(p_data->>'session_id')::uuid,p_data->>'refresh_hash','web');
  UPDATE public.keeptimer_mfa_contexts SET attempts=0,trusted_at=n,updated_at=n WHERE id=ctx;
  INSERT INTO public.keeptimer_mfa_verifications(id,context_id,challenge_id,proof_digest,result)
   VALUES(operation,ctx,c.id,p_data->>'proof_digest',jsonb_build_object('ok',false,'code','MFA_CHALLENGE_INVALID'));
  -- Includes session INSERT / unique idempotency waits; failure rolls ALL authority back.
  IF c.expires_at<=clock_timestamp() THEN RAISE EXCEPTION 'MFA_CODE_EXPIRED'; END IF;
  IF d.revocation_version<>coalesce((SELECT version FROM public.keeptimer_mfa_revocations WHERE user_id=target),0) THEN RAISE EXCEPTION 'MFA_CHALLENGE_INVALID'; END IF;
  RETURN jsonb_build_object('ok',true,'user',new_user);
 END IF;
 RAISE EXCEPTION 'AUTH_INPUT_INVALID';
END; $$;
REVOKE ALL ON FUNCTION public.keeptimer_mfa_command(text,jsonb) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.keeptimer_mfa_command(text,jsonb) TO service_role;

CREATE FUNCTION public.keeptimer_mfa_close_release() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path='' AS $$ DECLARE d record; BEGIN
 IF OLD.enabled AND NOT NEW.enabled THEN
  -- The release row is already exclusive; all MFA and retention take it first.
  FOR d IN SELECT id FROM public.keeptimer_mfa_contexts ORDER BY id FOR UPDATE LOOP
   UPDATE public.keeptimer_mfa_contexts SET verified_at='epoch',updated_at=clock_timestamp() WHERE id=d.id;
   UPDATE public.keeptimer_mfa_challenges SET consumed_at=clock_timestamp() WHERE context_id=d.id AND consumed_at IS NULL;
  END LOOP;
 END IF;
 RETURN NEW;
END; $$;
CREATE TRIGGER keeptimer_mfa_close_release AFTER UPDATE ON public.keeptimer_auth_release
 FOR EACH ROW EXECUTE FUNCTION public.keeptimer_mfa_close_release();
REVOKE ALL ON FUNCTION public.keeptimer_mfa_close_release() FROM PUBLIC,anon,authenticated,service_role;
CREATE FUNCTION public.keeptimer_mfa_maintain() RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path='' AS $$
DECLARE contexts integer; audits integer; challenges integer:=0; sends integer:=0; verifications integer:=0; removed integer; d record; c record;
BEGIN
 -- Works with closed gates too, but serializes with gate changes BEFORE child locks.
 PERFORM 1 FROM public.keeptimer_auth_release FOR SHARE;
 FOR d IN SELECT x.id FROM public.keeptimer_mfa_contexts x WHERE EXISTS(
  SELECT 1 FROM public.keeptimer_mfa_challenges old_ch WHERE old_ch.context_id=x.id AND old_ch.expires_at<clock_timestamp()-interval '7 days')
  ORDER BY x.id LIMIT 64 FOR UPDATE OF x SKIP LOCKED LOOP
  FOR c IN SELECT id FROM public.keeptimer_mfa_challenges WHERE context_id=d.id AND expires_at<clock_timestamp()-interval '7 days'
   ORDER BY id LIMIT 64 FOR UPDATE SKIP LOCKED LOOP
   WITH expired AS (SELECT id FROM public.keeptimer_mfa_sends WHERE challenge_id=c.id ORDER BY id LIMIT (64-sends) FOR UPDATE SKIP LOCKED)
   DELETE FROM public.keeptimer_mfa_sends WHERE id IN (SELECT id FROM expired);
   GET DIAGNOSTICS removed=ROW_COUNT;sends:=sends+removed;
   WITH expired AS (SELECT id FROM public.keeptimer_mfa_verifications WHERE challenge_id=c.id ORDER BY id LIMIT (64-verifications) FOR UPDATE SKIP LOCKED)
   DELETE FROM public.keeptimer_mfa_verifications WHERE id IN (SELECT id FROM expired);
   GET DIAGNOSTICS removed=ROW_COUNT;verifications:=verifications+removed;
   IF challenges<64 THEN
    DELETE FROM public.keeptimer_mfa_challenges WHERE id=c.id
     AND NOT EXISTS(SELECT 1 FROM public.keeptimer_mfa_sends WHERE challenge_id=c.id)
     AND NOT EXISTS(SELECT 1 FROM public.keeptimer_mfa_verifications WHERE challenge_id=c.id);
    GET DIAGNOSTICS removed=ROW_COUNT;challenges:=challenges+removed;
   END IF;
   EXIT WHEN sends>=64 AND verifications>=64 AND challenges>=64;
  END LOOP;
 END LOOP;
 WITH expired AS (SELECT id FROM public.keeptimer_mfa_contexts x WHERE updated_at<clock_timestamp()-interval '30 days'
  AND (locked_until IS NULL OR locked_until<clock_timestamp())
  AND NOT EXISTS(SELECT 1 FROM public.keeptimer_mfa_challenges WHERE context_id=x.id)
  AND NOT EXISTS(SELECT 1 FROM public.keeptimer_mfa_sends WHERE context_id=x.id)
  AND NOT EXISTS(SELECT 1 FROM public.keeptimer_mfa_verifications WHERE context_id=x.id)
  ORDER BY id LIMIT 64 FOR UPDATE SKIP LOCKED)
 DELETE FROM public.keeptimer_mfa_contexts WHERE id IN (SELECT id FROM expired);GET DIAGNOSTICS contexts=ROW_COUNT;
 WITH expired AS (SELECT id FROM public.keeptimer_mfa_risk_audit WHERE created_at<clock_timestamp()-interval '30 days'
  ORDER BY created_at LIMIT 64 FOR UPDATE SKIP LOCKED)
 DELETE FROM public.keeptimer_mfa_risk_audit WHERE id IN (SELECT id FROM expired);GET DIAGNOSTICS audits=ROW_COUNT;
 RETURN jsonb_build_object('contexts',contexts,'audits',audits,'challenges',challenges,'sends',sends,'verifications',verifications);
END; $$;
REVOKE ALL ON FUNCTION public.keeptimer_mfa_maintain() FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.keeptimer_mfa_maintain() TO service_role;
NOTIFY pgrst,'reload schema';
COMMIT;
