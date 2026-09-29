-- Phase 5. REVIEW ONLY: do not apply without explicit migration approval.
-- Additive metadata; no existing timer payload is rewritten by this migration.
BEGIN;
ALTER TABLE public.timers
  ADD COLUMN shared_revision bigint NOT NULL DEFAULT 0,
  ADD COLUMN shared_mutation_id uuid,
  ADD COLUMN shared_mutation_actor uuid,
  ADD COLUMN shared_command jsonb,
  ADD COLUMN shared_run_id uuid,
  ADD COLUMN shared_alarm_claimed boolean NOT NULL DEFAULT false;

CREATE TABLE public.keeptimer_shared_scopes (
  workspace_id uuid PRIMARY KEY REFERENCES public.workspaces(id),
  revision bigint NOT NULL DEFAULT 0
);
ALTER TABLE public.keeptimer_shared_scopes ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.keeptimer_shared_scopes FROM PUBLIC, anon, authenticated;

CREATE FUNCTION public.keeptimer_shared_lock(p_workspace uuid)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
BEGIN
  INSERT INTO public.keeptimer_shared_scopes(workspace_id) VALUES(p_workspace)
    ON CONFLICT DO NOTHING;
  PERFORM 1 FROM public.keeptimer_shared_scopes WHERE workspace_id=p_workspace FOR UPDATE;
END;
$$;

-- Only the service-role RPC below may open this transaction-local write path.
-- Existing unversioned RPC/direct INSERT routes cannot bypass it.
CREATE FUNCTION public.keeptimer_shared_write_guard()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
BEGIN
  IF NEW.is_shared IS TRUE OR (TG_OP='UPDATE' AND OLD.is_shared IS TRUE) THEN
    IF pg_catalog.current_setting('keeptimer.shared_protocol',true) IS DISTINCT FROM '5' THEN
      RAISE EXCEPTION 'SHARED_PROTOCOL_REQUIRED';
    END IF;
    IF TG_OP='UPDATE' AND OLD.record_status='deleted' THEN
      RAISE EXCEPTION 'SHARED_DELETED';
    END IF;
    NEW.shared_revision := CASE WHEN TG_OP='INSERT' THEN 1 ELSE OLD.shared_revision+1 END;
    UPDATE public.keeptimer_shared_scopes SET revision=revision+1 WHERE workspace_id=NEW.workspace_id;
    IF NOT FOUND THEN RAISE EXCEPTION 'SHARED_SCOPE_REQUIRED'; END IF;
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER keeptimer_shared_write_guard BEFORE INSERT OR UPDATE ON public.timers
FOR EACH ROW EXECUTE FUNCTION public.keeptimer_shared_write_guard();

CREATE FUNCTION public.keeptimer_shared_row(p_timer public.timers)
RETURNS jsonb LANGUAGE sql STABLE SET search_path = '' AS $$
 SELECT pg_catalog.to_jsonb(p_timer) || pg_catalog.jsonb_build_object('shared_revision',p_timer.shared_revision::text);
$$;

CREATE FUNCTION public.keeptimer_shared_request(p_actor_id uuid, p_request jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
DECLARE
  a public.users%ROWTYPE; t public.timers%ROWTYPE;
  w uuid; v_id uuid; mutation uuid; expected bigint;
  cmd text := p_request->>'command'; n timestamptz; target bigint; elapsed bigint;
  result jsonb; envelope jsonb; generation text; duplicate boolean := false;
BEGIN
  IF p_request IS NULL OR pg_catalog.jsonb_typeof(p_request)<>'object'
     OR p_request->>'protocol' IS DISTINCT FROM '5'
     OR cmd IS NULL OR cmd NOT IN ('snapshot','create','start','pause','set-pay','delete')
     OR EXISTS (SELECT 1 FROM pg_catalog.jsonb_object_keys(p_request) AS keys(key) WHERE key NOT IN
       ('protocol','command','timerId','mutationId','expectedRevision','name','type','targetMinutes','value')) THEN
    RAISE EXCEPTION 'SHARED_INVALID';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.jsonb_object_keys(p_request) AS keys(key) WHERE NOT (key = ANY(
    CASE cmd WHEN 'snapshot' THEN ARRAY['protocol','command']
      WHEN 'create' THEN ARRAY['protocol','command','timerId','mutationId','expectedRevision','name','type','targetMinutes']
      WHEN 'set-pay' THEN ARRAY['protocol','command','timerId','mutationId','expectedRevision','value']
      ELSE ARRAY['protocol','command','timerId','mutationId','expectedRevision'] END))) THEN RAISE EXCEPTION 'SHARED_INVALID'; END IF;
  SELECT * INTO a FROM public.users WHERE users.id=p_actor_id FOR SHARE;
  IF NOT FOUND OR a.disabled_at IS NOT NULL THEN RAISE EXCEPTION 'SHARED_ACCOUNT_DISABLED'; END IF;
  w := a.workspace_id;
  IF cmd <> 'snapshot' THEN
    v_id := (p_request->>'timerId')::uuid; mutation := (p_request->>'mutationId')::uuid;
    expected := (p_request->>'expectedRevision')::bigint;
    IF v_id IS NULL OR mutation IS NULL OR expected IS NULL OR expected<0 THEN RAISE EXCEPTION 'SHARED_INVALID'; END IF;
    IF cmd<>'create' THEN
      SELECT * INTO t FROM public.timers WHERE timers.id=v_id;
      IF NOT FOUND THEN RAISE EXCEPTION 'SHARED_NOT_FOUND'; END IF;
      IF t.is_shared IS DISTINCT FROM TRUE OR t.workspace_id IS NULL
        OR (a.role<>'superadmin' AND t.workspace_id IS DISTINCT FROM w) THEN RAISE EXCEPTION 'SHARED_FORBIDDEN'; END IF;
      w := t.workspace_id;
    END IF;
  END IF;
  IF w IS NULL THEN RAISE EXCEPTION 'SHARED_FORBIDDEN'; END IF;
  -- Lock order: actor -> scope -> timer. Closure never locks shared timers.
  PERFORM public.keeptimer_shared_lock(w);
  PERFORM pg_catalog.set_config('keeptimer.shared_protocol','5',true);
  n := pg_catalog.clock_timestamp();

  IF cmd='snapshot' THEN
    -- The entire snapshot is ONE JSON value in ONE RPC transaction, not a
    -- PostgREST rowset subject to max_rows. All shared writers hold this scope.
    UPDATE public.timers SET shared_run_id=id
    WHERE workspace_id=w AND is_shared IS TRUE AND archived_at IS NULL
      AND record_status='active' AND status='running' AND shared_run_id IS NULL AND ends_at IS NOT NULL;
    UPDATE public.timers SET status='completed', ended_at=ends_at,
      accumulated_ms=pg_catalog.trunc(target_minutes*60000)::bigint,
      duration_ms=pg_catalog.trunc(target_minutes*60000)::bigint
    WHERE workspace_id=w AND is_shared IS TRUE AND archived_at IS NULL
      AND record_status='active' AND type='down' AND status='running'
      AND ends_at<=n AND target_minutes>0;
    SELECT coalesce(pg_catalog.jsonb_agg(public.keeptimer_shared_row(x) ORDER BY x.id),'[]'::jsonb)
      INTO result FROM public.timers x WHERE x.workspace_id=w AND x.is_shared IS TRUE;
    envelope := pg_catalog.jsonb_build_object('timers',result,'complete',true);
  ELSE
    IF cmd='create' THEN
      IF expected<>0 OR pg_catalog.jsonb_typeof(p_request->'name') IS DISTINCT FROM 'string'
        OR pg_catalog.btrim(p_request->>'name')='' OR pg_catalog.char_length(p_request->>'name')>35
        OR p_request->>'type' IS NULL OR p_request->>'type' NOT IN ('up','down')
        OR pg_catalog.jsonb_typeof(p_request->'targetMinutes') IS DISTINCT FROM 'number'
        OR pg_catalog.trunc((p_request->>'targetMinutes')::numeric*60000)<1
        OR (p_request->>'targetMinutes')::numeric>1440 THEN RAISE EXCEPTION 'SHARED_INVALID'; END IF;
      -- ON CONFLICT must not fire INSERT guards for a duplicate when shared mode
      -- has since been disabled; inspect under the scope lock first.
      SELECT * INTO t FROM public.timers WHERE timers.id=v_id FOR UPDATE;
      IF NOT FOUND THEN
        INSERT INTO public.timers(id,user_id,created_by,workspace_id,name,type,target_minutes,
          is_shared,is_pay,status,record_status,accumulated_ms,paused_count,
          shared_mutation_id,shared_mutation_actor,shared_command)
        VALUES(v_id,p_actor_id,p_actor_id,w,pg_catalog.btrim(p_request->>'name'),p_request->>'type',
          (p_request->>'targetMinutes')::numeric,true,false,'idle','active',0,0,mutation,p_actor_id,p_request)
        ON CONFLICT DO NOTHING RETURNING * INTO t;
        IF NOT FOUND THEN SELECT * INTO t FROM public.timers WHERE timers.id=v_id FOR UPDATE; END IF;
      END IF;
      IF t.is_shared IS DISTINCT FROM TRUE OR t.workspace_id IS DISTINCT FROM w OR t.user_id IS DISTINCT FROM p_actor_id THEN
        RAISE EXCEPTION 'SHARED_FORBIDDEN';
      END IF;
      IF t.shared_mutation_id IS DISTINCT FROM mutation OR t.shared_command IS DISTINCT FROM p_request THEN
        RAISE EXCEPTION 'SHARED_CONFLICT';
      END IF;
    ELSE
      SELECT * INTO t FROM public.timers WHERE timers.id=v_id FOR UPDATE;
      n := pg_catalog.clock_timestamp();
      IF t.archived_at IS NOT NULL THEN RAISE EXCEPTION 'SHARED_DELETED'; END IF;
      duplicate := t.shared_mutation_id=mutation AND t.shared_mutation_actor=p_actor_id AND t.shared_command=p_request;
      IF NOT coalesce(duplicate,false) THEN
        IF t.shared_revision<>expected OR t.shared_mutation_id=mutation THEN RAISE EXCEPTION 'SHARED_CONFLICT'; END IF;
        IF t.record_status IS DISTINCT FROM 'active' THEN RAISE EXCEPTION 'SHARED_DELETED'; END IF;
        IF t.target_minutes IS NULL OR pg_catalog.trunc(t.target_minutes*60000)<1 OR t.target_minutes>1440
          OR t.target_minutes::text IN ('NaN','Infinity','-Infinity') THEN RAISE EXCEPTION 'SHARED_INVALID_STATE'; END IF;
        target := pg_catalog.trunc(t.target_minutes*60000)::bigint;
        elapsed := coalesce(t.accumulated_ms,0);
        IF t.status='running' THEN
          IF t.ends_at IS NULL THEN RAISE EXCEPTION 'SHARED_INVALID_STATE'; END IF;
          elapsed := greatest(elapsed, target-pg_catalog.floor(extract(epoch FROM (t.ends_at-n))*1000)::bigint);
          IF t.type='down' AND n>=t.ends_at THEN
            t.status:='completed'; t.ended_at:=t.ends_at; t.duration_ms:=target; elapsed:=target;
          END IF;
        END IF;
        IF cmd='start' THEN
          IF t.status NOT IN ('idle','paused') THEN RAISE EXCEPTION 'SHARED_TRANSITION'; END IF;
          t.status:='running'; t.started_at:=coalesce(t.started_at,n);
          t.ends_at:=n+(target-elapsed)*interval '1 millisecond'; t.shared_run_id:=mutation;
        ELSIF cmd='pause' THEN
          IF t.status='running' THEN
            t.status:='paused'; t.ends_at:=NULL; t.shared_run_id:=NULL; t.paused_count:=coalesce(t.paused_count,0)+1;
          ELSIF t.status<>'completed' THEN RAISE EXCEPTION 'SHARED_TRANSITION'; END IF;
        ELSIF cmd='set-pay' THEN
          IF pg_catalog.jsonb_typeof(p_request->'value') IS DISTINCT FROM 'boolean' THEN RAISE EXCEPTION 'SHARED_INVALID'; END IF;
          t.is_pay:=(p_request->>'value')::boolean;
        ELSIF cmd='delete' THEN t.record_status:='deleted'; t.shared_run_id:=NULL;
        END IF;
        UPDATE public.timers SET status=t.status,record_status=t.record_status,is_pay=t.is_pay,
          started_at=t.started_at,ends_at=t.ends_at,ended_at=t.ended_at,duration_ms=t.duration_ms,
          accumulated_ms=elapsed,paused_count=t.paused_count,shared_run_id=t.shared_run_id,
          shared_mutation_id=mutation,shared_mutation_actor=p_actor_id,shared_command=p_request
        WHERE timers.id=v_id RETURNING * INTO t;
      END IF;
    END IF;
    envelope:=pg_catalog.jsonb_build_object('timer',public.keeptimer_shared_row(t),'mutationId',mutation);
  END IF;
  SELECT revision::text INTO generation FROM public.keeptimer_shared_scopes WHERE workspace_id=w;
  RETURN envelope || pg_catalog.jsonb_build_object('protocol',5,'workspaceId',w,
    'generation',generation,'serverNow',n,'success',true);
END;
$$;

-- Internal deadline claim: no client clock, no client authorization parameters.
-- service_role only. Claim-before-delivery deliberately does not promise exactly-once delivery.
CREATE FUNCTION public.keeptimer_shared_due(p_id uuid, p_run uuid, p_ends timestamptz)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
DECLARE t public.timers%ROWTYPE; w uuid; n timestamptz; target bigint;
BEGIN
  SELECT workspace_id INTO w FROM public.timers WHERE id=p_id AND is_shared IS TRUE;
  IF w IS NULL THEN RETURN NULL; END IF;
  PERFORM public.keeptimer_shared_lock(w);
  SELECT * INTO t FROM public.timers WHERE id=p_id FOR UPDATE;
  n:=pg_catalog.clock_timestamp();
  IF t.record_status IS DISTINCT FROM 'active' OR t.archived_at IS NOT NULL OR t.shared_alarm_claimed
    OR t.shared_run_id IS DISTINCT FROM p_run OR p_run IS NULL
    OR t.ends_at IS DISTINCT FROM p_ends OR p_ends IS NULL OR p_ends>n
    OR t.target_minutes IS NULL OR pg_catalog.trunc(t.target_minutes*60000)<1 OR t.target_minutes>1440
    OR NOT (t.status='running' OR (t.type='down' AND t.status='completed' AND t.ended_at=p_ends)) THEN RETURN NULL; END IF;
  target:=pg_catalog.trunc(t.target_minutes*60000)::bigint;
  PERFORM pg_catalog.set_config('keeptimer.shared_protocol','5',true);
  UPDATE public.timers SET shared_alarm_claimed=true,
    status=CASE WHEN type='down' THEN 'completed' ELSE status END,
    accumulated_ms=CASE WHEN type='down' THEN target ELSE accumulated_ms END,
    ended_at=CASE WHEN type='down' THEN ends_at ELSE ended_at END,
    duration_ms=CASE WHEN type='down' THEN target ELSE duration_ms END
  WHERE id=p_id RETURNING * INTO t;
  RETURN pg_catalog.jsonb_build_object('protocol',5,'success',true,'workspaceId',w,'timer',public.keeptimer_shared_row(t),
    'generation',(SELECT revision::text FROM public.keeptimer_shared_scopes WHERE workspace_id=w),'serverNow',n);
END;
$$;

REVOKE ALL ON FUNCTION public.keeptimer_shared_lock(uuid) FROM PUBLIC,anon,authenticated;
REVOKE ALL ON FUNCTION public.keeptimer_shared_write_guard() FROM PUBLIC,anon,authenticated;
REVOKE ALL ON FUNCTION public.keeptimer_shared_row(public.timers) FROM PUBLIC,anon,authenticated;
REVOKE ALL ON FUNCTION public.keeptimer_shared_request(uuid,jsonb) FROM PUBLIC,anon,authenticated;
REVOKE ALL ON FUNCTION public.keeptimer_shared_due(uuid,uuid,timestamptz) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.keeptimer_shared_request(uuid,jsonb) TO service_role;
GRANT EXECUTE ON FUNCTION public.keeptimer_shared_due(uuid,uuid,timestamptz) TO service_role;
COMMIT;
