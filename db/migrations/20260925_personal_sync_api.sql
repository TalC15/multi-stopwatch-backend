-- Phase 2: apply after 20260925_company_account_deactivation.sql.
-- Additive only: existing timer rows are neither deleted nor rewritten.
BEGIN;

-- The running backend already reads this workspace setting. Fail the whole
-- migration if the live schema differs, instead of silently allowing new
-- shared creates without a working mode check.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
     WHERE table_schema = 'public' AND table_name = 'workspaces'
       AND column_name = 'shared_mode_enabled' AND data_type = 'boolean'
  ) THEN
    RAISE EXCEPTION 'KEEPTIMER_SHARED_MODE_SCHEMA_REQUIRED';
  END IF;
END;
$$;

ALTER TABLE public.timers
  ADD COLUMN IF NOT EXISTS sync_revision bigint NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS last_sync_mutation_id uuid;

-- Existing development rows may have no target. Enforce the new product rule
-- only on creation, without changing those rows or blocking their archival.
-- Locking the workspace serializes new shared creation with a mode toggle.
CREATE FUNCTION public.keeptimer_guard_new_timer()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $$
DECLARE
  v_shared_enabled boolean;
BEGIN
  IF NEW.target_minutes IS NULL OR NEW.target_minutes <= 0
     OR NEW.target_minutes::text IN ('NaN', 'Infinity', '-Infinity') THEN
    RAISE EXCEPTION 'KEEPTIMER_TIMER_TARGET_REQUIRED' USING ERRCODE = 'P0001';
  END IF;
  IF NEW.type = 'up' AND NEW.status = 'completed' THEN
    RAISE EXCEPTION 'KEEPTIMER_COUNTUP_CANNOT_COMPLETE' USING ERRCODE = 'P0001';
  END IF;
  IF NEW.is_shared IS TRUE THEN
    IF NEW.workspace_id IS NULL THEN
      RAISE EXCEPTION 'KEEPTIMER_SHARED_WORKSPACE_REQUIRED' USING ERRCODE = 'P0001';
    END IF;
    SELECT shared_mode_enabled INTO v_shared_enabled FROM public.workspaces
     WHERE id = NEW.workspace_id FOR SHARE;
    IF NOT FOUND OR v_shared_enabled IS DISTINCT FROM TRUE THEN
      RAISE EXCEPTION 'KEEPTIMER_SHARED_MODE_DISABLED' USING ERRCODE = 'P0001';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER keeptimer_new_timer_guard
BEFORE INSERT ON public.timers
FOR EACH ROW EXECUTE FUNCTION public.keeptimer_guard_new_timer();

-- Legacy PATCH/DELETE must advance the same revision as the new sync API.
-- A sync write sets revision+1 itself. A legacy mutation leaves revision
-- untouched; the trigger advances it and clears the duplicate marker.
CREATE FUNCTION public.keeptimer_personal_revision_guard()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $$
BEGIN
  IF OLD.workspace_id IS NOT NULL AND OLD.is_shared IS FALSE
     AND NEW IS DISTINCT FROM OLD THEN
    IF NEW.sync_revision = OLD.sync_revision THEN
      NEW.sync_revision := OLD.sync_revision + 1;
      NEW.last_sync_mutation_id := NULL;
    ELSIF NEW.sync_revision IS DISTINCT FROM OLD.sync_revision + 1 THEN
      RAISE EXCEPTION 'KEEPTIMER_SYNC_REVISION_INVALID' USING ERRCODE = 'P0001';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER keeptimer_personal_revision_guard
BEFORE UPDATE ON public.timers
FOR EACH ROW EXECUTE FUNCTION public.keeptimer_personal_revision_guard();

-- Lock order: authenticated actor FOR SHARE, then timer FOR UPDATE. Closure
-- locks the worker FOR UPDATE before archiving timers, so one operation wins
-- completely. The unique timer ID makes simultaneous creates converge.
CREATE FUNCTION public.keeptimer_sync_personal(
  p_actor_id uuid, p_timer_id uuid, p_mutation_id uuid,
  p_expected_revision bigint, p_state jsonb
)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $$
DECLARE
  v_actor record;
  v_timer public.timers%ROWTYPE;
  v_name text := p_state->>'name';
  v_type text := p_state->>'type';
  v_target numeric := (p_state->>'target_minutes')::numeric;
  v_pay boolean := (p_state->>'is_pay')::boolean;
  v_status text := p_state->>'status';
  v_ends timestamptz := (p_state->>'ends_at')::timestamptz;
  v_ended timestamptz := (p_state->>'ended_at')::timestamptz;
  v_duration bigint := (p_state->>'duration_ms')::bigint;
  v_elapsed bigint := (p_state->>'accumulated_ms')::bigint;
  v_pauses integer := (p_state->>'paused_count')::integer;
BEGIN
  IF p_timer_id IS NULL OR p_mutation_id IS NULL OR p_expected_revision IS NULL
     OR p_expected_revision < 0 OR p_state IS NULL
     OR pg_catalog.jsonb_typeof(p_state) <> 'object'
     OR v_name IS NULL OR pg_catalog.btrim(v_name) = ''
     OR v_type IS NULL OR v_type NOT IN ('up', 'down')
     OR v_target IS NULL OR v_target <= 0
     OR v_target::text IN ('NaN', 'Infinity', '-Infinity')
     OR v_pay IS NULL OR v_status IS NULL
     OR v_status NOT IN ('idle', 'running', 'paused', 'completed')
     OR (v_type = 'up' AND v_status = 'completed')
     OR (v_status = 'running' AND v_ends IS NULL)
     OR v_elapsed IS NULL OR v_elapsed < 0
     OR v_pauses IS NULL OR v_pauses < 0
     OR v_duration < 0 THEN
    RAISE EXCEPTION 'KEEPTIMER_SYNC_INVALID_STATE' USING ERRCODE = 'P0001';
  END IF;

  SELECT id, workspace_id, disabled_at INTO v_actor FROM public.users
   WHERE id = p_actor_id FOR SHARE;
  IF NOT FOUND OR v_actor.disabled_at IS NOT NULL THEN
    RAISE EXCEPTION 'KEEPTIMER_ACCOUNT_DISABLED' USING ERRCODE = 'P0001';
  END IF;
  IF v_actor.workspace_id IS NULL THEN
    RAISE EXCEPTION 'KEEPTIMER_PERSONAL_WORKSPACE_REQUIRED' USING ERRCODE = 'P0001';
  END IF;

  -- An insert is attempted only at revision zero. Never use an unrestricted
  -- upsert: ON CONFLICT leaves an existing owner's row untouched.
  IF p_expected_revision = 0 THEN
    INSERT INTO public.timers (
      id, user_id, created_by, workspace_id, is_shared, record_status,
      name, type, target_minutes, is_pay, status, started_at, ends_at, ended_at,
      duration_ms, accumulated_ms, paused_count,
      sync_revision, last_sync_mutation_id
    ) VALUES (
      p_timer_id, p_actor_id, p_actor_id, v_actor.workspace_id, false, 'active',
      v_name, v_type, v_target, v_pay, v_status,
      CASE WHEN v_status = 'running' THEN pg_catalog.clock_timestamp() ELSE NULL END,
      v_ends, v_ended,
      v_duration, v_elapsed, v_pauses, 1, p_mutation_id
    ) ON CONFLICT (id) DO NOTHING RETURNING * INTO v_timer;
    IF FOUND THEN
      RETURN pg_catalog.jsonb_build_object(
        'timer', pg_catalog.to_jsonb(v_timer), 'created', true, 'duplicate', false
      );
    END IF;
  END IF;

  SELECT * INTO v_timer FROM public.timers WHERE id = p_timer_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'KEEPTIMER_TIMER_NOT_FOUND' USING ERRCODE = 'P0001';
  END IF;
  IF v_timer.user_id IS DISTINCT FROM p_actor_id
     OR v_timer.workspace_id IS DISTINCT FROM v_actor.workspace_id
     OR v_timer.is_shared IS DISTINCT FROM FALSE THEN
    RAISE EXCEPTION 'KEEPTIMER_TIMER_FORBIDDEN' USING ERRCODE = 'P0001';
  END IF;
  IF v_timer.archived_at IS NOT NULL
     OR v_timer.record_status IS DISTINCT FROM 'active' THEN
    RAISE EXCEPTION 'KEEPTIMER_TIMER_NOT_ACTIVE' USING ERRCODE = 'P0001';
  END IF;
  IF v_timer.type IS DISTINCT FROM v_type
     OR v_timer.target_minutes IS DISTINCT FROM v_target THEN
    RAISE EXCEPTION 'KEEPTIMER_SYNC_IMMUTABLE_TARGET' USING ERRCODE = 'P0001';
  END IF;

  IF v_timer.sync_revision = p_expected_revision + 1
     AND v_timer.last_sync_mutation_id = p_mutation_id THEN
    IF ROW(v_timer.name, v_timer.type, v_timer.target_minutes, v_timer.is_pay,
           v_timer.status, v_timer.ends_at, v_timer.ended_at, v_timer.duration_ms,
           v_timer.accumulated_ms, v_timer.paused_count)
       IS NOT DISTINCT FROM
       ROW(v_name, v_type, v_target, v_pay, v_status, v_ends, v_ended,
           v_duration, v_elapsed, v_pauses) THEN
      RETURN pg_catalog.jsonb_build_object(
        'timer', pg_catalog.to_jsonb(v_timer), 'created', false, 'duplicate', true
      );
    END IF;
    RAISE EXCEPTION 'KEEPTIMER_SYNC_MUTATION_REUSED' USING ERRCODE = 'P0001';
  END IF;
  IF v_timer.sync_revision IS DISTINCT FROM p_expected_revision
     OR v_timer.last_sync_mutation_id = p_mutation_id THEN
    RAISE EXCEPTION 'KEEPTIMER_SYNC_REVISION_CONFLICT' USING ERRCODE = 'P0001';
  END IF;

  UPDATE public.timers SET
    name = v_name, is_pay = v_pay, status = v_status,
    ends_at = v_ends, ended_at = v_ended, duration_ms = v_duration,
    accumulated_ms = v_elapsed, paused_count = v_pauses,
    started_at = CASE WHEN v_status = 'running'
      THEN coalesce(started_at, pg_catalog.clock_timestamp()) ELSE started_at END,
    sync_revision = v_timer.sync_revision + 1,
    last_sync_mutation_id = p_mutation_id
   WHERE id = p_timer_id RETURNING * INTO v_timer;
  RETURN pg_catalog.jsonb_build_object(
    'timer', pg_catalog.to_jsonb(v_timer), 'created', false, 'duplicate', false
  );
END;
$$;

CREATE FUNCTION public.keeptimer_delete_personal(
  p_actor_id uuid, p_timer_id uuid, p_mutation_id uuid, p_expected_revision bigint
)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $$
DECLARE
  v_actor record;
  v_timer public.timers%ROWTYPE;
BEGIN
  IF p_timer_id IS NULL OR p_mutation_id IS NULL OR p_expected_revision IS NULL
     OR p_expected_revision < 0 THEN
    RAISE EXCEPTION 'KEEPTIMER_SYNC_INVALID_STATE' USING ERRCODE = 'P0001';
  END IF;
  SELECT workspace_id, disabled_at INTO v_actor FROM public.users
   WHERE id = p_actor_id FOR SHARE;
  IF NOT FOUND OR v_actor.disabled_at IS NOT NULL THEN
    RAISE EXCEPTION 'KEEPTIMER_ACCOUNT_DISABLED' USING ERRCODE = 'P0001';
  END IF;
  IF v_actor.workspace_id IS NULL THEN
    RAISE EXCEPTION 'KEEPTIMER_PERSONAL_WORKSPACE_REQUIRED' USING ERRCODE = 'P0001';
  END IF;
  SELECT * INTO v_timer FROM public.timers WHERE id = p_timer_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'KEEPTIMER_TIMER_NOT_FOUND' USING ERRCODE = 'P0001';
  END IF;
  IF v_timer.user_id IS DISTINCT FROM p_actor_id
     OR v_timer.workspace_id IS DISTINCT FROM v_actor.workspace_id
     OR v_timer.is_shared IS DISTINCT FROM FALSE THEN
    RAISE EXCEPTION 'KEEPTIMER_TIMER_FORBIDDEN' USING ERRCODE = 'P0001';
  END IF;
  IF v_timer.archived_at IS NOT NULL THEN
    RAISE EXCEPTION 'KEEPTIMER_ARCHIVED_TIMER_IMMUTABLE' USING ERRCODE = 'P0001';
  END IF;
  IF v_timer.record_status = 'deleted' THEN
    RETURN pg_catalog.jsonb_build_object(
      'timer', pg_catalog.to_jsonb(v_timer),
      'duplicate', v_timer.last_sync_mutation_id = p_mutation_id
    );
  END IF;
  IF v_timer.record_status IS DISTINCT FROM 'active' THEN
    RAISE EXCEPTION 'KEEPTIMER_TIMER_NOT_ACTIVE' USING ERRCODE = 'P0001';
  END IF;
  IF v_timer.sync_revision IS DISTINCT FROM p_expected_revision THEN
    RAISE EXCEPTION 'KEEPTIMER_SYNC_REVISION_CONFLICT' USING ERRCODE = 'P0001';
  END IF;
  UPDATE public.timers SET record_status = 'deleted',
    sync_revision = v_timer.sync_revision + 1, last_sync_mutation_id = p_mutation_id
   WHERE id = p_timer_id RETURNING * INTO v_timer;
  RETURN pg_catalog.jsonb_build_object(
    'timer', pg_catalog.to_jsonb(v_timer), 'duplicate', false
  );
END;
$$;

REVOKE ALL ON FUNCTION public.keeptimer_guard_new_timer()
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.keeptimer_personal_revision_guard()
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.keeptimer_sync_personal(uuid, uuid, uuid, bigint, jsonb)
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.keeptimer_delete_personal(uuid, uuid, uuid, bigint)
  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.keeptimer_sync_personal(uuid, uuid, uuid, bigint, jsonb)
  TO service_role;
GRANT EXECUTE ON FUNCTION public.keeptimer_delete_personal(uuid, uuid, uuid, bigint)
  TO service_role;

NOTIFY pgrst, 'reload schema';
COMMIT;
