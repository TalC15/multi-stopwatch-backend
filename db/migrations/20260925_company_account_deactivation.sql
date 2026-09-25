-- Phase 2B: review before applying. Never apply the superseded departure migration.
-- This migration retains every existing user, timer, session, and workspace row.
BEGIN;

ALTER TABLE public.users ADD COLUMN IF NOT EXISTS disabled_at timestamptz;
ALTER TABLE public.timers
  ADD COLUMN IF NOT EXISTS archived_at timestamptz,
  ADD COLUMN IF NOT EXISTS archive_elapsed_uncertain boolean NOT NULL DEFAULT false;

CREATE INDEX IF NOT EXISTS keeptimer_unarchived_personal_owner_idx
  ON public.timers (user_id, workspace_id, id)
  WHERE is_shared IS FALSE AND archived_at IS NULL;

-- Prevent physical deletion/cascades and preserve company account membership.
CREATE FUNCTION public.keeptimer_guard_company_user()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    IF OLD.workspace_id IS NOT NULL
       OR EXISTS (
         SELECT 1 FROM public.timers
          WHERE workspace_id IS NOT NULL
            AND (user_id = OLD.id OR created_by = OLD.id)
       ) THEN
      RAISE EXCEPTION 'KEEPTIMER_COMPANY_USER_DELETE_BLOCKED'
        USING ERRCODE = 'P0001';
    END IF;
    RETURN OLD;
  END IF;

  IF OLD.disabled_at IS NOT NULL AND NEW.disabled_at IS DISTINCT FROM OLD.disabled_at THEN
    RAISE EXCEPTION 'KEEPTIMER_ACCOUNT_REACTIVATION_BLOCKED'
      USING ERRCODE = 'P0001';
  END IF;
  IF OLD.disabled_at IS NOT NULL AND NEW IS DISTINCT FROM OLD THEN
    RAISE EXCEPTION 'KEEPTIMER_ACCOUNT_DISABLED' USING ERRCODE = 'P0001';
  END IF;

  -- A company account remains in its original workspace across role changes.
  -- Promotion to manager/superadmin is blocked until a separate, safe manager
  -- lifecycle exists; otherwise leave/join could move the same account.
  IF OLD.workspace_id IS NOT NULL AND OLD.role IN ('worker', 'manager') THEN
    IF NEW.workspace_id IS DISTINCT FROM OLD.workspace_id THEN
      RAISE EXCEPTION 'KEEPTIMER_COMPANY_WORKSPACE_IMMUTABLE'
        USING ERRCODE = 'P0001';
    END IF;
    IF (OLD.role = 'worker' AND NEW.role IS DISTINCT FROM 'worker')
       OR (OLD.role = 'manager' AND NEW.role IS DISTINCT FROM 'manager'
           AND NEW.role IS DISTINCT FROM 'worker') THEN
      RAISE EXCEPTION 'KEEPTIMER_COMPANY_ROLE_IMMUTABLE'
        USING ERRCODE = 'P0001';
    END IF;
  END IF;

  -- Role changes and departures cannot remove the only manager. The workspace
  -- row serializes competing manager changes in different user rows.
  IF OLD.role = 'manager' AND OLD.workspace_id IS NOT NULL
     AND (NEW.role IS DISTINCT FROM 'manager'
          OR NEW.workspace_id IS DISTINCT FROM OLD.workspace_id
          OR NEW.disabled_at IS NOT NULL) THEN
    PERFORM 1 FROM public.workspaces WHERE id = OLD.workspace_id FOR UPDATE;
    IF NOT EXISTS (
      SELECT 1 FROM public.users
       WHERE workspace_id = OLD.workspace_id AND role = 'manager'
         AND disabled_at IS NULL AND id <> OLD.id
    ) THEN
      RAISE EXCEPTION 'KEEPTIMER_LAST_MANAGER' USING ERRCODE = 'P0001';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER keeptimer_company_user_guard
BEFORE UPDATE OR DELETE ON public.users
FOR EACH ROW EXECUTE FUNCTION public.keeptimer_guard_company_user();

CREATE FUNCTION public.keeptimer_guard_workspace_delete()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM public.timers WHERE workspace_id = OLD.id)
     OR EXISTS (SELECT 1 FROM public.users WHERE workspace_id = OLD.id) THEN
    RAISE EXCEPTION 'KEEPTIMER_WORKSPACE_HISTORY_PROTECTED'
      USING ERRCODE = 'P0001';
  END IF;
  RETURN OLD;
END;
$$;

CREATE TRIGGER keeptimer_workspace_history_guard
BEFORE DELETE ON public.workspaces
FOR EACH ROW EXECUTE FUNCTION public.keeptimer_guard_workspace_delete();

-- FOR SHARE conflicts with the deactivation transaction's user FOR UPDATE.
-- This closes the login-before-session-INSERT race.
CREATE FUNCTION public.keeptimer_guard_session_write()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $$
DECLARE
  v_disabled_at timestamptz;
BEGIN
  IF NEW.revoked_at IS NULL THEN
    SELECT disabled_at INTO v_disabled_at FROM public.users
     WHERE id = NEW.user_id FOR SHARE;
    IF NOT FOUND OR v_disabled_at IS NOT NULL THEN
      RAISE EXCEPTION 'KEEPTIMER_ACCOUNT_DISABLED'
        USING ERRCODE = 'P0001';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER keeptimer_session_write_guard
BEFORE INSERT OR UPDATE ON public.sessions
FOR EACH ROW EXECUTE FUNCTION public.keeptimer_guard_session_write();

-- Refresh takes the user lock first. A direct session UPDATE would lock the
-- session first, then wait for the user in the trigger, reversing closure's
-- worker -> session order.
CREATE FUNCTION public.keeptimer_refresh_session(
  p_user_id uuid, p_session_id uuid, p_token_hash text
)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $$
DECLARE
  v_user record;
  v_session record;
BEGIN
  SELECT disabled_at INTO v_user FROM public.users
   WHERE id = p_user_id FOR SHARE;
  IF NOT FOUND OR v_user.disabled_at IS NOT NULL THEN
    RETURN false;
  END IF;

  SELECT revoked_at, refresh_token_hash INTO v_session FROM public.sessions
   WHERE id = p_session_id AND user_id = p_user_id FOR UPDATE;
  IF NOT FOUND OR v_session.revoked_at IS NOT NULL
     OR v_session.refresh_token_hash IS DISTINCT FROM p_token_hash THEN
    RETURN false;
  END IF;

  UPDATE public.sessions SET last_used_at = pg_catalog.clock_timestamp()
   WHERE id = p_session_id;
  RETURN true;
END;
$$;

-- Archive membership and identity cannot be changed, including by delayed
-- direct writes. An archived timer is immutable even if record_status='active'.
CREATE FUNCTION public.keeptimer_guard_timer_write()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $$
DECLARE
  v_user record;
BEGIN
  IF TG_OP = 'DELETE' THEN
    IF OLD.workspace_id IS NOT NULL OR OLD.archived_at IS NOT NULL THEN
      RAISE EXCEPTION 'KEEPTIMER_COMPANY_TIMER_DELETE_BLOCKED'
        USING ERRCODE = 'P0001';
    END IF;
    RETURN OLD;
  END IF;

  IF TG_OP = 'UPDATE' THEN
    IF OLD.archived_at IS NOT NULL THEN
      RAISE EXCEPTION 'KEEPTIMER_ARCHIVED_TIMER_IMMUTABLE'
        USING ERRCODE = 'P0001';
    END IF;
    IF OLD.workspace_id IS NOT NULL
       AND NEW.is_shared IS DISTINCT FROM OLD.is_shared THEN
      RAISE EXCEPTION 'KEEPTIMER_TIMER_MODE_IMMUTABLE' USING ERRCODE = 'P0001';
    END IF;
    IF OLD.workspace_id IS NOT NULL AND OLD.is_shared IS FALSE
       AND (NEW.user_id IS DISTINCT FROM OLD.user_id
            OR NEW.created_by IS DISTINCT FROM OLD.created_by
            OR NEW.workspace_id IS DISTINCT FROM OLD.workspace_id
            OR NEW.is_shared IS DISTINCT FROM OLD.is_shared) THEN
      RAISE EXCEPTION 'KEEPTIMER_PERSONAL_SCOPE_IMMUTABLE'
        USING ERRCODE = 'P0001';
    END IF;
    IF OLD.workspace_id IS NOT NULL AND OLD.is_shared IS TRUE
       AND (NEW.user_id IS DISTINCT FROM OLD.user_id
            OR NEW.created_by IS DISTINCT FROM OLD.created_by
            OR NEW.workspace_id IS DISTINCT FROM OLD.workspace_id) THEN
      RAISE EXCEPTION 'KEEPTIMER_SHARED_SCOPE_IMMUTABLE'
        USING ERRCODE = 'P0001';
    END IF;
    IF OLD.workspace_id IS NOT NULL AND OLD.is_shared IS FALSE
       AND OLD.record_status IS DISTINCT FROM 'active'
       AND NEW.record_status = 'active' THEN
      RAISE EXCEPTION 'KEEPTIMER_DELETED_TIMER_IMMUTABLE'
        USING ERRCODE = 'P0001';
    END IF;
  ELSIF NEW.archived_at IS NOT NULL THEN
    RAISE EXCEPTION 'KEEPTIMER_ARCHIVED_TIMER_IMMUTABLE'
      USING ERRCODE = 'P0001';
  END IF;

  IF NEW.workspace_id IS NOT NULL AND NEW.is_shared IS NULL THEN
    RAISE EXCEPTION 'KEEPTIMER_TIMER_SHARING_REQUIRED' USING ERRCODE = 'P0001';
  END IF;

  IF TG_OP = 'INSERT' OR NEW.is_shared IS FALSE THEN
    IF NEW.user_id IS NULL THEN
      RAISE EXCEPTION 'KEEPTIMER_TIMER_OWNER_REQUIRED' USING ERRCODE = 'P0001';
    END IF;
    SELECT workspace_id, disabled_at INTO v_user FROM public.users
     WHERE id = NEW.user_id FOR SHARE;
    IF NOT FOUND OR v_user.disabled_at IS NOT NULL THEN
      RAISE EXCEPTION 'KEEPTIMER_ACCOUNT_DISABLED' USING ERRCODE = 'P0001';
    END IF;
    IF NEW.workspace_id IS NOT NULL AND NEW.is_shared IS FALSE
       AND v_user.workspace_id IS DISTINCT FROM NEW.workspace_id THEN
      RAISE EXCEPTION 'KEEPTIMER_PERSONAL_WORKSPACE_MISMATCH'
        USING ERRCODE = 'P0001';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER keeptimer_timer_write_guard
BEFORE INSERT OR UPDATE OR DELETE ON public.timers
FOR EACH ROW EXECUTE FUNCTION public.keeptimer_guard_timer_write();

-- The backend's authenticated req.user.id is the ONLY source of actor ID.
-- Actor is locked before the timer row; this covers in-flight shared writes
-- without making a shared timer depend on whether its creator is active.
CREATE FUNCTION public.keeptimer_change_timer(
  p_actor_id uuid, p_timer_id uuid, p_updates jsonb, p_delete boolean
)
RETURNS public.timers LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $$
DECLARE
  v_actor record;
  v_personal_owner uuid;
  v_timer public.timers%ROWTYPE;
  v_updated public.timers%ROWTYPE;
BEGIN
  SELECT id, role, workspace_id, disabled_at INTO v_actor FROM public.users
   WHERE id = p_actor_id FOR SHARE;
  IF NOT FOUND OR v_actor.disabled_at IS NOT NULL THEN
    RAISE EXCEPTION 'KEEPTIMER_ACCOUNT_DISABLED' USING ERRCODE = 'P0001';
  END IF;

  -- A superadmin can edit another user's personal timer. Acquire that owner's
  -- lock before the timer lock, as closure acquires worker before timer.
  -- Company timers cannot change their sharing mode or personal ownership.
  SELECT user_id INTO v_personal_owner FROM public.timers
   WHERE id = p_timer_id AND is_shared IS FALSE;
  IF v_personal_owner IS NOT NULL AND v_personal_owner <> p_actor_id THEN
    PERFORM 1 FROM public.users WHERE id = v_personal_owner FOR SHARE;
  END IF;

  SELECT * INTO v_timer FROM public.timers WHERE id = p_timer_id FOR UPDATE;
  IF NOT FOUND OR v_timer.record_status IS DISTINCT FROM 'active'
     OR v_timer.archived_at IS NOT NULL THEN
    RAISE EXCEPTION 'KEEPTIMER_TIMER_NOT_ACTIVE' USING ERRCODE = 'P0001';
  END IF;

  IF NOT (v_actor.role = 'superadmin'
    OR (v_timer.is_shared IS TRUE AND v_timer.workspace_id IS NOT NULL
        AND v_timer.workspace_id = v_actor.workspace_id)
    OR (v_timer.is_shared IS FALSE AND v_timer.user_id = p_actor_id
        AND (v_timer.workspace_id IS NULL
             OR v_timer.workspace_id = v_actor.workspace_id))) THEN
    RAISE EXCEPTION 'KEEPTIMER_TIMER_FORBIDDEN' USING ERRCODE = 'P0001';
  END IF;

  IF p_delete THEN
    UPDATE public.timers SET record_status = 'deleted'
     WHERE id = p_timer_id RETURNING * INTO v_updated;
  ELSE
    IF p_updates IS NULL OR pg_catalog.jsonb_typeof(p_updates) <> 'object'
       OR EXISTS (
         SELECT 1 FROM pg_catalog.jsonb_object_keys(p_updates) AS k(key)
          WHERE key NOT IN ('status', 'is_pay', 'ends_at', 'ended_at',
                            'duration_ms', 'paused_count', 'record_status',
                            'accumulated_ms')
       ) THEN
      RAISE EXCEPTION 'KEEPTIMER_TIMER_INVALID_UPDATE' USING ERRCODE = 'P0001';
    END IF;
    IF p_updates ? 'record_status'
       AND (p_updates->>'record_status' IS NULL
            OR p_updates->>'record_status' NOT IN ('active', 'deleted')) THEN
      RAISE EXCEPTION 'KEEPTIMER_TIMER_INVALID_UPDATE' USING ERRCODE = 'P0001';
    END IF;
    IF v_timer.type = 'up' AND p_updates->>'status' = 'completed' THEN
      RAISE EXCEPTION 'KEEPTIMER_TIMER_INVALID_UPDATE' USING ERRCODE = 'P0001';
    END IF;

    UPDATE public.timers AS t SET
      status = CASE WHEN p_updates ? 'status' THEN p_updates->>'status' ELSE t.status END,
      is_pay = CASE WHEN p_updates ? 'is_pay' THEN (p_updates->>'is_pay')::boolean ELSE t.is_pay END,
      ends_at = CASE WHEN p_updates ? 'ends_at' THEN (p_updates->>'ends_at')::timestamptz ELSE t.ends_at END,
      ended_at = CASE WHEN p_updates ? 'ended_at' THEN (p_updates->>'ended_at')::timestamptz ELSE t.ended_at END,
      duration_ms = CASE WHEN p_updates ? 'duration_ms' THEN (p_updates->>'duration_ms')::bigint ELSE t.duration_ms END,
      accumulated_ms = CASE WHEN p_updates ? 'accumulated_ms' THEN (p_updates->>'accumulated_ms')::bigint ELSE t.accumulated_ms END,
      record_status = CASE WHEN p_updates ? 'record_status' THEN p_updates->>'record_status' ELSE t.record_status END,
      paused_count = CASE
        WHEN t.is_shared IS TRUE AND p_updates->>'status' = 'paused'
             AND t.status = 'running' THEN coalesce(t.paused_count, 0) + 1
        WHEN t.is_shared IS TRUE THEN t.paused_count
        WHEN p_updates ? 'paused_count' THEN (p_updates->>'paused_count')::integer
        ELSE t.paused_count END,
      started_at = CASE WHEN p_updates->>'status' = 'running'
        THEN coalesce(t.started_at, pg_catalog.clock_timestamp())
        ELSE t.started_at END
     WHERE t.id = p_timer_id RETURNING * INTO v_updated;
  END IF;
  RETURN v_updated;
END;
$$;

-- Lock actor (FOR SHARE), then worker (FOR UPDATE), then each timer in id
-- order. Session inserts and personal writes lock worker FOR SHARE first.
CREATE FUNCTION public.keeptimer_close_company_worker(p_actor_id uuid, p_worker_id uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $$
DECLARE
  v_actor record;
  v_worker record;
  v_timer record;
  v_closed_at timestamptz;
  v_target_ms numeric;
  v_elapsed_ms numeric;
  v_uncertain boolean;
  v_status text;
  v_countdown_finished boolean;
  v_ids uuid[] := ARRAY[]::uuid[];
BEGIN
  IF p_actor_id = p_worker_id THEN
    RAISE EXCEPTION 'KEEPTIMER_SELF_DEACTIVATION_BLOCKED' USING ERRCODE = 'P0001';
  END IF;
  SELECT id, role, workspace_id, disabled_at INTO v_actor FROM public.users
   WHERE id = p_actor_id FOR SHARE;
  IF NOT FOUND OR v_actor.disabled_at IS NOT NULL
     OR v_actor.role NOT IN ('manager', 'superadmin') THEN
    RAISE EXCEPTION 'KEEPTIMER_MANAGER_FORBIDDEN' USING ERRCODE = 'P0001';
  END IF;

  SELECT id, role, workspace_id, disabled_at INTO v_worker FROM public.users
   WHERE id = p_worker_id FOR UPDATE;
  IF NOT FOUND OR v_worker.role IS DISTINCT FROM 'worker'
     OR v_worker.workspace_id IS NULL
     OR (v_actor.role = 'manager'
         AND v_actor.workspace_id IS DISTINCT FROM v_worker.workspace_id) THEN
    RAISE EXCEPTION 'KEEPTIMER_WORKER_FORBIDDEN' USING ERRCODE = 'P0001';
  END IF;
  IF v_worker.disabled_at IS NOT NULL THEN
    SELECT coalesce(pg_catalog.array_agg(id), ARRAY[]::uuid[]) INTO v_ids
      FROM public.timers
     WHERE user_id = v_worker.id AND workspace_id = v_worker.workspace_id
       AND is_shared IS FALSE AND archived_at IS NOT NULL;
    RETURN pg_catalog.jsonb_build_object(
      'user_id', v_worker.id, 'workspace_id', v_worker.workspace_id,
      'already_disabled', true, 'archived_timer_ids', v_ids
    );
  END IF;

  -- Acquire all timer locks before computing one common close timestamp.
  PERFORM id FROM public.timers
   WHERE user_id = v_worker.id AND workspace_id = v_worker.workspace_id
     AND is_shared IS FALSE AND archived_at IS NULL
   ORDER BY id FOR UPDATE;
  v_closed_at := pg_catalog.clock_timestamp();

  FOR v_timer IN
    SELECT id, type, status, target_minutes, ends_at, accumulated_ms,
           duration_ms, ended_at
      FROM public.timers
     WHERE user_id = v_worker.id AND workspace_id = v_worker.workspace_id
       AND is_shared IS FALSE AND archived_at IS NULL
     ORDER BY id FOR UPDATE
  LOOP
    v_status := v_timer.status;
    v_uncertain := false;
    v_countdown_finished := false;
    v_elapsed_ms := v_timer.accumulated_ms;

    IF v_timer.status = 'running' THEN
      IF v_timer.type IN ('up', 'down')
         AND v_timer.target_minutes IS NOT NULL AND v_timer.target_minutes > 0
         AND v_timer.ends_at IS NOT NULL THEN
        v_target_ms := v_timer.target_minutes * 60000;
        v_elapsed_ms := v_target_ms -
          EXTRACT(EPOCH FROM (v_timer.ends_at - v_closed_at)) * 1000;
        IF v_timer.type = 'down' THEN
          v_countdown_finished := v_timer.ends_at <= v_closed_at;
          v_elapsed_ms := LEAST(v_elapsed_ms, v_target_ms);
        END IF;
        IF v_elapsed_ms < 0 OR v_elapsed_ms > 9223372036854775807::numeric
           OR (v_timer.accumulated_ms IS NOT NULL
               AND (v_timer.accumulated_ms < 0
                    OR v_elapsed_ms < v_timer.accumulated_ms))
           OR (v_timer.duration_ms IS NOT NULL
               AND (v_timer.duration_ms < 0
                    OR v_elapsed_ms < v_timer.duration_ms)) THEN
          v_uncertain := true;
        END IF;
      ELSE
        v_uncertain := true;
      END IF;
      v_status := CASE WHEN NOT v_uncertain AND v_countdown_finished
        THEN 'completed' ELSE 'paused' END;
    ELSIF (v_timer.accumulated_ms IS NULL AND v_timer.duration_ms IS NULL)
       OR v_timer.accumulated_ms < 0 OR v_timer.duration_ms < 0 THEN
      v_uncertain := true;
    END IF;

    UPDATE public.timers SET
      archived_at = v_closed_at,
      archive_elapsed_uncertain = v_uncertain,
      status = v_status,
      accumulated_ms = CASE WHEN v_timer.status = 'running' AND NOT v_uncertain
        THEN pg_catalog.round(v_elapsed_ms)::bigint ELSE v_timer.accumulated_ms END,
      duration_ms = CASE WHEN v_timer.status = 'running'
                               AND NOT v_uncertain AND v_countdown_finished
        THEN pg_catalog.round(v_target_ms)::bigint ELSE v_timer.duration_ms END,
      ended_at = CASE WHEN v_timer.status = 'running'
                           AND NOT v_uncertain AND v_countdown_finished
        THEN coalesce(v_timer.ended_at, v_timer.ends_at) ELSE v_timer.ended_at END
    WHERE id = v_timer.id;
    v_ids := pg_catalog.array_append(v_ids, v_timer.id);
  END LOOP;

  UPDATE public.users SET disabled_at = v_closed_at WHERE id = v_worker.id;
  UPDATE public.sessions SET revoked_at = v_closed_at
   WHERE user_id = v_worker.id AND revoked_at IS NULL;

  RETURN pg_catalog.jsonb_build_object(
    'user_id', v_worker.id, 'workspace_id', v_worker.workspace_id,
    'already_disabled', false, 'archived_timer_ids', v_ids
  );
END;
$$;

-- New functions are not callable from anonymous or authenticated clients.
REVOKE ALL ON FUNCTION public.keeptimer_change_timer(uuid, uuid, jsonb, boolean)
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.keeptimer_close_company_worker(uuid, uuid)
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.keeptimer_refresh_session(uuid, uuid, text)
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.keeptimer_guard_company_user()
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.keeptimer_guard_workspace_delete()
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.keeptimer_guard_session_write()
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.keeptimer_guard_timer_write()
  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.keeptimer_change_timer(uuid, uuid, jsonb, boolean)
  TO service_role;
GRANT EXECUTE ON FUNCTION public.keeptimer_close_company_worker(uuid, uuid)
  TO service_role;
GRANT EXECUTE ON FUNCTION public.keeptimer_refresh_session(uuid, uuid, text)
  TO service_role;

NOTIFY pgrst, 'reload schema';

COMMIT;
