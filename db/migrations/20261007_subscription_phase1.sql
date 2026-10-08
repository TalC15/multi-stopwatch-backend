-- Paid subscriptions, Phase 1: schema only. Apply after the three 202609 migrations.
-- No account conversion, timer writes, API, entitlement, or expiry jobs.
BEGIN;
SET LOCAL lock_timeout = '5s';

-- Serialize the preflight and role-constraint replacement with user/workspace
-- writes (and another run of this migration). A timeout rolls everything back.
LOCK TABLE public.users, public.workspaces IN ACCESS EXCLUSIVE MODE;

DO $$
DECLARE conflicts text;
BEGIN
  SELECT string_agg(role || '=' || n::text, ', ' ORDER BY role)
    INTO conflicts
    FROM (SELECT role, count(*) AS n FROM public.users
          WHERE disabled_at IS NULL AND role IN ('superadmin', 'agent')
          GROUP BY role HAVING count(*) > 1) AS duplicates;
  IF conflicts IS NOT NULL THEN
    RAISE EXCEPTION 'KEEPTIMER_PHASE1_ACTIVE_ROLE_CONFLICT: %', conflicts
      USING ERRCODE = '23505',
      HINT = 'Review conflicting accounts and explicitly disable/revoke the intended ones before retrying. No account was selected or deleted.';
  END IF;
END;
$$;

CREATE TABLE IF NOT EXISTS public.subscription_plans (
  code text PRIMARY KEY CHECK (code IN ('individual', 'team', 'enterprise')),
  display_name text NOT NULL CHECK (length(btrim(display_name)) > 0),
  enabled boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now()
);
-- A replay preserves deliberately changed catalog settings.
INSERT INTO public.subscription_plans(code, display_name, enabled) VALUES
  ('individual', 'Individual', true), ('team', 'Team', false),
  ('enterprise', 'Enterprise', false)
ON CONFLICT (code) DO NOTHING;

ALTER TABLE public.users
  ADD COLUMN IF NOT EXISTS plan_code text
    REFERENCES public.subscription_plans(code) ON DELETE RESTRICT,
  ADD COLUMN IF NOT EXISTS password_hash text,
  ADD COLUMN IF NOT EXISTS must_change_password boolean NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS mfa_email text;
-- Keep pin_hash and its NOT NULL constraint: the current backend still uses it.
ALTER TABLE public.users DROP CONSTRAINT IF EXISTS users_role_check;
ALTER TABLE public.users ADD CONSTRAINT users_role_check
  CHECK (role IN ('worker', 'manager', 'superadmin', 'agent'));
CREATE UNIQUE INDEX IF NOT EXISTS users_one_active_superadmin_idx
  ON public.users (role) WHERE role = 'superadmin' AND disabled_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS users_one_active_agent_idx
  ON public.users (role) WHERE role = 'agent' AND disabled_at IS NULL;

ALTER TABLE public.workspaces
  ADD COLUMN IF NOT EXISTS kind text NOT NULL DEFAULT 'team';
ALTER TABLE public.workspaces DROP CONSTRAINT IF EXISTS workspaces_kind_check;
ALTER TABLE public.workspaces ADD CONSTRAINT workspaces_kind_check
  CHECK (kind IN ('team', 'individual_private'));
ALTER TABLE public.workspaces DROP CONSTRAINT IF EXISTS workspaces_private_shape_check;
ALTER TABLE public.workspaces ADD CONSTRAINT workspaces_private_shape_check
  CHECK (kind <> 'individual_private' OR
    (owner_id IS NOT NULL AND invite_code IS NULL AND shared_mode_enabled IS FALSE));
CREATE UNIQUE INDEX IF NOT EXISTS workspaces_one_private_owner_idx
  ON public.workspaces(owner_id) WHERE kind = 'individual_private';
-- Preparation only: cross-table membership/kind transitions and API/UI hiding
-- must be enforced before any private workspace is provisioned (next phase).

CREATE TABLE IF NOT EXISTS public.subscriptions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
  plan_code text NOT NULL REFERENCES public.subscription_plans(code) ON DELETE RESTRICT,
  sequence_no integer NOT NULL CHECK (sequence_no > 0),
  starts_at timestamptz NOT NULL CHECK (isfinite(starts_at)),
  ends_at timestamptz NOT NULL CHECK (isfinite(ends_at)),
  term_months smallint NOT NULL CHECK (term_months BETWEEN 1 AND 12),
  amount_minor bigint NOT NULL CHECK (amount_minor >= 0),
  currency text NOT NULL DEFAULT 'TRY' CHECK (currency ~ '^[A-Z]{3}$'),
  created_by_user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL DEFAULT now(),
  cancelled_at timestamptz,
  cancelled_by_user_id uuid REFERENCES public.users(id) ON DELETE RESTRICT,
  cancellation_reason text CHECK (length(cancellation_reason) <= 1000),
  CONSTRAINT subscriptions_user_sequence_key UNIQUE (user_id, sequence_no),
  CONSTRAINT subscriptions_period_check CHECK (ends_at > starts_at),
  CONSTRAINT subscriptions_cancellation_check CHECK (
    (cancelled_at IS NULL AND cancelled_by_user_id IS NULL AND cancellation_reason IS NULL)
    OR (cancelled_at IS NOT NULL AND isfinite(cancelled_at) AND cancelled_by_user_id IS NOT NULL)
  )
);
-- No stored status: CASE WHEN cancelled_at IS NOT NULL THEN 'cancelled'
-- WHEN ends_at <= now() THEN 'expired' ELSE 'active' END.

CREATE TABLE IF NOT EXISTS public.admin_audit_log (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  actor_user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
  action text NOT NULL CHECK (action IN (
    'customer_created', 'subscription_created', 'subscription_renewed',
    'subscription_cancelled', 'password_reset', 'agent_created', 'agent_revoked'
  )),
  target_user_id uuid REFERENCES public.users(id) ON DELETE RESTRICT,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  -- Deliberately closed, typed metadata vocabulary. No arbitrary strings,
  -- nested objects, emails, passwords/PINs/OTPs, hashes, tokens or request bodies.
  CONSTRAINT admin_audit_log_metadata_check CHECK (
    jsonb_typeof(metadata) = 'object'
    AND metadata - ARRAY['subscription_id', 'sequence_no', 'plan_code']::text[] = '{}'::jsonb
    AND (NOT (metadata ? 'subscription_id') OR
      (jsonb_typeof(metadata->'subscription_id') = 'string' AND
       metadata->>'subscription_id' ~ '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'))
    AND (NOT (metadata ? 'sequence_no') OR
      (jsonb_typeof(metadata->'sequence_no') = 'number' AND
       metadata->>'sequence_no' ~ '^[1-9][0-9]{0,9}$' AND
       (metadata->>'sequence_no')::numeric <= 2147483647))
    AND (NOT (metadata ? 'plan_code') OR
      (jsonb_typeof(metadata->'plan_code') = 'string' AND
       metadata->>'plan_code' IN ('individual', 'team', 'enterprise')))
  )
);
CREATE INDEX IF NOT EXISTS admin_audit_log_target_time_idx
  ON public.admin_audit_log(target_user_id, created_at);

CREATE OR REPLACE FUNCTION public.keeptimer_deny_history_mutation()
RETURNS trigger LANGUAGE plpgsql SET search_path = '' AS $$
BEGIN
  RAISE EXCEPTION 'KEEPTIMER_HISTORY_APPEND_ONLY' USING ERRCODE = '42501';
END;
$$;
DROP TRIGGER IF EXISTS keeptimer_audit_append_only ON public.admin_audit_log;
CREATE TRIGGER keeptimer_audit_append_only
  BEFORE UPDATE OR DELETE OR TRUNCATE ON public.admin_audit_log
  FOR EACH STATEMENT EXECUTE FUNCTION public.keeptimer_deny_history_mutation();
DROP TRIGGER IF EXISTS keeptimer_subscription_no_delete ON public.subscriptions;
CREATE TRIGGER keeptimer_subscription_no_delete
  BEFORE DELETE OR TRUNCATE ON public.subscriptions
  FOR EACH STATEMENT EXECUTE FUNCTION public.keeptimer_deny_history_mutation();

CREATE OR REPLACE FUNCTION public.keeptimer_guard_subscription_history()
RETURNS trigger LANGUAGE plpgsql SET search_path = '' AS $$
BEGIN
  IF (to_jsonb(NEW) - ARRAY['cancelled_at', 'cancelled_by_user_id', 'cancellation_reason']::text[])
     IS DISTINCT FROM
     (to_jsonb(OLD) - ARRAY['cancelled_at', 'cancelled_by_user_id', 'cancellation_reason']::text[])
     OR (OLD.cancelled_at IS NOT NULL AND NEW IS DISTINCT FROM OLD) THEN
    RAISE EXCEPTION 'KEEPTIMER_SUBSCRIPTION_HISTORY_IMMUTABLE' USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS keeptimer_subscription_history_guard ON public.subscriptions;
CREATE TRIGGER keeptimer_subscription_history_guard BEFORE UPDATE ON public.subscriptions
  FOR EACH ROW EXECUTE FUNCTION public.keeptimer_guard_subscription_history();

-- Deny direct Supabase client access even when default table grants are broad.
-- The backend uses service_role (BYPASSRLS); application roles are users.role,
-- not PostgreSQL roles. No client policies or new SECURITY DEFINER RPCs.
ALTER TABLE public.subscription_plans ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.subscriptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.admin_audit_log ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.subscription_plans, public.subscriptions, public.admin_audit_log
  FROM PUBLIC, anon, authenticated, service_role;
GRANT SELECT ON public.subscription_plans TO service_role;
GRANT SELECT, INSERT ON public.subscriptions, public.admin_audit_log TO service_role;
GRANT UPDATE (cancelled_at, cancelled_by_user_id, cancellation_reason)
  ON public.subscriptions TO service_role;
REVOKE ALL ON FUNCTION public.keeptimer_deny_history_mutation()
  FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION public.keeptimer_guard_subscription_history()
  FROM PUBLIC, anon, authenticated, service_role;

COMMENT ON COLUMN public.subscription_plans.enabled IS
  'Sales availability authority for future backend transactions; FK does not authorize a sale.';
COMMENT ON COLUMN public.users.password_hash IS
  'One-way password hash only; nullable until password authentication replaces legacy PIN.';
COMMENT ON COLUMN public.users.mfa_email IS
  'Private MFA destination. Never include in audit metadata or logs.';
COMMENT ON COLUMN public.subscriptions.amount_minor IS
  'Externally collected amount recorded in minor currency units; not a payment transaction.';
COMMENT ON COLUMN public.subscriptions.cancellation_reason IS
  'Optional business reason only. Never store credentials, PIN, OTP, tokens or MFA email.';
COMMENT ON TABLE public.admin_audit_log IS
  'Append-only administration events. Only typed identifiers/enums/numbers in metadata. No secrets or request/response dumps.';
COMMENT ON COLUMN public.workspaces.kind IS
  'Phase 1 discriminator only. Do not provision private accounts until membership/entitlement/UI rules exist.';

NOTIFY pgrst, 'reload schema';
COMMIT;
