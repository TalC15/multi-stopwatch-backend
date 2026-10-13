-- Phase 7 management preparation. Adds new RPCs only; does not open any gate.
BEGIN;
SELECT public.keeptimer_auth_assert_owner();
CREATE TABLE public.keeptimer_auth_management_audit(
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), actor_user_id uuid NOT NULL REFERENCES public.users(id),
 session_id uuid NOT NULL REFERENCES public.sessions(id), target_user_id uuid REFERENCES public.users(id),
 workspace_id uuid REFERENCES public.workspaces(id), action text NOT NULL CHECK(action IN
 ('user_create','user_update','user_disable','force_logout','workspace_create','workspace_join','workspace_leave','workspace_toggle','workspace_invite')),
 occurred_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
ALTER TABLE public.keeptimer_auth_management_audit ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.keeptimer_auth_management_audit FROM PUBLIC,anon,authenticated,service_role;
CREATE FUNCTION public.keeptimer_auth_require_admin(p_actor uuid,p_session uuid) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path='' AS $$ BEGIN
 PERFORM public.keeptimer_auth_ready_gate();
 -- Same actor-first order as sales. General company management does NOT open or
 -- depend on the sales gate. Agent never receives this authority.
 PERFORM 1 FROM public.users WHERE id=p_actor AND role='superadmin' AND disabled_at IS NULL FOR UPDATE;
 IF NOT FOUND OR NOT public.keeptimer_auth_session(p_actor,p_session,'web') THEN RAISE EXCEPTION 'AUTH_FORBIDDEN'; END IF;
END; $$;
CREATE FUNCTION public.keeptimer_auth_management(p_actor uuid,p_session uuid,p_action text,p_data jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path='' AS $$
DECLARE allowed text[]; u record; w record; target uuid; workspace uuid; result jsonb; actor_workspace uuid; code text;
BEGIN
 PERFORM public.keeptimer_auth_require_admin(p_actor,p_session);
 allowed:=CASE p_action WHEN 'users' THEN ARRAY[]::text[] WHEN 'workspaces' THEN ARRAY[]::text[]
  WHEN 'workspace_detail' THEN ARRAY['id'] WHEN 'user_create' THEN ARRAY['username','pin_hash','role','workspace_id']
  WHEN 'user_update' THEN ARRAY['id','username','role','workspace_id'] WHEN 'user_disable' THEN ARRAY['id']
  WHEN 'force_logout' THEN ARRAY['id'] WHEN 'workspace_create' THEN ARRAY['name','invite_code']
  WHEN 'workspace_join' THEN ARRAY['inviteCode'] WHEN 'workspace_leave' THEN ARRAY[]::text[]
  WHEN 'workspace_toggle' THEN ARRAY[]::text[] WHEN 'workspace_invite' THEN ARRAY['invite_code']
  WHEN 'workspace' THEN ARRAY[]::text[] END;
 IF allowed IS NULL OR jsonb_typeof(p_data) IS DISTINCT FROM 'object' OR p_data-allowed<>'{}'::jsonb OR NOT(p_data ?& allowed)
  THEN RAISE EXCEPTION 'AUTH_INPUT_INVALID'; END IF;
 SELECT workspace_id INTO actor_workspace FROM public.users WHERE id=p_actor;
 IF p_action='users' THEN
  SELECT jsonb_build_object('users',coalesce(jsonb_agg(jsonb_build_object('id',id,'username',username,'role',role,
   'workspace_id',workspace_id,'created_at',created_at,'disabled_at',disabled_at) ORDER BY created_at,id),'[]'::jsonb)) INTO result
   FROM public.users WHERE disabled_at IS NULL;
 ELSIF p_action='workspaces' THEN
  SELECT jsonb_build_object('workspaces',coalesce(jsonb_agg(jsonb_build_object('id',id,'name',name,'owner_id',owner_id,
   'created_at',created_at,'invite_code',invite_code) ORDER BY created_at,id),'[]'::jsonb)) INTO result FROM public.workspaces WHERE kind='team';
 ELSIF p_action IN ('workspace_detail','workspace') THEN
  workspace:=CASE WHEN p_action='workspace' THEN actor_workspace ELSE (p_data->>'id')::uuid END;
  IF workspace IS NULL AND p_action='workspace' THEN result:=jsonb_build_object('workspace',NULL);
  ELSE
   SELECT * INTO w FROM public.workspaces WHERE id=workspace AND kind='team' FOR SHARE;
   IF NOT FOUND THEN RAISE EXCEPTION 'AUTH_RESOURCE_NOT_FOUND'; END IF;
   result:=jsonb_build_object('workspace',jsonb_build_object('id',w.id,'name',w.name,'owner_id',w.owner_id,
    'created_at',w.created_at,'invite_code',w.invite_code,'shared_mode_enabled',w.shared_mode_enabled));
   IF p_action='workspace_detail' THEN result:=result||jsonb_build_object('members',coalesce((SELECT jsonb_agg(jsonb_build_object(
    'id',id,'username',username,'role',role,'created_at',created_at) ORDER BY id) FROM public.users WHERE workspace_id=workspace AND disabled_at IS NULL),'[]'::jsonb)); END IF;
  END IF;
 ELSIF p_action='user_create' THEN
  IF p_data->>'username' IS NULL OR p_data->>'username' !~ '^[A-Za-z0-9_.-]{3,25}$' OR
   p_data->>'role' IS NULL OR p_data->>'role' NOT IN ('worker','manager') OR
   p_data->>'pin_hash' IS NULL OR p_data->>'pin_hash' !~ '^\$2[aby]\$12\$[./A-Za-z0-9]{53}$' THEN RAISE EXCEPTION 'AUTH_INPUT_INVALID'; END IF;
  workspace:=(p_data->>'workspace_id')::uuid;
  IF workspace IS NOT NULL THEN
   PERFORM 1 FROM public.workspaces WHERE id=workspace AND kind='team' FOR SHARE;
   IF NOT FOUND THEN RAISE EXCEPTION 'AUTH_FORBIDDEN'; END IF;
  END IF;
  INSERT INTO public.users(username,pin_hash,role,workspace_id,credential_kind)
   VALUES(p_data->>'username',p_data->>'pin_hash',p_data->>'role',workspace,'pin') RETURNING * INTO u;
  target:=u.id;result:=jsonb_build_object('success',true,'user',jsonb_build_object('id',u.id,'username',u.username,'role',u.role));
 ELSIF p_action IN ('user_update','user_disable','force_logout') THEN
  target:=(p_data->>'id')::uuid;
  SELECT * INTO u FROM public.users WHERE id=target FOR UPDATE;
  IF NOT FOUND OR u.disabled_at IS NOT NULL THEN RAISE EXCEPTION 'AUTH_RESOURCE_NOT_FOUND'; END IF;
  workspace:=u.workspace_id;
  IF p_action='user_update' THEN
   IF p_data->>'username' IS NULL OR p_data->>'username' !~ '^[A-Za-z0-9_.-]{3,25}$' THEN RAISE EXCEPTION 'AUTH_INPUT_INVALID'; END IF;
   -- Company/private identity and privileged roles are not reassigned here.
   -- Existing DB company guards further constrain worker/manager transitions.
   IF u.credential_kind='password' OR u.role IN ('superadmin','agent') THEN
    IF p_data->>'role' IS DISTINCT FROM u.role OR (p_data->>'workspace_id')::uuid IS DISTINCT FROM u.workspace_id THEN RAISE EXCEPTION 'AUTH_FORBIDDEN'; END IF;
   ELSE
    IF p_data->>'role' IS NULL OR p_data->>'role' NOT IN ('worker','manager') THEN RAISE EXCEPTION 'AUTH_FORBIDDEN'; END IF;
    workspace:=(p_data->>'workspace_id')::uuid;
    IF workspace IS NOT NULL THEN
     PERFORM 1 FROM public.workspaces WHERE id=workspace AND kind='team' FOR SHARE;
     IF NOT FOUND THEN RAISE EXCEPTION 'AUTH_FORBIDDEN'; END IF;
    END IF;
   END IF;
   UPDATE public.users SET username=p_data->>'username',role=p_data->>'role',workspace_id=workspace WHERE id=target;
  ELSE
   IF target=p_actor THEN RAISE EXCEPTION 'AUTH_FORBIDDEN'; END IF;
   PERFORM 1 FROM public.keeptimer_auth_accounts WHERE user_id=target FOR UPDATE;
   IF p_action='user_disable' THEN
    IF u.credential_kind<>'pin' OR u.role NOT IN ('worker','manager') OR (u.role='manager' AND u.workspace_id IS NOT NULL)
     THEN RAISE EXCEPTION 'AUTH_FORBIDDEN'; END IF;
    IF u.role='worker' AND u.workspace_id IS NOT NULL THEN
     PERFORM public.keeptimer_close_company_worker(p_actor,target);
    ELSE UPDATE public.users SET disabled_at=clock_timestamp() WHERE id=target; END IF;
   END IF;
   UPDATE public.sessions SET revoked_at=clock_timestamp() WHERE user_id=target AND revoked_at IS NULL;
   UPDATE public.keeptimer_auth_challenges SET consumed_at=clock_timestamp() WHERE user_id=target AND consumed_at IS NULL;
   DELETE FROM public.keeptimer_privileged_web_sessions WHERE user_id=target;
  END IF;
  result:=jsonb_build_object('success',true);
 ELSE
  IF p_action='workspace_create' THEN
   IF p_data->>'name' IS NULL OR length(btrim(p_data->>'name')) NOT BETWEEN 1 AND 100 THEN RAISE EXCEPTION 'AUTH_INPUT_INVALID'; END IF;
   code:=p_data->>'invite_code';
   IF code IS NULL OR code !~ '^[A-F0-9]{24}$' THEN RAISE EXCEPTION 'AUTH_INPUT_INVALID'; END IF;
   INSERT INTO public.workspaces(name,owner_id,kind,invite_code,shared_mode_enabled)
    VALUES(btrim(p_data->>'name'),p_actor,'team',code,false) RETURNING * INTO w;
   workspace:=w.id;UPDATE public.users SET workspace_id=workspace WHERE id=p_actor;
   result:=jsonb_build_object('success',true,'workspace',jsonb_build_object('id',w.id,'name',w.name,'owner_id',w.owner_id,'invite_code',w.invite_code));
  ELSIF p_action='workspace_join' THEN
   IF p_data->>'inviteCode' IS NULL OR length(p_data->>'inviteCode') NOT BETWEEN 1 AND 64 THEN RAISE EXCEPTION 'AUTH_INPUT_INVALID'; END IF;
   SELECT * INTO w FROM public.workspaces WHERE invite_code=upper(p_data->>'inviteCode') AND kind='team' FOR SHARE;
   IF NOT FOUND THEN RAISE EXCEPTION 'AUTH_RESOURCE_NOT_FOUND'; END IF;
   workspace:=w.id;UPDATE public.users SET workspace_id=workspace WHERE id=p_actor;
   result:=jsonb_build_object('success',true,'workspace',jsonb_build_object('id',w.id,'name',w.name));
  ELSIF p_action='workspace_leave' THEN
   workspace:=actor_workspace;
   IF workspace IS NULL THEN RAISE EXCEPTION 'AUTH_INPUT_INVALID'; END IF;
   UPDATE public.users SET workspace_id=NULL WHERE id=p_actor;result:=jsonb_build_object('success',true);
  ELSE
   workspace:=actor_workspace;
   SELECT * INTO w FROM public.workspaces WHERE id=workspace AND kind='team' FOR UPDATE;
   IF NOT FOUND THEN RAISE EXCEPTION 'AUTH_RESOURCE_NOT_FOUND'; END IF;
   IF p_action='workspace_toggle' THEN
    UPDATE public.workspaces SET shared_mode_enabled=NOT coalesce(shared_mode_enabled,false) WHERE id=workspace RETURNING * INTO w;
    result:=jsonb_build_object('success',true,'shared_mode_enabled',w.shared_mode_enabled);
   ELSE
    code:=p_data->>'invite_code';
    IF code IS NULL OR code !~ '^[A-F0-9]{24}$' THEN RAISE EXCEPTION 'AUTH_INPUT_INVALID'; END IF;
    UPDATE public.workspaces SET invite_code=code WHERE id=workspace;result:=jsonb_build_object('success',true,'invite_code',code);
   END IF;
  END IF;
 END IF;
 IF p_action NOT IN ('users','workspaces','workspace_detail','workspace') THEN
  INSERT INTO public.keeptimer_auth_management_audit(actor_user_id,session_id,target_user_id,workspace_id,action)
   VALUES(p_actor,p_session,target,workspace,p_action);
 END IF;
 -- After every SQL read/write/audit and every possible lock wait, not merely at entry.
 PERFORM public.keeptimer_auth_require_admin(p_actor,p_session);
 RETURN result;
END; $$;
REVOKE ALL ON FUNCTION public.keeptimer_auth_require_admin(uuid,uuid),public.keeptimer_auth_management(uuid,uuid,text,jsonb) FROM PUBLIC,anon,authenticated,service_role;
GRANT EXECUTE ON FUNCTION public.keeptimer_auth_management(uuid,uuid,text,jsonb) TO service_role;
NOTIFY pgrst, 'reload schema';
COMMIT;
