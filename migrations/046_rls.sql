-- 046: Row-Level Security (§8 шаг 7).
--
-- Контракт §5.1: FORCE обязателен (владелец таблицы иначе обходит RLS).
-- current_setting(..., true) при отсутствии GUC → '' → ::uuid падает → fail-closed.
-- Код обязан ходить через BindTenant / set_config в той же транзакции.
--
-- SECURITY DEFINER — только резолв ДО известного тенанта (login, fingerprint, токены).
-- После резолва вызывающий выставляет routineops.tenant_id сам.
SET lock_timeout = '5s';

DO $$
DECLARE
  t TEXT;
  scoped TEXT[] := ARRAY[
    'devices', 'device_groups', 'scripts', 'policies', 'users', 'api_tokens',
    'invitation_tokens', 'enrollment_tokens', 'directory_persons', 'audit_log',
    'audit_anchors', 'software_policy_rules',
    'device_software', 'alerts', 'tasks', 'process_events', 'admin_access_requests',
    'admin_session_changes', 'recovery_key_escrow', 'device_group_members',
    'policy_assignments', 'script_results', 'password_reset_tokens'
  ];
BEGIN
  FOREACH t IN ARRAY scoped LOOP
    IF to_regclass(t) IS NULL THEN
      CONTINUE;
    END IF;
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('DROP POLICY IF EXISTS %I ON %I', t || '_tenant_isolation', t);
    EXECUTE format(
      'CREATE POLICY %I ON %I USING (tenant_id = current_setting(''routineops.tenant_id'', true)::uuid) WITH CHECK (tenant_id = current_setting(''routineops.tenant_id'', true)::uuid)',
      t || '_tenant_isolation', t);
  END LOOP;
END $$;

-- ---------------------------------------------------------------------------
-- Pre-auth lookups (SECURITY DEFINER, search_path фиксирован)
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION auth_user_by_email(p_email TEXT)
RETURNS TABLE (
  id UUID, name TEXT, email TEXT, password_hash TEXT, role TEXT, created_at TIMESTAMPTZ
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT u.id, u.name, u.email, u.password_hash, u.role, u.created_at
  FROM users u WHERE u.email = p_email;
$$;

CREATE OR REPLACE FUNCTION auth_user_password_epoch(p_user_id UUID)
RETURNS TABLE (password_changed_at TIMESTAMPTZ, tenant_id UUID)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT u.password_changed_at, u.tenant_id FROM users u WHERE u.id = p_user_id;
$$;

CREATE OR REPLACE FUNCTION auth_device_by_fingerprint(p_fp TEXT)
RETURNS TABLE (id UUID, tenant_id UUID, status TEXT)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT d.id, d.tenant_id, d.status
  FROM devices d WHERE d.certificate_fingerprint = p_fp;
$$;

CREATE OR REPLACE FUNCTION auth_invitation_by_token(p_token TEXT)
RETURNS TABLE (
  id UUID, tenant_id UUID, email TEXT, role TEXT, token TEXT, invited_by UUID,
  created_at TIMESTAMPTZ, expires_at TIMESTAMPTZ, accepted_at TIMESTAMPTZ
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT i.id, i.tenant_id, i.email, i.role, i.token, i.invited_by,
         i.created_at, i.expires_at, i.accepted_at
  FROM invitation_tokens i WHERE i.token = p_token;
$$;

CREATE OR REPLACE FUNCTION auth_password_reset_by_token(p_token TEXT)
RETURNS TABLE (
  id UUID, user_id UUID, tenant_id UUID, token TEXT,
  created_at TIMESTAMPTZ, expires_at TIMESTAMPTZ, used_at TIMESTAMPTZ
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT t.id, t.user_id, t.tenant_id, t.token, t.created_at, t.expires_at, t.used_at
  FROM password_reset_tokens t WHERE t.token = p_token;
$$;

CREATE OR REPLACE FUNCTION auth_enrollment_by_hash(p_hash TEXT)
RETURNS TABLE (
  id UUID, tenant_id UUID, device_id UUID, group_id UUID, token_hash TEXT,
  max_uses INT, uses INT, require_approval BOOLEAN,
  expires_at TIMESTAMPTZ, used_at TIMESTAMPTZ
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT e.id, e.tenant_id, e.device_id, e.group_id, e.token_hash,
         e.max_uses, e.uses, e.require_approval, e.expires_at, e.used_at
  FROM enrollment_tokens e WHERE e.token_hash = p_hash;
$$;

-- Аутентификация API-токена: UPDATE last_used_at + RETURNING (обходит RLS до скоупа).
CREATE OR REPLACE FUNCTION auth_api_token_touch(p_hash TEXT)
RETURNS TABLE (
  id UUID, tenant_id UUID, name TEXT, role TEXT, created_by UUID,
  created_at TIMESTAMPTZ, expires_at TIMESTAMPTZ, last_used_at TIMESTAMPTZ
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
  UPDATE api_tokens a SET last_used_at = now()
  WHERE a.token_hash = p_hash AND (a.expires_at IS NULL OR a.expires_at > now())
  RETURNING a.id, a.tenant_id, a.name, a.role, a.created_by,
            a.created_at, a.expires_at, a.last_used_at;
$$;

-- DOWN (вручную при откате):
-- DROP FUNCTION IF EXISTS auth_api_token_touch(TEXT);
-- DROP FUNCTION IF EXISTS auth_enrollment_by_hash(TEXT);
-- DROP FUNCTION IF EXISTS auth_password_reset_by_token(TEXT);
-- DROP FUNCTION IF EXISTS auth_invitation_by_token(TEXT);
-- DROP FUNCTION IF EXISTS auth_device_by_fingerprint(TEXT);
-- DROP FUNCTION IF EXISTS auth_user_password_epoch(UUID);
-- DROP FUNCTION IF EXISTS auth_user_by_email(TEXT);
-- DO $$ DECLARE t TEXT; scoped TEXT[] := ARRAY[...]; BEGIN
--   FOREACH t IN ARRAY scoped LOOP
--     EXECUTE format('DROP POLICY IF EXISTS %I ON %I', t||'_tenant_isolation', t);
--     EXECUTE format('ALTER TABLE %I NO FORCE ROW LEVEL SECURITY', t);
--     EXECUTE format('ALTER TABLE %I DISABLE ROW LEVEL SECURITY', t);
--   END LOOP;
-- END $$;
