-- 045: мультитенантность — схема (§8 шаги 1–5 контракта).
--
-- Контракт: docs/multitenancy-contract.md (ADR-6). Существующая инсталляция
-- становится одно-тенантной: весь текущий парк → тенант по умолчанию с
-- фиксированным UUID. DEFAULT на колонках сохраняет работу кода, который ещё
-- не передаёт tenant_id явно (шаг 6 — постепенно).
--
-- RLS (шаг 7) и разделение system_settings (шаг 8) — ОТДЕЛЬНЫЕ миграции:
-- включать FORCE RLS до того, как код выставляет routineops.tenant_id, нельзя.
--
-- Идемпотентно: schema_migrations в проекте нет, файлы могут применяться повторно.
SET lock_timeout = '5s';

-- ===========================================================================
-- 1. Реестр тенантов + тенант по умолчанию
-- ===========================================================================
-- UUID зафиксирован и в internal/server/tenancy.DefaultTenantID. Не менять:
-- бэкфилл и DEFAULT колонок на него завязаны; смена = переезд всех строк.

CREATE TABLE IF NOT EXISTS tenants (
  id         UUID PRIMARY KEY,
  name       TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO tenants (id, name) VALUES
  ('00000000-0000-4000-8000-000000000001', 'Default')
ON CONFLICT (id) DO NOTHING;

-- ===========================================================================
-- 2–4. Колонка tenant_id → бэкфилл → NOT NULL + FK + DEFAULT
-- ===========================================================================

DO $$
DECLARE
  def UUID := '00000000-0000-4000-8000-000000000001';
  t   TEXT;
  own TEXT[] := ARRAY[
    'devices', 'device_groups', 'scripts', 'policies', 'users', 'api_tokens',
    'invitation_tokens', 'enrollment_tokens', 'directory_persons', 'audit_log',
    'audit_anchors', 'software_policy_rules'
  ];
  derived TEXT[] := ARRAY[
    'device_software', 'alerts', 'tasks', 'process_events', 'admin_access_requests',
    'admin_session_changes', 'recovery_key_escrow', 'device_group_members',
    'policy_assignments', 'script_results', 'password_reset_tokens'
  ];
BEGIN
  FOREACH t IN ARRAY own LOOP
    IF to_regclass(t) IS NULL THEN
      CONTINUE;
    END IF;
    EXECUTE format('ALTER TABLE %I ADD COLUMN IF NOT EXISTS tenant_id UUID', t);
    EXECUTE format('UPDATE %I SET tenant_id = $1 WHERE tenant_id IS NULL', t) USING def;
    EXECUTE format('ALTER TABLE %I ALTER COLUMN tenant_id SET DEFAULT %L', t, def);
    IF EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public' AND table_name = t AND column_name = 'tenant_id' AND is_nullable = 'YES'
    ) THEN
      EXECUTE format('ALTER TABLE %I ALTER COLUMN tenant_id SET NOT NULL', t);
    END IF;
    IF NOT EXISTS (
      SELECT 1 FROM pg_constraint WHERE conname = t || '_tenant_id_fkey'
    ) THEN
      EXECUTE format(
        'ALTER TABLE %I ADD CONSTRAINT %I FOREIGN KEY (tenant_id) REFERENCES tenants(id)',
        t, t || '_tenant_id_fkey');
    END IF;
    EXECUTE format('CREATE INDEX IF NOT EXISTS %I ON %I (tenant_id)', 'idx_' || t || '_tenant', t);
  END LOOP;

  -- derived: бэкфилл с родителя. script_results в схеме имеет device_id (не script_id) —
  -- копируем с devices; классификация Parent=scripts остаётся про смысл владения.
  IF to_regclass('device_software') IS NOT NULL THEN
    ALTER TABLE device_software ADD COLUMN IF NOT EXISTS tenant_id UUID;
    UPDATE device_software c SET tenant_id = d.tenant_id
      FROM devices d WHERE c.device_id = d.id AND c.tenant_id IS NULL;
  END IF;
  IF to_regclass('alerts') IS NOT NULL THEN
    ALTER TABLE alerts ADD COLUMN IF NOT EXISTS tenant_id UUID;
    UPDATE alerts c SET tenant_id = d.tenant_id
      FROM devices d WHERE c.device_id = d.id AND c.tenant_id IS NULL;
  END IF;
  IF to_regclass('tasks') IS NOT NULL THEN
    ALTER TABLE tasks ADD COLUMN IF NOT EXISTS tenant_id UUID;
    UPDATE tasks c SET tenant_id = d.tenant_id
      FROM devices d WHERE c.device_id = d.id AND c.tenant_id IS NULL;
  END IF;
  IF to_regclass('process_events') IS NOT NULL THEN
    ALTER TABLE process_events ADD COLUMN IF NOT EXISTS tenant_id UUID;
    UPDATE process_events c SET tenant_id = d.tenant_id
      FROM devices d WHERE c.device_id = d.id AND c.tenant_id IS NULL;
  END IF;
  IF to_regclass('admin_access_requests') IS NOT NULL THEN
    ALTER TABLE admin_access_requests ADD COLUMN IF NOT EXISTS tenant_id UUID;
    UPDATE admin_access_requests c SET tenant_id = d.tenant_id
      FROM devices d WHERE c.device_id = d.id AND c.tenant_id IS NULL;
  END IF;
  IF to_regclass('admin_session_changes') IS NOT NULL THEN
    ALTER TABLE admin_session_changes ADD COLUMN IF NOT EXISTS tenant_id UUID;
    UPDATE admin_session_changes c SET tenant_id = d.tenant_id
      FROM devices d WHERE c.device_id = d.id AND c.tenant_id IS NULL;
  END IF;
  IF to_regclass('recovery_key_escrow') IS NOT NULL THEN
    ALTER TABLE recovery_key_escrow ADD COLUMN IF NOT EXISTS tenant_id UUID;
    UPDATE recovery_key_escrow c SET tenant_id = d.tenant_id
      FROM devices d WHERE c.device_id = d.id AND c.tenant_id IS NULL;
  END IF;
  IF to_regclass('device_group_members') IS NOT NULL THEN
    ALTER TABLE device_group_members ADD COLUMN IF NOT EXISTS tenant_id UUID;
    UPDATE device_group_members c SET tenant_id = g.tenant_id
      FROM device_groups g WHERE c.group_id = g.id AND c.tenant_id IS NULL;
  END IF;
  IF to_regclass('policy_assignments') IS NOT NULL THEN
    ALTER TABLE policy_assignments ADD COLUMN IF NOT EXISTS tenant_id UUID;
    UPDATE policy_assignments c SET tenant_id = p.tenant_id
      FROM policies p WHERE c.policy_id = p.id AND c.tenant_id IS NULL;
  END IF;
  IF to_regclass('script_results') IS NOT NULL THEN
    ALTER TABLE script_results ADD COLUMN IF NOT EXISTS tenant_id UUID;
    UPDATE script_results c SET tenant_id = d.tenant_id
      FROM devices d WHERE c.device_id = d.id AND c.tenant_id IS NULL;
  END IF;
  IF to_regclass('password_reset_tokens') IS NOT NULL THEN
    ALTER TABLE password_reset_tokens ADD COLUMN IF NOT EXISTS tenant_id UUID;
    UPDATE password_reset_tokens c SET tenant_id = u.tenant_id
      FROM users u WHERE c.user_id = u.id AND c.tenant_id IS NULL;
  END IF;

  FOREACH t IN ARRAY derived LOOP
    IF to_regclass(t) IS NULL THEN
      CONTINUE;
    END IF;
    EXECUTE format('UPDATE %I SET tenant_id = $1 WHERE tenant_id IS NULL', t) USING def;
    EXECUTE format('ALTER TABLE %I ALTER COLUMN tenant_id SET DEFAULT %L', t, def);
    IF EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = 'public' AND table_name = t AND column_name = 'tenant_id' AND is_nullable = 'YES'
    ) THEN
      EXECUTE format('ALTER TABLE %I ALTER COLUMN tenant_id SET NOT NULL', t);
    END IF;
    IF NOT EXISTS (
      SELECT 1 FROM pg_constraint WHERE conname = t || '_tenant_id_fkey'
    ) THEN
      EXECUTE format(
        'ALTER TABLE %I ADD CONSTRAINT %I FOREIGN KEY (tenant_id) REFERENCES tenants(id)',
        t, t || '_tenant_id_fkey');
    END IF;
    EXECUTE format('CREATE INDEX IF NOT EXISTS %I ON %I (tenant_id)', 'idx_' || t || '_tenant', t);
  END LOOP;
END $$;

-- ===========================================================================
-- 5. Уникальные индексы → пер-тенантные (§6.1)
-- ===========================================================================

DROP INDEX IF EXISTS device_groups_name_unique;
CREATE UNIQUE INDEX IF NOT EXISTS device_groups_name_unique
  ON device_groups (tenant_id, lower(btrim(name)));

DROP INDEX IF EXISTS scripts_name_unique;
CREATE UNIQUE INDEX IF NOT EXISTS scripts_name_unique
  ON scripts (tenant_id, lower(btrim(name)));

DROP INDEX IF EXISTS policies_name_unique;
CREATE UNIQUE INDEX IF NOT EXISTS policies_name_unique
  ON policies (tenant_id, lower(btrim(name)));

ALTER TABLE users DROP CONSTRAINT IF EXISTS users_email_key;
DROP INDEX IF EXISTS users_email_key;
CREATE UNIQUE INDEX IF NOT EXISTS users_tenant_email_unique
  ON users (tenant_id, lower(email));

ALTER TABLE directory_persons DROP CONSTRAINT IF EXISTS directory_persons_object_guid_key;
DROP INDEX IF EXISTS directory_persons_object_guid_key;
CREATE UNIQUE INDEX IF NOT EXISTS directory_persons_tenant_object_guid_unique
  ON directory_persons (tenant_id, object_guid);

DROP INDEX IF EXISTS idx_directory_persons_sid;
CREATE UNIQUE INDEX IF NOT EXISTS idx_directory_persons_sid
  ON directory_persons (tenant_id, object_sid) WHERE object_sid IS NOT NULL;

DROP INDEX IF EXISTS idx_audit_log_seq;
CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_log_seq
  ON audit_log (tenant_id, seq) WHERE seq IS NOT NULL;

DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'audit_anchors_pkey'
  ) AND EXISTS (
    SELECT 1
    FROM pg_constraint c
    JOIN unnest(c.conkey) WITH ORDINALITY AS k(attnum, ord) ON true
    JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.attnum
    WHERE c.conname = 'audit_anchors_pkey'
    GROUP BY c.oid
    HAVING COUNT(*) = 1 AND bool_or(a.attname = 'seq')
  ) THEN
    ALTER TABLE audit_anchors DROP CONSTRAINT audit_anchors_pkey;
    ALTER TABLE audit_anchors ADD PRIMARY KEY (tenant_id, seq);
  ELSIF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'audit_anchors_pkey'
  ) THEN
    ALTER TABLE audit_anchors ADD PRIMARY KEY (tenant_id, seq);
  END IF;
END $$;

-- ---------------------------------------------------------------------------
-- DOWN (применять вручную; безопасен только на одно-тенантной инсталляции)
-- ---------------------------------------------------------------------------
-- ALTER TABLE audit_anchors DROP CONSTRAINT IF EXISTS audit_anchors_pkey;
-- ALTER TABLE audit_anchors ADD PRIMARY KEY (seq);
-- DROP INDEX IF EXISTS idx_audit_log_seq;
-- CREATE UNIQUE INDEX idx_audit_log_seq ON audit_log (seq) WHERE seq IS NOT NULL;
-- … далее DROP INDEX пер-тенантных, восстановление глобальных UNIQUE,
-- DROP COLUMN tenant_id, DROP TABLE tenants;
