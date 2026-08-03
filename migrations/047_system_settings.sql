-- 047: system_settings → mixed (§8 шаг 8, контракт §3.4).
--
-- tenant_id NOT NULL DEFAULT нулевого UUID = install-default.
-- Строка с реальным tenant_id = переопределение. PK (key, tenant_id).
-- FK на tenants нет: нулевой UUID — маркер, не строка реестра.
SET lock_timeout = '5s';

ALTER TABLE system_settings ADD COLUMN IF NOT EXISTS tenant_id UUID;

UPDATE system_settings
SET tenant_id = '00000000-0000-0000-0000-000000000000'
WHERE tenant_id IS NULL;

ALTER TABLE system_settings ALTER COLUMN tenant_id SET DEFAULT '00000000-0000-0000-0000-000000000000';
ALTER TABLE system_settings ALTER COLUMN tenant_id SET NOT NULL;

ALTER TABLE system_settings DROP CONSTRAINT IF EXISTS system_settings_pkey;
ALTER TABLE system_settings ADD PRIMARY KEY (key, tenant_id);

-- Mixed RLS: свой тенант + install-default на чтение; писать — только свой тенант.
ALTER TABLE system_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE system_settings FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS system_settings_tenant_isolation ON system_settings;
CREATE POLICY system_settings_tenant_isolation ON system_settings
  USING (
    tenant_id = current_setting('routineops.tenant_id', true)::uuid
    OR tenant_id = '00000000-0000-0000-0000-000000000000'::uuid
  )
  WITH CHECK (
    tenant_id = current_setting('routineops.tenant_id', true)::uuid
  );

-- Резолв tenant_id устройства до BindTenant (CreateAlert и др.).
CREATE OR REPLACE FUNCTION auth_device_tenant(p_device_id UUID)
RETURNS UUID
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT d.tenant_id FROM devices d WHERE d.id = p_device_id;
$$;

-- DOWN:
-- DROP FUNCTION IF EXISTS auth_device_tenant(UUID);
-- DROP POLICY IF EXISTS system_settings_tenant_isolation ON system_settings;
-- ALTER TABLE system_settings NO FORCE ROW LEVEL SECURITY;
-- ALTER TABLE system_settings DISABLE ROW LEVEL SECURITY;
-- ALTER TABLE system_settings DROP CONSTRAINT system_settings_pkey;
-- ALTER TABLE system_settings ADD PRIMARY KEY (key);
-- ALTER TABLE system_settings DROP COLUMN tenant_id;
