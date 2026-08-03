-- 051_oidc_tenant.sql
-- Q-20: oidc_providers вводится в мультитенантность (контракт §4, ScopeOwn).
--
-- 050 создал таблицу без tenant_id и не внёс её в список RLS из 046. Следствие:
-- IdP, заведённый одним тенантом, матчил пользователя по e-mail через глобальный
-- auth_user_by_email и выдавал JWT на чужую учётку. Тот же класс, что Q-14a.
--
-- Резолв провайдера в /auth/oidc/{id}/begin|callback происходит ДО входа, тенанта
-- в GUC ещё нет — поэтому пре-авторизационный резолв идёт через SECURITY DEFINER
-- (как auth_user_by_email в 046), а тенант берётся из вернувшейся строки.
--
-- Поправка к комментарию 050: client_secret НЕ зашифрован age/keystore — на сегодня
-- это base64 (oidc/service.go), то есть кодирование, а не шифрование. См. Q-19.
SET lock_timeout = '5s';

ALTER TABLE oidc_providers ADD COLUMN IF NOT EXISTS tenant_id UUID;

UPDATE oidc_providers
   SET tenant_id = '00000000-0000-4000-8000-000000000001'
 WHERE tenant_id IS NULL;

ALTER TABLE oidc_providers ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE oidc_providers ALTER COLUMN tenant_id SET DEFAULT '00000000-0000-4000-8000-000000000001';

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'oidc_providers_tenant_id_fkey'
  ) THEN
    ALTER TABLE oidc_providers
      ADD CONSTRAINT oidc_providers_tenant_id_fkey
      FOREIGN KEY (tenant_id) REFERENCES tenants(id);
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_oidc_providers_tenant ON oidc_providers (tenant_id);

-- RLS: тот же предикат, что у остальных ScopeOwn-таблиц в 046.
ALTER TABLE oidc_providers ENABLE ROW LEVEL SECURITY;
ALTER TABLE oidc_providers FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS oidc_providers_tenant_isolation ON oidc_providers;
CREATE POLICY oidc_providers_tenant_isolation ON oidc_providers
  USING (tenant_id = current_setting('routineops.tenant_id', true)::uuid)
  WITH CHECK (tenant_id = current_setting('routineops.tenant_id', true)::uuid);

-- ---------------------------------------------------------------------------
-- Pre-auth resolve (SECURITY DEFINER, search_path фиксирован).
-- Отдаёт строку независимо от enabled: проверку делает вызывающий, чтобы
-- «выключен» и «не существует» не схлопывались в один путь на стороне SQL.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION auth_oidc_provider(p_id UUID)
RETURNS TABLE (
  id UUID, tenant_id UUID, name TEXT, client_id TEXT, client_secret TEXT,
  issuer_url TEXT, redirect_uri TEXT, enabled BOOLEAN, created_at TIMESTAMPTZ
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT p.id, p.tenant_id, p.name, p.client_id, p.client_secret,
         p.issuer_url, p.redirect_uri, p.enabled, p.created_at
  FROM oidc_providers p WHERE p.id = p_id;
$$;
