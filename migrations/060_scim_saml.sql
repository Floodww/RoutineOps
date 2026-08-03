-- 060_scim_saml.sql
-- Q-45 (SCIM), Q-46 (SAML)

SET lock_timeout = '5s';

-- SCIM tokens will use existing api_tokens table, no new table needed.
-- SAML providers configuration
CREATE TABLE saml_providers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    idp_metadata_url TEXT,
    idp_metadata_xml TEXT,
    sp_entity_id TEXT NOT NULL,
    sp_acs_url TEXT NOT NULL,
    -- Ключевая пара SP хранится ЗДЕСЬ, а не генерируется в памяти при старте:
    -- IdP пинит сертификат SP, и пересоздание пары на каждом рестарте ломало бы
    -- доверие после любого деплоя. Приватник — в конверте AES-GCM (v1:...), как
    -- client_secret у OIDC (050): ключ выводится HKDF из JWT-секрета.
    sp_private_key TEXT,
    sp_certificate TEXT,
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX saml_providers_tenant_name_idx ON saml_providers(tenant_id, name);
CREATE INDEX idx_saml_providers_tenant ON saml_providers (tenant_id);

-- 🔴 RLS обязателен, и по той же причине, по которой он появился у oidc_providers
-- в 051: строка содержит конфигурацию входа в КОНКРЕТНЫЙ тенант. Без политики
-- любой запрос читает и правит чужого IdP — то есть чужую дверь. Предикат тот же,
-- что у остальных ScopeOwn-таблиц (046), GUC `routineops.tenant_id` с missing_ok.
ALTER TABLE saml_providers ENABLE ROW LEVEL SECURITY;
ALTER TABLE saml_providers FORCE ROW LEVEL SECURITY;
CREATE POLICY saml_providers_tenant_isolation ON saml_providers
  USING (tenant_id = current_setting('routineops.tenant_id', true)::uuid)
  WITH CHECK (tenant_id = current_setting('routineops.tenant_id', true)::uuid);

-- Анонимные begin/acs идут ДО того, как тенант известен (провайдер и определяет
-- тенант), поэтому им нужен тот же SECURITY DEFINER-обход, что у OIDC в 051.
CREATE OR REPLACE FUNCTION auth_saml_provider(p_id UUID)
RETURNS TABLE (
  id UUID, tenant_id UUID, name TEXT, idp_metadata_url TEXT, idp_metadata_xml TEXT,
  sp_entity_id TEXT, sp_acs_url TEXT, enabled BOOLEAN,
  sp_private_key TEXT, sp_certificate TEXT
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT s.id, s.tenant_id, s.name, s.idp_metadata_url, s.idp_metadata_xml,
         s.sp_entity_id, s.sp_acs_url, s.enabled, s.sp_private_key, s.sp_certificate
  FROM saml_providers s WHERE s.id = p_id AND s.enabled;
$$;

-- DOWN:
-- DROP FUNCTION IF EXISTS auth_saml_provider(UUID);
-- DROP TABLE IF EXISTS saml_providers;
