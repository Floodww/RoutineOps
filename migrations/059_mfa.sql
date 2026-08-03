-- 059_mfa.sql
-- Q-44 (MFA): Добавление полей для TOTP MFA к личностям и политики к тенантам.

SET lock_timeout = '5s';

ALTER TABLE identities
    ADD COLUMN IF NOT EXISTS mfa_enabled BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS mfa_secret TEXT,
    ADD COLUMN IF NOT EXISTS recovery_codes TEXT[];

ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS require_mfa BOOLEAN NOT NULL DEFAULT false;

DROP FUNCTION IF EXISTS auth_identity_by_email(TEXT);

CREATE OR REPLACE FUNCTION auth_identity_by_email(p_email TEXT)
RETURNS TABLE (
  id UUID, email TEXT, password_hash TEXT, password_changed_at TIMESTAMPTZ,
  is_provider_admin BOOLEAN, created_at TIMESTAMPTZ,
  mfa_enabled BOOLEAN, mfa_secret TEXT, recovery_codes TEXT[]
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT i.id, i.email, i.password_hash, i.password_changed_at, i.is_provider_admin, i.created_at,
         i.mfa_enabled, i.mfa_secret, i.recovery_codes
  FROM identities i WHERE lower(i.email) = lower(p_email);
$$;

-- mfa_secret должен быть зашифрован (AES-GCM), так же как client_secret OIDC в 050
-- recovery_codes — массив хэшей (например, SHA-256 или bcrypt)
