-- 064: у сервисного токена появляется ОБЛАСТЬ (Q-61).
--
-- 🔴 Формат — плоский SQL, без `-- +goose Up/Down`: см. шапку 061. Down живёт
-- комментарием, иначе psql выполнит его как живой SQL сразу после Up.
--
-- Зачем. У SCIM сознательно снят requireHuman: провизионинг по определению ходит
-- машиной, а не человеком. Но отдельной области у токена не было, поэтому в
-- /scim/v2/* проходил ЛЮБОЙ сервисный токен с ролью it_admin — то есть токен,
-- выданный под сборку или мониторинг, умел заводить и удалять пользователей панели.
-- Это штатный обход правила «всё, что выпускает или повышает права, — только
-- человеком», и обходился он одной строкой в чужом CI.
--
-- Область — это СУЖЕНИЕ, а не расширение: пустая строка означает прежнее поведение
-- (токен ходит всюду, куда пускает роль), 'scim' — «только SCIM и больше никуда».
-- Дефолт пустой намеренно: уже выпущенные токены не должны сломаться при накатке.

SET lock_timeout = '5s';

ALTER TABLE api_tokens ADD COLUMN scope TEXT NOT NULL DEFAULT '';
ALTER TABLE api_tokens ADD CONSTRAINT api_tokens_scope_check CHECK (scope IN ('', 'scim'));

-- Функция аутентификации обязана отдавать область: решение о доступе принимается
-- в миддлваре ДО хендлера, и второй поход в БД за областью означал бы, что она
-- читается не тем же запросом, который проверял срок жизни токена.
--
-- 🔴 DROP + CREATE, а не CREATE OR REPLACE: у функции меняется СОСТАВ возвращаемых
-- колонок, а replace такого не допускает (ERROR: cannot change return type).
DROP FUNCTION IF EXISTS auth_api_token_touch(TEXT);
CREATE FUNCTION auth_api_token_touch(p_hash TEXT)
RETURNS TABLE (
  id UUID, tenant_id UUID, name TEXT, role TEXT, scope TEXT, created_by UUID,
  created_at TIMESTAMPTZ, expires_at TIMESTAMPTZ, last_used_at TIMESTAMPTZ
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
  UPDATE api_tokens a SET last_used_at = now()
  WHERE a.token_hash = p_hash AND (a.expires_at IS NULL OR a.expires_at > now())
  RETURNING a.id, a.tenant_id, a.name, a.role, a.scope, a.created_by,
            a.created_at, a.expires_at, a.last_used_at;
$$;

-- DOWN:
-- DROP FUNCTION IF EXISTS auth_api_token_touch(TEXT);
-- CREATE FUNCTION auth_api_token_touch(p_hash TEXT)
-- RETURNS TABLE (id UUID, tenant_id UUID, name TEXT, role TEXT, created_by UUID,
--   created_at TIMESTAMPTZ, expires_at TIMESTAMPTZ, last_used_at TIMESTAMPTZ)
-- LANGUAGE sql SECURITY DEFINER SET search_path = public AS $$
--   UPDATE api_tokens a SET last_used_at = now()
--   WHERE a.token_hash = p_hash AND (a.expires_at IS NULL OR a.expires_at > now())
--   RETURNING a.id, a.tenant_id, a.name, a.role, a.created_by,
--             a.created_at, a.expires_at, a.last_used_at;
-- $$;
-- ALTER TABLE api_tokens DROP CONSTRAINT IF EXISTS api_tokens_scope_check;
-- ALTER TABLE api_tokens DROP COLUMN IF EXISTS scope;
