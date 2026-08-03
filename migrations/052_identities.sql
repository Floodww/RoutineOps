-- 052_identities.sql
-- ADR-7 (контракт §11): личность отделяется от членства.
--
-- До этой миграции строка в users была одновременно и человеком (пароль), и его
-- членством в тенанте (роль). Из-за этого один человек не мог состоять в двух
-- тенантах, а 045, сделав e-mail уникальным пер-тенантно, превратил это в дыру:
-- логин резолвится ДО тенанта, и auth_user_by_email на дубле отдавал две строки,
-- вызывающий брал первую (Q-22).
--
-- Здесь: identities = человек (глобально уникальный e-mail + пароль),
-- users = членство (тенант + роль). Пароль уезжает наверх, роль остаётся внизу.
-- provider_admin становится признаком личности (решение флуда 29.07): надзор над
-- инсталляцией не зависит от того, какой тенант человек сейчас выбрал.
--
-- users.password_hash / password_changed_at ЗДЕСЬ НЕ УДАЛЯЮТСЯ — только теряют
-- NOT NULL и перестают быть источником истины. Снос — миграция 053, после того как
-- код перестанет их читать. Иначе откат этой миграции терял бы пароли.
SET lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS identities (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email               TEXT        NOT NULL,
    password_hash       TEXT        NOT NULL,
    password_changed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Надзор над всей инсталляцией. Не роль в тенанте: ортогонален users.role,
    -- иерархии ролей не вводит (контракт §4, §11.3).
    is_provider_admin   BOOLEAN     NOT NULL DEFAULT false,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS identities_email_unique ON identities (lower(email));

-- ---------------------------------------------------------------------------
-- Бэкфилл — FAIL-CLOSED.
--
-- Один человек = один пароль (решение флуда 29.07). Совпадающие хеши на одном
-- адресе схлопываются в одну личность — это и есть мульти-членство. РАЗНЫЕ хеши
-- означают, что под одним адресом в разных тенантах живут разные люди либо пароль
-- где-то менялся врозь; молча выбрать один из них значит либо запереть человека,
-- либо отдать чужой тенант. Поэтому миграция падает со списком конфликтов.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
  conflicts TEXT;
BEGIN
  SELECT string_agg(DISTINCT lower(email), ', ')
    INTO conflicts
    FROM users
   GROUP BY lower(email)
  HAVING count(DISTINCT password_hash) > 1;

  IF conflicts IS NOT NULL THEN
    RAISE EXCEPTION
      'ADR-7 backfill: у одного e-mail разные password_hash в разных тенантах: %. '
      'Один человек = один пароль. Приведите пароли к одному (или разведите адреса) '
      'и повторите миграцию.', conflicts;
  END IF;
END $$;

INSERT INTO identities (email, password_hash, password_changed_at, is_provider_admin, created_at)
SELECT DISTINCT ON (lower(u.email))
       u.email,
       u.password_hash,
       -- Самая поздняя смена пароля: token-epoch не должен «поехать назад» и
       -- воскресить токены, отозванные сменой пароля в другом тенанте.
       max(u.password_changed_at) OVER (PARTITION BY lower(u.email)),
       bool_or(u.role = 'provider_admin') OVER (PARTITION BY lower(u.email)),
       min(u.created_at) OVER (PARTITION BY lower(u.email))
  FROM users u
 ORDER BY lower(u.email), u.created_at
ON CONFLICT DO NOTHING;

ALTER TABLE users ADD COLUMN IF NOT EXISTS identity_id UUID;

UPDATE users u
   SET identity_id = i.id
  FROM identities i
 WHERE lower(i.email) = lower(u.email)
   AND u.identity_id IS NULL;

ALTER TABLE users ALTER COLUMN identity_id SET NOT NULL;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'users_identity_id_fkey') THEN
    ALTER TABLE users
      ADD CONSTRAINT users_identity_id_fkey
      FOREIGN KEY (identity_id) REFERENCES identities(id) ON DELETE CASCADE;
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_users_identity ON users (identity_id);

-- Одно членство человека в тенанте. Две строки означали бы две роли сразу —
-- какая из них действует, было бы неопределено.
CREATE UNIQUE INDEX IF NOT EXISTS users_identity_tenant_unique ON users (identity_id, tenant_id);

-- provider_admin переехал на личность → в тенанте роль не остаётся. Понижаем до
-- наименьшей привилегии; it_admin в конкретном тенанте выдаётся явно (§11.6).
UPDATE users SET role = 'viewer' WHERE role = 'provider_admin';

-- Источник истины по паролю — identities. Колонки в users пока живы (см. шапку),
-- но больше не обязаны быть заполненными.
ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL;

-- ---------------------------------------------------------------------------
-- Pre-auth резолв переписывается на личность.
--
-- Возвращает ЛИЧНОСТЬ, а не членство: на этом шаге тенант ещё неизвестен и не
-- может быть известен — его выбирает человек после проверки пароля. Именно
-- поэтому e-mail обязан быть глобально уникальным (контракт §6.2, §11.5).
-- ---------------------------------------------------------------------------
DROP FUNCTION IF EXISTS auth_user_by_email(TEXT);

CREATE OR REPLACE FUNCTION auth_identity_by_email(p_email TEXT)
RETURNS TABLE (
  id UUID, email TEXT, password_hash TEXT, password_changed_at TIMESTAMPTZ,
  is_provider_admin BOOLEAN, created_at TIMESTAMPTZ
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT i.id, i.email, i.password_hash, i.password_changed_at, i.is_provider_admin, i.created_at
  FROM identities i WHERE lower(i.email) = lower(p_email);
$$;

-- Членства личности: список тенантов для селектора и проверка при переключении.
-- SECURITY DEFINER — вызывается сразу после проверки пароля, когда активного
-- тенанта (а значит и GUC) ещё нет.
CREATE OR REPLACE FUNCTION auth_identity_memberships(p_identity_id UUID)
RETURNS TABLE (user_id UUID, tenant_id UUID, tenant_name TEXT, role TEXT)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT u.id, u.tenant_id, t.name, u.role
  FROM users u
  JOIN tenants t ON t.id = u.tenant_id
  WHERE u.identity_id = p_identity_id
  ORDER BY t.name, u.id;
$$;

-- Token-epoch и признак надзора теперь читаются с личности, а не с членства:
-- пароль общий, значит и отзыв токенов сменой пароля обязан быть общим.
-- DROP обязателен: CREATE OR REPLACE не меняет тип возврата существующей функции.
DROP FUNCTION IF EXISTS auth_user_password_epoch(UUID);

CREATE OR REPLACE FUNCTION auth_user_password_epoch(p_user_id UUID)
RETURNS TABLE (password_changed_at TIMESTAMPTZ, tenant_id UUID, is_provider_admin BOOLEAN, identity_id UUID)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT i.password_changed_at, u.tenant_id, i.is_provider_admin, i.id
  FROM users u JOIN identities i ON i.id = u.identity_id
  WHERE u.id = p_user_id;
$$;
