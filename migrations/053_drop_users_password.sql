-- 053_drop_users_password.sql
-- Хвост ADR-7 (§11.6, шаг 3): снос колонок, оставшихся после 052.
--
-- 052 перенесла источник истины по паролю и надзору на identities, но колонки
-- password_hash и password_changed_at в users оставила живыми — иначе откат 052
-- терял бы пароли. Снос откладывался до тех пор, пока прод не будет пересоздан
-- с нуля (Q-21, §3 checkup.md), так что паролей, которые можно потерять, нет.
--
-- Дополнительно: provider_admin как роль в users больше не валидна (052 понизила
-- все такие строки до viewer), validRoles в коде сужается в этом же коммите.
SET lock_timeout = '5s';

-- ---------------------------------------------------------------------------
-- Fail-closed: осиротевшие членства.
--
-- Если хоть одна строка users имеет identity_id IS NULL, значит бэкфилл 052
-- не прошёл, и снос password_hash уничтожит единственную копию хеша пароля —
-- человек потеряет доступ. Падаем с внятным сообщением.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
  orphan_count BIGINT;
  orphan_emails TEXT;
BEGIN
  SELECT count(*), string_agg(email, ', ' ORDER BY email)
    INTO orphan_count, orphan_emails
    FROM users
   WHERE identity_id IS NULL;

  IF orphan_count > 0 THEN
    RAISE EXCEPTION
      '053: % строк users с identity_id IS NULL (осиротевшее членство — потеря '
      'доступа). Адреса: %. Сначала завершите бэкфилл 052.',
      orphan_count, orphan_emails;
  END IF;
END $$;

-- ---------------------------------------------------------------------------
-- Снос колонок. Источник истины — identities; код не обращается к users.*
-- по этим колонкам (проверено grep, см. implementation_plan.md).
-- ---------------------------------------------------------------------------
ALTER TABLE users DROP COLUMN IF EXISTS password_hash;
ALTER TABLE users DROP COLUMN IF EXISTS password_changed_at;
