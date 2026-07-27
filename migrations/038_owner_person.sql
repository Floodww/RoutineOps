-- 038: владелец устройства — КАРТОЧКА ЧЕЛОВЕКА, а не аккаунт панели.
--
-- Было два несовместимых смысла слова «владелец»:
--   owner_id           → users            — ручная привязка (Free), т.е. аккаунт С ВХОДОМ;
--   owner_directory_id → directory_persons — авто из AD (Enterprise), человек БЕЗ входа.
-- Во Free второй всегда пуст (синка нет), поэтому записать за сотрудником его ноутбук
-- можно было только пригласив сотрудника в панель и заставив завести пароль — хотя
-- работать в панели ему незачем. Аккаунты нужны админам и поддержке, а не владельцам.
--
-- Оставляем ОДИН смысл: владелец — строка directory_persons. В Enterprise её приносит
-- AD, во Free оператор заводит руками (source='manual'). Поле в карточке устройства одно,
-- переход Free→Enterprise бесшовный: включили AD — персоны поехали сами, а ручные
-- остались (авто-матч заполняет только устройства без владельца).
--
-- Имя таблицы directory_persons историческое (справочник появился под LDAP) и намеренно
-- НЕ переименовано: переименование задело бы enterprise-код, чей CI сейчас мёртв, а
-- выигрыш чисто косметический.

-- source различает происхождение строки. Нужен не для красоты: синк каталога гасит
-- флагом disabled всё, чего не увидел в последней выдаче (MarkDirectoryPersonsStale), и
-- без этого разделения первый же синк в Enterprise погасил бы всех, кого завели руками.
ALTER TABLE directory_persons ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'ldap';

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'directory_persons_source_chk') THEN
    ALTER TABLE directory_persons
      ADD CONSTRAINT directory_persons_source_chk CHECK (source IN ('ldap', 'manual'));
  END IF;
END $$;

-- Перенос уже назначенных владельцев-аккаунтов в карточки людей. По одной карточке на
-- пользователя, даже если за ним числится несколько устройств: object_guid уникален и
-- выводится из users.id, поэтому карточки не задваиваются.
--
-- ⚠️ Шаг ОДНОРАЗОВЫЙ, в отличие от DDL выше: два оператора ниже ссылаются на owner_id,
-- которого после этой же миграции не станет. Так и задумано — миграции применяются ровно
-- один раз (учёт в schema_migrations, migrate-сервис fail-closed) и целиком в одной
-- транзакции. Запускать файл руками повторно не нужно и не получится.
INSERT INTO directory_persons (object_guid, display_name, email, source)
SELECT DISTINCT
       'migrated-user:' || u.id::text,
       COALESCE(NULLIF(btrim(u.name), ''), u.email),
       u.email,
       'manual'
FROM users u
JOIN devices d ON d.owner_id = u.id
ON CONFLICT (object_guid) DO NOTHING;

-- Привязываем устройства к перенесённым карточкам. Перезаписываем owner_directory_id
-- ДАЖЕ если он заполнен: до этой миграции при обоих заполненных полях UI показывал
-- именно owner_id (ручное намерение оператора било автоматику), и после переноса
-- оператор обязан увидеть того же владельца, что видел вчера.
UPDATE devices d
SET    owner_directory_id = p.id
FROM   users u
JOIN   directory_persons p ON p.object_guid = 'migrated-user:' || u.id::text
WHERE  d.owner_id = u.id;

-- Колонку убираем, а не оставляем «на всякий случай»: назначить её больше нечем (ручка
-- и UI переведены на персоны), так что живой она была бы только источником путаницы.
-- Побочно обнуляется admin_access_requests.requested_by у НОВЫХ заявок — оно и раньше
-- было необязательным (см. Gateway.RequestAdminAccess: «заявка оформляется и без
-- назначенного владельца»), а панель-аккаунта у владельца теперь просто не существует.
-- Уже созданные заявки не трогаются: их requested_by ссылается на users напрямую.
DROP INDEX IF EXISTS idx_devices_owner_id;
ALTER TABLE devices DROP COLUMN IF EXISTS owner_id;
