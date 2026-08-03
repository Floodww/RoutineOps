-- 067: интерактивный сеанс с рабочим столом (docs/remote-desktop-contract.md, ADR-8).
--
-- 🔴 Формат файла: ПЛОСКИЙ SQL, без goose-аннотаций. Всё, что стоит после «-- DOWN:»,
-- закомментировано и живой SQL'ой не является.
--
-- Что здесь есть кроме таблицы, и почему это ОДНА миграция, а не три:
--
--   1. screen_sessions — журнал сеансов. Именно он, а не строка задачи, является
--      источником истины о жизни сеанса: TaskResult отдаётся сразу по исходу запроса
--      (§9.2), потому что FailStaleAckedTasks помечает failed любую задачу, висящую
--      в 'acked' дольше пятнадцати минут.
--   2. tenants.screen_access_mode — режим доступа (§4). Владелец разрешил unattended,
--      но заказчик в юрисдикции с обязательным уведомлением работника обязан иметь
--      возможность включить consent_required, НЕ пересобирая агента.
--   3. users.can_view_session_recording — отзываемый грант на просмотр записи (§5),
--      по форме can_reveal_escrow: право, а не роль (requireRole сравнивает строку,
--      роль в JWT одна).
--   4. devices.capabilities — что умеет БИНАРЬ на устройстве. Версии для гейта мало:
--      free-сборка той же версии удалённого стола не содержит вовсе, файлы вырезаны
--      тегом сборки (§9.17).
--   5. Дописывание screen_sessions в жёстко зашитые массивы 056 и 057. Без этого
--      перенос устройства и слияние тенанта оставили бы строки сеансов в старом
--      тенанте — под RLS они стали бы невидимы, но никуда бы не делись. Гейт
--      TestEveryTableClassified эти массивы не видит, поэтому правка едет здесь, той
--      же миграцией, что и таблица.

SET lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS screen_sessions (
    id             UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id      UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    device_id      UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,

    -- Кто смотрит. operator_id обнуляется вместе с учёткой, а e-mail остаётся:
    -- удалённый оператор не должен обезличивать уже состоявшийся сеанс.
    operator_id    UUID REFERENCES users(id) ON DELETE SET NULL,
    operator_email TEXT NOT NULL,

    -- Повод обязателен (§4). Оператор, которому нечего написать, не имеет причины
    -- подключаться; NOT NULL здесь — это и есть обязательность.
    reason         TEXT NOT NULL,

    mode           TEXT NOT NULL DEFAULT 'unattended',  -- unattended | consent_required
    profile        TEXT NOT NULL DEFAULT 'low',

    -- requested → active → ended. Промежуточного «умер, но мы не знаем» нет
    -- намеренно: сервер не имеет права держать сеанс активным, ожидая корректного
    -- закрытия (§7), обрыв стрима переводит в ended сам.
    status         TEXT NOT NULL DEFAULT 'requested',
    end_reason     TEXT,
    end_detail     TEXT,

    task_id        UUID,
    width          INTEGER,
    height         INTEGER,
    frames         BIGINT NOT NULL DEFAULT 0,
    bytes          BIGINT NOT NULL DEFAULT 0,

    -- Путь БЕЗ tenant_id внутри (§5): тенант живёт в этой строке, иначе перенос
    -- устройства между тенантами потребовал бы двигать байты по диску.
    recording_path TEXT,

    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at     TIMESTAMPTZ,
    ended_at       TIMESTAMPTZ,
    -- last_viewer_at — viewer-liveness (§9.9): нет запроса от аутентифицированного
    -- зрителя дольше потолка → сеанс закрывается. Иначе захват и запись продолжаются
    -- при закрытой вкладке.
    last_viewer_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_screen_sessions_tenant  ON screen_sessions (tenant_id);
CREATE INDEX IF NOT EXISTS idx_screen_sessions_device  ON screen_sessions (device_id, created_at DESC);
-- Частичный индекс под два горячих запроса: «есть ли живой сеанс на устройстве» и
-- подметание зависших. По всей таблице он был бы бесполезен — живых сеансов единицы.
CREATE INDEX IF NOT EXISTS idx_screen_sessions_live    ON screen_sessions (status, last_viewer_at)
    WHERE status IN ('requested', 'active');

ALTER TABLE screen_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE screen_sessions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS screen_sessions_tenant_isolation ON screen_sessions;
CREATE POLICY screen_sessions_tenant_isolation ON screen_sessions
  USING (tenant_id = current_setting('routineops.tenant_id', true)::uuid)
  WITH CHECK (tenant_id = current_setting('routineops.tenant_id', true)::uuid);

-- Режим доступа — свойство тенанта, а не константа кода (§4).
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS screen_access_mode TEXT NOT NULL DEFAULT 'unattended';

-- Право пересматривать записи (§5, решение владельца): только it_admin, и сам факт
-- просмотра пишется в аудит. Грант отзываемый — как can_reveal_escrow.
ALTER TABLE users ADD COLUMN IF NOT EXISTS can_view_session_recording BOOLEAN NOT NULL DEFAULT false;

-- Способности агентского бинаря. NULL и пустой массив означают «не сообщал» —
-- гейт обязан считать это отсутствием способности, а не разрешением.
ALTER TABLE devices ADD COLUMN IF NOT EXISTS capabilities TEXT[];

-- ---------------------------------------------------------------------------
-- Дописывание в жёстко зашитые массивы 056/057.
--
-- Функции пересоздаются целиком: PL/pgSQL не умеет «добавить элемент в массив в
-- теле существующей функции», а ALTER FUNCTION меняет только атрибуты. Тела ниже —
-- копии оригиналов ПЛЮС screen_sessions; расхождение с оригиналом, кроме этой
-- строки, было бы ошибкой.
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION admin_reparent_tenant(p_src UUID, p_dst UUID)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  src_name TEXT;
  t        TEXT;
BEGIN
  SELECT name INTO src_name FROM tenants WHERE id = p_src;

  DELETE FROM users u
   WHERE u.tenant_id = p_src
     AND EXISTS (SELECT 1 FROM users d
                  WHERE d.tenant_id = p_dst AND d.identity_id = u.identity_id);

  FOREACH t IN ARRAY ARRAY['device_groups', 'scripts', 'policies'] LOOP
    EXECUTE format(
      'UPDATE %I s SET name = s.name || '' (из '' || $2 || '')''
         WHERE s.tenant_id = $1
           AND EXISTS (SELECT 1 FROM %I d
                        WHERE d.tenant_id = $3 AND lower(d.name) = lower(s.name))',
      t, t) USING p_src, COALESCE(src_name, 'удалённого тенанта'), p_dst;
  END LOOP;

  FOREACH t IN ARRAY ARRAY[
    'devices', 'device_software', 'alerts', 'tasks', 'process_events',
    'admin_access_requests', 'admin_session_changes', 'recovery_key_escrow',
    'device_groups', 'device_group_members', 'policy_assignments',
    'scripts', 'script_results', 'policies', 'software_policy_rules',
    'enrollment_tokens', 'invitation_tokens', 'password_reset_tokens',
    'directory_persons', 'api_tokens', 'oidc_providers', 'users',
    'screen_sessions'
  ] LOOP
    EXECUTE format('UPDATE %I SET tenant_id = $2 WHERE tenant_id = $1', t)
      USING p_src, p_dst;
  END LOOP;

  UPDATE tenants SET deleted_at = now() WHERE id = p_src;
END;
$$;

CREATE OR REPLACE FUNCTION admin_move_device_tenant(p_device UUID, p_dst UUID)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  t TEXT;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM devices WHERE id = p_device) THEN
    RAISE EXCEPTION 'device % not found', p_device USING ERRCODE = 'no_data_found';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM tenants WHERE id = p_dst AND deleted_at IS NULL) THEN
    RAISE EXCEPTION 'tenant % not found', p_dst USING ERRCODE = 'no_data_found';
  END IF;

  DELETE FROM device_group_members WHERE device_id = p_device;

  FOREACH t IN ARRAY ARRAY[
    'device_software', 'alerts', 'tasks', 'process_events',
    'admin_access_requests', 'admin_session_changes', 'recovery_key_escrow',
    'screen_sessions'
  ] LOOP
    EXECUTE format('UPDATE %I SET tenant_id = $2 WHERE device_id = $1', t)
      USING p_device, p_dst;
  END LOOP;

  UPDATE devices SET tenant_id = p_dst, owner_directory_id = NULL WHERE id = p_device;
END;
$$;

-- DOWN:
-- DROP TABLE IF EXISTS screen_sessions;
-- ALTER TABLE tenants DROP COLUMN IF EXISTS screen_access_mode;
-- ALTER TABLE users   DROP COLUMN IF EXISTS can_view_session_recording;
-- ALTER TABLE devices DROP COLUMN IF EXISTS capabilities;
-- Функции 056/057 остаются в версии с screen_sessions: откат таблицы делает
-- соответствующий UPDATE безвредным no-op'ом, а восстановление старых тел
-- потребовало бы их дубля здесь третьим экземпляром.
