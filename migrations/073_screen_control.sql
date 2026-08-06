-- 073: управление в интерактивном сеансе (Ф3, docs/remote-desktop-contract.md §9.21).
--
-- 🔴 Формат файла: ПЛОСКИЙ SQL, без goose-аннотаций. Всё, что стоит после «-- DOWN:»,
-- закомментировано и живой SQL'ой не является.
--
-- Что здесь есть и почему это ОДНА миграция:
--
--   1. screen_sessions.control — сеанс запрошен С УПРАВЛЕНИЕМ. Свойство сеанса, а не
--      флаг в запросе: расширение области требует НОВОГО приглашения (§4 п.5), поэтому
--      колонка выставляется один раз при создании и дальше только снимается возвратом
--      управления.
--   2. screen_sessions.control_returned_at — когда управление вернули сотруднику.
--      §9.21 п.3 требует ОТДЕЛЬНЫХ событий на передачу и возврат: без момента возврата
--      «окно неатрибутируемости» считалось бы до конца сеанса, то есть шире, чем было.
--   3. screen_input_events — структурированный журнал ввода (§9.21 п.1). Отдельная
--      таблица, а не строки в audit_log: у аудита хеш-цепочка на тенанта, и десятки
--      строк в секунду от одного сеанса растворили бы в ней всё остальное.
--      Печатные символы сюда НЕ пишутся (§9.21 п.6) — только их количество.
--   4. Дописывание обеих таблиц в жёстко зашитые массивы 056/057 (как это делала 067).
--      Без этого перенос устройства и слияние тенанта оставили бы журнал ввода в старом
--      тенанте: под RLS он стал бы невидим, но никуда бы не делся.

SET lock_timeout = '5s';

ALTER TABLE screen_sessions ADD COLUMN IF NOT EXISTS control BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE screen_sessions ADD COLUMN IF NOT EXISTS control_returned_at TIMESTAMPTZ;

COMMENT ON COLUMN screen_sessions.control IS
  'Сеанс запрошен с управлением (Ф3). Область объявляется приглашением и на лету не расширяется.';
COMMENT ON COLUMN screen_sessions.control_returned_at IS
  'Момент возврата управления сотруднику. Закрывает окно неатрибутируемости раньше конца сеанса.';

CREATE TABLE IF NOT EXISTS screen_input_events (
    id          BIGSERIAL PRIMARY KEY,
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- device_id денормализован — как в admin_session_changes и screen_sessions:
    -- RLS-предикат не должен ходить по FK на каждую строку, а строк здесь много.
    device_id   UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    session_id  UUID NOT NULL REFERENCES screen_sessions(id) ON DELETE CASCADE,

    -- Оператор. id обнуляется вместе с учёткой, e-mail остаётся: удалённый оператор не
    -- должен обезличивать уже совершённые под чужой учётной записью действия.
    operator_id    UUID REFERENCES users(id) ON DELETE SET NULL,
    operator_email TEXT NOT NULL,

    -- kind: control_granted | control_returned | click | key | text | scroll | move
    kind        TEXT NOT NULL,

    -- detail — код клавиши или кнопка. Для kind='text' здесь ПУСТО: печатные символы не
    -- пишутся по умолчанию (§9.21 п.6), а полный keylog — отдельный выключенный режим со
    -- своим грантом, которого в этой миграции нет.
    detail      TEXT NOT NULL DEFAULT '',

    -- events — сколько событий свёрнуто в строку. Движения мыши и набор текста пишутся
    -- агрегатами: строка на каждое движение — это десятки строк в секунду на сеанс, и
    -- журнал перестал бы быть читаемым ровно тогда, когда понадобится.
    events      INTEGER NOT NULL DEFAULT 1,

    -- offset_ms — от начала сеанса, а не абсолютное время: журнал ввода смотрят рядом с
    -- записью сеанса, и «на 14-й минуте» полезнее, чем «в 14:37:02».
    offset_ms   BIGINT NOT NULL DEFAULT 0,

    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_screen_input_events_session
  ON screen_input_events (session_id, offset_ms);
CREATE INDEX IF NOT EXISTS idx_screen_input_events_tenant
  ON screen_input_events (tenant_id, created_at DESC);
-- Под выгрузку «окна неатрибутируемости» по устройству и по персоне (§9.21 п.4).
CREATE INDEX IF NOT EXISTS idx_screen_input_events_device
  ON screen_input_events (device_id, created_at DESC);

ALTER TABLE screen_input_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE screen_input_events FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS screen_input_events_tenant_isolation ON screen_input_events;
CREATE POLICY screen_input_events_tenant_isolation ON screen_input_events
  USING (tenant_id = current_setting('routineops.tenant_id', true)::uuid)
  WITH CHECK (tenant_id = current_setting('routineops.tenant_id', true)::uuid);

-- ---------------------------------------------------------------------------
-- Дописывание в жёстко зашитые массивы 056/057.
--
-- Функции пересоздаются целиком: PL/pgSQL не умеет «добавить элемент в массив в теле
-- существующей функции». Тела ниже — копии версии из 067 ПЛЮС screen_input_events;
-- расхождение с ними, кроме этой строки, было бы ошибкой. Гейт
-- TestScopedTablesAreReparented смотрит на ЭТОТ файл (константы в tables_test.go).
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
    'screen_sessions', 'screen_input_events'
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
    'screen_sessions', 'screen_input_events'
  ] LOOP
    EXECUTE format('UPDATE %I SET tenant_id = $2 WHERE device_id = $1', t)
      USING p_device, p_dst;
  END LOOP;

  UPDATE devices SET tenant_id = p_dst, owner_directory_id = NULL WHERE id = p_device;
END;
$$;

-- DOWN:
-- DROP TABLE IF EXISTS screen_input_events;
-- ALTER TABLE screen_sessions DROP COLUMN IF EXISTS control;
-- ALTER TABLE screen_sessions DROP COLUMN IF EXISTS control_returned_at;
-- Функции 056/057 остаются в версии с screen_input_events: откат таблицы делает
-- соответствующий UPDATE безвредным no-op'ом, а восстановление прежних тел потребовало
-- бы их третьего экземпляра в дереве.
