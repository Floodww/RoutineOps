-- 044: аудит выданных админ-прав — улики сессии (дельта ПО и служб).
--
-- Контракт с агентской стороной — во внутреннем документе. Фиксируется изменение
-- ОПРЕДЕЛЕНИЙ (запись инвентаря, определение службы), не runtime. Сводка лежит
-- колонками в саму заявку: список заявок обязан рендериться без JOIN и N+1.
--
-- Идемпотентно (IF NOT EXISTS / ON CONFLICT DO NOTHING): schema_migrations в
-- проекте нет, файлы накатываются через migrate и могут применяться повторно.
SET lock_timeout = '5s';

-- ---------------------------------------------------------------------------
-- 1. Сводка на заявке
-- ---------------------------------------------------------------------------

ALTER TABLE admin_access_requests ADD COLUMN IF NOT EXISTS baseline_captured_at TIMESTAMPTZ;
ALTER TABLE admin_access_requests ADD COLUMN IF NOT EXISTS changes_final_at     TIMESTAMPTZ;
ALTER TABLE admin_access_requests ADD COLUMN IF NOT EXISTS changes_summary      JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE admin_access_requests ADD COLUMN IF NOT EXISTS changes_completeness TEXT NOT NULL DEFAULT 'unspecified';
ALTER TABLE admin_access_requests ADD COLUMN IF NOT EXISTS changes_rebooted     BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE admin_access_requests ADD COLUMN IF NOT EXISTS changes_truncated    BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE admin_access_requests ADD COLUMN IF NOT EXISTS software_health      TEXT NOT NULL DEFAULT '';
ALTER TABLE admin_access_requests ADD COLUMN IF NOT EXISTS services_health      TEXT NOT NULL DEFAULT '';
ALTER TABLE admin_access_requests ADD COLUMN IF NOT EXISTS last_window_seq      INTEGER NOT NULL DEFAULT 0;

-- ---------------------------------------------------------------------------
-- 2. Строки дельты (append-only)
-- ---------------------------------------------------------------------------
-- device_id денормализован намеренно: §5 контракта мультитенантности требует
-- дешёвого RLS-предиката без хода по FK. Классификация — в tenancy.Tables.
--
-- UNIQUE (request_id, window_seq, kind, identity_key) + ON CONFLICT DO NOTHING:
-- повторный отчёт не стирает историю (K-1). DELETE на пути приёма запрещён.

CREATE TABLE IF NOT EXISTS admin_session_changes (
  id                 UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  request_id         UUID NOT NULL REFERENCES admin_access_requests(id) ON DELETE CASCADE,
  device_id          UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  window_seq         INTEGER NOT NULL,
  kind               TEXT NOT NULL,
  subject            TEXT NOT NULL,
  display_name       TEXT NOT NULL DEFAULT '',
  identity_key       TEXT NOT NULL DEFAULT '',
  old_value          TEXT NOT NULL DEFAULT '',
  new_value          TEXT NOT NULL DEFAULT '',
  vendor             TEXT NOT NULL DEFAULT '',
  scope              TEXT NOT NULL DEFAULT '',
  attribution        TEXT NOT NULL DEFAULT 'unknown',
  attribution_reason TEXT NOT NULL DEFAULT '',
  observed_at        TIMESTAMPTZ NOT NULL,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (request_id, window_seq, kind, identity_key)
);

CREATE INDEX IF NOT EXISTS idx_admin_session_changes_request
  ON admin_session_changes(request_id);
CREATE INDEX IF NOT EXISTS idx_admin_session_changes_device
  ON admin_session_changes(device_id, created_at DESC);

-- Свипер ищет «базовая линия есть, финала нет» среди закрытых заявок. Индекс
-- узкий: открытые approved с живой сессией сюда не попадают.
CREATE INDEX IF NOT EXISTS idx_admin_access_evidence_gap
  ON admin_access_requests (status, baseline_captured_at)
  WHERE baseline_captured_at IS NOT NULL AND changes_final_at IS NULL;

-- ---------------------------------------------------------------------------
-- 3. Глобальные настройки
-- ---------------------------------------------------------------------------
-- collect_admin_session_changes = true: решение владельца (28.07) — после апгрейда
-- фича ВКЛЮЧЕНА. На проводе правило не меняется: поля нет у старого сервера =
-- агент не собирает (нулевое значение в FetchAdminStatusResponse).
--
-- admin_session_snapshot_interval_sec: 0 = дефолт агента (1800). Сервер клампит
-- значения <300 при отдаче в FetchAdminStatus.

INSERT INTO system_settings (key, value) VALUES
  ('collect_admin_session_changes', 'true'),
  ('admin_session_snapshot_interval_sec', '0')
ON CONFLICT (key) DO NOTHING;
