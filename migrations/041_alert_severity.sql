-- 041: уровни критичности алертов и маршрутизация уведомлений.
--
-- До этого все алерты были равны: таблица alerts не различала «деструктив идёт
-- прямо сейчас» и «агент не выходил на связь два часа», а notifier рассылал в
-- Telegram всё подряд одинаковым текстом всем it_admin. Знание о том, что важнее,
-- существовало ровно в одном месте — в константе TYPE_ORDER во фронтенде
-- (web/src/pages/Alerts.tsx). То есть приоритет инцидента жил в браузере и не был
-- доступен ни серверу, ни уведомлениям, ни экспорту.
--
-- Идемпотентно (IF NOT EXISTS): schema_migrations в проекте нет, файлы
-- накатываются вручную через psql -f и могут быть применены повторно.

-- ---------------------------------------------------------------------------
-- 1. Критичность самого алерта
-- ---------------------------------------------------------------------------

-- Критичность фиксируется В МОМЕНТ СОЗДАНИЯ и дальше живёт со строкой — ровно по
-- той же причине, по которой в 029 роль фиксируется при выпуске токена. Если бы
-- она вычислялась из alert_type на чтении, то правка карты по умолчанию задним
-- числом переписывала бы историю: инцидент, разобранный как «средний», через
-- полгода отображался бы критическим, и разбор постфактум («что мы тогда видели»)
-- стал бы невозможен. Плюс это даёт оператору право поднять/опустить критичность
-- конкретного алерта, не трогая правило.
--
-- DEFAULT 'medium' нужен только для строк, вставленных мимо кода (ручной psql):
-- штатный путь всегда передаёт значение явно из alerting.DefaultFor.
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS severity TEXT NOT NULL DEFAULT 'medium';

-- Бэкфилл существующих строк по типу. Карта обязана совпадать с
-- internal/server/alerting.defaults — расхождение ловится тестом
-- TestDefaultsMatchMigration, чтобы SQL и Go не разъехались молча.
UPDATE alerts SET severity = CASE alert_type
    WHEN 'filevault_revoke_failed'      THEN 'critical'
    WHEN 'lock_tamper'                  THEN 'critical'
    WHEN 'filevault_secret_mismatch'    THEN 'high'
    -- Выше нарушений политики не по «серьёзности вообще», а потому что обесценивает
    -- тишину: пока признак висит, отсутствие остальных событий с машины ничего не
    -- доказывает. Порядок внутри уровня задаёт alerting.typeOrder.
    WHEN 'outbox_unavailable'           THEN 'high'
    WHEN 'forbidden_software'           THEN 'high'
    WHEN 'unauthorized_install'         THEN 'medium'
    WHEN 'unauthorized_settings_change' THEN 'medium'
    WHEN 'agent_unreachable'            THEN 'low'
    -- Неизвестный тип — 'high', а НЕ 'low' и не 'medium'. Незнакомый тип означает
    -- агента новее сервера: событие, которое мы не умеем классифицировать, не
    -- должно молча уходить ниже порога доставки оператора. 'high' доставляется
    -- при любом разумном пороге, но не претендует на «будить ночью».
    ELSE 'high'
  END
  WHERE severity = 'medium';

-- CHECK, а не enum-тип: alert_type в этой таблице сознательно свободный TEXT
-- (gateway кладёт strings.ToLower от имени proto-энума), и заводить строгий тип
-- рядом со свободным было бы непоследовательно. CHECK при этом не даёт опечатке
-- в severity протечь в БД и сломать сортировку.
ALTER TABLE alerts DROP CONSTRAINT IF EXISTS alerts_severity_check;
ALTER TABLE alerts ADD CONSTRAINT alerts_severity_check
    CHECK (severity IN ('critical', 'high', 'medium', 'low'));

-- Эскалация: когда по этому алерту в последний раз уходило напоминание. NULL =
-- ни разу. Отдельная колонка, а не пересчёт по created_at, потому что напоминание
-- должно быть повторяемым (каждые N минут, пока не приняли), а не однократным.
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS escalated_at TIMESTAMPTZ;

-- Индекс под выборку «непринятые, по убыванию критичности». Порядок колонок
-- повторяет ORDER BY в ListAlerts: сначала непринятые, потом критичность, потом
-- свежесть. severity — TEXT, поэтому сортируется не по важности, а по алфавиту
-- ('critical' < 'high' < 'low' < 'medium'); ранг задаётся выражением в запросе,
-- и индекс здесь помогает только фильтрации по acknowledged_at.
CREATE INDEX IF NOT EXISTS idx_alerts_unacked_severity
    ON alerts (acknowledged_at, severity, created_at DESC);

-- ---------------------------------------------------------------------------
-- 2. Маршрутизация: порог доставки на получателя
-- ---------------------------------------------------------------------------

-- Простейшая честная форма «дежурств» из роадмапа: каждый it_admin сам решает, с
-- какой критичности его беспокоить в Telegram. Отдельной таблицы правил не
-- заводим — она нужна, когда появятся каналы кроме телеги (SIEM/webhook, Этап 1),
-- и её форма должна проектироваться вместе с ними, а не угадываться сейчас.
--
-- 🔴 DEFAULT 'low' выбран намеренно и означает «всё как раньше». Любой более
-- высокий дефолт при накате миграции ТИХО отписал бы существующих админов от
-- части уведомлений, которые они получали вчера, — это худший класс регрессии:
-- ничего не сломалось, просто перестало приходить. Тише становится только по
-- явному действию оператора.
ALTER TABLE users ADD COLUMN IF NOT EXISTS notify_min_severity TEXT NOT NULL DEFAULT 'low';

ALTER TABLE users DROP CONSTRAINT IF EXISTS users_notify_min_severity_check;
ALTER TABLE users ADD CONSTRAINT users_notify_min_severity_check
    CHECK (notify_min_severity IN ('critical', 'high', 'medium', 'low'));

-- ---------------------------------------------------------------------------
-- DOWN (проверено, применять вручную)
-- ---------------------------------------------------------------------------
-- ALTER TABLE users  DROP CONSTRAINT IF EXISTS users_notify_min_severity_check;
-- ALTER TABLE users  DROP COLUMN IF EXISTS notify_min_severity;
-- DROP INDEX IF EXISTS idx_alerts_unacked_severity;
-- ALTER TABLE alerts DROP CONSTRAINT IF EXISTS alerts_severity_check;
-- ALTER TABLE alerts DROP COLUMN IF EXISTS escalated_at;
-- ALTER TABLE alerts DROP COLUMN IF EXISTS severity;
