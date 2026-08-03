-- 063: интеграции SIEM обзаводятся секретом, фильтром событий и статусом доставки (Q-63).
--
-- 🔴 Формат — плоский SQL, без `-- +goose Up/Down`: см. шапку 061. Всё, что стоит
-- после `-- +goose Down`, psql выполняет как живой SQL. Down живёт комментарием.
--
-- Зачем это, если ручки CRUD были и раньше. Настроить приёмник из панели было
-- нельзя вовсе (страницы нет), а проверить настройку — нечем: единственным
-- признаком «работает» была тишина, неотличимая от «адрес неверный, события никуда
-- не едут». Именно эту болезнь ревью уже находило в самом экспортёре.

SET lock_timeout = '5s';

-- secret — конверт AES-GCM (`v1:…`), как client_secret у OIDC (050) и приватник SP
-- у SAML (060). Ключ выводится HKDF из JWT-секрета под собственной меткой, поэтому
-- утечка одного секрета не открывает остальные.
--
-- Смысл секрета — подпись webhook'а: приёмник обязан уметь отличить наши события от
-- чужого POST'а на тот же адрес. Для syslog/CEF подписи нет: там транспорт
-- односторонний и места под неё в формате не предусмотрено.
ALTER TABLE siem_integrations ADD COLUMN secret TEXT;

-- event_filter — список действий журнала, которые уезжают в этот приёмник.
-- ПУСТОЙ массив означает «все», а не «ни одного»: приёмник ИБ, который по умолчанию
-- не получает ничего, — это худший из возможных дефолтов.
ALTER TABLE siem_integrations ADD COLUMN event_filter TEXT[] NOT NULL DEFAULT '{}';

-- Статус доставки. Живёт в строке интеграции, а не в отдельной таблице истории:
-- оператору нужно ответить на вопрос «доезжает ли сейчас», а не поднять хронику.
-- Счётчики накопительные — по ним видно и разовый сбой, и systematic.
ALTER TABLE siem_integrations ADD COLUMN last_delivery_at TIMESTAMPTZ;
ALTER TABLE siem_integrations ADD COLUMN last_status TEXT CHECK (last_status IN ('ok', 'error'));
ALTER TABLE siem_integrations ADD COLUMN last_error TEXT;
ALTER TABLE siem_integrations ADD COLUMN error_count BIGINT NOT NULL DEFAULT 0;
ALTER TABLE siem_integrations ADD COLUMN delivered_count BIGINT NOT NULL DEFAULT 0;

-- 🔴 Тип `syslog` до сих пор ЛГАЛ: код слал по нему CEF (worker/siem.go, pushSyslog
-- собирает `CEF:0|RoutineOps|…`). Оператор, выбравший «syslog», получал в приёмнике
-- CEF и не понимал, почему парсер syslog его не разбирает.
--
-- Разводим честно: `cef` — то, что код делал всегда; `syslog` — обычный текст
-- RFC 5424. Существующие строки переезжают в `cef`, потому что именно это они и
-- делали: менять поведение уже настроенного приёмника молча нельзя.
ALTER TABLE siem_integrations DROP CONSTRAINT IF EXISTS siem_integrations_type_check;
UPDATE siem_integrations SET type = 'cef' WHERE type = 'syslog';
ALTER TABLE siem_integrations ADD CONSTRAINT siem_integrations_type_check
  CHECK (type IN ('syslog', 'webhook', 'cef'));

-- DOWN:
-- ALTER TABLE siem_integrations DROP CONSTRAINT IF EXISTS siem_integrations_type_check;
-- UPDATE siem_integrations SET type = 'syslog' WHERE type = 'cef';
-- ALTER TABLE siem_integrations ADD CONSTRAINT siem_integrations_type_check CHECK (type IN ('syslog', 'webhook'));
-- ALTER TABLE siem_integrations DROP COLUMN IF EXISTS delivered_count;
-- ALTER TABLE siem_integrations DROP COLUMN IF EXISTS error_count;
-- ALTER TABLE siem_integrations DROP COLUMN IF EXISTS last_error;
-- ALTER TABLE siem_integrations DROP COLUMN IF EXISTS last_status;
-- ALTER TABLE siem_integrations DROP COLUMN IF EXISTS last_delivery_at;
-- ALTER TABLE siem_integrations DROP COLUMN IF EXISTS event_filter;
-- ALTER TABLE siem_integrations DROP COLUMN IF EXISTS secret;
