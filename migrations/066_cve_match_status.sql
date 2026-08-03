-- 066: у найденной уязвимости появляется статус сопоставления (Q-62).
--
-- 🔴 Формат — плоский SQL, без `-- +goose Up/Down`: см. шапку 061. Всё, что стоит
-- после `-- +goose Down`, psql выполняет как живой SQL. Down живёт комментарием.
--
-- Зачем. Матчер сравнивал версии через `strings.Contains(версия, шаблон)` и ошибался
-- в обе стороны: шаблон `1.2` совпадал с `11.2.0` и `1.20.5`, а любой диапазон вида
-- «всё до 2.0» не совпадал ни с чем. Но хуже обеих ошибок было третье: версию,
-- которую сопоставить не удалось, матчер ПРОПУСКАЛ МОЛЧА. В отчёте это выглядело как
-- «уязвимостей нет» там, где на самом деле «мы не смогли посмотреть», — и именно
-- такой отчёт показывают аудитору.

SET lock_timeout = '5s';

-- match_status:
--   matched — версия разобрана и попала в уязвимый диапазон. Это уязвимость.
--   unknown — сопоставить не удалось. Это НЕ «уязвимо» и НЕ «чисто», это «требует
--             ручной проверки», и в интерфейсе оно живёт отдельной колонкой.
ALTER TABLE device_vulnerabilities ADD COLUMN match_status TEXT NOT NULL DEFAULT 'matched';
ALTER TABLE device_vulnerabilities ADD CONSTRAINT device_vulnerabilities_match_status_check
  CHECK (match_status IN ('matched', 'unknown'));

-- match_detail — что именно не разобралось и чья это зона: версия ПО приходит с
-- устройства (чинит инвентаризация), шаблон — из справочника (чинит поставщик фида).
-- Без этого различия оператор видит «не сопоставлено» и не знает, куда идти.
ALTER TABLE device_vulnerabilities ADD COLUMN match_detail TEXT NOT NULL DEFAULT '';

-- Записанная версия ПО на момент сопоставления. Инвентарь меняется, а отчёт должен
-- отвечать на вопрос «что мы видели, когда решили, что это уязвимо».
ALTER TABLE device_vulnerabilities ADD COLUMN software_version TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_device_vulnerabilities_status
  ON device_vulnerabilities (tenant_id, match_status);

-- О старых данных. Строки, записанные прежним матчером, помечаются `matched` —
-- потому что именно так их и трактовал интерфейс. Переносить их в `unknown` было бы
-- честнее по факту (доверять тому сравнению нельзя), но это разом объявило бы весь
-- накопленный отчёт непроверенным. Матчер переписывает уязвимости устройства
-- целиком на каждом пересчёте инвентаря, поэтому данные вытеснятся сами.

-- DOWN:
-- DROP INDEX IF EXISTS idx_device_vulnerabilities_status;
-- ALTER TABLE device_vulnerabilities DROP COLUMN IF EXISTS software_version;
-- ALTER TABLE device_vulnerabilities DROP COLUMN IF EXISTS match_detail;
-- ALTER TABLE device_vulnerabilities DROP CONSTRAINT IF EXISTS device_vulnerabilities_match_status_check;
-- ALTER TABLE device_vulnerabilities DROP COLUMN IF EXISTS match_status;
