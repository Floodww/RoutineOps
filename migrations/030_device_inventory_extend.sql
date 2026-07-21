-- 030: расширение инвентаря устройства (proto DeviceInfo, поля 12–20).
-- Приходит от агента на каждом ReportInventory (UpsertInventory).
--
-- Контракт значений (см. proto/agent.proto, DeviceInfo): недоступное на данной
-- ОС значение — NULL/'' («не знаю»), НЕ выдуманный false; поэтому трёхзначные
-- признаки (domain_joined/tpm/secure_boot) — TEXT "true"/"false"/'', не BOOLEAN.
-- Пустое значение от агента НЕ затирает уже известное (sticky-паттерн
-- COALESCE(NULLIF(...)) в UpsertInventory) — кроме console_user: там пустая
-- строка это реальный факт «за консолью никого», пишется как есть.
ALTER TABLE devices ADD COLUMN IF NOT EXISTS arch            TEXT;   -- amd64 / arm64
ALTER TABLE devices ADD COLUMN IF NOT EXISTS console_user    TEXT;   -- Windows: DOMAIN\user (домен сохранён для матчинга с каталогом)
ALTER TABLE devices ADD COLUMN IF NOT EXISTS disk_encryption TEXT;   -- 'enabled'/'disabled' (FileVault/BitLocker/LUKS системного тома)
ALTER TABLE devices ADD COLUMN IF NOT EXISTS os_patch_date   TEXT;   -- ISO 'YYYY-MM-DD', дата последнего обновления ОС
ALTER TABLE devices ADD COLUMN IF NOT EXISTS boot_time       BIGINT; -- unix-время загрузки ОС (не uptime — стабильно между отчётами)
ALTER TABLE devices ADD COLUMN IF NOT EXISTS disk_free       TEXT;   -- свободно на системном томе, человекочитаемо
ALTER TABLE devices ADD COLUMN IF NOT EXISTS domain_joined   TEXT;   -- 'true'/'false' (Windows: PartOfDomain; mac/linux — заведомое 'false')
ALTER TABLE devices ADD COLUMN IF NOT EXISTS tpm             TEXT;   -- 'true'/'false' — Windows
ALTER TABLE devices ADD COLUMN IF NOT EXISTS secure_boot     TEXT;   -- 'true'/'false' — Windows (legacy BIOS = 'false')
