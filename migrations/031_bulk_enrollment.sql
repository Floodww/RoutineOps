-- 031: bulk enrollment — массовая регистрация устройств одним токеном.
-- Токен перестаёт быть привязан к одному устройству: он может нести группу,
-- быть многоразовым (лимит + счётчик) и решать, нужно ли одобрение при энролле.
-- Устройство создаётся САМО при энролле (см. storage.BeginBulkEnroll), а не
-- заранее админом. Легаси одноразовые токены (device_id задан) работают как прежде.
ALTER TABLE enrollment_tokens ALTER COLUMN device_id DROP NOT NULL;
ALTER TABLE enrollment_tokens ADD COLUMN IF NOT EXISTS group_id UUID
    REFERENCES device_groups(id) ON DELETE SET NULL;                 -- целевая группа партии (опц.)
ALTER TABLE enrollment_tokens ADD COLUMN IF NOT EXISTS max_uses INTEGER;   -- NULL = безлимит до expires_at
ALTER TABLE enrollment_tokens ADD COLUMN IF NOT EXISTS uses INTEGER NOT NULL DEFAULT 0;
ALTER TABLE enrollment_tokens ADD COLUMN IF NOT EXISTS require_approval BOOLEAN NOT NULL DEFAULT true;

-- Статусы устройства (devices.status = TEXT, без CHECK) получают два новых значения,
-- миграции не требующих, но фиксируем для истории:
--   pending_approval — bulk-энролл ждёт одобрения: Connect/heartbeat/инвентарь разрешены
--                      (админ видит машину), политики/скрипты гейтятся до одобрения.
--   rejected         — отклонён из очереди: gateway режет Connect/heartbeat/все RPC (как blocked).
