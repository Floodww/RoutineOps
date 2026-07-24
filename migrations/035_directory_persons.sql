-- 035: LDAP-каталог (Phase 1) — персоны каталога + авто-привязка владельца.
--
-- Модель Free/Enterprise (роадмап §29): данные-модель и РУЧНАЯ привязка (owner_id→users) —
-- Free; АВТОМАТИКА из каталога — Enterprise. Таблица directory_persons и колонки ниже
-- живут в ОБЩЕЙ схеме (как escrow-миграция 022), но заполняет их ТОЛЬКО enterprise-синк
-- (internal/server/directory, //go:build enterprise). В open-core/Free-срезе они всегда
-- пусты/NULL — синка нет.

-- Стабильный SID интерактивного юзера, доложенный агентом (proto console_user_sid=21).
-- Ключ матча с каталогом по objectSid — rename-proof, в отличие от console_user-логина.
-- Персистим на устройстве: нужен для ПЕРЕМАТЧА задним числом, когда синк подтянет персону
-- позже (роадмап §121-123). "" / NULL = неизвестно.
ALTER TABLE devices ADD COLUMN IF NOT EXISTS console_user_sid TEXT;

-- Персоны из каталога (AD/LDAP). Канон привязки — object_guid (AD objectGUID /
-- LDAP entryUUID): стабилен при переименовании логина. object_sid — для точного матча
-- по Windows-SID из инвентаря.
CREATE TABLE IF NOT EXISTS directory_persons (
    id                 UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    object_guid        TEXT NOT NULL UNIQUE,   -- канон, ключ привязки
    object_sid         TEXT,                   -- AD objectSid; матч по console_user_sid
    sam_account        TEXT,                   -- sAMAccountName / uid; матч по логину (fallback)
    user_principal     TEXT,                   -- userPrincipalName (user@domain)
    display_name       TEXT,
    email              TEXT,
    distinguished_name TEXT,
    disabled           BOOLEAN NOT NULL DEFAULT false, -- отключённая учётка в каталоге
    synced_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- Матч по SID (точный) и по логину без регистра (fallback). object_sid не UNIQUE на уровне
-- колонки — историческая осторожность (мигрированные SID могут дублироваться), уникальность
-- гарантирует object_guid.
CREATE UNIQUE INDEX IF NOT EXISTS idx_directory_persons_sid  ON directory_persons(object_sid) WHERE object_sid IS NOT NULL;
CREATE INDEX        IF NOT EXISTS idx_directory_persons_sam  ON directory_persons(lower(sam_account));

-- Авто-владелец из каталога. Отдельно от owner_id→users (Free-ручной): каталожная персона
-- НЕ панель-аккаунт. UI показывает directory-владельца, если проставлен, иначе owner_id.
-- ON DELETE SET NULL: удаление персоны из каталога не роняет устройство.
ALTER TABLE devices ADD COLUMN IF NOT EXISTS owner_directory_id UUID
    REFERENCES directory_persons(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_devices_owner_directory_id ON devices(owner_directory_id);
