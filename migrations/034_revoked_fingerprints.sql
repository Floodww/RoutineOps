-- 034: тумбстоун отозванных cert-fingerprint'ов.
-- Удаление устройства (DELETE FROM devices) сносит строку вместе с её
-- certificate_fingerprint. Но серт на самой машине остаётся валидным, и на следующем
-- Connect gateway по ADR-1 заводит устройство ЗАНОВО из cert CN — отличить «новое
-- устройство» от «воскресшего удалённого» на коннекте нельзя: оба приходят с неизвестным
-- серверу fingerprint. Итог — устройство-призрак с новым id и осиротевший агент.
-- Fingerprint удаляемого устройства пишем сюда; Connect отозванный отпечаток режет
-- (как decommissioned/blocked). Реэнролл выдаёт НОВЫЙ серт (новый fingerprint) — под
-- тумбстоун не попадает, штатная перерегистрация машины работает.
CREATE TABLE IF NOT EXISTS revoked_fingerprints (
    fingerprint TEXT PRIMARY KEY,
    device_id   UUID,
    revoked_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
