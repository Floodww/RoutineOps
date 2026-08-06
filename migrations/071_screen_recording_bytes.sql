-- 071: реальный размер записи сеанса — основа квоты на ТЕНАНТА.
--
-- Потолок был только на сеанс (512 МБ, см. DefaultMaxSessionBytes). Он защищает от одного
-- аномального сеанса и ничего не говорит про парк: сто сеансов по сто мегабайт кончают
-- диск ровно так же, просто не за раз. Первым при этом падает не удалённый стол, а
-- Postgres — то есть весь сервер.
--
-- Почему НЕ считаем по существующей колонке bytes. Она считает байты СТРИМА и растёт даже
-- тогда, когда запись не велась вовсе (отказ ввода-вывода, обрыв по квоте): квота, взятая
-- по ней, отняла бы у тенанта место, которое на диске не занято ничем. Здесь нужен размер
-- ФАЙЛА, и его знает только рекордер.
--
-- GREATEST при записи (см. Store.End) — по той же причине, что у frames/bytes: End
-- идемпотентна, и durable-событие агента, пришедшее после обрыва стрима, о размере
-- серверной записи не знает ничего. Нулём из него затирать реальный размер нельзя.

ALTER TABLE screen_sessions
  ADD COLUMN IF NOT EXISTS recording_bytes BIGINT NOT NULL DEFAULT 0;

COMMENT ON COLUMN screen_sessions.recording_bytes IS
  'Размер файла записи в байтах; 0 = записи на диске нет. Слагаемое квоты тенанта';

-- Частичный индекс: суммируются только сеансы с записью, и таких меньшинство после
-- ретеншена. Полный индекс по tenant_id тут бесполезен — RLS и так режет выборку.
CREATE INDEX IF NOT EXISTS idx_screen_sessions_recording_bytes
  ON screen_sessions (tenant_id)
  WHERE recording_path IS NOT NULL;

-- Откат:
-- DROP INDEX IF EXISTS idx_screen_sessions_recording_bytes;
-- ALTER TABLE screen_sessions DROP COLUMN IF EXISTS recording_bytes;
