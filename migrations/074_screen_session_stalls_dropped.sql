-- 074: счётчики stalls и dropped у сеанса экрана.
--
-- 🔴 Формат файла: ПЛОСКИЙ SQL, без goose-аннотаций. Всё, что стоит после «-- DOWN:»,
-- закомментировано и живой SQL'ой не является.
--
-- Зачем колонки. Агент считает оба числа с самого появления телеметрии и исправно кладёт
-- их в SessionStats: stalls — сколько раз бюджет полосы упёрся в потолок паузы, dropped —
-- сколько кадров выброшено по «latest frame wins». Сервер их ВЫБРАСЫВАЛ: Store.Progress
-- писал только frames/bytes, Store.End — тоже, а единственная ветка, где они попадали
-- хотя бы в лог, живёт в стриме и на живом пути не срабатывает ни разу (проверено полем
-- 07.08: за 20 минут двух сеансов ноль строк — телеметрия едет durable-очередью и
-- обрабатывается в Event, а не в стриме).
--
-- Цена этого была не косметической. «Картинка дёргается» и «картинка отстаёт» — разные
-- дефекты с разными причинами: первый это dropped (кадры не успевают уехать), второй —
-- stalls (упёрлись в бюджет полосы). Без обоих счётчиков в БД разбор полевой жалобы
-- начинался с «frames растёт, а дальше неизвестно».
--
-- GREATEST при записи — по той же причине, что у frames/bytes: телеметрия приходит
-- durable-очередью и может доехать ПОСЛЕ терминального события сеанса, а счётчики
-- монотонны, и откатывать их назад запоздавшим замером нельзя.

SET lock_timeout = '5s';

ALTER TABLE screen_sessions
  ADD COLUMN IF NOT EXISTS stalls  BIGINT NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS dropped BIGINT NOT NULL DEFAULT 0;

COMMENT ON COLUMN screen_sessions.stalls IS
  'Сколько раз петля кадров упёрлась в потолок паузы бюджета полосы (агентский счётчик).';
COMMENT ON COLUMN screen_sessions.dropped IS
  'Сколько кадров выброшено по «latest frame wins» до отправки (агентский счётчик).';

-- DOWN:
-- ALTER TABLE screen_sessions DROP COLUMN IF EXISTS dropped;
-- ALTER TABLE screen_sessions DROP COLUMN IF EXISTS stalls;
