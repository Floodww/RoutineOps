-- 070: признак неполной записи сеанса экрана.
--
-- Зачем колонка, когда есть манифест. Признак `truncated` в manifest.json существовал и
-- раньше, но лежал ФАЙЛОМ внутри самой записи: чтобы его увидеть, надо было сначала
-- скачать запись — то есть узнать, что улика неполная, можно было только уже глядя на
-- неё. В журнале сеансов и в карточке устройства запись при этом выглядела целой.
--
-- §6 контракта требует обратного: в режиме unattended запись — единственный способ
-- восстановить, что именно видел оператор, поэтому её неполнота обязана быть видна ТАМ
-- ЖЕ, где виден сам факт сеанса, и до скачивания.
--
-- reason отдельным полем, а не строкой в detail: причин ровно две и они разной природы.
--   quota    — упёрлись в потолок на сеанс, это штатная защита диска;
--   io_error — писать не удалось (нет места, том отвалился), это отказ инфраструктуры.
-- Смешивать их в одном флаге значит потерять единственное, что отличает «мы так решили»
-- от «у нас сломалось».

ALTER TABLE screen_sessions
  ADD COLUMN IF NOT EXISTS recording_truncated BOOLEAN NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS recording_truncated_reason TEXT NOT NULL DEFAULT '';

COMMENT ON COLUMN screen_sessions.recording_truncated IS
  'Запись оборвана до конца сеанса: смотреть в ней нечего за пределами оборванного места';
COMMENT ON COLUMN screen_sessions.recording_truncated_reason IS
  'quota | io_error | пусто (запись полная)';

-- Откат:
-- ALTER TABLE screen_sessions
--   DROP COLUMN IF EXISTS recording_truncated,
--   DROP COLUMN IF EXISTS recording_truncated_reason;
