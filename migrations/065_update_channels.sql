-- 065: каналы обновлений и канареечная выкатка по группам (Q-52).
--
-- 🔴 Формат — плоский SQL, без `-- +goose Up/Down`: см. шапку 061. Всё, что стоит
-- после `-- +goose Down`, psql выполняет как живой SQL. Down живёт комментарием.
--
-- Зачем. Публикация релиза сейчас уезжает на ВЕСЬ парк сразу: манифест один на
-- os/arch, агент берёт последний по created_at. На десяти машинах это терпимо, на
-- тысяче — способ положить парк одним плохим билдом. Обратной дороги нет по
-- устройству: self-update сам не откатывается, а anti-rollback floor запрещает
-- движение назад по определению — чинится только новой версией вперёд, то есть
-- выкаткой на уже сломанный парк.

SET lock_timeout = '5s';

-- Канал у ГРУППЫ, а не у устройства. Группы уже есть, уже назначаются политики и
-- скрипты, и «канареечная группа» — это то, чем оператор оперирует и так. Колонка у
-- устройства означала бы отдельный механизм назначения (bulk-правка тысячи строк)
-- ради того же результата.
ALTER TABLE device_groups ADD COLUMN update_channel TEXT NOT NULL DEFAULT 'stable';
ALTER TABLE device_groups ADD CONSTRAINT device_groups_update_channel_check
  CHECK (update_channel IN ('stable', 'beta'));

-- Канал у релиза. DEFAULT 'stable' переводит ВСЁ уже опубликованное в stable — это
-- и есть правда: то, что раскатано на парк, стабильно по факту.
ALTER TABLE agent_releases ADD COLUMN channel TEXT NOT NULL DEFAULT 'stable';
ALTER TABLE agent_releases ADD CONSTRAINT agent_releases_channel_check
  CHECK (channel IN ('stable', 'beta'));

-- Выборка манифеста идёт по (os, arch, channel) с сортировкой по created_at.
CREATE INDEX IF NOT EXISTS idx_agent_releases_channel
  ON agent_releases (os, arch, channel, created_at DESC);

-- Резолв канала устройства — обход его групп; индекс по device_id уже есть (006).
--
-- Семантика, которую здесь стоит зафиксировать, потому что из схемы её не видно:
--
--   1. beta — НАДМНОЖЕСТВО stable. Устройство канала beta видит max(последний
--      stable, последний beta), а не «только beta». Иначе продвижение обкатанной
--      версии из beta в stable отнимало бы её у канарейки: строка меняет канал, и
--      beta внезапно оказывается пустым. Канарейка обязана быть НЕ СТАРЕЕ парка.
--
--   2. Устройство состоит в нескольких группах, и канал разрешается по МАКСИМУМУ:
--      хоть одна beta-группа — устройство на beta. Канареечная группа добавляется
--      меткой поверх рабочих, и правило «минимум» делало бы её бессмысленной —
--      машина в любой обычной группе осталась бы на stable.

-- DOWN:
-- DROP INDEX IF EXISTS idx_agent_releases_channel;
-- ALTER TABLE agent_releases DROP CONSTRAINT IF EXISTS agent_releases_channel_check;
-- ALTER TABLE agent_releases DROP COLUMN IF EXISTS channel;
-- ALTER TABLE device_groups DROP CONSTRAINT IF EXISTS device_groups_update_channel_check;
-- ALTER TABLE device_groups DROP COLUMN IF EXISTS update_channel;
