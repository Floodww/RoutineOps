-- 033: имена скриптов и скрипт-политик уникальны.
-- Продолжение 026 (там то же самое сделано для device_groups). Ни схема, ни код не
-- мешали завести два скрипта «Проверка антивируса»: в UI они неразличимы, а YAML-apply
-- на таком расползании ломается — по имени невозможно понять, какой из двух обновлять.
-- Имя становится идентичностью ресурса, поэтому оно обязано быть однозначным.
--
-- Сравнение нечувствительно к регистру и краевым пробелам («  Проверка » == «проверка»),
-- потому что именно так люди путаются. Хранится имя как введено.

-- 1. Пустые имена и имена из одних пробелов: NOT NULL их пропускал.
--    Чиним ДО дедупликации, иначе все пустые попадут в одну партицию и получат суффиксы.
UPDATE scripts  SET name = 'Скрипт '  || left(id::text, 8) WHERE btrim(name) = '';
UPDATE policies SET name = 'Политика ' || left(id::text, 8) WHERE btrim(name) = '';

-- 2. Разводим существующие дубли: самому старому имя оставляем, остальным дописываем
--    фрагмент id. Суффикс из id, а не порядковый номер: « (2)» могло бы столкнуться с
--    уже существующим «Проверка (2)» и уронить индекс ниже.
WITH ranked AS (
  SELECT id, name,
         row_number() OVER (PARTITION BY lower(btrim(name)) ORDER BY created_at, id) AS rn
  FROM scripts
)
UPDATE scripts s
SET    name = ranked.name || ' #' || left(s.id::text, 8)
FROM   ranked
WHERE  s.id = ranked.id AND ranked.rn > 1;

WITH ranked AS (
  SELECT id, name,
         row_number() OVER (PARTITION BY lower(btrim(name)) ORDER BY created_at, id) AS rn
  FROM policies
)
UPDATE policies p
SET    name = ranked.name || ' #' || left(p.id::text, 8)
FROM   ranked
WHERE  p.id = ranked.id AND ranked.rn > 1;

-- 3. Гарантии на будущее. Идемпотентно: миграции гоняет migrate-сервис по
--    schema_migrations, но ручной повтор не должен падать.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'scripts_name_not_blank') THEN
    ALTER TABLE scripts ADD CONSTRAINT scripts_name_not_blank CHECK (btrim(name) <> '');
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'policies_name_not_blank') THEN
    ALTER TABLE policies ADD CONSTRAINT policies_name_not_blank CHECK (btrim(name) <> '');
  END IF;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS scripts_name_unique  ON scripts  (lower(btrim(name)));
CREATE UNIQUE INDEX IF NOT EXISTS policies_name_unique ON policies (lower(btrim(name)));
