-- 043: удаление установленного ПО. task_type получает значение 'uninstall'
-- (домен колонки открытый, как у 'lock'/'decommission'/'reboot' — CHECK'а нет).
--
-- Колонки хранят СЕЛЕКТОР ЦЕЛИ, а не команду. Это главное свойство контракта (proto
-- UninstallCommand): агент не выполняет присланную строку деинсталлятора и вообще не
-- принимает от сервера команд ОС — он заново снимает инвентарь, находит запись по
-- селектору в СВОЁМ свежем снимке и выполняет метод, который его собственный коллектор
-- считает применимым. Хранить здесь готовую команду означало бы завести второй канал
-- произвольного исполнения на устройстве — мимо подписи, аудита и потолков скриптов.
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS uninstall_software_name    TEXT NOT NULL DEFAULT '';
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS uninstall_version          TEXT NOT NULL DEFAULT '';
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS uninstall_uninstall_id     TEXT NOT NULL DEFAULT '';
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS uninstall_install_location TEXT NOT NULL DEFAULT '';
-- Метод — СВЕРКА, а не приказ: агент сравнивает его с тем, что определил сам, и при
-- расхождении отказывает. Расхождение значит, что запись на машине изменилась после
-- снимка, а инвентарь на сервере всегда чуть устарел (снимок раз в 5 минут).
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS uninstall_method           TEXT NOT NULL DEFAULT '';
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS uninstall_scope            TEXT NOT NULL DEFAULT '';
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS uninstall_reason           TEXT NOT NULL DEFAULT '';

-- 🔴 Исход — ОТДЕЛЬНОЕ поле, а не текст в output. TaskStatus (completed/failed) для
-- этой команды слишком груб: TARGET_CHANGED («обнови инвентарь и повтори»), AMBIGUOUS
-- («уточни цель»), NOT_REMOVABLE («делать нечего»), SELF_PROTECTED («ты целился в
-- агента») требуют РАЗНЫХ действий оператора, и по прозе это не разбирается и не
-- агрегируется. Отдельно STILL_PRESENT против FAILED — различие безопасности, а не
-- косметики: msiexec отдаёт 0 на снос, отложенный до перезагрузки, а pkgutil --forget
-- чистит только квитанцию, поэтому агент отчитывается по ПОВТОРНОМУ снимку, а не по
-- коду возврата. Спрятать это в текст значило бы потерять то, ради чего оно сделано.
--
-- Домен открытый (как у task_type): значения приходят из proto UninstallOutcome, и
-- CHECK пришлось бы двигать миграцией на каждое новое — притом что сервер незнакомый
-- исход обязан принять и показать, а не отвергнуть.
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS uninstall_outcome         TEXT NOT NULL DEFAULT '';

-- Частичный уникальный индекс: на устройство разом живёт не более ОДНОЙ недоставленной
-- заявки на снос конкретной цели. Повтор клика оператора обязан попадать в ТУ ЖЕ задачу
-- (агент дедуплицирует durably по task_id, и новый id для него — новая команда).
-- Ключ включает и имя, и машинный ключ: два разных продукта сносятся параллельно, а
-- один и тот же дважды — нет.
CREATE UNIQUE INDEX IF NOT EXISTS idx_tasks_one_pending_uninstall
  ON tasks (device_id, uninstall_software_name, uninstall_uninstall_id)
  WHERE task_type = 'uninstall' AND status = 'pending';
