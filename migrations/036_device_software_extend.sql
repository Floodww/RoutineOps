-- 036: расширение инвентаря ПО (proto SoftwareItem, поля 3–8).
-- Приходит от агента на каждом ReportInventory (UpsertInventory перезаписывает
-- весь набор строк устройства целиком, поэтому sticky-паттерн COALESCE здесь не
-- нужен: снимок авторитетен, старых значений сохранять не от чего).
--
-- Пустая строка = «источник не отдал», НЕ выдуманное значение: диалект arch
-- (amd64/x86_64/noarch/universal) сознательно НЕ нормализуется ни агентом, ни
-- сервером — единый словарь потеряет информацию, нужную для CPE/purl при
-- будущем скане на CVE. Нормализация — задача потребителя, не хранилища.
ALTER TABLE device_software ADD COLUMN IF NOT EXISTS vendor           TEXT NOT NULL DEFAULT '';  -- издатель/мейнтейнер
ALTER TABLE device_software ADD COLUMN IF NOT EXISTS install_location TEXT NOT NULL DEFAULT '';  -- путь установки
ALTER TABLE device_software ADD COLUMN IF NOT EXISTS arch             TEXT NOT NULL DEFAULT '';  -- в диалекте источника
ALTER TABLE device_software ADD COLUMN IF NOT EXISTS uninstall_id     TEXT NOT NULL DEFAULT '';  -- ProductCode / bundle id / имя пакета
-- uninstall_method — чем агент СМОЖЕТ снять ПО: '' (нечем, fail-safe) / msi /
-- windows_quiet / macos_app_bundle / dpkg / rpm / pacman / apk. Хранится строкой,
-- а не числом enum'а: номера protobuf — деталь транспорта, в БД от них остаётся
-- только загадка при чтении глазами. Список открытый (агент добавит менеджер
-- пакетов — сервер не потребует миграции), поэтому CHECK намеренно нет.
ALTER TABLE device_software ADD COLUMN IF NOT EXISTS uninstall_method TEXT NOT NULL DEFAULT '';
-- scope — 'machine' (на машину) или 'user' (в профиль пользователя).
-- Per-user установки до 2.6.0 не доезжали до сервера ВООБЩЕ: правило запрещённого
-- ПО на них не срабатывало, и установка «на себя» была рабочим обходом запрета.
-- Теперь доезжают и обязаны считаться нарушением наравне с machine-установками —
-- при том что снять их нечем (из-под LocalSystem/root чужой профиль не тронуть,
-- метод снятия таким записям агент не выдаёт).
ALTER TABLE device_software ADD COLUMN IF NOT EXISTS scope            TEXT NOT NULL DEFAULT '';
