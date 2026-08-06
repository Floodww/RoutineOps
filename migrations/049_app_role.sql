-- 049: App-роль без superuser/bypassrls (Q-14).
--
-- Сервер (pgxpool) подключается под mdm_app → RLS FORCE реально изолирует тенантов.
-- Роль mdm (владелец БД и таблиц) остаётся для migrate-сервиса (DDL).
--
-- SECURITY DEFINER функции из 046/047/048 принадлежат mdm (owner) и выполняются
-- с его привилегиями → pre-auth lookups продолжают обходить RLS корректно.
--
-- Пароль mdm_app задаётся вручную ПОСЛЕ миграции:
--   ALTER ROLE mdm_app PASSWORD 'сгенерированный_пароль';
-- Не хардкодим в SQL — секреты в миграциях = утечка через git / срез.
SET lock_timeout = '5s';

-- 🔴 `IF NOT EXISTS` здесь — проверка-и-действие, а не атомарная операция: роль в
-- PostgreSQL живёт на уровне КЛАСТЕРА, а не базы. Два наката, идущих одновременно,
-- оба видят «роли нет», оба выполняют CREATE ROLE, и второй падает
-- `duplicate key ... pg_authid_rolname_index`. Поймано живьём: тестовые пакеты гоняются
-- параллельно против одного сервера, каждый накатывает миграции в СВОЮ базу — и падал
-- случайный пакет, то есть жалоба приходила на невиновного.
--
-- Тот же сценарий ждёт нас на нескольких узлах (Q-53): два migrate-контейнера,
-- стартовавших вместе, ведут себя ровно так же. Поэтому гонку глушим по существу —
-- перехватом duplicate_object, а не расстановкой задержек.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mdm_app') THEN
    CREATE ROLE mdm_app LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
  END IF;
EXCEPTION WHEN duplicate_object THEN
  -- Роль успел создать параллельный накат. Это ровно то состояние, которого мы и
  -- добивались, — молча продолжаем.
  NULL;
END $$;

-- Подключение к БД (имя динамическое — работает и на mdm, и на тестовых БД).
DO $$
BEGIN
  EXECUTE format('GRANT CONNECT ON DATABASE %I TO mdm_app', current_database());
END $$;

-- DML на всех таблицах в public (текущих и будущих).
GRANT USAGE ON SCHEMA public TO mdm_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO mdm_app;
ALTER DEFAULT PRIVILEGES FOR ROLE mdm IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO mdm_app;

-- Sequences (gen_random_uuid() не нужно, но serial/bigserial если появится).
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO mdm_app;
ALTER DEFAULT PRIVILEGES FOR ROLE mdm IN SCHEMA public
  GRANT USAGE, SELECT ON SEQUENCES TO mdm_app;

-- EXECUTE на функции (SECURITY DEFINER из 046/047/048 + стандартные).
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO mdm_app;
ALTER DEFAULT PRIVILEGES FOR ROLE mdm IN SCHEMA public
  GRANT EXECUTE ON FUNCTIONS TO mdm_app;

-- set_config для GUC routineops.tenant_id — доступен всем ролям по умолчанию,
-- отдельный GRANT не нужен.

-- DOWN (вручную при откате):
-- REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM mdm_app;
-- REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM mdm_app;
-- REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public FROM mdm_app;
-- REVOKE CONNECT ON DATABASE current_database() FROM mdm_app;
-- ALTER DEFAULT PRIVILEGES FOR ROLE mdm IN SCHEMA public
--   REVOKE ALL ON TABLES FROM mdm_app;
-- ALTER DEFAULT PRIVILEGES FOR ROLE mdm IN SCHEMA public
--   REVOKE ALL ON SEQUENCES FROM mdm_app;
-- ALTER DEFAULT PRIVILEGES FOR ROLE mdm IN SCHEMA public
--   REVOKE ALL ON FUNCTIONS FROM mdm_app;
-- DROP ROLE IF EXISTS mdm_app;
