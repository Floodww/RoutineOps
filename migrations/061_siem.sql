-- 061: интеграции SIEM (Q-47) — выгрузка журнала наружу по syslog/CEF и вебхуком.
--
-- 🔴 Формат файла: ПЛОСКИЙ SQL. Никаких `-- +goose Up/Down`: миграции катит
-- scripts/migrate.sh через `psql -f`, то есть выполняется ВЕСЬ файл целиком.
-- Аннотации goose для psql — обычные комментарии, и всё, что стоит после
-- `-- +goose Down`, отрабатывает как живой SQL: таблица создавалась и тут же
-- дропалась, а миграция записывалась как успешно применённая. Down живёт
-- комментарием, как во всех остальных миграциях.

SET lock_timeout = '5s';

CREATE TABLE siem_integrations (
    id         UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id  UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    type       TEXT NOT NULL CHECK (type IN ('syslog', 'webhook')),
    url        TEXT NOT NULL,
    enabled    BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_siem_integrations_tenant ON siem_integrations (tenant_id);

-- RLS: предикат ТОТ ЖЕ, что у остальных ScopeOwn-таблиц (046/051).
-- 🔴 GUC называется `routineops.tenant_id`, а не `app.current_tenant`, и читается
-- с missing_ok=true: без второго аргумента незаданный GUC роняет запрос ошибкой
-- вместо fail-closed нуля строк. FORCE — чтобы политика действовала и на владельца
-- таблицы, иначе миграционная роль ходит мимо изоляции.
ALTER TABLE siem_integrations ENABLE ROW LEVEL SECURITY;
ALTER TABLE siem_integrations FORCE ROW LEVEL SECURITY;
CREATE POLICY siem_integrations_tenant_isolation ON siem_integrations
  USING (tenant_id = current_setting('routineops.tenant_id', true)::uuid)
  WITH CHECK (tenant_id = current_setting('routineops.tenant_id', true)::uuid);

-- DOWN:
-- DROP TABLE IF EXISTS siem_integrations;
