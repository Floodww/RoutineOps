-- 062: справочник CVE и найденные уязвимости устройств (Q-50).
--
-- 🔴 Формат — плоский SQL, без `-- +goose Up/Down`: см. шапку 061. Всё, что стояло
-- после `-- +goose Down`, выполнялось как живой SQL и сносило только что созданные
-- таблицы, а миграция помечалась применённой.
--
-- Скоуп таблиц (обязателен по docs/multitenancy-contract.md §7, см. tenancy/tables.go):
--   cve_dictionary, cve_affected_software — ГЛОБАЛЬНЫЕ. Это внешний справочник
--     (фид БДУ/NVD), одинаковый для всей инсталляции; тенантского содержания в нём
--     нет, а копия на тенанта означала бы N копий одного фида и рассинхрон между ними.
--   device_vulnerabilities — ТЕНАНТСКАЯ через устройство: строка привязана к
--     конкретной машине, и видна должна быть ровно тому, кому видна машина.

SET lock_timeout = '5s';

CREATE TABLE cve_dictionary (
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    cve_id       TEXT NOT NULL UNIQUE,
    description  TEXT NOT NULL,
    cvss_score   NUMERIC(3,1),
    published_at TIMESTAMPTZ
);
CREATE INDEX idx_cve_dictionary_cve_id ON cve_dictionary (cve_id);

CREATE TABLE cve_affected_software (
    cve_id          TEXT NOT NULL REFERENCES cve_dictionary(cve_id) ON DELETE CASCADE,
    software_name   TEXT NOT NULL,
    version_pattern TEXT NOT NULL,
    PRIMARY KEY (cve_id, software_name, version_pattern)
);

CREATE TABLE device_vulnerabilities (
    -- tenant_id денормализован намеренно (контракт мультитенантности §5, слой 1):
    -- предикат RLS не должен ходить по FK на каждую строку, а строк здесь
    -- «устройство × уязвимость». Источник истины — devices.tenant_id.
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    device_id     UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    cve_id        TEXT NOT NULL REFERENCES cve_dictionary(cve_id) ON DELETE CASCADE,
    software_name TEXT NOT NULL,
    detected_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (device_id, cve_id)
);
CREATE INDEX idx_device_vulnerabilities_device ON device_vulnerabilities (device_id);

-- RLS по денормализованному tenant_id. GUC — `routineops.tenant_id` с missing_ok,
-- как в 046/051 (не `app.current_tenant`: такого GUC в проекте нет, и без второго
-- аргумента незаданный GUC роняет запрос вместо fail-closed нуля строк).
--
-- WITH CHECK обязателен отдельно: USING фильтрует ЧТЕНИЕ, но без WITH CHECK ничто
-- не мешает записать строку про чужое устройство — а пишет сюда фоновый матчер.
ALTER TABLE device_vulnerabilities ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_vulnerabilities FORCE ROW LEVEL SECURITY;
CREATE POLICY device_vulnerabilities_tenant_isolation ON device_vulnerabilities
  USING (tenant_id = current_setting('routineops.tenant_id', true)::uuid)
  WITH CHECK (tenant_id = current_setting('routineops.tenant_id', true)::uuid);

-- DOWN:
-- DROP TABLE IF EXISTS device_vulnerabilities;
-- DROP TABLE IF EXISTS cve_affected_software;
-- DROP TABLE IF EXISTS cve_dictionary;
