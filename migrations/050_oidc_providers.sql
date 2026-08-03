-- 050_oidc_providers.sql
-- OIDC-провайдеры для SSO. Каждая строка — IdP (Google, Azure AD, Okta и др.).
-- client_secret хранится в зашифрованном виде (age/keystore на уровне сервиса).
-- per-installation: tenant_id = tenancy.DefaultTenantID для инсталляций без мультитенантности.

CREATE TABLE oidc_providers (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name          TEXT    NOT NULL,           -- отображаемое имя, напр. «Google»
    client_id     TEXT    NOT NULL,
    client_secret TEXT    NOT NULL,           -- зашифровано, хранится в сервисе
    issuer_url    TEXT    NOT NULL,           -- https://accounts.google.com
    redirect_uri  TEXT    NOT NULL,           -- https://<host>/api/v1/auth/oidc/<id>/callback
    enabled       BOOLEAN NOT NULL DEFAULT true,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
