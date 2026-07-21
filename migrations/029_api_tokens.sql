-- 029: сервисные API-токены для автоматизации (CLI, CI, YAML-apply).
--
-- До этого единственным входом в API был JWT из httpOnly-куки живого человека:
-- скриптовать это можно было только логином с паролем и вытаскиванием куки, что
-- для CI неприемлемо. Токен даёт неинтерактивный вход по Authorization: Bearer.
--
-- Идемпотентно (IF NOT EXISTS): таблицы schema_migrations в проекте нет, файлы
-- накатываются вручную через psql -f и могут быть применены повторно.

CREATE TABLE IF NOT EXISTS api_tokens (
  id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name         TEXT NOT NULL,
  -- Только SHA-256-хеш, как в 028 для enrollment_tokens: утечка дампа БД не должна
  -- давать рабочие учётные данные. Плейнтекст показывается ОДИН раз при создании.
  -- Соль не нужна и здесь тоже: токен — 32 случайных байта, словарной атаки нет,
  -- а для поиска по равенству хеш обязан быть детерминированным.
  token_hash   TEXT NOT NULL,
  -- Роль фиксируется В МОМЕНТ ВЫПУСКА и дальше живёт своей жизнью: если бы она
  -- читалась из users на каждый запрос, понижение админа до viewer молча урезало
  -- бы работающую автоматизацию, а повышение — тихо расширило права токена.
  role         TEXT NOT NULL,
  -- ON DELETE CASCADE намеренно: уволили админа, удалили учётку — его сервисные
  -- токены умирают вместе с ней. Иначе автоматизация ушедшего сотрудника продолжает
  -- ходить в API с его правами. Отказ при этом громкий (401), а не тихий.
  created_by   UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  -- NULL = бессрочный. Срок опционален намеренно: обязательный породил бы ровно
  -- один сценарий — «истёк ночью, деплой встал», после чего все ставят 100 лет.
  expires_at   TIMESTAMPTZ,
  last_used_at TIMESTAMPTZ
);

-- Уникальность хеша + индекс под поиск при аутентификации (одна строка на запрос).
CREATE UNIQUE INDEX IF NOT EXISTS idx_api_tokens_token_hash ON api_tokens(token_hash);

-- Список токенов в UI сортируется по свежести.
CREATE INDEX IF NOT EXISTS idx_api_tokens_created_at ON api_tokens(created_at DESC);
