-- N6: enrollment-токены хранятся хешированными (SHA-256), не plaintext. Дамп БД
-- больше не отдаёт пригодный к использованию токен. Plaintext возвращается ТОЛЬКО
-- в момент выдачи (ответ create/reenroll) — фронт берёт его оттуда и повторно
-- не запрашивает (эндпоинт re-display теперь отдаёт лишь expires_at).
ALTER TABLE enrollment_tokens ADD COLUMN token_hash TEXT;

-- Бэкфилл существующих строк: sha256(token) в hex. Postgres 11+ имеет встроенный
-- sha256(bytea); token::bytea = ASCII-байты, совпадает с []byte(token) в Go.
UPDATE enrollment_tokens SET token_hash = encode(sha256(token::bytea), 'hex');

-- Удаляем plaintext-колонку (уносит UNIQUE-констрейнт enrollment_tokens_token_key).
DROP INDEX IF EXISTS idx_enrollment_tokens_token;
ALTER TABLE enrollment_tokens DROP COLUMN token;

ALTER TABLE enrollment_tokens ALTER COLUMN token_hash SET NOT NULL;
CREATE UNIQUE INDEX idx_enrollment_tokens_token_hash ON enrollment_tokens(token_hash);
