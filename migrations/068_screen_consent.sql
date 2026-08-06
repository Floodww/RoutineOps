-- 068: зафиксированный исход согласия сотрудника на сеанс просмотра экрана
-- (docs/remote-desktop-contract.md §4, ADR-8 п.3).
--
-- 🔴 Формат файла: ПЛОСКИЙ SQL, без goose-аннотаций. Всё, что стоит после «-- DOWN:»,
-- закомментировано и живой SQL'ой не является.
--
-- Зачем колонки, если режим уже лежит в screen_sessions.mode.
--
-- mode отвечает на вопрос «что было ОБЪЯВЛЕНО», а не «что произошло». До этой миграции
-- строка сеанса с mode='consent_required' означала ровно одно: тенант так настроен.
-- Спрашивали ли сотрудника, ответил ли он и что именно — в базе не было НИГДЕ, при том
-- что ADR-8 п.3 требует «зафиксированного исхода согласия» как условия первого кадра.
-- В споре с работником журнал предъявлял настройку тенанта вместо факта.
--
-- Значения consent_state:
--   NULL      — режим unattended, вопрос не задавался (это не «нет ответа», а «вопроса
--               не было»; отдельное значение здесь только запутало бы);
--   GRANTED   — сотрудник разрешил;
--   DENIED    — сотрудник отказал;
--   TIMEOUT   — сотрудник промолчал. По §4 это отказ, но отличать его от осознанного
--               «нет» обязательно: молчание чаще означает «отошёл», и оператор, увидев
--               TIMEOUT, позвонит, а увидев DENIED — не станет;
--   UNAVAILABLE — спросить было негде (диалог не поднялся, сборка без графической
--               подсистемы). Тоже отказ, но чинить надо установку, а не отношения.

SET lock_timeout = '5s';

ALTER TABLE screen_sessions ADD COLUMN IF NOT EXISTS consent_state TEXT;
ALTER TABLE screen_sessions ADD COLUMN IF NOT EXISTS consent_at    TIMESTAMPTZ;

-- Ограничение перечислением, а не свободным текстом: значение приезжает от агента, и
-- опечатка в коде агента иначе тихо легла бы в журнал как новое «состояние согласия».
ALTER TABLE screen_sessions DROP CONSTRAINT IF EXISTS screen_sessions_consent_state_chk;
ALTER TABLE screen_sessions ADD CONSTRAINT screen_sessions_consent_state_chk
    CHECK (consent_state IS NULL
           OR consent_state IN ('GRANTED', 'DENIED', 'TIMEOUT', 'UNAVAILABLE'));

-- Индекс под единственный запрос, который по этим колонкам ходит: «покажи сеансы, где
-- согласие спрашивали и не получили». Частичный — строк с NULL подавляющее большинство
-- (unattended по умолчанию), и держать их в индексе незачем.
CREATE INDEX IF NOT EXISTS idx_screen_sessions_consent
    ON screen_sessions (tenant_id, consent_at DESC)
    WHERE consent_state IS NOT NULL AND consent_state <> 'GRANTED';

-- DOWN:
-- DROP INDEX IF EXISTS idx_screen_sessions_consent;
-- ALTER TABLE screen_sessions DROP CONSTRAINT IF EXISTS screen_sessions_consent_state_chk;
-- ALTER TABLE screen_sessions DROP COLUMN IF EXISTS consent_at;
-- ALTER TABLE screen_sessions DROP COLUMN IF EXISTS consent_state;
