-- 069: резолв пользователя по токену привязки Telegram до того, как известен тенант.
--
-- Зачем. Токен привязки генерится в панели и уносится человеком в мессенджер; обратно
-- он приходит от Telegram Bot API, где никакой нашей сессии нет — ни JWT, ни серта, ни
-- тенанта. Ровно тот же случай, что у приглашения (auth_invitation_by_token, 046) и
-- сброса пароля: строка находится ПО глобально уникальному секрету, и тенант берётся
-- из неё, а не наоборот.
--
-- До этой миграции бот читал users обычным запросом. Под FORCE RLS (046 + роль mdm_app
-- из 049) без выставленного routineops.tenant_id предикат не совпадает ни с одной
-- строкой — привязка молча отвечала «токен не найден или уже использован» на верном
-- токене. Обход тенантов здесь не годится: он превратил бы уникальность токена в
-- перебор и дал бы разное поведение при коллизии.
--
-- SECURITY DEFINER + фиксированный search_path — как у всех auth_*: функция намеренно
-- исполняется вне тенантского скоупа, после неё вызывающий обязан выставить тенант сам
-- (возвращаем tenant_id именно для этого).

CREATE OR REPLACE FUNCTION auth_user_by_link_token(p_token TEXT)
RETURNS TABLE (
  id UUID, tenant_id UUID, identity_id UUID, name TEXT, email TEXT, role TEXT,
  created_at TIMESTAMPTZ
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT u.id, u.tenant_id, u.identity_id, u.name, u.email, u.role, u.created_at
  FROM users u
  -- Пустой токен не должен находить пользователя, у которого поле пустое: очищенный
  -- после привязки токен хранится как '' (см. SetUserLinkToken), и без этого условия
  -- любой /start без аргумента цеплялся бы к первому попавшемуся.
  WHERE u.telegram_link_token = p_token AND p_token <> '';
$$;

-- Откат:
-- DROP FUNCTION IF EXISTS auth_user_by_link_token(TEXT);
