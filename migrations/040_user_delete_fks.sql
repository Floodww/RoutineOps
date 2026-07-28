-- 040: удаление пользователя панели становится возможным.
--
-- Ручки удаления не было вообще, и добавить её было нельзя: admin_access_requests
-- ссылается на users ДВУМЯ полями без ON DELETE, то есть по умолчанию NO ACTION —
-- любая заявка на локальные права, когда-либо оформленная или рассмотренная этим
-- человеком, навсегда держала его строку. Уволенного администратора приходилось
-- оставлять в системе.
--
-- SET NULL, а не CASCADE: заявка — это журнал того, что на устройстве запрашивали
-- повышение прав, и он обязан пережить увольнение того, кто её оформил. CASCADE стёр
-- бы историю вместе с человеком, то есть удаление аккаунта чистило бы следы.
--
-- Осиротевшая заявка безопасна: с миграции 038 requested_by у НОВЫХ заявок и так
-- всегда NULL (Gateway.RequestAdminAccess — владелец устройства теперь карточка
-- человека, а не аккаунт панели), обнуление исторических строк ничего нового не вносит.
--
-- Остальные ссылки на users уже разобраны и не трогаются: invitation_tokens.invited_by
-- и recovery_key_escrow.revealed_by — SET NULL (журнал переживает удаление),
-- password_reset_tokens.user_id и api_tokens.created_by — CASCADE (учётные данные
-- уходят вместе с владельцем; для api_tokens это ЧАСТЬ контракта удаления — иначе
-- сервисный токен уволенного продолжал бы работать). audit_log ссылки не имеет
-- намеренно: журнал безопасности не должен зависеть от жизни строки в users.
ALTER TABLE admin_access_requests DROP CONSTRAINT IF EXISTS admin_access_requests_requested_by_fkey;
ALTER TABLE admin_access_requests ADD  CONSTRAINT admin_access_requests_requested_by_fkey
  FOREIGN KEY (requested_by) REFERENCES users(id) ON DELETE SET NULL;

ALTER TABLE admin_access_requests DROP CONSTRAINT IF EXISTS admin_access_requests_decided_by_fkey;
ALTER TABLE admin_access_requests ADD  CONSTRAINT admin_access_requests_decided_by_fkey
  FOREIGN KEY (decided_by) REFERENCES users(id) ON DELETE SET NULL;
