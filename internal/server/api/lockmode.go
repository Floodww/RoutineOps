package api

import (
	"context"
	"errors"

	"github.com/Floodww/RoutineOps/internal/server/storage"
	"github.com/go-chi/chi/v5"
)

// Шов режима блокировки. Open-core допускает только overlay; enterprise-оверлей
// (internal/server/escrow) регистрирует Policy, разрешающую filevault при готовом
// escrow. lockDevice маппит эти ошибки: Unavailable→409 (фича не готова), Invalid→400.
var (
	ErrLockModeUnavailable = errors.New("lock mode unavailable")
	ErrLockModeInvalid     = errors.New("invalid lock mode")
)

// LockModePolicy валидирует запрошенный режим лока. nil-возврат = режим разрешён.
type LockModePolicy interface {
	ValidateMode(mode string) error
}

// overlayOnlyPolicy — дефолт open-core: overlay ок, filevault недоступен (enterprise),
// прочее — невалидно.
type overlayOnlyPolicy struct{}

func (overlayOnlyPolicy) ValidateMode(mode string) error {
	switch mode {
	case "", storage.LockModeOverlay:
		return nil
	case storage.LockModeFileVault:
		return ErrLockModeUnavailable
	default:
		return ErrLockModeInvalid
	}
}

// RouterOption — расширение роутера enterprise-оверлеем (внутри authed-группы).
// RouterOption настраивает хендлер ДО объявления роутов.
//
// 🔴 Роутера в сигнатуре НЕТ намеренно. Пока он был, опция могла смонтировать
// роут прямо на переданный роутер — и ровно это уронило прод: опции стали
// применяться раньше, чем существуют группы, и WithOIDCService получил nil.
// Монтирование теперь возможно ТОЛЬКО через списки (WithPublicRoutes,
// WithRoutes, WithAdminRoutes, WithHumanAdminRoutes), которые NewRouter
// разворачивает каждый в своём месте. Класс ошибки закрыт типом, а не памятью.
type RouterOption func(*Handler)

// WithLockModePolicy заменяет дефолтную overlay-only политику (enterprise).
func WithLockModePolicy(p LockModePolicy) RouterOption {
	return func(h *Handler) { h.lockPolicy = p }
}

// WithReleasePubKey задаёт base64 ed25519 публичного ключа релиза; сервер отдаёт его
// агенту в enroll-ответе (release_pubkey). Универсальный (не привязанный к деплою)
// агент проверяет самообновление этим ключом вместо вшитого на сборке.
func WithReleasePubKey(key string) RouterOption {
	return func(h *Handler) { h.releasePubKey = key }
}

// Опции роутов не монтируют сразу, а КОПЯТ функции монтирования на хендлере:
// точек монтирования четыре (публичная, authed, admin, human-admin), и они
// объявлены в разных местах NewRouter. Раньше опции применялись одним проходом
// внутри authed-группы, поэтому публичной точки не существовало в принципе — а
// именно она нужна SSO: begin/acs идут ДО аутентификации, это и есть вход.
//
// Порядок сохранения = порядок монтирования: enterprise-оверлей передаёт опции
// списком, и его порядок обязан быть предсказуемым.

// WithPublicRoutes монтирует роуты ДО аутентификации (SSO-редиректы, приём
// assertion от IdP). Открывать здесь что-либо кроме входа нельзя.
func WithPublicRoutes(mount func(*Handler, chi.Router)) RouterOption {
	return func(h *Handler) { h.publicMounts = append(h.publicMounts, mount) }
}

// WithRoutes монтирует дополнительные роуты enterprise (напр. /escrow/status) в
// authed-группу (все роли).
func WithRoutes(mount func(*Handler, chi.Router)) RouterOption {
	return func(h *Handler) { h.authedMounts = append(h.authedMounts, mount) }
}

// WithAdminRoutes монтирует enterprise-роуты в подгруппу с гейтом it_admin (для
// мутирующих/чувствительных операций вроде применения лицензии). Инфраструктура
// (не enterprise-логика): open-core просто не передаёт таких опций.
func WithAdminRoutes(mount func(*Handler, chi.Router)) RouterOption {
	return func(h *Handler) { h.adminMounts = append(h.adminMounts, mount) }
}

// WithHumanAdminRoutes — как WithAdminRoutes, но дополнительно режет сервисные токены
// (requireHuman). Для операций, которые ВЫДАЮТ доступ: выгрузка заэскроенного
// recovery-ключа — это ключ от зашифрованного диска, автоматике такое не отдаём.
// Сам requireHuman не экспортируем: снаружи он бесполезен без claimsKey.
func WithHumanAdminRoutes(mount func(*Handler, chi.Router)) RouterOption {
	return func(h *Handler) { h.humanAdminMounts = append(h.humanAdminMounts, mount) }
}

// WithTelegramBotUsername отдаёт функцию, возвращающую @username бота этого деплоя
// (getMe). Функция, а не строка: getMe ходит в сеть и на старте может ещё не ответить.
func WithTelegramBotUsername(fn func(context.Context) string) RouterOption {
	return func(h *Handler) { h.telegramBotUsername = fn }
}
