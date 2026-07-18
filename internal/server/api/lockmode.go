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
type RouterOption func(*Handler, chi.Router)

// WithLockModePolicy заменяет дефолтную overlay-only политику (enterprise).
func WithLockModePolicy(p LockModePolicy) RouterOption {
	return func(h *Handler, _ chi.Router) { h.lockPolicy = p }
}

// WithReleasePubKey задаёт base64 ed25519 публичного ключа релиза; сервер отдаёт его
// агенту в enroll-ответе (release_pubkey). Универсальный (не привязанный к деплою)
// агент проверяет самообновление этим ключом вместо вшитого на сборке.
func WithReleasePubKey(key string) RouterOption {
	return func(h *Handler, _ chi.Router) { h.releasePubKey = key }
}

// WithRoutes монтирует дополнительные роуты enterprise (напр. /escrow/status) в
// authed-группу (все роли).
func WithRoutes(mount func(*Handler, chi.Router)) RouterOption {
	return func(h *Handler, r chi.Router) { mount(h, r) }
}

// WithAdminRoutes монтирует enterprise-роуты в подгруппу с гейтом it_admin (для
// мутирующих/чувствительных операций вроде применения лицензии). Инфраструктура
// (не enterprise-логика): open-core просто не передаёт таких опций.
func WithAdminRoutes(mount func(*Handler, chi.Router)) RouterOption {
	return func(h *Handler, r chi.Router) {
		r.Group(func(ar chi.Router) {
			ar.Use(h.requireRole("it_admin"))
			mount(h, ar)
		})
	}
}

// WithTelegramBotUsername отдаёт функцию, возвращающую @username бота этого деплоя
// (getMe). Функция, а не строка: getMe ходит в сеть и на старте может ещё не ответить.
func WithTelegramBotUsername(fn func(context.Context) string) RouterOption {
	return func(h *Handler, _ chi.Router) { h.telegramBotUsername = fn }
}
