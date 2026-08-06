package api

import "context"

// ScreenPurger — физическое удаление записей экрана. Реализуется enterprise-оверлеем
// (internal/server/screen); в open-core записей не существует, и хэндл остаётся nil.
//
// 🔴 Зачем отдельный шов, когда есть каскады в схеме. Каскад удаляет СТРОКИ: у
// screen_sessions FK на tenants и devices стоят ON DELETE CASCADE (миграция 067). Файлы
// записей лежат на диске и каскадом не удаляются ничем. То есть удаление устройства или
// тенанта уносило именно то, из чего можно узнать, какие файлы остались, — и запись
// экрана сотрудника оставалась на томе навсегда, уже без единой ссылки. §6 контракта
// требует обратного: персональные данные не остаются у прежнего контролёра и не
// переезжают к другому.
//
// Отсюда и порядок: purge ВСЕГДА до удаления/переноса строки, и его отказ отменяет всю
// операцию. Удалить устройство, не сумев удалить его записи, — худший из исходов:
// оператору сказали «удалено», а данные остались и стали неотслеживаемыми.
type ScreenPurger interface {
	// PurgeDevice — все записи одного устройства.
	PurgeDevice(ctx context.Context, tenantID, deviceID string) error
	// PurgeTenant — все записи тенанта (его устройства перестают существовать).
	PurgeTenant(ctx context.Context, tenantID string) error
}

// WithScreenPurger подключает enterprise-реализацию. Отдельной опции в
// composition-root нет намеренно: её ставит screen.Routes вместе с самими ручками —
// подключить удалённый стол и забыть про удаление его следов должно быть невозможно.
func WithScreenPurger(p ScreenPurger) RouterOption {
	return func(h *Handler) { h.screenPurge = p }
}

// purgeScreenDevice — записи устройства, если фича собрана. nil-purger в open-core
// означает «записей не бывает», а не «пропустить проверку».
func (h *Handler) purgeScreenDevice(ctx context.Context, tenantID, deviceID string) error {
	if h.screenPurge == nil {
		return nil
	}
	return h.screenPurge.PurgeDevice(ctx, tenantID, deviceID)
}

func (h *Handler) purgeScreenTenant(ctx context.Context, tenantID string) error {
	if h.screenPurge == nil {
		return nil
	}
	return h.screenPurge.PurgeTenant(ctx, tenantID)
}
