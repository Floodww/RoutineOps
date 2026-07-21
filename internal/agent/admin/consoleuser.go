package admin

import "sync"

// lastConsoleUser — значение последней УСПЕШНОЙ пробы (см. ConsoleUser).
var (
	consoleUserMu   sync.Mutex
	lastConsoleUser string
)

// ConsoleUser — текущий консольный пользователь для инвентаря, в максимально
// сырой форме: Windows — DOMAIN\user (домен сохранён, см. osConsoleUserFull),
// macOS/Linux — имя учётки активного сеанса. "" = за консолью никого.
//
// При НЕУСПЕШНОЙ пробе возвращается последнее известное значение, а не "":
// сервер трактует "" как факт «за консолью никого» и пишет его в БД как есть
// (console_user — единственное non-sticky поле upsert-а инвентаря), поэтому
// транзиентный сбой пробы (WMI/loginctl/stat) затирал бы реального пользователя
// до следующего успешного цикла. Настоящий логаут — успешная проба с пустым
// результатом — по-прежнему уходит как "" и чистит поле.
//
// ВАЖНО (ПДн): поле уходит в инвентарь устройства. На боевые машины сотрудников
// его выкатывают только после согласования с ИБ — это ограничение процесса
// деплоя, не кода (контракт хендоффа 2026-07-19).
func ConsoleUser() string { return consoleUserCached(osConsoleUserFull) }

// consoleUserCached — логика last-known-good отдельно от платформенной пробы,
// чтобы тест подставлял свою (в проде probe — всегда osConsoleUserFull).
func consoleUserCached(probe func() (string, bool)) string {
	u, ok := probe()
	consoleUserMu.Lock()
	defer consoleUserMu.Unlock()
	if !ok {
		return lastConsoleUser
	}
	lastConsoleUser = u
	return u
}
