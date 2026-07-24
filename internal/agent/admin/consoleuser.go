package admin

import "sync"

// lastConsoleUser/lastConsoleSID — значения последней УСПЕШНОЙ пробы (см.
// ConsoleIdentity). Пара обновляется атомарно: SID обязан соответствовать
// именно тому логину, что уехал в console_user того же снимка.
var (
	consoleUserMu   sync.Mutex
	lastConsoleUser string
	lastConsoleSID  string
)

// ConsoleIdentity — текущий консольный пользователь для инвентаря одним
// снимком: (логин, SID). Логин в максимально сырой форме: Windows —
// DOMAIN\user (домен сохранён, см. osConsoleUserFull), macOS/Linux — имя
// учётки активного сеанса. ("", "") = за консолью никого.
//
// SID — стабильный идентификатор учётки для матча с каталогом (LDAP Phase 1):
// логин переименовывают, SID остаётся. Деривация СТРОГО от доложенного логина
// (osUserSID), не отдельной пробой сессии — две независимые пробы могли бы
// разъехаться (fast user switching), и SID уехал бы от другого пользователя,
// чем console_user. Есть только на Windows; на прочих ОС всегда "" (сервер
// деградирует на резолв логина/ручную привязку). Отказ резолва SID при живом
// логине тоже отдаёт (user, "") — best-effort, серверный fallback.
//
// При НЕУСПЕШНОЙ пробе возвращается последняя известная пара, а не пустота:
// сервер трактует "" как факт «за консолью никого» и пишет его в БД как есть
// (console_user — non-sticky поле upsert-а инвентаря), поэтому транзиентный
// сбой пробы (WMI/loginctl/stat) затирал бы реального пользователя до
// следующего успешного цикла. Настоящий логаут — успешная проба с пустым
// результатом — по-прежнему уходит как ("", "") и чистит оба поля.
//
// ВАЖНО (ПДн): логин и SID уходят в инвентарь устройства. На боевые машины
// сотрудников их выкатывают только после согласования с ИБ — это ограничение
// процесса деплоя, не кода (контракт хендоффа 2026-07-19).
func ConsoleIdentity() (user, sid string) {
	return consoleIdentityCached(osConsoleUserFull, osUserSID)
}

// consoleIdentityCached — логика last-known-good отдельно от платформенных
// проб, чтобы тест подставлял свои (в проде — всегда osConsoleUserFull +
// osUserSID). sidOf зовётся только при успешной пробе с непустым логином: на
// "" резолвить нечего, а при отказе пробы валиден только кэш.
func consoleIdentityCached(probe func() (string, bool), sidOf func(string) string) (string, string) {
	u, ok := probe()
	var sid string
	if ok && u != "" {
		sid = sidOf(u) // до захвата мьютекса: LSA-резолв не должен держать кэш
	}
	consoleUserMu.Lock()
	defer consoleUserMu.Unlock()
	if !ok {
		return lastConsoleUser, lastConsoleSID
	}
	lastConsoleUser, lastConsoleSID = u, sid
	return u, sid
}
