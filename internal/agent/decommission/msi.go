package decommission

import (
	"context"
	"log/slog"
)

// UnregisterSubcommand — имя подкоманды агента, снимающей MSI-регистрацию. Это
// КОНТРАКТ между build/msi/uninstall.bat и диспетчером в cmd/agent, и он живёт
// константой ровно поэтому: ренейм подкоманды без правки батника даёт в поле
// «неизвестная команда» и код 2, а снос при этом идёт дальше — то есть возвращается
// молчаливый провал того же класса, который эта команда и чинит. Контрактный тест
// (wxs_contract_test.go) сверяет батник с этой константой.
const UnregisterSubcommand = "msi-unregister"

// Коды возврата подкоманды. Их читает uninstall.bat и по ним печатает исход, поэтому
// они часть того же контракта. 2 намеренно НЕ используется: это код «неизвестная
// команда» из диспетчера cmd/agent — так батник отличает старый exe от отказа.
const (
	UnregisterExitOK     = 0 // регистрация снята либо её не было
	UnregisterExitFailed = 1 // снять не удалось — запись в ARP останется
	UnregisterExitReboot = 3 // регистрация снята, часть файлов уйдёт после перезагрузки
)

// Коды возврата msiexec. Пороговая трактовка bat-делетера (buildDeleterScript,
// `if errorlevel N`) вынужденно грубая: там 1619/1620 неотличимы от 3010 — оба
// «выходим». Здесь код точный, поэтому «продукта нет» (1605, штатный no-op) отделяется
// от «удаление провалилось» (1603). Источник — MsiExec.exe error messages Microsoft.
const (
	msiSuccess          = 0
	msiInstallFailure   = 1603
	msiUnknownProduct   = 1605 // продукта нет: снимать нечего
	msiProductUninstall = 1614 // продукт уже удалён — для нас то же самое
	msiInstallBusy      = 1618 // мьютекс _MSIExecute держит другая установка
	msiPackageOpenFail  = 1619 // кэшированный пакет в C:\Windows\Installer недоступен
	msiPackageInvalid   = 1620
	msiRebootInitiated  = 1641 // успех, установщик инициировал перезагрузку
	msiSafeBootDisabled = 1652 // Windows Installer недоступен в безопасном режиме
	msiRebootRequired   = 3010 // успех, занятые файлы удалятся после перезагрузки
)

// msiOutcome — трактовка кода возврата msiexec.
type msiOutcome int

const (
	msiOutcomeDone   msiOutcome = iota // продукт снят
	msiOutcomeGone                     // продукта уже не было — снимать нечего
	msiOutcomeReboot                   // снят, но часть файлов уйдёт после перезагрузки
	msiOutcomeBusy                     // установщик занят — повторить
	msiOutcomeFailed                   // не снят
)

// classifyMSIExit переводит код возврата msiexec в решение. Функция чистая и живёт без
// build-тега намеренно: именно здесь легче всего ошибиться в сторону молчаливого
// провала (посчитать 1605 отказом — и батник начнёт рапортовать «[ЧАСТИЧНО]» на каждой
// не-MSI установке; посчитать 1603 успехом — и ARP-хвост вернётся без единого сигнала),
// поэтому она проверяется табличным тестом на любой платформе, а не только в
// windows-джобе.
//
// 3010 и 1641 документированы Microsoft как УСПЕХ наравне с 0: удаление завершено,
// отложена только физическая чистка занятых файлов.
func classifyMSIExit(code int) msiOutcome {
	switch code {
	case msiSuccess:
		return msiOutcomeDone
	case msiUnknownProduct, msiProductUninstall:
		// Гонка между MsiEnumRelatedProducts и /x: продукт успели снять. Цель
		// достигнута — регистрации нет. 1614 (ERROR_PRODUCT_UNINSTALLED) означает ровно
		// то же самое и попал бы в отказ, заставив батник рапортовать «[ЧАСТИЧНО]» на
		// успешно снятой машине.
		return msiOutcomeGone
	case msiRebootRequired, msiRebootInitiated:
		return msiOutcomeReboot
	case msiInstallBusy:
		return msiOutcomeBusy
	default:
		return msiOutcomeFailed
	}
}

// msiExitHint переводит код возврата msiexec в подсказку оператору. Голое число в
// выводе батника бесполезно ровно так же, как молчание: администратор в безопасном
// режиме не пойдёт искать таблицу кодов Microsoft.
func msiExitHint(code int) string {
	switch code {
	case msiSafeBootDisabled:
		return "Windows Installer не работает в безопасном режиме — перезагрузитесь в ОБЫЧНЫЙ " +
			"режим и запустите снятие ещё раз, иначе запись в «Установка и удаление программ» останется"
	case msiPackageOpenFail, msiPackageInvalid:
		return "кэшированный пакет в C:\\Windows\\Installer недоступен или повреждён — " +
			"регистрацию придётся снять вручную"
	case msiInstallFailure:
		return "удаление завершилось фатальной ошибкой — повторите с логом: " +
			"msiexec /x {ProductCode} /qn /l*v %TEMP%\\routineops-msi.log"
	default:
		return "см. коды возврата msiexec в документации Microsoft"
	}
}

// MSIUnregisterResult — исход снятия MSI-регистрации.
type MSIUnregisterResult struct {
	// Found — продукт найден по стабильному UpgradeCode и снят. false — ручная/не-MSI
	// установка либо запись уже снята; это НЕ ошибка.
	Found bool
	// ProductCode найденного продукта (для лога); "" если не найден.
	ProductCode string
	// ExitCode — код возврата msiexec (0, если его не звали).
	ExitCode int
	// RebootNeeded — msiexec отдал 3010/1641: регистрация снята, но часть файлов была
	// занята и удалится после перезагрузки.
	RebootNeeded bool
}

// UnregisterMSI снимает ШТАТНУЮ MSI-установку агента: находит ProductCode по
// стабильному UpgradeCode (тот же resolveProductCode, что у самосноса) и выполняет
// `msiexec /x`. Вне Windows — no-op.
//
// 🔴 Зачем это отдельной командой, а не строчкой в uninstall.bat. Ручное снятие
// (остановить службу → снять файлы → почистить реестр) НЕ трогает регистрацию в
// Installer-БД: продукт остаётся числиться установленным, хотя на диске от него
// ничего нет. Следующая установка ТОГО ЖЕ пакета видит Installed=true, уходит в
// maintenance и не выполняет ни Launch-условие на обязательные свойства, ни
// EnrollExec — msiexec отдаёт 0, а на машине не появляется ни службы, ни сертов.
// Поймано в поле: молчаливый успех при нулевом результате.
//
// Батник намеренно не знает ни UpgradeCode, ни ProductCode, ни слова msiexec: поиск
// продукта по DisplayName в реестре разъезжается при ренейме, а `wmic product` на
// живой машине запускает переконфигурацию каждого установленного MSI. Единственный
// корректный способ — MsiEnumRelatedProducts по стабильному UpgradeCode, и он уже
// написан здесь же.
//
// Продукт не найден — Found=false, err=nil.
func UnregisterMSI(ctx context.Context, log *slog.Logger) (MSIUnregisterResult, error) {
	return unregisterMSI(ctx, log)
}
